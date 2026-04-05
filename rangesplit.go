package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Range-split decision & execution.
//
// Detection (shouldSplit) is response-header-based: no URL extension list, no
// HEAD/Range probe. The first upstream request is a normal single-link forward
// (see forwardOrSplit in mitm.go). Its response headers — Content-Length (or
// Content-Range on 206), Accept-Ranges, Content-Encoding, Content-Type — tell
// us everything we need to decide whether to abort and re-fetch in parallel.
//
// Execution (splitAcrossLinks) divides the effective byte range across chunks,
// spawns one fetcher goroutine per chunk (each bound to a healthy Link's
// source IP, round-robin), and streams them back to the client in order
// through per-chunk bounded in-memory buffers. No temp files, no polling.

// rangeSplitThreshold is the minimum effective response size that justifies
// paying an extra RTT to launch N parallel connections. Below this, single
// link is faster.
const rangeSplitThreshold = 10 * 1024 * 1024 // 10 MB

// readSliceSize is the unit at which fetchers read from upstream and hand
// bytes to the drain goroutine through the buffered channel.
const readSliceSize = 64 * 1024

// splitDecision captures what shouldSplit learned from the initial response.
type splitDecision struct {
	effStart int64 // first absolute byte the client wants (0 if no client Range)
	effEnd   int64 // last absolute byte the client wants (inclusive)
	total    int64 // total file size (for Content-Range reply)
	// True if client sent a Range header — affects response status (206 vs 200)
	// and whether we emit a Content-Range header in the reply.
	clientSentRange bool
}

// shouldSplit inspects the upstream response of a single-link forward and
// decides whether to abort it and re-fetch across multiple links. Returns
// (decision, true) if yes.
//
// Signals that make us split:
//   - Method is GET
//   - Status is 200 OK (full body) or 206 Partial Content (server honored client Range)
//   - Content-Length (or Content-Range total) indicates >= rangeSplitThreshold bytes
//   - Accept-Ranges: bytes is advertised (server supports ranges)
//   - Content-Encoding is absent/identity (we can't reassemble compressed chunks)
//   - Content-Type is not a streaming/adaptive-player type
//   - The Balancer has >= 2 healthy links
func shouldSplit(req *http.Request, resp *http.Response, b *Balancer) (splitDecision, bool) {
	var d splitDecision
	if req.Method != http.MethodGet {
		return d, false
	}

	// Determine effective range + size first, so we only log rejection
	// reasons for responses that WERE size candidates. Silently skipping
	// a multi-hundred-MB download is the #1 "WTF why didn't it split"
	// case — logging the specific header that killed the decision lets
	// you point a finger at the server or your config immediately.
	switch resp.StatusCode {
	case http.StatusOK:
		if resp.ContentLength <= 0 {
			return d, false
		}
		d.total = resp.ContentLength
		d.effStart = 0
		d.effEnd = resp.ContentLength - 1
	case http.StatusPartialContent:
		s, e, total, ok := parseContentRange(resp.Header.Get("Content-Range"))
		if !ok || total <= 0 {
			return d, false
		}
		d.effStart = s
		d.effEnd = e
		d.total = total
		d.clientSentRange = req.Header.Get("Range") != ""
	default:
		return d, false
	}

	rangeSize := d.effEnd - d.effStart + 1
	if rangeSize < rangeSplitThreshold {
		return d, false
	}

	// From here on the response is a size candidate (>= threshold). Any
	// further rejection gets logged so the user can see WHY their big
	// download stayed on one link.
	logReject := func(reason string) {
		log.Printf("[mitm] no-split %s%s: %s (size=%s)",
			req.URL.Host, req.URL.Path, reason, humanBytes(rangeSize))
	}

	if healthy := b.HealthyLinks(); len(healthy) < 2 {
		logReject(fmt.Sprintf("only %d healthy link(s)", len(healthy)))
		return d, false
	}
	// Range support signal:
	//   - 200 response: require Accept-Ranges: bytes (server hasn't proven it yet)
	//   - 206 response: implicit (server just honored a Range request)
	if resp.StatusCode == http.StatusOK &&
		!strings.EqualFold(resp.Header.Get("Accept-Ranges"), "bytes") {
		logReject(fmt.Sprintf("no Accept-Ranges: bytes (got %q)", resp.Header.Get("Accept-Ranges")))
		return d, false
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		logReject(fmt.Sprintf("Content-Encoding=%q (cannot reassemble compressed body)", enc))
		return d, false
	}
	if ct := strings.ToLower(resp.Header.Get("Content-Type")); isStreamingContentType(ct) {
		logReject(fmt.Sprintf("streaming Content-Type=%q", ct))
		return d, false
	}
	return d, true
}

// humanBytes renders a byte count as a compact human-readable string
// (e.g. "42.3MB"). Used only in logs — never parsed.
func humanBytes(n int64) string {
	switch {
	case n >= 1024*1024*1024:
		return fmt.Sprintf("%.1fGB", float64(n)/(1024*1024*1024))
	case n >= 1024*1024:
		return fmt.Sprintf("%.1fMB", float64(n)/(1024*1024))
	case n >= 1024:
		return fmt.Sprintf("%.1fKB", float64(n)/1024)
	}
	return fmt.Sprintf("%dB", n)
}

// isStreamingContentType matches content-types where parallel range chunks
// would break adaptive players. Explicitly does NOT match
// "application/octet-stream" (the default for opaque binary downloads).
func isStreamingContentType(ct string) bool {
	if strings.HasPrefix(ct, "video/") || strings.HasPrefix(ct, "audio/") {
		return true
	}
	return ct == "text/event-stream" ||
		strings.HasPrefix(ct, "application/x-mpegurl") ||
		strings.HasPrefix(ct, "application/vnd.apple.mpegurl") ||
		strings.HasPrefix(ct, "application/dash+xml") ||
		strings.HasPrefix(ct, "application/vnd.ms-sstr+xml")
}

// parseContentRange parses an HTTP Content-Range header of the form
// "bytes X-Y/Z" or "bytes X-Y/*". Returns (start, end, total, ok).
// A total of "*" yields total=-1, ok=true.
func parseContentRange(cr string) (start, end, total int64, ok bool) {
	cr = strings.TrimSpace(strings.TrimPrefix(cr, "bytes "))
	slash := strings.IndexByte(cr, '/')
	if slash < 0 {
		return 0, 0, 0, false
	}
	rangePart, totalPart := cr[:slash], cr[slash+1:]
	dash := strings.IndexByte(rangePart, '-')
	if dash < 0 {
		return 0, 0, 0, false
	}
	s, err := strconv.ParseInt(rangePart[:dash], 10, 64)
	if err != nil {
		return 0, 0, 0, false
	}
	e, err := strconv.ParseInt(rangePart[dash+1:], 10, 64)
	if err != nil || e < s {
		return 0, 0, 0, false
	}
	if totalPart == "*" {
		return s, e, -1, true
	}
	t, err := strconv.ParseInt(totalPart, 10, 64)
	if err != nil {
		return 0, 0, 0, false
	}
	return s, e, t, true
}

// chunkTargetSize is the nominal per-chunk size. Small enough that a fast
// link naturally pulls more chunks than a slow link off the shared work
// queue (self-balancing under asymmetric link speeds); large enough to
// amortize HTTP/range-request overhead and keep the number of temp spool
// files manageable.
const chunkTargetSize = 32 * 1024 * 1024 // 32 MB

// maxChunks caps the number of chunks (and therefore temp files) for very
// large downloads. For a 100 GB download this yields chunks of ~200 MB
// instead of 3200 tiny files.
const maxChunks = 512

// workersPerLink is the number of concurrent range-fetcher goroutines we
// run per healthy link. Each worker pulls chunks from the shared queue.
// 4 is a pragmatic compromise: enough parallelism per link to saturate a
// typical mobile/tether connection, few enough to avoid per-host connection
// limits or server-side rate-limits.
const workersPerLink = 4

// computeChunks picks a chunk count based on the byte range size. Target a
// fixed ~32 MB per chunk so we get many chunks — more chunks means finer-
// grained work-stealing on the shared queue, which is what lets a fast link
// naturally take ~2x the work of a slow link without any explicit weighting.
//
// Minimum of 2 (must be splittable), maximum of maxChunks (bounds temp-file
// count for huge downloads).
func computeChunks(size int64, numLinks int) int {
	_ = numLinks // unused; kept for call-site compat
	n := int(size / chunkTargetSize)
	if size%chunkTargetSize != 0 {
		n++
	}
	if n < 2 {
		n = 2
	}
	if n > maxChunks {
		n = maxChunks
	}
	return n
}

// bufferSlots returns the per-chunk in-memory buffer depth in units of
// readSliceSize slices. Scales with chunk size, clamped to a sane RAM budget.
// Typical: 2 MB floor, 16 MB ceiling per chunk.
func bufferSlots(chunkSize int64) int {
	budget := chunkSize / 4
	const floor = 2 * 1024 * 1024
	const ceil = 16 * 1024 * 1024
	if budget < floor {
		budget = floor
	}
	if budget > ceil {
		budget = ceil
	}
	return int(budget / readSliceSize)
}

// splitAcrossLinks performs the parallel-fetch + in-order stream. It's called
// by forwardOrSplit (in mitm.go) after the single-link probe response has
// revealed the file is a range-split candidate. The initial response body
// must have already been drained/closed by the caller.
//
// Response headers to clone to the client (scheme+host already set) are
// carried in hdrs. We strip hop-by-hop, Content-Range, Content-Length and set
// our own.
func splitAcrossLinks(w http.ResponseWriter, req *http.Request, hdrs http.Header, d splitDecision, b *Balancer, recent *RecentConns) {
	healthy := b.HealthyLinks()

	// Verification probe: do a tiny Range: bytes=0-0 to confirm the server's
	// advertised total. Catches the case where a 200-OK Content-Length lied
	// (or pointed at a file the server was still writing). One extra RTT,
	// reuses the existing transport/h2 connection, cheap insurance against
	// blowing hours on a bad size.
	if actualTotal, ok := probeTotalSize(req, healthy[0]); ok && actualTotal != d.total {
		log.Printf("[mitm] split %s%s: probe total=%d differs from advertised=%d — adjusting",
			req.URL.Host, req.URL.Path, actualTotal, d.total)
		if d.effEnd >= actualTotal {
			d.effEnd = actualTotal - 1
		}
		if d.effStart >= actualTotal {
			http.Error(w, "mergenet: requested range beyond actual file size", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		d.total = actualTotal
	}

	rangeSize := d.effEnd - d.effStart + 1
	numChunks := computeChunks(rangeSize, len(healthy))
	chunkSize := rangeSize / int64(numChunks)
	slots := bufferSlots(chunkSize)

	// Snapshot per-link byte counters so we can report the delta at the
	// end — answers "was the download actually spread across both links?"
	// at a single glance without cross-referencing the TUI.
	t0 := time.Now()
	byteSnapshot := make(map[string]int64, len(healthy))
	linkNames := make([]string, 0, len(healthy))
	for _, l := range healthy {
		byteSnapshot[l.Name] = atomic.LoadInt64(&l.BytesIn)
		linkNames = append(linkNames, l.Name)
	}
	perLinkSummary := func() string {
		parts := make([]string, 0, len(healthy))
		for _, l := range healthy {
			delta := atomic.LoadInt64(&l.BytesIn) - byteSnapshot[l.Name]
			parts = append(parts, fmt.Sprintf("%s=%s", l.Name, humanBytes(delta)))
		}
		return strings.Join(parts, " ")
	}

	log.Printf("[mitm] split %s%s: bytes %d-%d/%d (%s) in %d chunks (~%s each) over %d links [%s] %d workers/link",
		req.URL.Host, req.URL.Path, d.effStart, d.effEnd, d.total, humanBytes(rangeSize),
		numChunks, humanBytes(chunkSize), len(healthy), strings.Join(linkNames, ","), workersPerLink)
	_ = slots

	// Copy upstream headers minus hop-by-hop and length/range we override.
	for k, vs := range hdrs {
		if isHopByHop(k) ||
			strings.EqualFold(k, "Content-Length") ||
			strings.EqualFold(k, "Content-Range") {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Length", strconv.FormatInt(rangeSize, 10))
	status := http.StatusOK
	if d.clientSentRange {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", d.effStart, d.effEnd, d.total))
		status = http.StatusPartialContent
	}
	w.WriteHeader(status)
	flushIfPossible(w)

	// Per-chunk bounded channels. Context cancel propagates client disconnect
	// or fetcher error to all fetchers so we don't keep downloading bytes the
	// client will never consume.
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()

	bufs := make([]*chunkBuf, numChunks)
	for i := range bufs {
		bufs[i] = newChunkBuf(slots)
	}
	// Ensure temp files are removed no matter how we exit (success, client
	// disconnect, fetcher error). close() also wakes any blocked drainTo.
	defer func() {
		for _, b := range bufs {
			b.close()
		}
	}()
	// Precompute each chunk's byte range. We do NOT pre-assign a link —
	// chunks sit in a shared work queue and any worker on any link may
	// claim them. This is the key to handling asymmetric link speeds: a
	// 2x-faster link naturally pulls ~2x more chunks off the queue than
	// a slow link, so both links finish at roughly the same time instead
	// of the fast link going idle after its pre-assigned share.
	starts := make([]int64, numChunks)
	ends := make([]int64, numChunks)
	for i := 0; i < numChunks; i++ {
		starts[i] = d.effStart + int64(i)*chunkSize
		ends[i] = starts[i] + chunkSize - 1
		if i == numChunks-1 {
			ends[i] = d.effEnd
		}
	}

	// Work queue. Pre-filled with every chunk index; workers range-read
	// until empty. Close happens after the loop below enqueues all indices.
	queue := make(chan int, numChunks)
	for i := 0; i < numChunks; i++ {
		queue <- i
	}
	close(queue)

	// Per-link worker pool. Each worker is PERMANENTLY bound to its link
	// (no chunk migration between links), so once a chunk is claimed by a
	// worker on linkX it is fetched via linkX with retries on that same
	// link. If the link is completely dead, fetchChunk exhausts its
	// attempts, cancel() fires, and the drain bails with an error — we do
	// not silently re-route the chunk to the other link and collapse the
	// split to a single link's throughput.
	var fetcherErr atomic.Value // first worker error, for logging
	var wg sync.WaitGroup
	for _, link := range healthy {
		for w := 0; w < workersPerLink; w++ {
			wg.Add(1)
			go func(link *Link, workerID int) {
				defer wg.Done()
				for idx := range queue {
					if ctx.Err() != nil {
						return
					}
					fetchChunk(ctx, req, b, link, starts[idx], ends[idx], bufs[idx], recent)
					// fetchChunk stores its own terminal error in the
					// spool's err field; drainTo surfaces it. We also
					// record the FIRST error here just for logging.
					if e := bufs[idx].getErr(); e != nil && fetcherErr.Load() == nil {
						fetcherErr.Store(e)
					}
				}
			}(link, w)
		}
	}
	// When all workers exit (queue drained + all in-flight chunks done or
	// failed), we're done producing. The drain goroutine may still be
	// streaming — it exits on its own when it reaches the last chunk.
	go func() { wg.Wait() }()

	// Drain in order. First write failure or fetcher error cancels the rest.
	var delivered int64
	for i := 0; i < numChunks; i++ {
		n, err := bufs[i].drainTo(w)
		delivered += n
		if err != nil {
			log.Printf("[mitm] split %s%s: chunk %d drain err=%v — delivered %s/%s in %s — per-link %s (TRUNCATED)",
				req.URL.Host, req.URL.Path, i, err, humanBytes(delivered), humanBytes(rangeSize),
				time.Since(t0).Truncate(time.Millisecond), perLinkSummary())
			cancel()
			return
		}
	}
	flushIfPossible(w)
	elapsed := time.Since(t0).Truncate(time.Millisecond)
	rate := "-"
	if secs := elapsed.Seconds(); secs > 0.01 {
		rate = fmt.Sprintf("%.1fMB/s", float64(delivered)/(1024*1024)/secs)
	}
	if delivered != rangeSize {
		log.Printf("[mitm] split %s%s: MISMATCH delivered=%s expected=%s in %s @ %s — per-link %s (file will be truncated)",
			req.URL.Host, req.URL.Path, humanBytes(delivered), humanBytes(rangeSize),
			elapsed, rate, perLinkSummary())
	} else {
		log.Printf("[mitm] split %s%s: DONE delivered=%s in %s @ %s — per-link %s",
			req.URL.Host, req.URL.Path, humanBytes(delivered), elapsed, rate, perLinkSummary())
	}
}

// probeTotalSize asks the server for bytes=0-0 and parses the Content-Range
// total. Returns (total, true) on success. Used to cross-check an advertised
// Content-Length before committing to N parallel range requests.
func probeTotalSize(base *http.Request, link *Link) (int64, bool) {
	ctx, cancel := context.WithTimeout(base.Context(), 10*time.Second)
	defer cancel()
	outReq := base.Clone(ctx)
	outReq.Method = http.MethodGet
	outReq.Body = nil
	outReq.RequestURI = ""
	outReq.Header = base.Header.Clone()
	outReq.Header.Set("Range", "bytes=0-0")
	outReq.Header.Del("Content-Length")
	client := &http.Client{Transport: linkTransport(link), Timeout: 15 * time.Second}
	resp, err := client.Do(outReq)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusPartialContent {
		return 0, false
	}
	_, _, total, ok := parseContentRange(resp.Header.Get("Content-Range"))
	if !ok || total <= 0 {
		return 0, false
	}
	return total, true
}

// ----- chunkBuf: disk-spooled byte pipeline -------------------------------

// chunkBuf carries bytes from one chunk's fetcher to the drain goroutine
// via a temp file. Fetcher appends to the file, drain reads from it (via a
// separate fd) and streams to the client. A sync.Cond signals "new bytes
// available" / "fetcher finished".
//
// Why disk instead of a bounded in-memory channel? The drain writes chunks
// to the client in strict order (0, 1, 2, ...), so with an in-memory cap
// every non-head chunk is bottlenecked at (cap) bytes regardless of how fast
// its link can fetch. For multi-GB downloads that causes head-of-line
// blocking: only one chunk makes progress at a time, and each link alternates
// between active and idle instead of both running at full speed.
//
// With a disk spool the fetcher is never blocked on back-pressure from the
// drain, so every chunk on every link keeps downloading at full link speed.
// The caller (splitAcrossLinks) is responsible for calling close() to remove
// the temp file.
type chunkBuf struct {
	writeF *os.File // append-only write fd
	readF  *os.File // separate read fd, advances independently
	path   string   // temp file path (for cleanup)

	mu      sync.Mutex
	cond    *sync.Cond
	written int64 // total bytes appended by fetcher
	done    bool  // fetcher called finish()
	err     error // fetcher's terminal error, if any
	closed  bool  // close() was called; drain should exit
}

// newChunkBuf creates a new disk-backed spool. The slots parameter is kept
// for API compatibility but ignored — the spool is bounded by disk, not RAM.
func newChunkBuf(slots int) *chunkBuf {
	_ = slots
	f, err := os.CreateTemp("", "mergenet-chunk-*.tmp")
	if err != nil {
		panic(fmt.Sprintf("mergenet: create temp spool: %v", err))
	}
	rf, err := os.OpenFile(f.Name(), os.O_RDONLY, 0)
	if err != nil {
		f.Close()
		os.Remove(f.Name())
		panic(fmt.Sprintf("mergenet: open temp spool for read: %v", err))
	}
	c := &chunkBuf{writeF: f, readF: rf, path: f.Name()}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// push appends p to the spool. Returns ctx.Err() if context is cancelled.
func (c *chunkBuf) push(ctx context.Context, p []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n, werr := c.writeF.Write(p)
	if n > 0 {
		c.mu.Lock()
		c.written += int64(n)
		c.mu.Unlock()
		c.cond.Broadcast()
	}
	if werr != nil {
		return fmt.Errorf("spool write: %w", werr)
	}
	return nil
}

// finish signals that the fetcher has stopped producing data. Must be called
// exactly once by fetchChunk at the end of its lifetime.
func (c *chunkBuf) finish(err error) {
	c.mu.Lock()
	c.done = true
	if err != nil && c.err == nil {
		c.err = err
	}
	c.mu.Unlock()
	c.cond.Broadcast()
}

// setErr / getErr preserved for test compatibility.
func (c *chunkBuf) setErr(err error) {
	c.mu.Lock()
	if err != nil {
		c.err = err
	}
	c.mu.Unlock()
}
func (c *chunkBuf) getErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// drainTo streams the spool to w, blocking until the fetcher finishes.
// Returns bytes delivered and the first write error OR the fetcher's
// terminal error after a successful drain.
func (c *chunkBuf) drainTo(w io.Writer) (int64, error) {
	var delivered int64
	rbuf := make([]byte, 128*1024)
	for {
		c.mu.Lock()
		for c.written == delivered && !c.done && !c.closed {
			c.cond.Wait()
		}
		avail := c.written - delivered
		done := c.done
		closed := c.closed
		terr := c.err
		c.mu.Unlock()

		if closed {
			return delivered, fmt.Errorf("spool closed")
		}

		for avail > 0 {
			toRead := int64(len(rbuf))
			if toRead > avail {
				toRead = avail
			}
			n, rerr := c.readF.Read(rbuf[:toRead])
			if n > 0 {
				nw, werr := w.Write(rbuf[:n])
				delivered += int64(nw)
				avail -= int64(n)
				if werr != nil {
					return delivered, werr
				}
				if nw != n {
					return delivered, io.ErrShortWrite
				}
			}
			if rerr != nil {
				return delivered, fmt.Errorf("spool read: %w", rerr)
			}
		}

		if done {
			// Re-check written under lock: fetcher may have appended more
			// right before calling finish().
			c.mu.Lock()
			final := c.written
			c.mu.Unlock()
			if delivered >= final {
				return delivered, terr
			}
			// Loop again; there are more bytes to drain.
		}
	}
}

// close releases spool resources and deletes the temp file. Safe to call
// concurrently with a blocked drainTo — it will wake drain with an error.
func (c *chunkBuf) close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.cond.Broadcast()
	c.writeF.Close()
	c.readF.Close()
	os.Remove(c.path)
}

// maxChunkAttempts is the per-chunk retry budget. A retry opens a fresh TCP
// connection on the SAME link and resumes from the last byte we successfully
// pushed downstream. We deliberately do NOT migrate the chunk to the other
// link: transient failures (h2 GOAWAY, idle-kill, mid-body RST, server short
// response) are almost always fixed by a fresh connection on the same
// interface, and staying put preserves the per-chunk link assignment so
// parallel downloads actually use BOTH interfaces instead of collapsing to
// whichever link answers retries fastest.
const maxChunkAttempts = 5

// fetchChunk GETs bytes=start-end from upstream and pushes read slices into
// buf. Resilient to mid-transfer failures: tracks bytes pushed, on error it
// re-issues Range: bytes=(start+pushed)-(end) on the SAME link and continues.
// The drainer never sees the retry — bytes arrive in order.
//
// Bounded by maxChunkAttempts; beyond that the chunk fails and the whole
// download aborts (client gets a truncated body unless it resumes).
func fetchChunk(ctx context.Context, base *http.Request, b *Balancer, initial *Link, start, end int64, buf *chunkBuf, recent *RecentConns) {
	var terminalErr error
	defer func() {
		buf.finish(terminalErr)
	}()

	// Pushed = total bytes successfully handed to drain so far. Always
	// restart from (start + pushed).
	var pushed int64
	link := initial

	for attempt := 0; attempt < maxChunkAttempts; attempt++ {
		if ctx.Err() != nil {
			terminalErr = ctx.Err()
			return
		}
		if attempt > 0 {
			// Exponential backoff: 100ms, 200ms, 400ms, 800ms
			delay := time.Duration(100*(1<<uint(attempt-1))) * time.Millisecond
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				terminalErr = ctx.Err()
				return
			}
			log.Printf("[mitm] chunk %d-%d retry %d via %s (pushed=%d)", start, end, attempt, link.Name, pushed)
		}

		t0 := time.Now()
		err := fetchChunkOnce(ctx, base, link, start+pushed, end, buf, recent, &pushed)
		if err == nil {
			log.Printf("[mitm] chunk %d-%d via %s: OK (%d B in %s)",
				start, end, link.Name, end-start+1, time.Since(t0).Truncate(time.Millisecond))
			return // chunk complete
		}
		if ctx.Err() != nil {
			terminalErr = ctx.Err()
			return
		}
		log.Printf("[mitm] chunk %d-%d via %s failed (pushed=%d/%d): %v", start, end, link.Name, pushed, end-start+1, err)
	}
	terminalErr = fmt.Errorf("chunk %d-%d: exhausted %d attempts on %s", start, end, maxChunkAttempts, link.Name)
}

// fetchChunkOnce does one attempt at fetching [curStart, end] via link.
// Pushes each read slice to buf, incrementing *pushed atomically through
// caller so retries resume from the correct offset.
// Returns nil on success, or an error describing where it failed.
func fetchChunkOnce(ctx context.Context, base *http.Request, link *Link, curStart, end int64, buf *chunkBuf, recent *RecentConns, pushed *int64) error {
	atomic.AddInt64(&link.ActiveConns, 1)
	atomic.AddInt64(&link.TotalConns, 1)
	defer atomic.AddInt64(&link.ActiveConns, -1)

	outReq := base.Clone(ctx)
	outReq.Method = http.MethodGet
	outReq.Body = nil
	outReq.RequestURI = ""
	outReq.Header = base.Header.Clone()
	outReq.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", curStart, end))
	outReq.Header.Del("Content-Length")

	client := &http.Client{Transport: linkTransport(link), Timeout: 0}
	resp, err := client.Do(outReq)
	if err != nil {
		return fmt.Errorf("dial/request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	// Cross-check the Content-Range total against our decision's total so a
	// single lying/wrong server reply can't silently poison the whole download.
	if cr := resp.Header.Get("Content-Range"); cr != "" {
		if _, _, total, ok := parseContentRange(cr); ok && total > 0 {
			if end >= total {
				return fmt.Errorf("content-range total=%d < requested end=%d (file shorter than advertised)", total, end)
			}
		}
	}

	expected := end - curStart + 1
	var fetched int64
	for {
		slice := make([]byte, readSliceSize)
		n, rerr := resp.Body.Read(slice)
		if n > 0 {
			atomic.AddInt64(&link.BytesIn, int64(n))
			if perr := buf.push(ctx, slice[:n]); perr != nil {
				return perr // context cancelled — drain gave up, don't retry
			}
			fetched += int64(n)
			*pushed += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fmt.Errorf("read: %w", rerr)
		}
	}
	// Verify byte count — EOF alone is NOT proof of completion. A short 206
	// body (server-clamped range, mid-transfer reset silently treated as EOF,
	// etc.) would otherwise silently truncate the final file.
	if fetched != expected {
		return fmt.Errorf("short read: got %d bytes, expected %d (bytes=%d-%d)",
			fetched, expected, curStart, end)
	}
	recent.Add(ConnRecord{Ts: time.Now(), Link: link.Name, Target: fmt.Sprintf("range %d-%d (%d B)", curStart, end, fetched)})
	return nil
}

