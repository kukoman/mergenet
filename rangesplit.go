package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
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
	if len(b.HealthyLinks()) < 2 {
		return d, false
	}

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
	// Range support signal:
	//   - 200 response: require Accept-Ranges: bytes (server hasn't proven it yet)
	//   - 206 response: implicit (server just honored a Range request)
	if resp.StatusCode == http.StatusOK &&
		!strings.EqualFold(resp.Header.Get("Accept-Ranges"), "bytes") {
		return d, false
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		return d, false
	}
	if isStreamingContentType(strings.ToLower(resp.Header.Get("Content-Type"))) {
		return d, false
	}
	return d, true
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

// computeChunks picks a chunk count based on the byte range size and the
// number of healthy links. Rule of thumb: more streams on bigger files
// to overcome per-flow throughput caps on mobile/tether links.
//
//	< 50 MB        -> 1 stream per link
//	< 500 MB       -> 2 streams per link
//	>= 500 MB      -> 4 streams per link
//
// Clamped to [2, 16] and constrained so each chunk is at least 2 MB.
func computeChunks(size int64, numLinks int) int {
	if numLinks < 1 {
		numLinks = 1
	}
	perLink := 1
	switch {
	case size >= 500*1024*1024:
		perLink = 4
	case size >= 50*1024*1024:
		perLink = 2
	}
	n := numLinks * perLink
	if n < 2 {
		n = 2
	}
	if n > 16 {
		n = 16
	}
	// Ensure each chunk is >= 2 MB to avoid tiny-chunk overhead.
	const minChunkBytes = 2 * 1024 * 1024
	for n > 2 && size/int64(n) < minChunkBytes {
		n--
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

	log.Printf("[mitm] split %s%s: bytes %d-%d/%d (%d B) in %d chunks over %d links (buf=%dx%dKB/chunk)",
		req.URL.Host, req.URL.Path, d.effStart, d.effEnd, d.total, rangeSize, numChunks, len(healthy), slots, readSliceSize/1024)

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
	for i := 0; i < numChunks; i++ {
		start := d.effStart + int64(i)*chunkSize
		end := start + chunkSize - 1
		if i == numChunks-1 {
			end = d.effEnd
		}
		link := healthy[i%len(healthy)]
		log.Printf("[mitm] chunk %d: bytes=%d-%d (%d B) → %s", i, start, end, end-start+1, link.Name)
		go fetchChunk(ctx, req, b, link, start, end, bufs[i], recent)
	}

	// Drain in order. First write failure or fetcher error cancels the rest.
	var delivered int64
	for i := 0; i < numChunks; i++ {
		n, err := bufs[i].drainTo(w)
		delivered += n
		if err != nil {
			log.Printf("[mitm] split %s%s: chunk %d drain err=%v — delivered %d/%d bytes (TRUNCATED)",
				req.URL.Host, req.URL.Path, i, err, delivered, rangeSize)
			cancel()
			return
		}
	}
	flushIfPossible(w)
	if delivered != rangeSize {
		log.Printf("[mitm] split %s%s: MISMATCH delivered=%d expected=%d (file will be truncated)",
			req.URL.Host, req.URL.Path, delivered, rangeSize)
	} else {
		log.Printf("[mitm] split %s%s: DONE delivered=%d bytes", req.URL.Host, req.URL.Path, delivered)
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

// ----- chunkBuf: bounded in-memory byte pipeline --------------------------

// chunkBuf carries bytes from one chunk's fetcher to the drain goroutine
// via a bounded buffered channel. Fetcher owns the writer end, drain owns
// the reader end. The channel's capacity imposes backpressure — when full,
// the fetcher blocks until drain consumes slices. No disk, no polling.
type chunkBuf struct {
	data chan []byte  // nil-terminated by close(data)
	err  atomic.Value // stored as error on fetcher failure
}

func newChunkBuf(slots int) *chunkBuf {
	if slots < 2 {
		slots = 2
	}
	return &chunkBuf{data: make(chan []byte, slots)}
}

// push sends a slice to the drain goroutine, or returns ctx.Err() if cancelled.
// The slice must not be reused by the caller after push returns nil.
func (c *chunkBuf) push(ctx context.Context, p []byte) error {
	select {
	case c.data <- p:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// setErr stores the fetcher's terminal error. Called before close(c.data).
func (c *chunkBuf) setErr(err error) {
	if err != nil {
		c.err.Store(err)
	}
}

// getErr returns the stored fetcher error, or nil.
func (c *chunkBuf) getErr() error {
	if v := c.err.Load(); v != nil {
		return v.(error)
	}
	return nil
}

// drainTo writes all pushed slices to w until the fetcher closes the channel.
// Returns bytes written and the first write error OR the fetcher error after
// successful drain.
func (c *chunkBuf) drainTo(w io.Writer) (int64, error) {
	var written int64
	for slice := range c.data {
		n, err := w.Write(slice)
		written += int64(n)
		if err != nil {
			// Drain remaining slices to unblock the fetcher (which may
			// still be holding on a full channel), then bail.
			go func() {
				for range c.data {
				}
			}()
			return written, err
		}
	}
	return written, c.getErr()
}

// maxChunkAttempts is the per-chunk retry budget. On each failure we switch
// to a different healthy link (if available) and resume from the last byte
// we successfully pushed downstream.
const maxChunkAttempts = 5

// fetchChunk GETs bytes=start-end from upstream and pushes read slices into
// buf. Resilient to mid-transfer failures: tracks bytes pushed, on TCP error
// it re-issues Range: bytes=(start+pushed)-(end) on a different healthy link
// and continues. The drainer never sees the retry — bytes arrive in order.
//
// Bounded by maxChunkAttempts; beyond that the chunk fails and the whole
// download aborts (client gets a truncated body unless it resumes).
func fetchChunk(ctx context.Context, base *http.Request, b *Balancer, initial *Link, start, end int64, buf *chunkBuf, recent *RecentConns) {
	var terminalErr error
	defer func() {
		buf.setErr(terminalErr)
		close(buf.data)
	}()

	// Pushed = total bytes successfully handed to drain so far. Always
	// restart from (start + pushed).
	var pushed int64
	link := initial
	lastFailed := (*Link)(nil)

	for attempt := 0; attempt < maxChunkAttempts; attempt++ {
		if ctx.Err() != nil {
			terminalErr = ctx.Err()
			return
		}
		// On retry, switch to any healthy link that isn't the one that just failed.
		if attempt > 0 {
			link = pickAlternative(b, lastFailed)
			if link == nil {
				terminalErr = fmt.Errorf("chunk %d-%d: no healthy links left after %d attempts", start, end, attempt)
				return
			}
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
		lastFailed = link
		log.Printf("[mitm] chunk %d-%d via %s failed (pushed=%d/%d): %v", start, end, link.Name, pushed, end-start+1, err)
	}
	terminalErr = fmt.Errorf("chunk %d-%d: exhausted %d attempts", start, end, maxChunkAttempts)
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

// pickAlternative returns any healthy link that isn't `avoid`. Falls back to
// `avoid` itself if it's the only remaining healthy link (better to retry
// there than give up). Returns nil if nothing is healthy.
func pickAlternative(b *Balancer, avoid *Link) *Link {
	healthy := b.HealthyLinks()
	if len(healthy) == 0 {
		return nil
	}
	for _, l := range healthy {
		if l != avoid {
			return l
		}
	}
	return healthy[0] // only `avoid` is healthy — retry on it anyway
}
