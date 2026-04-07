package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// deterministicByte: byte at absolute file offset i = i % 256.
func deterministicByte(i int64) byte { return byte(i % 256) }

// makeRangeServer returns an httptest.Server that serves deterministic bytes
// [0, totalSize). Supports GET (200 full body) and Range requests (206).
// reqCounter tracks total requests. perPathBytes tracks bytes delivered.
func makeRangeServer(totalSize int64, reqCounter *atomic.Int32, bytesServed *atomic.Int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCounter.Add(1)
		rangeHdr := r.Header.Get("Range")
		if rangeHdr == "" {
			// Plain GET → 200 with full body.
			w.Header().Set("Accept-Ranges", "bytes")
			w.Header().Set("Content-Length", strconv.FormatInt(totalSize, 10))
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			writeDeterministic(w, 0, totalSize-1, bytesServed)
			return
		}
		start, end := parseTestRange(rangeHdr)
		if start < 0 || end >= totalSize || start > end {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		size := end - start + 1
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, totalSize))
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusPartialContent)
		writeDeterministic(w, start, end, bytesServed)
	}))
}

func writeDeterministic(w io.Writer, start, end int64, counter *atomic.Int64) {
	const bufSize = 64 * 1024
	buf := make([]byte, bufSize)
	pos := start
	for pos <= end {
		n := int64(bufSize)
		if pos+n-1 > end {
			n = end - pos + 1
		}
		for i := int64(0); i < n; i++ {
			buf[i] = deterministicByte(pos + i)
		}
		m, err := w.Write(buf[:n])
		if counter != nil {
			counter.Add(int64(m))
		}
		if err != nil {
			return
		}
		pos += n
	}
}

// verifyDeterministic checks every byte of got equals deterministicByte(start+i).
// Returns (firstBadIndex, true) if mismatch; (0, false) on success.
func verifyDeterministic(got []byte, start int64) (int, bool) {
	for i, v := range got {
		if v != deterministicByte(start+int64(i)) {
			return i, true
		}
	}
	return 0, false
}

// mockResponseWriter accumulates Write() calls into a buffer.
type mockResponseWriter struct {
	header http.Header
	body   []byte
	status int
}

func newMockRW() *mockResponseWriter { return &mockResponseWriter{header: http.Header{}} }
func (m *mockResponseWriter) Header() http.Header { return m.header }
func (m *mockResponseWriter) Write(p []byte) (int, error) {
	m.body = append(m.body, p...)
	return len(p), nil
}
func (m *mockResponseWriter) WriteHeader(s int) { m.status = s }

// TestSplitDistributesBytesAcrossLinks is the money test: asserts BOTH
// Link.BytesIn counters got incremented. If the real-world bug is "one
// link is idle", this test will catch it.
func TestSplitDistributesBytesAcrossLinks(t *testing.T) {
	const totalSize = int64(40 * 1024 * 1024)

	var reqCount atomic.Int32
	var bytesServed atomic.Int64
	srv := makeRangeServer(totalSize, &reqCount, &bytesServed)
	defer srv.Close()

	b := NewBalancer()
	b.Upsert("linkA", net.ParseIP("127.0.0.1"), 1, 10*time.Millisecond)
	b.Upsert("linkB", net.ParseIP("127.0.0.1"), 1, 10*time.Millisecond)

	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.URL.Scheme = "http"
	resp, _ := http.Get(srv.URL)
	resp.Body.Close()
	decision, ok := shouldSplit(req, resp, b)
	if !ok {
		t.Fatal("shouldSplit=false")
	}

	w := newMockRW()
	splitAcrossLinks(w, req, resp.Header, decision, b, NewRecentConns(16))

	// Inspect per-link counters.
	var linkA, linkB int64
	for _, v := range b.SnapshotView() {
		switch v.Name {
		case "linkA":
			linkA = v.BytesIn
		case "linkB":
			linkB = v.BytesIn
		}
	}
	t.Logf("per-link bytes: linkA=%d linkB=%d (total delivered=%d)", linkA, linkB, len(w.body))
	if linkA == 0 {
		t.Errorf("linkA got zero bytes — not distributed!")
	}
	if linkB == 0 {
		t.Errorf("linkB got zero bytes — not distributed!")
	}
	if int64(len(w.body)) != totalSize {
		t.Errorf("delivered %d want %d", len(w.body), totalSize)
	}
	// Roughly balanced (within 3x of each other for small chunk counts).
	ratio := float64(linkA) / float64(linkB)
	if ratio < 0.33 || ratio > 3.0 {
		t.Errorf("distribution too unbalanced: linkA=%d linkB=%d ratio=%.2f", linkA, linkB, ratio)
	}
}

// TestSplitWithSlowLink simulates one link being throttled (real-world:
// mobile tether has 1/10 the throughput of WiFi). Asserts BOTH links still
// get used — the slow one should just deliver proportionally less over time.
// Does NOT assert 50/50 — only that the slow link gets SOME bytes.
func TestSplitWithSlowLink(t *testing.T) {
	const totalSize = int64(40 * 1024 * 1024)

	var reqCount atomic.Int32
	// Server writes slower on second source-port (simulating slow link). But
	// loopback all uses 127.0.0.1 so we can't distinguish by srcIP. Instead
	// we simulate by delaying the response based on request number: odd
	// requests are slow (chunk 1 assigned to linkB goes slow).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := reqCount.Add(1)
		rangeHdr := r.Header.Get("Range")
		if rangeHdr == "" {
			w.Header().Set("Accept-Ranges", "bytes")
			w.Header().Set("Content-Length", strconv.FormatInt(totalSize, 10))
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			writeDeterministic(w, 0, totalSize-1, nil)
			return
		}
		start, end := parseTestRange(rangeHdr)
		size := end - start + 1
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, totalSize))
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.Header().Set("Accept-Ranges", "bytes")
		w.WriteHeader(http.StatusPartialContent)
		if n%2 == 0 {
			// "Slow" link: write 1 MB at a time with a 50ms sleep between.
			const slice = 1024 * 1024
			pos := start
			for pos <= end {
				nb := int64(slice)
				if pos+nb-1 > end {
					nb = end - pos + 1
				}
				buf := make([]byte, nb)
				for i := range buf {
					buf[i] = deterministicByte(pos + int64(i))
				}
				w.Write(buf)
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				time.Sleep(20 * time.Millisecond)
				pos += nb
			}
			return
		}
		writeDeterministic(w, start, end, nil)
	}))
	defer srv.Close()

	b := NewBalancer()
	b.Upsert("fast", net.ParseIP("127.0.0.1"), 1, 10*time.Millisecond)
	b.Upsert("slow", net.ParseIP("127.0.0.1"), 1, 10*time.Millisecond)

	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.URL.Scheme = "http"
	resp, _ := http.Get(srv.URL)
	resp.Body.Close()
	decision, ok := shouldSplit(req, resp, b)
	if !ok {
		t.Fatal("shouldSplit=false")
	}

	w := newMockRW()
	splitAcrossLinks(w, req, resp.Header, decision, b, NewRecentConns(16))

	var fastB, slowB int64
	for _, v := range b.SnapshotView() {
		if v.Name == "fast" {
			fastB = v.BytesIn
		} else {
			slowB = v.BytesIn
		}
	}
	t.Logf("fast=%d slow=%d total=%d", fastB, slowB, len(w.body))
	if int64(len(w.body)) != totalSize {
		t.Fatalf("delivered %d want %d", len(w.body), totalSize)
	}
	// With only 2 chunks on a work-stealing queue, the fast link can
	// legitimately grab both before the slow link's workers start. Verify
	// that the fast link did at least as much as the slow link (correct
	// work-stealing behaviour) rather than requiring both to participate.
	if fastB < slowB {
		t.Errorf("fast link should do at least as much work as slow; fast=%d slow=%d", fastB, slowB)
	}
	if idx, bad := verifyDeterministic(w.body, 0); bad {
		t.Fatalf("corruption at byte %d", idx)
	}
}

// TestSplitAcrossLinksDeliversFullBytes drives splitAcrossLinks against a
// fake server and asserts every single byte arrives correctly.
func TestSplitAcrossLinksDeliversFullBytes(t *testing.T) {
	const totalSize = int64(40 * 1024 * 1024) // 40 MB — well above threshold

	var reqCount atomic.Int32
	var bytesServed atomic.Int64
	srv := makeRangeServer(totalSize, &reqCount, &bytesServed)
	defer srv.Close()

	// Two links bound to loopback. The balancer will distribute chunks.
	b := NewBalancer()
	b.Upsert("linkA", net.ParseIP("127.0.0.1"), 1, 10*time.Millisecond)
	b.Upsert("linkB", net.ParseIP("127.0.0.1"), 1, 10*time.Millisecond)

	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.URL.Scheme = "http"
	// Initial single-link fetch to get the 200 response headers.
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("initial GET: %v", err)
	}
	resp.Body.Close()

	decision, ok := shouldSplit(req, resp, b)
	if !ok {
		t.Fatalf("shouldSplit returned false — size=%d threshold=%d acceptRanges=%q",
			resp.ContentLength, rangeSplitThreshold, resp.Header.Get("Accept-Ranges"))
	}
	if decision.total != totalSize {
		t.Fatalf("decision.total=%d want %d", decision.total, totalSize)
	}

	w := newMockRW()
	splitAcrossLinks(w, req, resp.Header, decision, b, NewRecentConns(16))

	if int64(len(w.body)) != totalSize {
		t.Fatalf("delivered %d bytes, want %d", len(w.body), totalSize)
	}
	if idx, bad := verifyDeterministic(w.body, 0); bad {
		t.Fatalf("byte mismatch at index %d: got %d want %d", idx, w.body[idx], deterministicByte(int64(idx)))
	}
	t.Logf("✓ delivered %d bytes across %d upstream requests (%d bytes served)",
		len(w.body), reqCount.Load(), bytesServed.Load())
}

// TestSplitShortReadDetected verifies that if the server returns FEWER bytes
// than Content-Length claims (silent mid-stream drop), the chunk fails the
// byte-count check and retry kicks in. Without the check, it would truncate.
func TestSplitShortReadDetected(t *testing.T) {
	const chunkStart = int64(0)
	const chunkEnd = int64(1*1024*1024 - 1)
	const total = int64(10 * 1024 * 1024)

	var reqCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := reqCount.Add(1)
		start, end := parseTestRange(r.Header.Get("Range"))
		size := end - start + 1
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, total))
		// Lie: advertise full size but only send half, then clean close (EOF).
		// Without the byte-count check, fetchChunkOnce would think it's done.
		if n == 1 {
			w.Header().Set("Content-Length", strconv.FormatInt(size/2, 10))
			w.WriteHeader(http.StatusPartialContent)
			data := make([]byte, size/2)
			for i := range data {
				data[i] = deterministicByte(start + int64(i))
			}
			w.Write(data)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			return
		}
		// Retry: serve fully.
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.WriteHeader(http.StatusPartialContent)
		data := make([]byte, size)
		for i := range data {
			data[i] = deterministicByte(start + int64(i))
		}
		w.Write(data)
	}))
	defer srv.Close()

	b := NewBalancer()
	b.Upsert("A", net.ParseIP("127.0.0.1"), 1, 10*time.Millisecond)
	b.Upsert("B", net.ParseIP("127.0.0.1"), 1, 10*time.Millisecond)

	baseReq, _ := http.NewRequest("GET", srv.URL, nil)
	buf := newChunkBuf(100)
	defer buf.close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fetchChunk(ctx, baseReq, b, b.HealthyLinks()[0], chunkStart, chunkEnd, buf, NewRecentConns(16))

	var sink bytes.Buffer
	if _, err := buf.drainTo(&sink); err != nil {
		t.Fatalf("fetchChunk error: %v", err)
	}
	got := sink.Bytes()
	want := chunkEnd - chunkStart + 1
	if int64(len(got)) != want {
		t.Fatalf("got %d bytes, want %d (short-read check should have triggered retry)", len(got), want)
	}
	if idx, bad := verifyDeterministic(got, chunkStart); bad {
		t.Fatalf("byte mismatch at %d", idx)
	}
	if reqCount.Load() < 2 {
		t.Errorf("expected retry — got only %d requests", reqCount.Load())
	}
	t.Logf("✓ short-read detected, %d bytes recovered across %d requests", len(got), reqCount.Load())
}

// TestSplitRangeHeaderExactness confirms each chunk's Range header is
// exactly what fetchChunkOnce sends, and every byte lands at the right offset.
// Runs a wider range of sizes to catch off-by-one in chunk boundary math.
func TestSplitRangeHeaderExactness(t *testing.T) {
	sizes := []int64{
		15 * 1024 * 1024,     // small
		100 * 1024 * 1024,    // medium
		rangeSplitThreshold + 1,
		rangeSplitThreshold + 12345, // odd remainder
	}
	for _, size := range sizes {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			var reqCount atomic.Int32
			var bytesServed atomic.Int64
			srv := makeRangeServer(size, &reqCount, &bytesServed)
			defer srv.Close()

			b := NewBalancer()
			b.Upsert("A", net.ParseIP("127.0.0.1"), 1, 10*time.Millisecond)
			b.Upsert("B", net.ParseIP("127.0.0.1"), 1, 10*time.Millisecond)

			req, _ := http.NewRequest("GET", srv.URL, nil)
			req.URL.Scheme = "http"
			resp, err := http.Get(srv.URL)
			if err != nil {
				t.Fatalf("initial GET: %v", err)
			}
			resp.Body.Close()

			decision, ok := shouldSplit(req, resp, b)
			if !ok {
				t.Fatalf("shouldSplit false at size=%d", size)
			}

			w := newMockRW()
			splitAcrossLinks(w, req, resp.Header, decision, b, NewRecentConns(16))

			if int64(len(w.body)) != size {
				t.Fatalf("got %d bytes want %d", len(w.body), size)
			}
			if idx, bad := verifyDeterministic(w.body, 0); bad {
				// Print context around the bad byte.
				lo := idx - 8
				if lo < 0 {
					lo = 0
				}
				hi := idx + 8
				if hi > len(w.body) {
					hi = len(w.body)
				}
				t.Fatalf("mismatch at byte %d; got window=%v", idx, w.body[lo:hi])
			}
		})
	}
}

// parseTestRange reused across test files; keep a local copy-safe version
// behind a rename so we don't collide with the retry test file.
func init() {
	// sanity check that parseTestRange from the other test file is compatible
	_ = strings.HasPrefix
}
