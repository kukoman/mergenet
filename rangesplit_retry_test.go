package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestChunkRetryResume verifies fetchChunk recovers from a mid-transfer
// connection drop: the server closes the socket after sending half the
// requested bytes on the first request, then serves normally on retry.
// The drainer must see a complete, correctly-ordered byte stream.
func TestChunkRetryResume(t *testing.T) {
	const (
		chunkStart = int64(0)
		chunkEnd   = int64(1*1024*1024 - 1) // 1 MB chunk
		total      = int64(10 * 1024 * 1024) // pretend file is 10 MB
	)

	var reqCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := reqCount.Add(1)
		start, end := parseTestRange(r.Header.Get("Range"))
		size := end - start + 1

		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, total))
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.Header().Set("Accept-Ranges", "bytes")
		w.WriteHeader(http.StatusPartialContent)

		// Content is a deterministic pattern: byte at absolute offset i = i%256
		data := make([]byte, size)
		for i := range data {
			data[i] = byte((start + int64(i)) % 256)
		}

		if n == 1 {
			// First request: send half then hard-close the TCP connection.
			halfway := size / 2
			w.Write(data[:halfway])
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			if hj, ok := w.(http.Hijacker); ok {
				c, _, _ := hj.Hijack()
				c.Close()
			}
			return
		}
		// Subsequent requests: serve normally.
		w.Write(data)
	}))
	defer srv.Close()

	// Use loopback as LocalIP so linkTransport's Dialer binding works with the
	// httptest server (also on loopback). Two Links with different names so
	// pickAlternative has a second choice.
	b := NewBalancer()
	b.Upsert("A", net.ParseIP("127.0.0.1"), 1, 10*time.Millisecond)
	b.Upsert("B", net.ParseIP("127.0.0.1"), 1, 10*time.Millisecond)

	baseReq, _ := http.NewRequest("GET", srv.URL, nil)
	buf := newChunkBuf(100)
	defer buf.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fetchChunk(ctx, baseReq, b, b.HealthyLinks()[0], chunkStart, chunkEnd, buf, NewRecentConns(16))

	// Drain the spool into a byte slice and verify.
	var sink bytes.Buffer
	if _, err := buf.drainTo(&sink); err != nil {
		t.Fatalf("fetchChunk error: %v", err)
	}
	got := sink.Bytes()
	want := chunkEnd - chunkStart + 1
	if int64(len(got)) != want {
		t.Fatalf("got %d bytes, want %d", len(got), want)
	}
	if reqCount.Load() < 2 {
		t.Errorf("expected at least 2 upstream requests (first fails, second succeeds), got %d", reqCount.Load())
	}
	// Verify every byte matches the deterministic pattern (no duplication, no gaps).
	for i, v := range got {
		exp := byte((chunkStart + int64(i)) % 256)
		if v != exp {
			t.Fatalf("byte %d: got %d, want %d (first divergence)", i, v, exp)
		}
	}
	t.Logf("recovered %d bytes across %d upstream requests", len(got), reqCount.Load())
}

// parseTestRange parses "bytes=X-Y" used only by the test server handler.
func parseTestRange(h string) (int64, int64) {
	h = strings.TrimPrefix(h, "bytes=")
	dash := strings.IndexByte(h, '-')
	s, _ := strconv.ParseInt(h[:dash], 10, 64)
	e, _ := strconv.ParseInt(h[dash+1:], 10, 64)
	return s, e
}
