package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// slowEmptyBody is an io.ReadCloser that returns (0, nil) on the first
// Read and (0, io.EOF) on every subsequent Read. This mimics the behavior
// of http2.requestBody when END_STREAM arrives on the HEADERS frame but
// the pipe hasn't propagated EOF yet. That non-EOF first read fools Go's
// http.Transport chunked-probe into enabling Transfer-Encoding: chunked
// on a GET, which strict origins/WAFs reject with 411 Length Required.
type slowEmptyBody struct{ calls int }

func (s *slowEmptyBody) Read(p []byte) (int, error) {
	s.calls++
	if s.calls == 1 {
		return 0, nil
	}
	return 0, io.EOF
}
func (s *slowEmptyBody) Close() error { return nil }

// Regression: a GET whose Body reports (0, nil) before EOF must NEVER
// cause mergenet to emit Transfer-Encoding: chunked to upstream.
func TestMITMGetWithSlowEmptyBodyNeverChunks(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TransferEncoding) > 0 {
			t.Errorf("upstream saw TransferEncoding=%v on GET — must be empty", r.TransferEncoding)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	balancer := NewBalancer()
	balancer.Upsert("testlink", net.ParseIP("127.0.0.1"), 1, time.Millisecond)
	recent := NewRecentConns(10)

	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Body = &slowEmptyBody{}
	req.ContentLength = -1 // h2 commonly reports unknown length
	req.RequestURI = ""

	rr := httptest.NewRecorder()
	forwardOrSplit(rr, req, balancer, recent)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d body=%q", rr.Code, rr.Body.String())
	}
}
