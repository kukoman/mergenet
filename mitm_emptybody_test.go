package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMITMNoEmptyBodyChunking(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TransferEncoding) > 0 {
			t.Errorf("Expected no TransferEncoding, got %v", r.TransferEncoding)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	scorer := NewLinkScorer()
	balancer := NewBalancer()
	balancer.scorer = scorer
	balancer.Upsert("testlink", net.ParseIP("127.0.0.1"), 1, time.Millisecond)

	recent := NewRecentConns(10)

	req, _ := http.NewRequest("GET", ts.URL, http.NoBody)
	req.RequestURI = ""
	rr := httptest.NewRecorder()

	forwardOrSplit(rr, req, balancer, recent)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rr.Code)
	}
}
