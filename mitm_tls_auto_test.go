package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMITMAutoTLSFallback(t *testing.T) {
	// Create an upstream test server with a valid but untrusted cert
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success-auto-fallback"))
	}))
	defer ts.Close()

	scorer := NewLinkScorer()
	balancer := NewBalancer()
	balancer.scorer = scorer
    // Create dummy local link pointing nowhere to inject for the dialer
    balancer.Upsert("testlink", net.ParseIP("127.0.0.1"), 1, time.Millisecond)

	recent := NewRecentConns(10)
    
	req, _ := http.NewRequest("GET", ts.URL, nil)
	rr := httptest.NewRecorder()

	forwardOrSplit(rr, req, balancer, recent)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected fallback to succeed with 200 OK, got %d. Body: %s", rr.Code, rr.Body.String())
	}
	
	if rr.Body.String() != "success-auto-fallback" {
		t.Fatalf("Expected body 'success-auto-fallback', got %s", rr.Body.String())
	}
}
