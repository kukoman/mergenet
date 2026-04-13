package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMITMTLSServerReal(t *testing.T) {
	// Upstream with bad cert
	targetServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("markomedik fixed"))
	}))
	defer targetServer.Close()

	// Setup mergenet MITM server
	scorer := NewLinkScorer()
	balancer := NewBalancer()
	balancer.scorer = scorer
	// It should use the local connection.
	balancer.Upsert("local", net.ParseIP("127.0.0.1"), 1, time.Millisecond)
	recent := NewRecentConns(10)

	// The MITM handler
	handler := &mitmHandler{
		target: targetServer.URL[8:], // strip "https://"
		b:      balancer,
		recent: recent,
	}

	// Launch it in httptest.NewServer
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	// Send an actual request via http.Get
	resp, err := http.Get(proxyServer.URL)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d. Body: %s", resp.StatusCode, string(body))
	}
	if string(body) != "markomedik fixed" {
		t.Fatalf("Expected 'markomedik fixed', got %s", string(body))
	}
}
