package main

import (
    "io"
"net/http"
"testing"
)

func TestReplayBody(t *testing.T) {
req, _ := http.NewRequest("GET", "http://example.com", http.NoBody)
    
    // Simulate what happens in roundtrip error
    outReq := req.Clone(req.Context())
    outReq.Body.Close()
    
    outReqRetry := req.Clone(req.Context())
    _, err := io.ReadAll(outReqRetry.Body)
    if err != nil {
        t.Fatalf("Failed to read: %v", err)
    }
}
