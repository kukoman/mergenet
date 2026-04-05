//go:build integration

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"
)

// TestMITMLiveSites starts an in-process mergenet proxy with MITM enabled
// (using an ephemeral CA, no system trust changes) and fetches a range of
// real HTTPS sites through it. Flags any site that fails to load fully.
func TestMITMLiveSites(t *testing.T) {
	ca, err := LoadOrCreateCA()
	if err != nil {
		t.Fatalf("load CA: %v", err)
	}

	b := NewBalancer()
	// Use the real eth0 IP so requests actually reach the internet.
	b.Upsert("eth0", net.ParseIP("172.29.245.180"), 1, 10*time.Millisecond)

	mitm := NewMITMController()
	mitm.Set(true)
	pc := &ProxyConfig{
		Balancer: b,
		Recent:   NewRecentConns(64),
		Minter:   NewMinter(ca),
		MITMCtrl: mitm,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go ServeSOCKS5(ln, pc)
	proxyURL := &url.URL{Scheme: "http", Host: ln.Addr().String()}
	t.Logf("proxy listening at %s", proxyURL)

	// Build HTTP client that trusts the mergenet CA.
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool},
			ForceAttemptHTTP2: true,
		},
	}

	sites := []string{
		"https://example.com/",
		"https://www.google.com/",
		"https://www.github.com/",
		"https://www.cloudflare.com/",
		"https://www.wikipedia.org/",
		"https://news.ycombinator.com/",
		"https://httpbin.org/get",
		"https://www.bbc.com/",
	}

	type result struct {
		url    string
		status int
		bytes  int
		err    error
		took   time.Duration
	}
	results := make([]result, len(sites))
	var wg sync.WaitGroup
	for i, u := range sites {
		wg.Add(1)
		go func(i int, u string) {
			defer wg.Done()
			t0 := time.Now()
			req, _ := http.NewRequest("GET", u, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
			resp, err := client.Do(req)
			if err != nil {
				results[i] = result{url: u, err: err, took: time.Since(t0)}
				return
			}
			defer resp.Body.Close()
			body, rerr := io.ReadAll(resp.Body)
			results[i] = result{url: u, status: resp.StatusCode, bytes: len(body), err: rerr, took: time.Since(t0)}
		}(i, u)
	}
	wg.Wait()

	fails := 0
	for _, r := range results {
		if r.err != nil {
			fmt.Printf("  FAIL %s  err=%v  took=%s\n", r.url, r.err, r.took)
			fails++
			continue
		}
		if r.status < 200 || r.status >= 400 {
			fmt.Printf("  FAIL %s  status=%d bytes=%d took=%s\n", r.url, r.status, r.bytes, r.took)
			fails++
			continue
		}
		fmt.Printf("  OK   %s  status=%d bytes=%d took=%s\n", r.url, r.status, r.bytes, r.took)
	}
	if fails > 0 {
		t.Errorf("%d/%d sites failed to load through MITM", fails, len(results))
	}
}
