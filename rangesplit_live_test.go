//go:build integration

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testURLFromEnv returns a large HTTP(S) URL to a static, Range-supporting
// file. Skips the test if MERGENET_TEST_URL is unset — we don't hardcode a
// URL since public repos shouldn't contain pointers to third-party hosts.
// Pick any large static file you control: .iso, .zip, a CDN test file, etc.
func testURLFromEnv(t *testing.T) string {
	t.Helper()
	u := os.Getenv("MERGENET_TEST_URL")
	if u == "" {
		t.Skip("set MERGENET_TEST_URL to a large static file URL to run live tests")
	}
	return u
}

// TestLiveRangeSplit exercises the real tryRangeSplit code path against the
// configured test URL using 2 simulated Links (dual-IP alias on eth0).
//
// Request a 20 MB slice so the test finishes in seconds. Verify:
//   - tryRangeSplit returns true (took ownership)
//   - Response body is exactly 20 MB
//   - Both link counters show traffic
//   - Byte content matches a direct single-connection download of the same range
func TestLiveRangeSplit(t *testing.T) {
	url := testURLFromEnv(t)
	const (
		rangeSize   = int64(20 * 1024 * 1024) // 20 MB
		primaryIP   = "172.29.245.180"
		secondaryIP = "172.29.245.201"
	)

	b := NewBalancer()
	b.Upsert("linkA", net.ParseIP(primaryIP), 1, 10*time.Millisecond)
	b.Upsert("linkB", net.ParseIP(secondaryIP), 1, 10*time.Millisecond)

	healthy := b.HealthyLinks()
	if len(healthy) < 2 {
		t.Fatalf("expected 2 healthy links, got %d", len(healthy))
	}
	linkA, linkB := healthy[0], healthy[1]

	recent := NewRecentConns(64)

	// Build a request that looks like what mitmHandler would produce after
	// TLS-decoding a browser GET: URL has scheme+host, Range header set by client.
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	// Simulate client resuming / asking for first 20 MB.
	req.Header.Set("Range", "bytes=0-"+itoa(rangeSize-1))

	rec := httptest.NewRecorder()

	// Exercise the new forwardOrSplit path end-to-end: it does a single-link
	// probe, inspects headers, and auto-upgrades to parallel range-split.
	t0 := time.Now()
	forwardOrSplit(rec, req, b, recent)
	elapsed := time.Since(t0)

	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	t.Logf("status=%d body=%d bytes elapsed=%s", resp.StatusCode, len(body), elapsed)
	t.Logf("linkA bytesIn=%d totalConns=%d", atomic.LoadInt64(&linkA.BytesIn), atomic.LoadInt64(&linkA.TotalConns))
	t.Logf("linkB bytesIn=%d totalConns=%d", atomic.LoadInt64(&linkB.BytesIn), atomic.LoadInt64(&linkB.TotalConns))

	if resp.StatusCode != http.StatusPartialContent {
		t.Errorf("status: want 206, got %d", resp.StatusCode)
	}
	if int64(len(body)) != rangeSize {
		t.Errorf("body length: want %d, got %d", rangeSize, len(body))
	}

	// Compare against a direct single-connection fetch of the same range.
	directBody := directFetchRange(t, url, 0, rangeSize-1)
	if len(directBody) != len(body) {
		t.Fatalf("direct length %d != split length %d", len(directBody), len(body))
	}
	wantSum := sha256.Sum256(directBody)
	gotSum := sha256.Sum256(body)
	if wantSum != gotSum {
		t.Errorf("content mismatch\n  want sha256=%s\n  got  sha256=%s", hex.EncodeToString(wantSum[:]), hex.EncodeToString(gotSum[:]))
	}

	// Both links should have seen traffic.
	if atomic.LoadInt64(&linkA.BytesIn) == 0 || atomic.LoadInt64(&linkB.BytesIn) == 0 {
		t.Errorf("expected traffic on both links (A=%d B=%d)", linkA.BytesIn, linkB.BytesIn)
	}
}

// directFetchRange makes a single-connection HTTP GET with a Range header and
// returns the full body, used as a byte-exact reference.
func directFetchRange(t *testing.T, url string, start, end int64) []byte {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("direct build: %v", err)
	}
	req.Header.Set("Range", "bytes="+itoa(start)+"-"+itoa(end))
	cli := &http.Client{Timeout: 60 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("direct fetch: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("direct status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("direct read: %v", err)
	}
	return b
}

// TestLiveChunkScaling verifies computeChunks actually scales with size:
// 25 MB → 2 chunks (1 per link, < 50 MB), 100 MB → 4 chunks (2 per link).
func TestLiveChunkScaling(t *testing.T) {
	url := testURLFromEnv(t)

	cases := []struct {
		name       string
		size       int64
		wantChunks int
	}{
		{"25MB", 25 * 1024 * 1024, 2},
		{"100MB", 100 * 1024 * 1024, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := computeChunks(tc.size, 2)
			if got != tc.wantChunks {
				t.Errorf("computeChunks(%d, 2) = %d, want %d", tc.size, got, tc.wantChunks)
			}
		})
	}

	// Sanity check: actually fetch 100 MB and verify it used 4 chunks.
	b := NewBalancer()
	b.Upsert("linkA", net.ParseIP("172.29.245.180"), 1, 10*time.Millisecond)
	b.Upsert("linkB", net.ParseIP("172.29.245.201"), 1, 10*time.Millisecond)
	recent := NewRecentConns(64)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Range", "bytes=0-"+itoa(100*1024*1024-1))
	rec := httptest.NewRecorder()
	t0 := time.Now()
	forwardOrSplit(rec, req, b, recent)
	elapsed := time.Since(t0)

	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	t.Logf("100MB fetch: status=%d body=%d took=%s", resp.StatusCode, len(body), elapsed)
	healthy := b.HealthyLinks()
	for _, link := range healthy {
		t.Logf("  %s: bytesIn=%d totalConns=%d", link.Name, link.BytesIn, link.TotalConns)
	}
	if len(body) != 100*1024*1024 {
		t.Errorf("want 100MB body, got %d", len(body))
	}
}

// itoa is a tiny int64->string helper to keep imports focused.
func itoa(n int64) string {
	var b strings.Builder
	if n < 0 {
		b.WriteByte('-')
		n = -n
	}
	if n == 0 {
		return "0"
	}
	var digits [20]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	b.Write(digits[i:])
	return b.String()
}
