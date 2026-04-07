package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func mkLink(name string, weight int, healthy bool) *Link {
	return &Link{Name: name, LocalIP: net.ParseIP("127.0.0.1"), Weight: weight, Healthy: healthy}
}

func TestBalancerPickReturnsNilWhenNoLinks(t *testing.T) {
	b := NewBalancer()
	if b.Pick() != nil {
		t.Fatal("expected nil pick with no links")
	}
}

func TestBalancerPickReturnsNilWhenAllUnhealthy(t *testing.T) {
	b := NewBalancer()
	b.AddLink(mkLink("a", 1, false))
	b.AddLink(mkLink("b", 1, false))
	if b.Pick() != nil {
		t.Fatal("expected nil pick when all unhealthy")
	}
}

func TestBalancerEqualWeightRoundRobin(t *testing.T) {
	b := NewBalancer()
	b.AddLink(mkLink("a", 1, true))
	b.AddLink(mkLink("b", 1, true))
	counts := map[string]int{}
	for i := 0; i < 100; i++ {
		counts[b.Pick().Name]++
	}
	if counts["a"] != 50 || counts["b"] != 50 {
		t.Fatalf("expected 50/50, got %v", counts)
	}
}

func TestBalancerWeightedRoundRobin(t *testing.T) {
	b := NewBalancer()
	b.AddLink(mkLink("a", 2, true))
	b.AddLink(mkLink("b", 1, true))
	counts := map[string]int{}
	for i := 0; i < 300; i++ {
		counts[b.Pick().Name]++
	}
	if counts["a"] != 200 || counts["b"] != 100 {
		t.Fatalf("expected 200/100, got %v", counts)
	}
}

func TestBalancerSkipsUnhealthy(t *testing.T) {
	b := NewBalancer()
	b.AddLink(mkLink("a", 1, true))
	b.AddLink(mkLink("b", 1, false))
	for i := 0; i < 20; i++ {
		if b.Pick().Name != "a" {
			t.Fatal("expected only 'a' to be picked")
		}
	}
}

func TestBalancerGetLinkAndSetHealthy(t *testing.T) {
	b := NewBalancer()
	b.AddLink(mkLink("a", 1, true))
	b.SetHealthy("a", false)
	if b.Pick() != nil {
		t.Fatal("expected nil after marking unhealthy")
	}
	b.SetHealthy("a", true)
	if b.Pick() == nil {
		t.Fatal("expected pick after marking healthy")
	}
}

func TestPickPrefersHigherScoringLink(t *testing.T) {
	scorer := NewLinkScorer()
	b := NewBalancer()
	b.scorer = scorer

	fast := mkLink("fast", 1, true)
	fast.ProbeLatency = 10 * time.Millisecond
	slow := mkLink("slow", 1, true)
	slow.ProbeLatency = 100 * time.Millisecond

	b.AddLink(fast)
	b.AddLink(slow)

	// Feed scorer so fast link has higher EWMA
	for i := 0; i < 5; i++ {
		scorer.RecordSample(fast, 10_000_000, 1*time.Second)
		scorer.RecordSample(slow, 1_000_000, 1*time.Second)
	}

	// Pick 20 times — fast should win every time (no stale links)
	for i := 0; i < 20; i++ {
		picked := b.Pick()
		if picked == nil {
			t.Fatal("expected non-nil pick")
		}
		if picked.Name != "fast" {
			t.Fatalf("pick %d: expected 'fast', got '%s'", i, picked.Name)
		}
		atomic.AddInt64(&picked.ActiveConns, -1) // release
	}
}

func TestPickFallsBackToProbeLatencyOnColdStart(t *testing.T) {
	// Disable exploration so stale links don't get randomly picked.
	orig := randFloat64
	randFloat64 = func() float64 { return 1.0 }
	defer func() { randFloat64 = orig }()

	scorer := NewLinkScorer()
	b := NewBalancer()
	b.scorer = scorer

	fast := mkLink("fast", 1, true)
	fast.ProbeLatency = 5 * time.Millisecond
	slow := mkLink("slow", 1, true)
	slow.ProbeLatency = 200 * time.Millisecond

	b.AddLink(fast)
	b.AddLink(slow)

	// No samples — cold start uses probe latency
	for i := 0; i < 10; i++ {
		picked := b.Pick()
		if picked.Name != "fast" {
			t.Fatalf("cold start pick %d: expected 'fast', got '%s'", i, picked.Name)
		}
		atomic.AddInt64(&picked.ActiveConns, -1)
	}
}

func TestPickStillWorksWithNilScorer(t *testing.T) {
	b := NewBalancer()
	// No scorer set — should fall back to round-robin
	b.AddLink(mkLink("a", 1, true))
	b.AddLink(mkLink("b", 1, true))

	counts := map[string]int{}
	for i := 0; i < 100; i++ {
		l := b.Pick()
		counts[l.Name]++
		atomic.AddInt64(&l.ActiveConns, -1)
	}
	if counts["a"] != 50 || counts["b"] != 50 {
		t.Fatalf("nil scorer should round-robin 50/50, got %v", counts)
	}
}
