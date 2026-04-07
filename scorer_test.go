package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestRecordSampleUpdatesEWMA(t *testing.T) {
	s := NewLinkScorer()
	link := &Link{Name: "wifi", LocalIP: net.ParseIP("10.0.0.1")}

	s.RecordSample(link, 1_000_000, 1*time.Second) // 1 MB/s

	score := s.Score(link)
	if score <= 0 {
		t.Fatalf("expected positive score after sample, got %f", score)
	}
}

func TestScoreIncreasesWithThroughput(t *testing.T) {
	s := NewLinkScorer()
	slow := &Link{Name: "tether", LocalIP: net.ParseIP("10.0.0.1")}
	fast := &Link{Name: "wifi", LocalIP: net.ParseIP("10.0.0.2")}

	s.RecordSample(slow, 500_000, 1*time.Second)
	s.RecordSample(slow, 500_000, 1*time.Second)
	s.RecordSample(slow, 500_000, 1*time.Second)

	s.RecordSample(fast, 5_000_000, 1*time.Second)
	s.RecordSample(fast, 5_000_000, 1*time.Second)
	s.RecordSample(fast, 5_000_000, 1*time.Second)

	if s.Score(fast) <= s.Score(slow) {
		t.Fatalf("fast link (%f) should score higher than slow (%f)", s.Score(fast), s.Score(slow))
	}
}

func TestScorePenalizesActiveConns(t *testing.T) {
	s := NewLinkScorer()
	link := &Link{Name: "wifi", LocalIP: net.ParseIP("10.0.0.1")}

	s.RecordSample(link, 5_000_000, 1*time.Second)
	s.RecordSample(link, 5_000_000, 1*time.Second)
	s.RecordSample(link, 5_000_000, 1*time.Second)

	scoreIdle := s.Score(link)

	link.ActiveConns = 3
	scoreBusy := s.Score(link)

	if scoreBusy >= scoreIdle {
		t.Fatalf("busy score (%f) should be less than idle score (%f)", scoreBusy, scoreIdle)
	}
	ratio := scoreBusy / scoreIdle
	if ratio < 0.20 || ratio > 0.30 {
		t.Fatalf("expected ratio ~0.25, got %f", ratio)
	}
}

func TestIgnoresLongLivedSamples(t *testing.T) {
	s := NewLinkScorer()
	link := &Link{Name: "wifi", LocalIP: net.ParseIP("10.0.0.1")}

	s.RecordSample(link, 5_000_000, 1*time.Second)
	s.RecordSample(link, 5_000_000, 1*time.Second)
	s.RecordSample(link, 5_000_000, 1*time.Second)
	scoreBefore := s.Score(link)

	s.RecordSample(link, 100_000, 120*time.Second)
	scoreAfter := s.Score(link)

	if scoreBefore != scoreAfter {
		t.Fatalf("long-lived sample should be ignored: before=%f after=%f", scoreBefore, scoreAfter)
	}
}

func TestIgnoresZeroByteSamples(t *testing.T) {
	s := NewLinkScorer()
	link := &Link{Name: "wifi", LocalIP: net.ParseIP("10.0.0.1")}

	s.RecordSample(link, 0, 1*time.Second)

	score := s.Score(link)
	if score != 0 {
		t.Fatalf("expected zero score with no valid samples, got %f", score)
	}
}

func TestColdStartUsesProbeLatency(t *testing.T) {
	s := NewLinkScorer()
	fast := &Link{Name: "wifi", LocalIP: net.ParseIP("10.0.0.1"), ProbeLatency: 10 * time.Millisecond}
	slow := &Link{Name: "tether", LocalIP: net.ParseIP("10.0.0.2"), ProbeLatency: 100 * time.Millisecond}

	// No samples recorded — should fall back to probe latency
	fastScore := s.Score(fast)
	slowScore := s.Score(slow)

	if fastScore <= slowScore {
		t.Fatalf("lower latency link should score higher: fast=%f slow=%f", fastScore, slowScore)
	}
}

func TestColdStartTransitionsToEWMA(t *testing.T) {
	s := NewLinkScorer()
	link := &Link{Name: "wifi", LocalIP: net.ParseIP("10.0.0.1"), ProbeLatency: 10 * time.Millisecond}

	coldScore := s.Score(link)

	// Record enough samples to exit cold start
	for i := 0; i < coldStartThreshold; i++ {
		s.RecordSample(link, 5_000_000, 1*time.Second)
	}

	warmScore := s.Score(link)

	// Both should be positive but from different formulas
	if coldScore <= 0 || warmScore <= 0 {
		t.Fatalf("both scores should be positive: cold=%f warm=%f", coldScore, warmScore)
	}
}

func TestIsStaleWithNoSamples(t *testing.T) {
	s := NewLinkScorer()
	link := &Link{Name: "wifi", LocalIP: net.ParseIP("10.0.0.1")}

	if !s.IsStale(link) {
		t.Fatal("link with no samples should be stale")
	}
}

func TestIsStaleAfterRecordSample(t *testing.T) {
	s := NewLinkScorer()
	link := &Link{Name: "wifi", LocalIP: net.ParseIP("10.0.0.1")}

	s.RecordSample(link, 1_000_000, 1*time.Second)

	if s.IsStale(link) {
		t.Fatal("link should not be stale immediately after sample")
	}
}

func TestFullScoringScenario(t *testing.T) {
	orig := randFloat64
	randFloat64 = func() float64 { return 1.0 }
	defer func() { randFloat64 = orig }()

	scorer := NewLinkScorer()
	b := NewBalancer()
	b.scorer = scorer

	wifi := &Link{Name: "wifi", LocalIP: net.ParseIP("10.0.0.1"), Weight: 1, Healthy: true, ProbeLatency: 10 * time.Millisecond}
	tether := &Link{Name: "tether", LocalIP: net.ParseIP("10.0.0.2"), Weight: 1, Healthy: true, ProbeLatency: 50 * time.Millisecond}
	b.AddLink(wifi)
	b.AddLink(tether)

	// Phase 1: Cold start — should prefer wifi (lower probe latency)
	picked := b.Pick()
	if picked.Name != "wifi" {
		t.Fatalf("cold start: expected wifi, got %s", picked.Name)
	}
	atomic.AddInt64(&picked.ActiveConns, -1)

	// Phase 2: Feed samples — wifi is faster
	for i := 0; i < 5; i++ {
		scorer.RecordSample(wifi, 10_000_000, 1*time.Second)
		scorer.RecordSample(tether, 2_000_000, 1*time.Second)
	}

	// Should consistently pick wifi
	for i := 0; i < 10; i++ {
		picked = b.Pick()
		if picked.Name != "wifi" {
			t.Fatalf("warm phase: expected wifi, got %s (wifi score=%f, tether score=%f)",
				picked.Name, scorer.Score(wifi), scorer.Score(tether))
		}
		atomic.AddInt64(&picked.ActiveConns, -1)
	}

	// Phase 3: Simulate YouTube stream on wifi (3 active conns)
	atomic.StoreInt64(&wifi.ActiveConns, 3)

	// wifi score = ~10M / (1+3) = ~2.5M
	// tether score = ~2M / (1+0) = ~2M
	// wifi still wins slightly
	wifiScore := scorer.Score(wifi)
	tetherScore := scorer.Score(tether)
	t.Logf("wifi=%f tether=%f (wifi loaded with 3 conns)", wifiScore, tetherScore)

	// Phase 4: More load on wifi (5 active conns)
	atomic.StoreInt64(&wifi.ActiveConns, 5)

	// wifi score = ~10M / (1+5) = ~1.67M
	// tether score = ~2M / (1+0) = ~2M
	// tether should now win
	wifiScore = scorer.Score(wifi)
	tetherScore = scorer.Score(tether)
	if tetherScore <= wifiScore {
		t.Fatalf("heavily loaded wifi should lose: wifi=%f tether=%f", wifiScore, tetherScore)
	}

	picked = b.Pick()
	if picked.Name != "tether" {
		t.Fatalf("heavy load: expected tether, got %s", picked.Name)
	}
	atomic.AddInt64(&picked.ActiveConns, -1)

	// Cleanup
	atomic.StoreInt64(&wifi.ActiveConns, 0)
}
