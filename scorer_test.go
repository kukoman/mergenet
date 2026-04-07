package main

import (
	"net"
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
