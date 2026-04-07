package main

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ewmaHalfLife       = 5.0 // seconds
	coldStartThreshold = 3   // minimum samples before trusting EWMA
	staleThreshold     = 10 * time.Second
	exploreProb        = 0.1 // probability of picking a stale link
	maxSampleDuration  = 60 * time.Second
)

type linkEWMA struct {
	throughput  float64   // bytes/sec EWMA
	lastUpdated time.Time // when EWMA was last fed a sample
	samples     int       // total samples recorded
}

type LinkScorer struct {
	mu    sync.Mutex
	stats map[*Link]*linkEWMA
}

func NewLinkScorer() *LinkScorer {
	return &LinkScorer{stats: make(map[*Link]*linkEWMA)}
}

// RecordSample feeds a completed request's throughput into the EWMA for the
// given link. Ignores zero-byte samples and long-lived connections (>60s).
func (s *LinkScorer) RecordSample(link *Link, bytes int64, dur time.Duration) {
	if bytes <= 0 || dur <= 0 || dur > maxSampleDuration {
		return
	}

	bps := float64(bytes) / dur.Seconds()

	s.mu.Lock()
	defer s.mu.Unlock()

	st := s.stats[link]
	if st == nil {
		st = &linkEWMA{}
		s.stats[link] = st
	}

	now := time.Now()
	if st.samples == 0 {
		st.throughput = bps
	} else {
		dt := now.Sub(st.lastUpdated).Seconds()
		if dt < 0 {
			dt = 0
		}
		alpha := 1 - math.Exp(-dt/ewmaHalfLife)
		st.throughput = alpha*bps + (1-alpha)*st.throughput
	}
	st.lastUpdated = now
	st.samples++
}

// Score returns the current score for a link. Higher is better.
// Cold-start links (< coldStartThreshold samples) use probe latency as
// a stand-in. Returns 0 if the link has never been sampled and has no
// probe latency.
func (s *LinkScorer) Score(link *Link) float64 {
	s.mu.Lock()
	st := s.stats[link]
	var throughput float64
	var samples int
	if st != nil {
		throughput = st.throughput
		samples = st.samples
	}
	s.mu.Unlock()

	if samples < coldStartThreshold {
		lat := link.ProbeLatency
		if lat > 0 {
			return 1_000_000 / lat.Seconds()
		}
		if samples == 0 {
			return 0
		}
	}

	activeConns := atomic.LoadInt64(&link.ActiveConns)
	return throughput / float64(1+activeConns)
}

// IsStale reports whether the link's EWMA data is older than staleThreshold.
func (s *LinkScorer) IsStale(link *Link) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats[link]
	if st == nil || st.samples == 0 {
		return true
	}
	return time.Since(st.lastUpdated) > staleThreshold
}
