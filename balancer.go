package main

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Link holds per-interface state. Mutable scalar fields (Healthy, LocalIP,
// ProbeLatency, Weight) are ONLY accessed under Balancer.mu. Counter fields
// (ActiveConns, TotalConns, BytesIn, BytesOut) are ONLY accessed atomically.
type Link struct {
	Name         string
	LocalIP      net.IP
	Weight       int
	Healthy      bool
	ProbeLatency time.Duration
	ActiveConns  int64
	TotalConns   int64
	BytesIn      int64
	BytesOut     int64
}

// LinkView is a point-in-time value snapshot of a Link safe for display code
// to use without locking.
type LinkView struct {
	Name         string
	LocalIP      net.IP
	Weight       int
	Healthy      bool
	ProbeLatency time.Duration
	ActiveConns  int64
	TotalConns   int64
	BytesIn      int64
	BytesOut     int64
}

type Balancer struct {
	mu    sync.Mutex
	links []*Link
	next  int
}

func NewBalancer() *Balancer {
	return &Balancer{}
}

// AddLink adds a new link if no link with the same name already exists.
func (b *Balancer) AddLink(l *Link) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, existing := range b.links {
		if existing.Name == l.Name {
			return
		}
	}
	b.links = append(b.links, l)
}

// Upsert updates the named link's IP + probe latency and marks it healthy,
// creating it if missing. Returns (wasHealthy, existed) for the pre-update state.
func (b *Balancer) Upsert(name string, ip net.IP, weight int, lat time.Duration) (wasHealthy, existed bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, l := range b.links {
		if l.Name == name {
			wasHealthy = l.Healthy
			existed = true
			l.Healthy = true
			l.LocalIP = ip
			l.ProbeLatency = lat
			return
		}
	}
	b.links = append(b.links, &Link{
		Name: name, LocalIP: ip, Weight: weight, Healthy: true, ProbeLatency: lat,
	})
	return false, false
}

// SetHealthy flips the Healthy flag for a link. Returns the previous state,
// or false if no such link.
func (b *Balancer) SetHealthy(name string, healthy bool) (wasHealthy bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, l := range b.links {
		if l.Name == name {
			wasHealthy = l.Healthy
			l.Healthy = healthy
			return
		}
	}
	return
}

// HealthyLinks returns the currently-healthy links as pointers. The slice is
// a snapshot; individual Link fields may change after this call. Safe to use
// for atomic counter updates (which are always atomic) and acceptable for
// transient reads of LocalIP since adapter IP changes are rare.
func (b *Balancer) HealthyLinks() []*Link {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]*Link, 0, len(b.links))
	for _, l := range b.links {
		if l.Healthy {
			out = append(out, l)
		}
	}
	return out
}

// SnapshotView returns a point-in-time value-copy of every link. Safe to read
// without any locking.
func (b *Balancer) SnapshotView() []LinkView {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]LinkView, len(b.links))
	for i, l := range b.links {
		out[i] = LinkView{
			Name:         l.Name,
			LocalIP:      l.LocalIP,
			Weight:       l.Weight,
			Healthy:      l.Healthy,
			ProbeLatency: l.ProbeLatency,
			ActiveConns:  atomic.LoadInt64(&l.ActiveConns),
			TotalConns:   atomic.LoadInt64(&l.TotalConns),
			BytesIn:      atomic.LoadInt64(&l.BytesIn),
			BytesOut:     atomic.LoadInt64(&l.BytesOut),
		}
	}
	return out
}

// Pick returns a healthy link via weighted round-robin, or nil if no healthy
// links exist. Atomically increments the chosen link's connection counters.
// Caller MUST decrement ActiveConns when the connection ends.
func (b *Balancer) Pick() *Link {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Build round-robin slice: each healthy link appears Weight times.
	var total int
	for _, l := range b.links {
		if l.Healthy {
			w := l.Weight
			if w < 1 {
				w = 1
			}
			total += w
		}
	}
	if total == 0 {
		return nil
	}
	idx := b.next % total
	b.next++
	// Walk weighted slots without allocating.
	for _, l := range b.links {
		if !l.Healthy {
			continue
		}
		w := l.Weight
		if w < 1 {
			w = 1
		}
		if idx < w {
			atomic.AddInt64(&l.ActiveConns, 1)
			atomic.AddInt64(&l.TotalConns, 1)
			return l
		}
		idx -= w
	}
	return nil // unreachable
}
