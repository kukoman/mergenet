package main

import (
	"testing"
)

// Repeated PickForHost for the same host should return the same link every
// time, even when Pick() would otherwise rotate. This is what keeps
// Cloudflare's IP-bound `cf_clearance` cookie valid: all AJAX requests to a
// challenge domain egress via the same WAN link.
func TestPickForHostIsStickyPerHost(t *testing.T) {
	b := NewBalancer()
	b.AddLink(mkLink("a", 1, true))
	b.AddLink(mkLink("b", 1, true))

	first := b.PickForHost("example.com")
	if first == nil {
		t.Fatal("expected a link for example.com")
	}
	for i := 0; i < 50; i++ {
		got := b.PickForHost("example.com")
		if got == nil || got.Name != first.Name {
			t.Fatalf("iter %d: expected %q, got %v", i, first.Name, got)
		}
	}
}

// Different hosts may be pinned to different links. The point is consistency
// per-host, not globally.
func TestPickForHostDistributesAcrossHosts(t *testing.T) {
	b := NewBalancer()
	b.AddLink(mkLink("a", 1, true))
	b.AddLink(mkLink("b", 1, true))

	names := map[string]bool{}
	hosts := []string{
		"one.example.com", "two.example.com", "three.example.com",
		"four.example.com", "five.example.com", "six.example.com",
	}
	for _, h := range hosts {
		l := b.PickForHost(h)
		if l == nil {
			t.Fatalf("nil link for host %q", h)
		}
		names[l.Name] = true
	}
	if len(names) < 2 {
		t.Fatalf("expected both links to receive at least one host, got %v", names)
	}
}

// If the pinned link goes unhealthy, PickForHost must fall back to another
// healthy link and then stay pinned to that new link.
func TestPickForHostFailsOverWhenPinnedLinkUnhealthy(t *testing.T) {
	b := NewBalancer()
	b.AddLink(mkLink("a", 1, true))
	b.AddLink(mkLink("b", 1, true))

	first := b.PickForHost("example.com")
	if first == nil {
		t.Fatal("expected a link")
	}
	b.SetHealthy(first.Name, false)

	second := b.PickForHost("example.com")
	if second == nil {
		t.Fatal("expected failover link")
	}
	if second.Name == first.Name {
		t.Fatalf("expected failover to a different link, still got %q", first.Name)
	}
	// New pin must stick.
	for i := 0; i < 20; i++ {
		got := b.PickForHost("example.com")
		if got == nil || got.Name != second.Name {
			t.Fatalf("iter %d: expected pinned %q, got %v", i, second.Name, got)
		}
	}
}

// With no healthy links, PickForHost returns nil (same contract as Pick).
func TestPickForHostNilWhenNoHealthy(t *testing.T) {
	b := NewBalancer()
	b.AddLink(mkLink("a", 1, false))
	if b.PickForHost("example.com") != nil {
		t.Fatal("expected nil when no healthy links")
	}
}
