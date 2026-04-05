package main

import (
	"net"
	"testing"
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
