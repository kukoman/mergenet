package main

import (
	"sync"
	"testing"
	"time"
)

func TestRecentConnsRingBufferWraps(t *testing.T) {
	r := NewRecentConns(3)
	for i := 0; i < 5; i++ {
		r.Add(ConnRecord{Ts: time.Now(), Link: "wifi", Target: "x"})
	}
	snap := r.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("expected 3 entries after wrap, got %d", len(snap))
	}
}

func TestRecentConnsSnapshotIsOrderedNewestLast(t *testing.T) {
	r := NewRecentConns(5)
	for _, name := range []string{"a", "b", "c"} {
		r.Add(ConnRecord{Ts: time.Now(), Link: name, Target: "t"})
	}
	snap := r.Snapshot()
	if len(snap) != 3 || snap[0].Link != "a" || snap[2].Link != "c" {
		t.Fatalf("snapshot order wrong: %+v", snap)
	}
}

func TestRecentConnsConcurrentAdds(t *testing.T) {
	r := NewRecentConns(100)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				r.Add(ConnRecord{Ts: time.Now(), Link: "x", Target: "y"})
			}
		}()
	}
	wg.Wait()
	if len(r.Snapshot()) != 100 {
		t.Fatalf("expected 100 entries, got %d", len(r.Snapshot()))
	}
}
