package main

import (
	"sync"
	"time"
)

type ConnRecord struct {
	Ts     time.Time `json:"ts"`
	Link   string    `json:"link"`
	Target string    `json:"target"`
}

type RecentConns struct {
	mu    sync.Mutex
	buf   []ConnRecord
	size  int
	head  int // index of oldest entry
	count int // number of entries currently stored
}

func NewRecentConns(size int) *RecentConns {
	return &RecentConns{buf: make([]ConnRecord, size), size: size}
}

func (r *RecentConns) Add(rec ConnRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count < r.size {
		r.buf[(r.head+r.count)%r.size] = rec
		r.count++
	} else {
		r.buf[r.head] = rec
		r.head = (r.head + 1) % r.size
	}
}

func (r *RecentConns) Snapshot() []ConnRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ConnRecord, r.count)
	for i := 0; i < r.count; i++ {
		out[i] = r.buf[(r.head+i)%r.size]
	}
	return out
}
