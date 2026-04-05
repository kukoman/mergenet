package main

import (
	"bytes"
	"context"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// LogSink is an io.Writer that buffers log output in memory and periodically
// flushes it to disk, opening and closing the file on each flush so the log
// file isn't held locked while mergenet runs. Writing is gated by an atomic
// on/off switch (toggled at runtime via 'l'+Enter in the TUI).
//
// Default state: OFF. When OFF, Write is a no-op — nothing is buffered and no
// disk I/O happens. When ON, writes accumulate in an in-memory buffer and are
// appended to the target file every FlushInterval (default 5s), or on Close.
//
// Opening+closing per flush keeps the file unlocked between flushes so the
// user can tail/open it live in another editor (matters on Windows, where
// Go's default open holds an exclusive share by default anyway, but more
// importantly so the file on disk is always up-to-date and not just on exit).
type LogSink struct {
	path          string
	flushInterval time.Duration

	enabled atomic.Bool

	mu  sync.Mutex
	buf bytes.Buffer
}

// NewLogSink returns a disabled sink. Call Enable/Toggle to turn it on.
func NewLogSink(path string, flushInterval time.Duration) *LogSink {
	if flushInterval <= 0 {
		flushInterval = 5 * time.Second
	}
	return &LogSink{path: path, flushInterval: flushInterval}
}

// Enabled reports whether log writing is currently on.
func (s *LogSink) Enabled() bool { return s.enabled.Load() }

// Toggle flips the enabled state and returns the new value.
func (s *LogSink) Toggle() bool {
	next := !s.enabled.Load()
	s.enabled.Store(next)
	return next
}

// Write implements io.Writer. Returns len(p) even when disabled so callers
// (like the stdlib log package) never see an error.
func (s *LogSink) Write(p []byte) (int, error) {
	if !s.enabled.Load() {
		return len(p), nil
	}
	if s.path == "" {
		return len(p), nil
	}
	s.mu.Lock()
	n, err := s.buf.Write(p)
	s.mu.Unlock()
	return n, err
}

// Flush appends the buffered bytes to the file and releases the file handle.
// Safe to call even when the sink is disabled (will flush any pending bytes
// written before it was disabled).
func (s *LogSink) Flush() error {
	if s.path == "" {
		return nil
	}
	s.mu.Lock()
	if s.buf.Len() == 0 {
		s.mu.Unlock()
		return nil
	}
	data := make([]byte, s.buf.Len())
	copy(data, s.buf.Bytes())
	s.buf.Reset()
	s.mu.Unlock()

	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

// RunFlusher flushes the sink at FlushInterval until ctx is cancelled, then
// does one final flush before returning. Run it in its own goroutine.
func (s *LogSink) RunFlusher(ctx context.Context) {
	t := time.NewTicker(s.flushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = s.Flush()
			return
		case <-t.C:
			_ = s.Flush()
		}
	}
}
