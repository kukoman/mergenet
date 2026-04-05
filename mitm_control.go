package main

import (
	"bufio"
	"os"
	"strings"
	"sync/atomic"
)

// MITMController is the runtime on/off switch for HTTPS interception. It lives
// separately from the rest of ProxyConfig so the proxy hot-path does a single
// atomic load to decide whether to tunnel or MITM a CONNECT.
//
// Intended usage: MITM is OFF by default — the proxy behaves as a pure TCP
// pass-through (fast, no HEAD probes, no serialized request loops, no broken
// WebSocket upgrades). The user flips it ON only while they intend to download
// a large file, so the download's HTTPS GET gets intercepted and range-split
// across both links. Once the download finishes, the user flips it OFF again.
//
// The toggle is flipped via the TUI ('m' + Enter). No CLI flags, no restart.
type MITMController struct {
	on atomic.Bool
}

// NewMITMController returns a controller in the OFF state.
func NewMITMController() *MITMController { return &MITMController{} }

// Enabled reports whether MITM interception is currently active.
func (m *MITMController) Enabled() bool { return m.on.Load() }

// Toggle flips the state and returns the new value.
func (m *MITMController) Toggle() bool {
	// Load-then-store; single writer (TUI key handler) so no CAS loop needed.
	next := !m.on.Load()
	m.on.Store(next)
	return next
}

// Set forces the controller to a specific state.
func (m *MITMController) Set(v bool) { m.on.Store(v) }

// runKeypressLoop watches stdin for single-character commands typed by the user
// in the terminal hosting the TUI. Terminals on Windows/macOS/Linux are
// line-buffered by default, so the user types 'm' + Enter. We don't put the
// terminal into raw mode — staying line-buffered keeps this cross-platform and
// dependency-free, and the TUI redraws every second so the typed character
// only briefly pollutes the screen before the next redraw clears it.
//
// Commands:
//
//	m  — toggle MITM on/off
//	l  — toggle log file writing on/off (may be nil if no log sink configured)
//	q  — quit (same as Ctrl+C)
//
// Exits when `done` is closed.
func runKeypressLoop(ctrl *MITMController, sink *LogSink, done <-chan struct{}) {
	scanner := bufio.NewScanner(os.Stdin)
	lines := make(chan string)
	go func() {
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	for {
		select {
		case <-done:
			return
		case line, ok := <-lines:
			if !ok {
				return
			}
			cmd := strings.ToLower(strings.TrimSpace(line))
			switch cmd {
			case "m":
				if ctrl != nil {
					ctrl.Toggle()
				}
			case "l":
				if sink != nil {
					sink.Toggle()
				}
			}
		}
	}
}
