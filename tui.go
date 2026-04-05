package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// ANSI escape codes. Windows 10+ terminals enable VT processing by default.
const (
	ansiClear     = "\033[2J\033[H"
	ansiHome      = "\033[H"
	ansiClearDown = "\033[J"  // clear from cursor to end of screen
	ansiClearEOL  = "\033[K" // clear from cursor to end of line
	ansiReset     = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiGray   = "\033[90m"
)

// linkSnap is a point-in-time snapshot used for rate calculation.
type linkSnap struct {
	BytesIn  int64
	BytesOut int64
}

// TUIStatus holds startup/runtime configuration to display permanently.
// MITMAvailable is static (set once at startup based on CA load + admin/cert status).
// MITMCtrl is read live at each redraw to reflect the runtime on/off toggle.
type TUIStatus struct {
	Admin         bool
	MITMAvailable bool // CA loaded + minter ready (prerequisite for interception)
	CAInstalled   bool
	RegFixApplied bool
	MITMCtrl      *MITMController // live runtime toggle (may be nil)
	LogSink       *LogSink        // live log-writing toggle (may be nil)
}

// RunTUI renders a live status view until ctx-like signal arrives.
// Blocks until os.Interrupt is received via sigCh.
func RunTUI(listen string, status TUIStatus, b *Balancer, recent *RecentConns, sigCh <-chan struct{}) {
	prev := map[string]linkSnap{}
	prevTime := time.Now()

	// First draw
	draw(listen, status, b, recent, prev, 0)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-sigCh:
			return
		case t := <-ticker.C:
			dt := t.Sub(prevTime).Seconds()
			if dt <= 0 {
				dt = 1
			}
			draw(listen, status, b, recent, prev, dt)
			// Update prev snapshot for next tick
			prev = map[string]linkSnap{}
			for _, v := range b.SnapshotView() {
				prev[v.Name] = linkSnap{BytesIn: v.BytesIn, BytesOut: v.BytesOut}
			}
			prevTime = t
		}
	}
}

func draw(listen string, status TUIStatus, b *Balancer, recent *RecentConns, prev map[string]linkSnap, dt float64) {
	var sb strings.Builder
	sb.WriteString(ansiHome)

	// Header
	sb.WriteString(ansiBold + ansiCyan + "mergenet" + ansiReset)
	sb.WriteString(ansiDim + " v" + Version + ansiReset)
	sb.WriteString("   " + ansiDim + "proxy:" + ansiReset + " " + listen)
	sb.WriteString("   " + ansiDim + time.Now().Format("15:04:05") + ansiReset + "\n")

	// MITM live state (read from controller every draw)
	mitmOn := status.MITMCtrl != nil && status.MITMCtrl.Enabled()

	// Status indicators line
	sb.WriteString(" ")
	sb.WriteString(statusIndicator("ADMIN", status.Admin))
	sb.WriteString("  ")
	sb.WriteString(mitmIndicator(status.MITMAvailable, mitmOn))
	sb.WriteString("  ")
	sb.WriteString(statusIndicator("CA INSTALLED", status.CAInstalled))
	sb.WriteString("  ")
	sb.WriteString(statusIndicator("WIFI POLICY FIX", status.RegFixApplied))
	sb.WriteString("\n")

	// Action hint line — only show what's actually broken.
	switch {
	case !status.MITMAvailable && !status.CAInstalled:
		sb.WriteString(" " + ansiYellow + "⚠  CA not installed — single-file download splitting disabled. Run once as Administrator to fix." + ansiReset + "\n")
	case !status.MITMAvailable:
		sb.WriteString(" " + ansiYellow + "⚠  MITM disabled (--no-mitm or CA load failed)" + ansiReset + "\n")
	case !status.RegFixApplied:
		sb.WriteString(" " + ansiYellow + "⚠  WiFi-keep-alive policy fix not applied — WiFi may drop when tethering. Run once as Administrator." + ansiReset + "\n")
	}

	sb.WriteString(ansiDim + strings.Repeat("─", 100) + ansiReset + "\n")

	// Links table
	links := b.SnapshotView()
	anyHealthy := false
	for _, l := range links {
		if l.Healthy {
			anyHealthy = true
			break
		}
	}
	if !anyHealthy {
		sb.WriteString(ansiRed + ansiBold + " ⚠  NO HEALTHY LINKS — proxy is refusing new connections" + ansiReset + "\n")
		sb.WriteString(ansiDim + strings.Repeat("─", 100) + ansiReset + "\n")
	}

	sb.WriteString(ansiBold)
	sb.WriteString(fmt.Sprintf(" %-14s %-16s %-8s %-7s %-7s %-8s %-12s %-12s %-10s %-10s\n",
		"LINK", "IP", "STATUS", "PROBE", "ACTIVE", "TOTAL", "DOWN", "UP", "↓ MB/s", "↑ MB/s"))
	sb.WriteString(ansiReset)

	for _, l := range links {
		statusColor := ansiGreen
		statusText := "● UP  "
		if !l.Healthy {
			statusColor = ansiRed
			statusText = "● DOWN"
		}
		rateIn, rateOut := 0.0, 0.0
		if dt > 0 {
			if p, ok := prev[l.Name]; ok {
				if di := l.BytesIn - p.BytesIn; di > 0 {
					rateIn = float64(di) / dt / 1048576.0
				}
				if do := l.BytesOut - p.BytesOut; do > 0 {
					rateOut = float64(do) / dt / 1048576.0
				}
			}
		}
		sb.WriteString(fmt.Sprintf(" %-14s %-16s %s%s%s  %-7s %-7d %-7d %-12s %-12s %-10.2f %-10.2f\n",
			truncate(l.Name, 14),
			l.LocalIP.String(),
			statusColor, statusText, ansiReset,
			fmt.Sprintf("%dms", l.ProbeLatency.Milliseconds()),
			l.ActiveConns,
			l.TotalConns,
			fmtBytes(l.BytesIn),
			fmtBytes(l.BytesOut),
			rateIn,
			rateOut,
		))
	}

	sb.WriteString(ansiDim + strings.Repeat("─", 100) + ansiReset + "\n")
	sb.WriteString(ansiBold + " RECENT CONNECTIONS" + ansiReset + ansiDim + " (newest first)" + ansiReset + "\n")

	recs := recent.Snapshot()
	// newest last in ring; reverse. Show last 12 to keep the UI within ~28 lines.
	max := 12
	start := len(recs) - 1
	n := 0
	for i := start; i >= 0 && n < max; i-- {
		r := recs[i]
		n++
		tag := fmt.Sprintf("[%s]", r.Link)
		color := ansiCyan
		if r.Link == "local" {
			color = ansiGray
		}
		sb.WriteString(fmt.Sprintf(" %s%s%s  %s%-14s%s  %s\n",
			ansiDim, r.Ts.Format("15:04:05"), ansiReset,
			color, tag, ansiReset,
			truncate(r.Target, 70),
		))
	}
	if n == 0 {
		sb.WriteString(ansiDim + "  (none yet — configure Windows proxy: 127.0.0.1:1080 and browse)" + ansiReset + "\n")
	}

	sb.WriteString(ansiDim + strings.Repeat("─", 100) + ansiReset + "\n")
	logOn := status.LogSink != nil && status.LogSink.Enabled()
	logHint := "'l'+Enter: log OFF"
	if logOn {
		logHint = ansiGreen + "'l'+Enter: log ON" + ansiReset + ansiDim
	} else if status.LogSink == nil {
		logHint = "'l'+Enter: log n/a"
	}
	sb.WriteString(ansiDim + " Ctrl+C quit   •   'm'+Enter: toggle MITM   •   " + logHint + "   •   proxy → 127.0.0.1:1080" + ansiReset + "\n")
	sb.WriteString(ansiClearDown) // wipe any stale content from previous bigger draw

	// Clear to end of line before every newline so shorter lines overwrite longer previous ones.
	out := strings.ReplaceAll(sb.String(), "\n", ansiClearEOL+"\n")
	os.Stdout.WriteString(out)
}

func statusIndicator(label string, ok bool) string {
	if ok {
		return ansiGreen + "●" + ansiReset + " " + label
	}
	return ansiRed + "○" + ansiReset + " " + ansiDim + label + ansiReset
}

// mitmIndicator renders a three-state MITM dot:
//   - green "MITM ON"  : CA ready AND runtime toggle enabled (intercepting now)
//   - yellow "MITM OFF": CA ready but toggle disabled (type 'm' + Enter to arm)
//   - red "MITM N/A"   : CA not installed / minter failed (cannot intercept)
func mitmIndicator(available, on bool) string {
	switch {
	case !available:
		return ansiRed + "○" + ansiReset + " " + ansiDim + "MITM N/A" + ansiReset
	case on:
		return ansiGreen + "●" + ansiReset + " " + ansiBold + "MITM ON" + ansiReset
	default:
		return ansiYellow + "◐" + ansiReset + " " + "MITM OFF"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 4 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func fmtBytes(n int64) string {
	f := float64(n)
	switch {
	case f >= 1073741824:
		return fmt.Sprintf("%.2f GB", f/1073741824)
	case f >= 1048576:
		return fmt.Sprintf("%.1f MB", f/1048576)
	case f >= 1024:
		return fmt.Sprintf("%.1f KB", f/1024)
	default:
		return fmt.Sprintf("%d B", n)
	}
}
