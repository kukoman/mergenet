package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

var Version = "1.5.0"

const (
	probeTarget  = "1.1.1.1:53"
	probeTimeout = 2 * time.Second
	scanInterval = 5 * time.Second
)

func main() {
	var (
		listen      = flag.String("listen", "127.0.0.1:1080", "proxy listen address (SOCKS5 + HTTP)")
		dryRun      = flag.Bool("dry-run", false, "print discovered adapters and exit")
		logMode     = flag.Bool("log", false, "use scrolling log output instead of live TUI")
		logFile     = flag.String("logfile", "mergenet.log", "file to capture logs to in TUI mode (empty = discard)")
		noMitm      = flag.Bool("no-mitm", false, "disable HTTPS interception even when running as admin")
		installCert = flag.Bool("install-cert", false, "install mergenet CA into the system trust store (admin/sudo required) and exit")
		uninstallC  = flag.Bool("uninstall-cert", false, "remove mergenet CA from the system trust store (admin/sudo required) and exit")
		setupOnly   = flag.Bool("setup-only", false, "(internal) run admin setup tasks and exit — used by elevation path")
		noElevate   = flag.Bool("no-elevate", false, "don't offer automatic elevation when running non-admin (Windows UAC only)")
		insecure    = flag.Bool("insecure", false, "skip upstream TLS certification verification (helps with MITM connection errors)")
	)
	flag.Parse()

	GlobalInsecureSkipVerify = *insecure

	enableVirtualTerminal()

	if *installCert {
		if err := InstallCA(); err != nil {
			log.Fatalf("install-cert: %v", err)
		}
		fmt.Println("mergenet CA installed. You can now run with --mitm.")
		return
	}
	if *uninstallC {
		if err := UninstallCA(); err != nil {
			log.Fatalf("uninstall-cert: %v", err)
		}
		fmt.Println("mergenet CA removed.")
		return
	}
	if *setupOnly {
		if err := DoSetupOnly(); err != nil {
			fmt.Printf("setup failed: %v\nPress Enter to close.\n", err)
			fmt.Scanln()
			os.Exit(1)
		}
		return
	}

	log.SetFlags(log.Ltime)

	listenAddr := *listen

	if *dryRun {
		runDryRun()
		return
	}

	fmt.Printf("mergenet v%s starting\n", Version)

	scorer := NewLinkScorer()
	balancer := NewBalancer()
	balancer.scorer = scorer
	recent := NewRecentConns(200)

	// Initial discovery (visible in normal stdout before TUI takes over).
	fmt.Println("scanning adapters...")
	scanOnce(balancer)
	healthy := countHealthy(balancer)
	fmt.Printf("%d link(s) active\n", healthy)
	for _, v := range balancer.SnapshotView() {
		state := "UP"
		if !v.Healthy {
			state = "DOWN"
		}
		fmt.Printf("  [%s] %s %s (probe %dms)\n", v.Name, v.LocalIP, state, v.ProbeLatency.Milliseconds())
	}

	if healthy < 2 {
		fmt.Println()
		fmt.Println("⚠  Only 1 link detected — mergenet needs at least 2 to split traffic.")
		fmt.Println()
		if runtime.GOOS == "windows" {
			fmt.Println("   Common cause on Windows: WiFi automatically disconnects when USB tether")
			fmt.Println("   (or Ethernet) connects, due to the \"Minimize simultaneous connections\"")
			fmt.Println("   policy. To disable it, open CMD as Administrator and run:")
			fmt.Println()
			fmt.Println("   reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy\" /v fMinimizeConnections /t REG_DWORD /d 0 /f")
			fmt.Println()
			fmt.Println("   Then reconnect WiFi + tether and restart mergenet.")
		} else {
			fmt.Println("   Make sure both links (e.g. WiFi + USB-tethered phone / second WiFi) are")
			fmt.Println("   connected and have an IPv4 address. Check with `--dry-run`.")
		}
		fmt.Println()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Background rescan loop.
	go func() {
		ticker := time.NewTicker(scanInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				scanOnce(balancer)
			}
		}
	}()

	// Build proxy config + capture status for TUI header.
	// MITM auto-arms if CA is ready — the interceptor detects download URLs by
	// extension on the fly and range-splits them, while forwarding everything
	// else normally (including WebSockets, which get raw-spliced). User can
	// still toggle MITM off at runtime via 'm'+Enter if needed.
	mitmCtrl := NewMITMController()
	pc := &ProxyConfig{Balancer: balancer, Scorer: scorer, Recent: recent, MITMCtrl: mitmCtrl}
	status := TUIStatus{Admin: IsAdmin(), MITMCtrl: mitmCtrl}

	if status.Admin {
		applyFMinimizeConnectionsFix()
		status.RegFixApplied = IsFMinimizeConnectionsDisabled()
		if runtime.GOOS == "windows" && !status.RegFixApplied {
			fmt.Println("⚠  Could not disable fMinimizeConnections policy (reg add failed).")
			fmt.Println("   WiFi may be killed when USB tether connects. Check Group Policy settings.")
		}
		if !*noMitm {
			ca, err := LoadOrCreateCA()
			if err != nil {
				log.Fatalf("load CA: %v", err)
			}
			if !isCAInstalled() {
				if err := InstallCA(); err != nil {
					fmt.Printf("⚠  CA install failed: %v\n", err)
					fmt.Println("   HTTPS interception (single-file splitting) is DISABLED.")
					fmt.Println("   Retry with: mergenet.exe --install-cert  (as admin)")
				} else {
					status.CAInstalled = true
					pc.Minter = NewMinter(ca)
				}
			} else {
				status.CAInstalled = true
				pc.Minter = NewMinter(ca)
			}
			status.MITMAvailable = pc.Minter != nil
		}
	} else {
		// Non-admin path. Check what's already been done by a previous admin run.
		status.CAInstalled = isCAInstalled()
		status.RegFixApplied = IsFMinimizeConnectionsDisabled()

		if !status.CAInstalled && !*noMitm && !*noElevate {
			if runtime.GOOS == "windows" {
				fmt.Println("first-time setup: requesting elevation for CA install + WiFi policy fix (UAC prompt)...")
				fmt.Println("  (click Yes on the UAC dialog; click No and MITM will be disabled)")
			} else {
				fmt.Println("first-time setup: CA not installed (single-file splitting disabled).")
			}
			if err := ElevateForSetup(); err != nil {
				fmt.Printf("⚠  Elevation failed: %v\n", err)
				if runtime.GOOS == "windows" {
					fmt.Println("   This usually means you clicked No on the UAC prompt.")
					fmt.Println("   To fix: re-run mergenet.exe and approve UAC,")
					fmt.Println("           OR run with --no-mitm to skip single-file splitting,")
					fmt.Println("           OR run: mergenet.exe --install-cert  (as admin, one-time).")
				}
			}
			// Re-check after setup.
			status.CAInstalled = isCAInstalled()
			status.RegFixApplied = IsFMinimizeConnectionsDisabled()
			if !status.CAInstalled {
				fmt.Println("⚠  CA still not installed after setup attempt — MITM disabled.")
				fmt.Println("   Single-file downloads will NOT be split. Run --install-cert as admin to retry.")
			}
			if runtime.GOOS == "windows" && !status.RegFixApplied {
				fmt.Println("⚠  fMinimizeConnections policy not applied — WiFi may drop when tether connects.")
			}
		} else if !status.CAInstalled && !*noMitm && *noElevate {
			fmt.Println("note: CA not installed and --no-elevate set → MITM disabled (no single-file splitting).")
		}
		// If CA is installed, we can MITM even without admin.
		if status.CAInstalled && !*noMitm {
			ca, err := LoadOrCreateCA()
			if err != nil {
				fmt.Printf("warning: CA is installed but couldn't load key: %v\n", err)
			} else {
				pc.Minter = NewMinter(ca)
				status.MITMAvailable = true
			}
		}
	}

	// Auto-arm MITM whenever it's available. The interceptor routes each
	// request on the fly: download extensions get range-split, WebSockets
	// get raw-spliced, everything else forwards single-link.
	if status.MITMAvailable && !*noMitm {
		mitmCtrl.Set(true)
	}

	// Start proxy listener.
	proxyLn, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fatalListenError(listenAddr, err)
	}
	mode := "SOCKS5 + HTTP"
	if pc.Minter != nil {
		mode += " + MITM"
	}
	fmt.Printf("proxy (%s) listening on %s\n", mode, listenAddr)
	fmt.Printf("→ set your system proxy (HTTP + HTTPS) to: %s\n", listenAddr)
	fmt.Println()
	go ServeSOCKS5(proxyLn, pc)

	// Wait for signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	done := make(chan struct{})
	go func() {
		<-sigCh
		close(done)
	}()

	// TUI mode log sink: buffered in-memory writer that flushes to disk every
	// 5s, opening+closing the file per flush (so the log file isn't held
	// open/locked for the whole session). Disabled by default — user toggles
	// with 'l'+Enter when they actually want to capture logs.
	var logSink *LogSink
	if !*logMode && *logFile != "" {
		logSink = NewLogSink(*logFile, 5*time.Second)
		flushCtx, flushCancel := context.WithCancel(context.Background())
		defer flushCancel()
		go logSink.RunFlusher(flushCtx)
		status.LogSink = logSink
	}

	// TUI stdin keystroke listener: 'm'+Enter toggles MITM, 'l'+Enter toggles
	// log writing. Started whenever the TUI is up — either toggle is useful
	// on its own, so don't gate on MITM availability.
	if !*logMode {
		go runKeypressLoop(mitmCtrl, logSink, done)
	}

	if *logMode {
		// Classic scrolling log. Block until signal.
		<-done
	} else {
		// TUI mode: route log output through the sink (no-op until toggled on).
		var logOut io.Writer = io.Discard
		if logSink != nil {
			logOut = logSink
		}
		log.SetOutput(logOut)
		time.Sleep(400 * time.Millisecond)
		RunTUI(listenAddr, status, balancer, scorer, recent, done)
		// Restore stdout and exit cleanly.
		log.SetOutput(os.Stderr)
		fmt.Print("\033[0m\n")
		if logSink != nil {
			_ = logSink.Flush()
		}
	}

	fmt.Println("shutting down")
	_ = proxyLn.Close()
	cancel()
}

func countHealthy(b *Balancer) int {
	n := 0
	for _, v := range b.SnapshotView() {
		if v.Healthy {
			n++
		}
	}
	return n
}

func runDryRun() {
	adapters, err := EnumerateAdapters()
	if err != nil {
		log.Fatalf("enumerate: %v", err)
	}
	for _, a := range adapters {
		if a.Skipped != "" {
			fmt.Printf("  [skip] %-40s (%s)\n", a.Name, a.Skipped)
			continue
		}
		lat, err := ProbeAdapter(a.IPv4, probeTarget, probeTimeout)
		if err != nil {
			fmt.Printf("  [fail] %-40s %s (probe: %v)\n", a.Name, a.IPv4, err)
			continue
		}
		fmt.Printf("  [ok]   %-40s %-16s probe: %v\n", a.Name, a.IPv4, lat.Truncate(time.Millisecond))
	}
}

// scanOnce enumerates adapters, probes candidates, syncs balancer state.
func scanOnce(b *Balancer) {
	adapters, err := EnumerateAdapters()
	if err != nil {
		log.Printf("scan: enumerate error: %v", err)
		return
	}

	seenUsable := map[string]bool{}
	for _, a := range adapters {
		if a.Skipped != "" || a.IPv4 == nil {
			continue
		}
		lat, err := ProbeAdapter(a.IPv4, probeTarget, probeTimeout)
		if err != nil {
			if b.SetHealthy(a.Name, false) {
				log.Printf("[%s] went DOWN (probe failed: %v)", a.Name, err)
			}
			continue
		}
		seenUsable[a.Name] = true
		wasHealthy, existed := b.Upsert(a.Name, a.IPv4, 1, lat)
		if !existed || !wasHealthy {
			log.Printf("[%s] came UP (%s, probe: %v)", a.Name, a.IPv4, lat.Truncate(time.Millisecond))
		}
	}

	for _, v := range b.SnapshotView() {
		if !seenUsable[v.Name] && v.Healthy {
			log.Printf("[%s] went DOWN (adapter gone)", v.Name)
			b.SetHealthy(v.Name, false)
		}
	}
}

// fatalListenError prints an actionable explanation of a listener bind
// failure and exits. Specialises the common port-already-in-use case
// (typically another mergenet instance still running) with platform-
// appropriate commands to find and stop the offending process. Holds the
// console open on Windows double-click launches so the user actually sees
// the message before the window closes.
func fatalListenError(addr string, err error) {
	port := addr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		port = addr[i+1:]
	}
	fmt.Fprintln(os.Stderr)
	if isAddrInUse(err) {
		fmt.Fprintf(os.Stderr, "ERROR: cannot start proxy on %s — port already in use.\n\n", addr)
		fmt.Fprintln(os.Stderr, "Another process is bound to that port (usually a previous mergenet")
		fmt.Fprintln(os.Stderr, "instance that's still running). Find and stop it:")
		fmt.Fprintln(os.Stderr)
		if runtime.GOOS == "windows" {
			fmt.Fprintf(os.Stderr, "    netstat -ano | findstr :%s\n", port)
			fmt.Fprintln(os.Stderr, "    taskkill /F /PID <pid>")
		} else {
			fmt.Fprintf(os.Stderr, "    lsof -iTCP:%s -sTCP:LISTEN -n -P\n", port)
			fmt.Fprintln(os.Stderr, "    kill <pid>")
		}
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Or start mergenet on a different port:")
		fmt.Fprintln(os.Stderr, "    mergenet --listen 127.0.0.1:1081")
	} else {
		fmt.Fprintf(os.Stderr, "ERROR: cannot bind to %s: %v\n\n", addr, err)
		fmt.Fprintln(os.Stderr, "Try a different address/port:")
		fmt.Fprintln(os.Stderr, "    mergenet --listen 127.0.0.1:1081")
	}
	fmt.Fprintln(os.Stderr)
	pauseOnDoubleClick()
	os.Exit(1)
}

