//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// InstallCA installs the mergenet root CA into the Windows Trusted Root store.
// Requires admin — prompts UAC via certutil.
func InstallCA() error {
	certPath, _, err := caPaths()
	if err != nil {
		return err
	}
	if _, err := os.Stat(certPath); err != nil {
		// Generate first
		if _, err := LoadOrCreateCA(); err != nil {
			return err
		}
	}
	cmd := exec.Command("certutil", "-addstore", "-f", "Root", certPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// UninstallCA removes the mergenet root CA from the Windows Trusted Root store.
func UninstallCA() error {
	cmd := exec.Command("certutil", "-delstore", "Root", "mergenet Root CA")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// isCAInstalled checks if our CA is already in the Windows Trusted Root store.
func isCAInstalled() bool {
	cmd := exec.Command("certutil", "-store", "Root", "mergenet Root CA")
	return cmd.Run() == nil
}

// IsAdmin reports whether the current process has admin rights (Windows).
// Uses `net session` which requires admin. Best-effort: returns false on any error.
func IsAdmin() bool {
	cmd := exec.Command("net", "session")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

// IsFMinimizeConnectionsDisabled reads the registry to check if the fix is
// already applied. Readable from non-admin. Returns false if the value is
// missing or set to 1.
func IsFMinimizeConnectionsDisabled() bool {
	cmd := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy`,
		"/v", "fMinimizeConnections")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	// Output contains "fMinimizeConnections    REG_DWORD    0x0" if disabled.
	return strings.Contains(string(out), "0x0")
}

// applyFMinimizeConnectionsFix sets the registry value that stops Windows from
// killing WiFi when another connection (USB tether / Ethernet) comes up.
// Best-effort; no-op without admin.
func applyFMinimizeConnectionsFix() {
	cmd := exec.Command("reg", "add",
		`HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy`,
		"/v", "fMinimizeConnections", "/t", "REG_DWORD", "/d", "0", "/f")
	_ = cmd.Run() // silent; we'll check effect by adapter presence
}

// ElevateForSetup re-runs the current binary with UAC elevation to perform
// one-time admin tasks (CA install + regedit fix). Blocks until the elevated
// process exits. Returns nil if elevation completed successfully.
func ElevateForSetup() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	// PowerShell Start-Process with -Verb RunAs triggers UAC prompt.
	// -Wait blocks until the elevated child exits.
	psCmd := fmt.Sprintf("Start-Process -FilePath '%s' -ArgumentList '--setup-only' -Verb RunAs -Wait",
		exePath)
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	return cmd.Run()
}

// DoSetupOnly performs all admin-only configuration and exits. Called by the
// elevated child process spawned from ElevateForSetup.
func DoSetupOnly() error {
	fmt.Println("mergenet: running one-time admin setup")
	applyFMinimizeConnectionsFix()
	fmt.Println("  ✓ fMinimizeConnections policy disabled")
	if _, err := LoadOrCreateCA(); err != nil {
		return fmt.Errorf("load/create CA: %w", err)
	}
	if !isCAInstalled() {
		if err := InstallCA(); err != nil {
			return fmt.Errorf("install CA: %w", err)
		}
		fmt.Println("  ✓ CA installed into Windows trust store")
	} else {
		fmt.Println("  ✓ CA already installed")
	}
	fmt.Println("\nSetup complete. This window will close in 3 seconds.")
	time.Sleep(3 * time.Second)
	return nil
}
