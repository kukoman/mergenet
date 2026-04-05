//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// IsAdmin reports whether the current process has root privileges.
// On macOS/Linux, CA install/uninstall into the system keychain requires root.
func IsAdmin() bool {
	return os.Geteuid() == 0
}

// IsFMinimizeConnectionsDisabled is a Windows-only concept. Return true so the
// TUI shows this "requirement" as satisfied on non-Windows platforms.
func IsFMinimizeConnectionsDisabled() bool { return true }

// applyFMinimizeConnectionsFix is a no-op outside Windows.
func applyFMinimizeConnectionsFix() {}

// InstallCA adds the mergenet root CA to the system trust store.
//   - macOS: /Library/Keychains/System.keychain via `security` (needs sudo)
//   - Linux: not implemented — install ca.pem into your distro's CA bundle manually,
//     or run with --no-mitm.
func InstallCA() error {
	certPath, _, err := caPaths()
	if err != nil {
		return err
	}
	if _, err := os.Stat(certPath); err != nil {
		if _, err := LoadOrCreateCA(); err != nil {
			return err
		}
	}
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("security", "add-trusted-cert",
			"-d", "-r", "trustRoot",
			"-k", "/Library/Keychains/System.keychain", certPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	default:
		return fmt.Errorf("automatic CA install not supported on %s — install %s into your system trust store manually, or run with --no-mitm",
			runtime.GOOS, certPath)
	}
}

// UninstallCA removes the mergenet root CA from the system trust store.
func UninstallCA() error {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("security", "delete-certificate",
			"-c", "mergenet Root CA",
			"/Library/Keychains/System.keychain")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	default:
		return fmt.Errorf("automatic CA uninstall not supported on %s", runtime.GOOS)
	}
}

// isCAInstalled checks if our CA is present in the system trust store.
func isCAInstalled() bool {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("security", "find-certificate",
			"-c", "mergenet Root CA",
			"/Library/Keychains/System.keychain")
		return cmd.Run() == nil
	default:
		return false
	}
}

// ElevateForSetup: no UAC equivalent on macOS/Linux. Tell the user to re-run
// with sudo, or bypass MITM entirely with --no-mitm.
func ElevateForSetup() error {
	return fmt.Errorf("automatic elevation is Windows-only. Re-run with `sudo` to install the CA, or start with --no-mitm to skip single-file splitting")
}

// DoSetupOnly runs one-time admin setup when invoked as root.
func DoSetupOnly() error {
	if !IsAdmin() {
		return fmt.Errorf("--setup-only requires root; re-run with sudo")
	}
	fmt.Println("mergenet: running one-time admin setup")
	if _, err := LoadOrCreateCA(); err != nil {
		return fmt.Errorf("load/create CA: %w", err)
	}
	if !isCAInstalled() {
		if err := InstallCA(); err != nil {
			return fmt.Errorf("install CA: %w", err)
		}
		fmt.Println("  ✓ CA installed into system trust store")
	} else {
		fmt.Println("  ✓ CA already installed")
	}
	fmt.Println("Setup complete.")
	return nil
}
