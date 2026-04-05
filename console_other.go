//go:build !windows

package main

// enableVirtualTerminal is a no-op on non-Windows platforms (ANSI works natively).
func enableVirtualTerminal() {}

// pauseOnDoubleClick is a no-op on non-Windows platforms. The double-click
// vanishing-window problem is Windows-specific; Unix users always run from
// a shell that persists after the process exits.
func pauseOnDoubleClick() {}
