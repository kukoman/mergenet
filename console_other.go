//go:build !windows

package main

// enableVirtualTerminal is a no-op on non-Windows platforms (ANSI works natively).
func enableVirtualTerminal() {}
