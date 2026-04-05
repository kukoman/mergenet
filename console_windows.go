package main

import (
	"os"
	"syscall"
	"unsafe"
)

const enableVirtualTerminalProcessing = 0x0004

// enableVirtualTerminal turns on ANSI/VT escape processing on Windows stdout.
// Without this, codes like \x1b[31m print as literal "←[31m".
func enableVirtualTerminal() {
	k := syscall.NewLazyDLL("kernel32.dll")
	getMode := k.NewProc("GetConsoleMode")
	setMode := k.NewProc("SetConsoleMode")

	h := syscall.Handle(os.Stdout.Fd())
	var mode uint32
	r, _, _ := getMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return
	}
	_, _, _ = setMode.Call(uintptr(h), uintptr(mode|enableVirtualTerminalProcessing))
}

// pauseOnDoubleClick waits for Enter if this process is the sole owner of
// its console window — i.e. it was double-clicked from Explorer rather
// than launched from an existing cmd/PowerShell/terminal session. Without
// this pause, a fatal error message would flash for an instant before the
// console window closes, leaving the user with no idea what went wrong.
//
// The detection uses GetConsoleProcessList: if only one process (us) is
// attached to the console, we own it and must hold it open. When launched
// from a shell the shell is also attached (count >= 2), and we return
// immediately so the shell keeps the error visible on its own.
//
// If the WinAPI call fails for any reason we return silently rather than
// block — better to lose a pause than hang a terminal user forever.
func pauseOnDoubleClick() {
	k := syscall.NewLazyDLL("kernel32.dll")
	getList := k.NewProc("GetConsoleProcessList")
	var buf [4]uint32
	r, _, _ := getList.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r != 1 {
		return // shared console (launched from a shell), or call failed
	}
	os.Stderr.WriteString("Press Enter to exit...")
	var b [1]byte
	_, _ = os.Stdin.Read(b[:])
}
