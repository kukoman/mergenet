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
