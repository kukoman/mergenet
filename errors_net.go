package main

import (
	"errors"
	"syscall"
)

// Network bind-error helpers. These sit between Go's platform-portable
// syscall constants and the raw WSA codes that Windows Go emits: on
// Windows, net/* returns errors wrapping syscall.Errno(10048/10049)
// directly, NOT the cross-platform syscall.EADDRINUSE/EADDRNOTAVAIL
// constants (which on Windows are synthetic APPLICATION_ERROR values).
// Both forms are checked so call sites are portable without build tags.

// isAddrInUse reports whether err is EADDRINUSE / WSAEADDRINUSE — the
// port is already bound by another socket. Typically another mergenet
// instance still running.
func isAddrInUse(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == 10048 // Windows: WSAEADDRINUSE
	}
	return false
}

// isBindUnavailable reports whether err is EADDRNOTAVAIL / WSAEADDRNOTAVAIL
// ("requested address is not valid in its context"). The local source
// address we tried to bind to does not exist on any interface right now
// — almost always because a Link's cached LocalIP briefly disagrees with
// the actual adapter state (Wi-Fi roam, DHCP renewal, VPN toggle,
// sleep/wake). Callers use this to decide whether to retry on another
// link: a bind failure happens before any bytes are written, so retry
// is safe regardless of HTTP method or request body.
func isBindUnavailable(err error) bool {
	if errors.Is(err, syscall.EADDRNOTAVAIL) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == 10049 // Windows: WSAEADDRNOTAVAIL
	}
	return false
}
