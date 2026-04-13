package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// link_net.go — per-Link networking resources.
//
// Every Link represents an outbound network path through a specific
// source IP. This file is the single place that knows how to turn a
// *Link into:
//
//   1. net.Dialer bound to the link's source IP — Link.NewDialer
//   2. http.Transport bound to the link's source IP — Link.Transport
//
// ALL dialers and transports produced here RE-READ link.LocalIP on
// every Dial, not at construction. If an adapter's IPv4 changes
// (Wi-Fi roam, DHCP renewal, VPN toggle, sleep/wake), scanOnce
// updates link.LocalIP and the very next connection picks up the new
// source IP automatically. Capturing LocalIP once would poison the
// dialer/transport permanently — every request would fail with
// EADDRNOTAVAIL until the process restarted. That was a real bug
// (fixed in v1.2.3).
//
// Why both a dialer factory AND a cached transport:
//
//   - NewDialer serves short-lived, one-shot dials (SOCKS/HTTP-CONNECT
//     pass-through, WebSocket hijack, probes). Each call returns a
//     freshly-minted dialer, so LocalIP is current at that moment.
//
//   - Transport serves long-lived HTTP clients (MITM forward, range-
//     split chunks) that reuse connections via connection pooling. It
//     must be cached so that pooled conns survive across requests,
//     but its DialContext closure re-reads LocalIP so new conns added
//     to the pool always reflect the current adapter state.

// linkTransports caches one http.Transport per Link for the lifetime
// of the process. Keyed by Link pointer because Links are unique,
// long-lived instances owned by the Balancer.
var (
	linkTransportMu sync.RWMutex
	linkTransports  = map[*Link]*http.Transport{}
	GlobalInsecureSkipVerify bool
)

// NewDialer returns a net.Dialer whose LocalAddr is bound to this
// link's CURRENT LocalIP. Because LocalAddr is read at this call,
// callers should Dial immediately rather than holding the returned
// dialer across time — otherwise they risk binding to a stale IP.
// Use Transport instead for any HTTP client that reuses connections.
func (l *Link) NewDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: l.LocalIP},
		Timeout:   timeout,
	}
}

// Transport returns the cached http.Transport for this link. The
// transport's DialContext creates a fresh dialer per dial, so the
// source IP always reflects the current link.LocalIP even across
// adapter address changes. Lazily initialised on first call; safe
// for concurrent use.
func (l *Link) Transport() *http.Transport {
	linkTransportMu.RLock()
	if tr, ok := linkTransports[l]; ok {
		linkTransportMu.RUnlock()
		return tr
	}
	linkTransportMu.RUnlock()

	linkTransportMu.Lock()
	defer linkTransportMu.Unlock()
	if tr, ok := linkTransports[l]; ok {
		return tr
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Fresh dialer per dial: LocalIP read NOW, not when the
			// transport was constructed. This is the fix for the
			// stale-source-IP poisoning bug.
			d := &net.Dialer{
				LocalAddr: &net.TCPAddr{IP: l.LocalIP},
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			return d.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: GlobalInsecureSkipVerify,
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   16,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true, // pass-through client's Accept-Encoding
	}
	// Enable HTTP/2 PING-based health checking so idle connections
	// that died (server GOAWAY, network blip) are detected and evicted
	// before a real request hangs on them until ResponseHeaderTimeout.
	// Without this, OAuth callbacks after a long auth page visit hit
	// "http2: timeout awaiting response headers" on stale connections.
	h2t, err := http2.ConfigureTransports(tr)
	if err != nil {
		log.Printf("[%s] http2.ConfigureTransports: %v (falling back to auto-h2)", l.Name, err)
	} else {
		h2t.ReadIdleTimeout = 10 * time.Second // send PING after 10s idle
		h2t.PingTimeout = 5 * time.Second      // close conn if no PONG within 5s
	}
	linkTransports[l] = tr
	return tr
}
