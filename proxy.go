package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

const (
	socks5Version = 0x05
	authNoAuth    = 0x00
	authNoAccept  = 0xFF
)

var (
	errBadVersion      = errors.New("socks5: bad version")
	errNoAcceptable    = errors.New("socks5: no acceptable auth methods")
	errShortRead       = errors.New("socks5: short read")
	errUnsupportedCmd  = errors.New("socks5: unsupported cmd")
	errUnsupportedAtyp = errors.New("socks5: unsupported atyp")
)

const (
	cmdConnect = 0x01
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess          = 0x00
	repServerFailure    = 0x01
	repNetworkUnreach   = 0x03
	repHostUnreach      = 0x04
	repCmdNotSupported  = 0x07
	repAtypNotSupported = 0x08
)

type socksRequest struct {
	Target string // "host:port"
}

// ProxyConfig holds runtime settings for the proxy.
type ProxyConfig struct {
	Balancer *Balancer
	Recent   *RecentConns
	Minter   *Minter         // nil = MITM unavailable (CA not installed)
	MITMCtrl *MITMController // runtime on/off switch; nil = always off
}

// mitmActive reports whether, for this CONNECT, we should intercept rather
// than tunnel. Both the cert minter AND the runtime toggle must say yes.
func (pc *ProxyConfig) mitmActive() bool {
	return pc.Minter != nil && pc.MITMCtrl != nil && pc.MITMCtrl.Enabled()
}

// ServeSOCKS5 accepts connections on ln and dispatches each to either the
// SOCKS5 or HTTP proxy handler based on the first byte received. Blocks.
func ServeSOCKS5(ln net.Listener, pc *ProxyConfig) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handleConn(c, pc)
	}
}

// handleConn peeks the first byte and routes to the SOCKS5 or HTTP handler.
// SOCKS5 starts with 0x05; HTTP starts with an ASCII method like G, P, C, etc.
func handleConn(client net.Conn, pc *ProxyConfig) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReader(client)
	first, err := br.Peek(1)
	if err != nil || len(first) == 0 {
		return
	}
	if first[0] == socks5Version {
		handleSOCKS5(client, br, pc)
		return
	}
	handleHTTP(client, br, pc)
}

// ----- Dialer selection & outbound dialing --------------------------------
//
// Outbound proxy traffic flows through this layer. The contract is:
//
//   1. handlers call dialLink(target, balancer)
//   2. dialLink picks a healthy link, dials bound to that link's source IP,
//      and retries once on another link if the first dial fails
//   3. callers receive a *LinkConn that owns the link's accounting lifetime;
//      deferring upstream.Close() both closes the wire AND releases the
//      link's ActiveConns counter
//
// Callers never interact with net.Dialer, b.Pick(), or ActiveConns directly.
// That centralises retry policy, bookkeeping, and error classification so
// that SOCKS, HTTP CONNECT, and HTTP forward paths all share identical
// behaviour — and so that evolving the policy (backoff, circuit breaking,
// per-error classification) is a single-file change.

// errNoHealthyLinks is returned by dialLink when the balancer has no
// currently-healthy link to hand out. Callers distinguish this from a
// generic dial failure to pick the right client-facing status code.
var errNoHealthyLinks = errors.New("no healthy links")

// LinkConn is a dialed upstream connection paired with the Link it flows
// through. Produced exclusively by dialLink. Close releases the link's
// ActiveConns counter in addition to closing the wire; the release is
// idempotent so accidental double-Close does not corrupt the counter.
//
// Link is nil for loopback targets (Name == "local"), in which case no
// accounting is performed.
type LinkConn struct {
	Conn     net.Conn
	Link     *Link
	Name     string
	released int32
}

// Close closes the underlying connection and releases the link's
// ActiveConns counter. Safe to call more than once.
func (lc *LinkConn) Close() error {
	err := lc.Conn.Close()
	if lc.Link != nil && atomic.CompareAndSwapInt32(&lc.released, 0, 1) {
		atomic.AddInt64(&lc.Link.ActiveConns, -1)
	}
	return err
}

// dialChoice is an internal handle produced by chooseDialer: a dialer
// bound to a link's source IP, plus the link itself for accounting.
// Consumed only by dialLink.
type dialChoice struct {
	dialer *net.Dialer
	link   *Link // nil for loopback
	name   string
}

// release undoes the ActiveConns increment that b.Pick() performed when
// this choice was constructed. Called by dialLink on every failed attempt.
func (d *dialChoice) release() {
	if d.link != nil {
		atomic.AddInt64(&d.link.ActiveConns, -1)
	}
}

// chooseDialer selects a healthy link via b.Pick() and builds a dialer
// bound to its source IP. Loopback targets bypass link selection and get
// an unbound dialer. Returns nil when no healthy link exists.
//
// Each call increments ActiveConns on the picked link; the caller MUST
// either use the returned choice to open a conn (ownership transferred to
// a LinkConn, released on Close) or call release() on failure.
func chooseDialer(target string, b *Balancer) *dialChoice {
	if isLoopbackTarget(target) {
		return &dialChoice{
			dialer: &net.Dialer{Timeout: 10 * time.Second},
			name:   "local",
		}
	}
	link := b.Pick()
	if link == nil {
		return nil
	}
	// LocalIP is a snapshot read from the link at Pick time. It can lag
	// the adapter's actual state until the next scanOnce cycle — that
	// lag is what dialLink's retry is designed to tolerate.
	return &dialChoice{
		dialer: &net.Dialer{
			LocalAddr: &net.TCPAddr{IP: link.LocalIP},
			Timeout:   10 * time.Second,
		},
		link: link,
		name: link.Name,
	}
}

// dialLink opens a TCP connection to target through a healthy link,
// retrying once on a different link if the first dial fails. Returns an
// owning LinkConn on success, or errNoHealthyLinks / the first dial error
// on failure.
//
// Why retry is needed:
//
//   A Link caches its LocalIP, refreshed only on scanOnce (every
//   scanInterval, currently 5s). When the OS changes an adapter's IPv4
//   address — Wi-Fi roam, DHCP renewal, VPN toggle, sleep/wake — the
//   cached IP becomes briefly stale. A Dial bound to that stale IP fails
//   with EADDRNOTAVAIL (Windows: WSAEADDRNOTAVAIL, "requested address is
//   not valid in its context") because no interface currently owns it.
//   The next scanOnce heals the state, but without retry every request
//   in the gap surfaces to the user as a broken page load.
//
// Why retry is safe:
//
//   EADDRNOTAVAIL (and any other dial failure) happens before any bytes
//   are written upstream. There is no partial-request ambiguity: a
//   transparent retry on another link cannot cause duplicate side-effects
//   for the target server.
//
// Why two attempts is enough:
//
//   b.Pick() uses weighted round-robin, so attempt #2 naturally rotates
//   to a different healthy link when one exists. With a single healthy
//   link, Pick returns it again and we surface the original error — same
//   outcome as no-retry, at the cost of one extra syscall. The background
//   scan loop will mark the link unhealthy on its next cycle; we do NOT
//   race it from here, to avoid flapping a link that scanOnce just
//   successfully re-probed.
//
// Not used by rangesplit / MITM paths, which have their own chunk-level
// retry semantics in rangesplit.go.
func dialLink(target string, b *Balancer) (*LinkConn, error) {
	const maxAttempts = 2
	var firstErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		ch := chooseDialer(target, b)
		if ch == nil {
			if firstErr != nil {
				return nil, firstErr
			}
			return nil, errNoHealthyLinks
		}
		conn, err := ch.dialer.Dial("tcp", target)
		if err == nil {
			return &LinkConn{Conn: conn, Link: ch.link, Name: ch.name}, nil
		}
		ch.release()
		if firstErr == nil {
			firstErr = err
		}
		if ch.link == nil {
			// Loopback: no other link exists to rotate to.
			break
		}
	}
	return nil, firstErr
}

// ----- SOCKS5 -------------------------------------------------------------

func socks5Greeting(r io.Reader, w io.Writer) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	if header[0] != socks5Version {
		return errBadVersion
	}
	nmethods := int(header[1])
	if nmethods == 0 {
		return errShortRead
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(r, methods); err != nil {
		return err
	}
	for _, m := range methods {
		if m == authNoAuth {
			_, err := w.Write([]byte{socks5Version, authNoAuth})
			return err
		}
	}
	_, _ = w.Write([]byte{socks5Version, authNoAccept})
	return errNoAcceptable
}

func socks5ReadRequest(r io.Reader) (*socksRequest, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	if head[0] != socks5Version {
		return nil, errBadVersion
	}
	if head[1] != cmdConnect {
		return nil, fmt.Errorf("%w: %d", errUnsupportedCmd, head[1])
	}
	var host string
	switch head[3] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		host = net.IP(b).String()
	case atypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return nil, err
		}
		db := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(r, db); err != nil {
			return nil, err
		}
		host = string(db)
	case atypIPv6:
		return nil, fmt.Errorf("%w: IPv6", errUnsupportedAtyp)
	default:
		return nil, fmt.Errorf("%w: %d", errUnsupportedAtyp, head[3])
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(r, pb); err != nil {
		return nil, err
	}
	port := binary.BigEndian.Uint16(pb)
	return &socksRequest{Target: fmt.Sprintf("%s:%d", host, port)}, nil
}

// socks5Reply writes a SOCKS5 reply with the given rep code and a zero bound address.
func socks5Reply(w io.Writer, rep byte) error {
	_, err := w.Write([]byte{socks5Version, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func handleSOCKS5(client net.Conn, br *bufio.Reader, pc *ProxyConfig) {
	b, recent := pc.Balancer, pc.Recent
	if err := socks5Greeting(br, client); err != nil {
		return
	}
	req, err := socks5ReadRequest(br)
	if err != nil {
		rep := byte(repServerFailure)
		switch {
		case errors.Is(err, errUnsupportedAtyp):
			rep = repAtypNotSupported
		case errors.Is(err, errUnsupportedCmd):
			rep = repCmdNotSupported
		}
		_ = socks5Reply(client, rep)
		return
	}

	upstream, err := dialLink(req.Target, b)
	if err != nil {
		if errors.Is(err, errNoHealthyLinks) {
			_ = socks5Reply(client, repNetworkUnreach)
		} else {
			_ = socks5Reply(client, repHostUnreach)
			log.Printf("dial %s failed: %v", req.Target, err)
		}
		return
	}
	defer upstream.Close()

	if err := socks5Reply(client, repSuccess); err != nil {
		return
	}
	client.SetDeadline(time.Time{})

	recent.Add(ConnRecord{Ts: time.Now(), Link: upstream.Name, Target: req.Target})
	log.Printf("[%s] -> %s", upstream.Name, req.Target)

	spliceCountedConns(client, upstream.Conn, upstream.Link)
}

// ----- HTTP proxy ---------------------------------------------------------

// handleHTTP serves an HTTP proxy request (either CONNECT or a forward GET/POST/etc).
func handleHTTP(client net.Conn, br *bufio.Reader, pc *ProxyConfig) {
	b, recent := pc.Balancer, pc.Recent
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	var target string
	if req.Method == http.MethodConnect {
		target = req.Host
		if !strings.Contains(target, ":") {
			target += ":443"
		}
		// If MITM is toggled on right now, intercept HTTPS instead of tunneling.
		// Otherwise fall through to pure TCP pass-through below.
		if pc.mitmActive() && !isLoopbackTarget(target) {
			if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\nProxy-Agent: mergenet\r\n\r\n")); err != nil {
				return
			}
			InterceptHTTPS(client, target, pc.Minter, b, recent)
			return
		}
	} else {
		if req.URL.Host == "" {
			writeHTTPError(client, 400, "non-proxy request — configure your browser/OS to use this as a proxy")
			return
		}
		target = req.URL.Host
		if !strings.Contains(target, ":") {
			target += ":80"
		}
	}

	upstream, err := dialLink(target, b)
	if err != nil {
		if errors.Is(err, errNoHealthyLinks) {
			writeHTTPError(client, 503, "no healthy links")
		} else {
			writeHTTPError(client, 502, "dial failed")
			log.Printf("HTTP dial %s failed: %v", target, err)
		}
		return
	}
	defer upstream.Close()

	recent.Add(ConnRecord{Ts: time.Now(), Link: upstream.Name, Target: target})
	log.Printf("[%s] %s %s", upstream.Name, req.Method, target)

	if req.Method == http.MethodConnect {
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\nProxy-Agent: mergenet\r\n\r\n")); err != nil {
			return
		}
		client.SetDeadline(time.Time{})
		spliceCountedConns(client, upstream.Conn, upstream.Link)
		return
	}

	// Forward plain HTTP request. Rewrite request-URI to relative path.
	req.RequestURI = ""
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	if err := req.Write(upstream.Conn); err != nil {
		return
	}
	client.SetDeadline(time.Time{})

	// Stream response bytes back with incremental counting.
	var inCtr *int64
	if upstream.Link != nil {
		inCtr = &upstream.Link.BytesIn
	}
	_, _ = copyWithCounter(client, upstream.Conn, inCtr)
}

// writeHTTPError writes a minimal HTTP/1.1 error response with a mergenet-
// prefixed plaintext body.
func writeHTTPError(w io.Writer, code int, msg string) {
	body := "mergenet: " + msg
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}

// ----- Shared splice ------------------------------------------------------

// spliceCountedConns copies bytes bidirectionally and updates link byte counters
// (if link != nil) INCREMENTALLY as bytes flow — not just at the end — so
// long-lived streams (video, websockets) show live rates in the TUI.
// Returns when both directions have finished.
func spliceCountedConns(client, upstream net.Conn, link *Link) {
	done := make(chan struct{}, 2)
	var outCtr, inCtr *int64
	if link != nil {
		outCtr = &link.BytesOut
		inCtr = &link.BytesIn
	}
	go func() {
		copyWithCounter(upstream, client, outCtr)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		copyWithCounter(client, upstream, inCtr)
		if tcp, ok := client.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// copyWithCounter is like io.Copy but increments *counter atomically after each
// chunk is written. counter may be nil.
func copyWithCounter(dst io.Writer, src io.Reader, counter *int64) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				total += int64(nw)
				if counter != nil {
					atomic.AddInt64(counter, int64(nw))
				}
			}
			if ew != nil {
				return total, ew
			}
			if nr != nw {
				return total, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return total, nil
			}
			return total, er
		}
	}
}

// isLoopbackTarget returns true if "host:port" refers to the local machine.
func isLoopbackTarget(target string) bool {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
