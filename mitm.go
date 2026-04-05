package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)


// InterceptHTTPS MITM-terminates a CONNECT. The CONNECT response has already
// been written to client. This wraps the client in an http.Server which
// handles both HTTP/2 (multiplexed streams — no 6-connection-per-origin limit)
// and HTTP/1.1 (for WebSocket upgrades) via ALPN negotiation. Per-request
// concurrency is handled by the server: each request runs in its own
// goroutine, so a long-polling / SSE / streaming response on one stream no
// longer blocks any other request.
func InterceptHTTPS(client net.Conn, target string, minter *Minter, b *Balancer, recent *RecentConns) {
	host, _, _ := net.SplitHostPort(target)
	if host == "" {
		host = target
	}

	srv := &http.Server{
		TLSConfig: &tls.Config{
			GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				name := hi.ServerName
				if name == "" {
					name = host
				}
				return minter.Get(name)
			},
			// Offer h2 first; h1 kept as fallback for WebSocket clients.
			NextProtos: []string{"h2", "http/1.1"},
		},
		Handler:           &mitmHandler{target: target, b: b, recent: recent},
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 30 * time.Second,
		// Deliberately NOT setting ReadTimeout / WriteTimeout — those would
		// kill long-lived SSE / long-poll responses.
	}

	ln := newOneConnListener(client)
	defer ln.Close()
	_ = srv.ServeTLS(ln, "", "")
}

// mitmHandler dispatches each MITM-intercepted request: range-split if the URL
// looks like a large download, raw-splice if it's a WebSocket upgrade, plain
// forward-via-Transport otherwise.
type mitmHandler struct {
	target string
	b      *Balancer
	recent *RecentConns
}

func (h *mitmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The handler receives a request whose URL has path + query but no scheme/host.
	// Fill them in so the upstream Transport knows where to dial.
	r.URL.Scheme = "https"
	r.URL.Host = h.target
	r.RequestURI = ""

	log.Printf("[mitm] %s https://%s%s range=%q", r.Method, h.target, r.URL.Path, r.Header.Get("Range"))

	// WebSocket / HTTP Upgrade. Only reachable via HTTP/1.1 (Go's h2 server
	// doesn't dispatch Extended CONNECT here by default, and browsers still
	// use h1 for WebSocket), so Hijack is safe to call.
	if isUpgradeRequest(r) {
		handleUpgrade(w, r, h.b, h.recent)
		return
	}

	// Single-link forward, then auto-upgrade to parallel range-split if the
	// response headers reveal a large, seekable, uncompressed, non-streaming
	// body. See shouldSplit in rangesplit.go.
	forwardOrSplit(w, r, h.b, h.recent)
}

// ----- per-request dispatchers --------------------------------------------

// forwardOrSplit proxies one request to upstream via a single balanced link,
// inspects response headers, and either (a) streams the response body back
// normally or (b) aborts the single-link body, frees the link, and re-fetches
// the effective byte range in parallel across all healthy links.
//
// Detection is free: we look at Content-Length / Accept-Ranges / Content-Type
// on the response we would have served anyway. Small responses, streaming
// content, and servers without range support all fall through with zero
// extra round-trips.
func forwardOrSplit(w http.ResponseWriter, req *http.Request, b *Balancer, recent *RecentConns) {
	link := b.Pick()
	if link == nil {
		http.Error(w, "mergenet: no healthy links", http.StatusServiceUnavailable)
		return
	}
	linkReleased := false
	releaseLink := func() {
		if !linkReleased {
			atomic.AddInt64(&link.ActiveConns, -1)
			linkReleased = true
		}
	}
	defer releaseLink()

	tr := link.Transport()

	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""
	if outReq.Body != nil {
		outReq.Body = &countingReadCloser{rc: outReq.Body, counter: &link.BytesOut}
	}
	stripHopByHop(outReq.Header)

	resp, err := tr.RoundTrip(outReq)
	// Retry once on a different link if the dial failed with a bind
	// error (stale source IP from an adapter flap). Bind errors happen
	// before any request bytes are written, so retry is safe. We only
	// retry when the request has no body — otherwise we'd need to reset
	// or re-clone the body, which isn't worth the complexity for the
	// 99% case (browser GETs, including range requests for media).
	if err != nil && isBindUnavailable(err) && outReq.Body == nil {
		log.Printf("[%s] MITM bind failed, retrying on another link: %v", link.Name, err)
		releaseLink()
		if next := b.Pick(); next != nil {
			link = next
			linkReleased = false
			tr = link.Transport()
			resp, err = tr.RoundTrip(outReq)
		}
	}
	if err != nil {
		http.Error(w, "mergenet: "+err.Error(), http.StatusBadGateway)
		log.Printf("[%s] MITM forward %s %s failed: %v", link.Name, req.Method, req.URL.Host, err)
		return
	}

	recent.Add(ConnRecord{Ts: time.Now(), Link: link.Name, Target: fmt.Sprintf("%s %s", req.Method, req.URL.Host)})
	log.Printf("[%s] MITM %s %s%s -> %d (len=%d)", link.Name, req.Method, req.URL.Host, req.URL.Path, resp.StatusCode, resp.ContentLength)

	// Range-split candidate? If yes, abort this single-link body and re-fetch
	// the effective byte range in parallel.
	if decision, ok := shouldSplit(req, resp, b); ok {
		resp.Body.Close()
		releaseLink()
		splitAcrossLinks(w, req, resp.Header, decision, b, recent)
		return
	}
	defer resp.Body.Close()

	// Not a split candidate — stream the body back normally.
	for k, vs := range resp.Header {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	flushIfPossible(w)
	_, _ = copyWithCounter(w, resp.Body, &link.BytesIn)
}

// handleUpgrade services an HTTP/1.1 Upgrade (WebSocket, etc.) by hijacking
// the client connection and splicing it with a freshly-dialed upstream TLS
// connection over one balanced link.
func handleUpgrade(w http.ResponseWriter, req *http.Request, b *Balancer, recent *RecentConns) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "mergenet: hijack unsupported", http.StatusInternalServerError)
		return
	}
	link := b.Pick()
	if link == nil {
		http.Error(w, "mergenet: no healthy links", http.StatusServiceUnavailable)
		return
	}
	defer atomic.AddInt64(&link.ActiveConns, -1)

	host, _, err := net.SplitHostPort(req.URL.Host)
	if err != nil {
		host = req.URL.Host
	}
	rawUp, err := link.NewDialer(10 * time.Second).Dial("tcp", req.URL.Host)
	if err != nil {
		http.Error(w, "mergenet: upstream dial failed", http.StatusBadGateway)
		log.Printf("[%s] MITM upgrade dial %s failed: %v", link.Name, req.URL.Host, err)
		return
	}
	upstream := tls.Client(rawUp, &tls.Config{ServerName: host})
	if err := upstream.Handshake(); err != nil {
		rawUp.Close()
		http.Error(w, "mergenet: upstream TLS failed", http.StatusBadGateway)
		return
	}

	// Hijack AFTER upstream is ready so we can still write an error via
	// ResponseWriter if the dial fails.
	client, buf, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	defer client.Close()
	defer upstream.Close()

	// Forward the upgrade request as-is to upstream.
	req.RequestURI = ""
	if err := req.Write(upstream); err != nil {
		return
	}
	// Drain any bytes the client pipelined after the upgrade handshake.
	if buf != nil {
		if n := buf.Reader.Buffered(); n > 0 {
			data, _ := buf.Reader.Peek(n)
			if _, werr := upstream.Write(data); werr != nil {
				return
			}
			_, _ = buf.Reader.Discard(n)
		}
	}

	recent.Add(ConnRecord{Ts: time.Now(), Link: link.Name, Target: fmt.Sprintf("UPGRADE %s", req.URL.Host)})
	log.Printf("[%s] MITM UPGRADE %s%s", link.Name, req.URL.Host, req.URL.Path)

	// Bidirectional splice with per-direction byte accounting.
	done := make(chan struct{}, 2)
	go func() {
		copyWithCounter(upstream, client, &link.BytesOut)
		done <- struct{}{}
	}()
	go func() {
		copyWithCounter(client, upstream, &link.BytesIn)
		done <- struct{}{}
	}()
	<-done
}

// isUpgradeRequest reports whether req carries an HTTP/1.1 Upgrade header
// (WebSocket, HTTP/2-over-TLS upgrade hint, etc.).
func isUpgradeRequest(req *http.Request) bool {
	if strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return true
	}
	for _, v := range req.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

// ----- hop-by-hop header handling ------------------------------------------

var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailers":            {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

func isHopByHop(h string) bool {
	_, ok := hopByHopHeaders[strings.ToLower(h)]
	return ok
}

func stripHopByHop(h http.Header) {
	for k := range h {
		if isHopByHop(k) {
			h.Del(k)
		}
	}
}

// flushIfPossible calls Flush on the ResponseWriter if it implements http.Flusher.
func flushIfPossible(w http.ResponseWriter) {
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// ----- counting helpers ----------------------------------------------------

// countingReadCloser wraps an io.ReadCloser and increments a counter for every
// byte read. Used to track request-body upload bytes.
type countingReadCloser struct {
	rc      io.ReadCloser
	counter *int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 && c.counter != nil {
		atomic.AddInt64(c.counter, int64(n))
	}
	return n, err
}

func (c *countingReadCloser) Close() error { return c.rc.Close() }

// Per-Link HTTP transport resources live in link_net.go (Link.Transport,
// Link.NewDialer). All call sites below use those methods so every
// dial re-reads link.LocalIP and stays correct across adapter flaps.

// ----- one-shot listener for InterceptHTTPS --------------------------------

// oneConnListener wraps a single net.Conn as a net.Listener so we can hand it
// to http.Server.ServeTLS. Accept() returns the wrapped conn exactly once,
// then blocks until Close() is called so http.Server stops its accept loop.
type oneConnListener struct {
	conn   net.Conn
	done   chan struct{}
	once   sync.Once
	served atomic.Bool
}

func newOneConnListener(c net.Conn) *oneConnListener {
	return &oneConnListener{conn: c, done: make(chan struct{})}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if l.served.Swap(true) {
		<-l.done
		return nil, net.ErrClosed
	}
	return l.conn, nil
}

func (l *oneConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *oneConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
