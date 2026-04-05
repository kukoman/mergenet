# mergenet — architecture handover

## What it does (in one paragraph)

mergenet is a local SOCKS5+HTTP proxy that round-robins each new TCP connection across all your active network interfaces (WiFi, USB-tethered phone, second WiFi, etc.), bound to each adapter's local IP via `net.Dialer{LocalAddr}`. This gives you parallel browsing/download throughput across multiple links "for free" — the browser opens N connections per site, they scatter across your adapters. On top of that, HTTPS traffic is **MITM-intercepted** (using a locally-trusted generated CA) so mergenet can inspect response headers and **auto-detect large range-supporting downloads**: when `Content-Length` is ≥ 10 MB and the server advertises `Accept-Ranges: bytes`, the proxy aborts the single-link transfer and re-fetches the effective byte range in parallel across all healthy links, streaming chunks back in order through bounded in-memory buffers. Per-chunk retry on TCP failure means a dropped link mid-transfer doesn't kill the download.

---

## Data flow

### 1. Browser points system proxy at `127.0.0.1:1080`

All traffic hits [proxy.go](proxy.go) `ServeSOCKS5` which peeks the first byte to detect SOCKS5 (`0x05`) vs HTTP (`G`/`P`/`C`…) and dispatches to `handleSOCKS5` or `handleHTTP`. Both handlers converge on one decision: **tunnel or intercept**.

### 2. Per-connection adapter selection

`chooseDialer(target, balancer)` picks a healthy link via `Balancer.Pick()` (weighted round-robin), creates a `net.Dialer` with `LocalAddr = link.LocalIP`, and dials. The kernel then routes that socket out the matching interface, regardless of the default route. **This is the core trick** — no tun/tap, no routing tables, just per-socket source binding.

### 3a. Tunnel path (default for most HTTPS)

For HTTPS CONNECTs where MITM is not active, `spliceCountedConns(client, upstream, link)` bidirectionally copies bytes with per-direction counters. Browser's TLS handshake happens directly with the real origin server — we never see plaintext. HTTP/2 multiplexing works natively, no serialization. Fast.

### 3b. MITM path (for HTTPS CONNECTs when `MITMController.Enabled()`)

This is the complex bit. See "MITM subsystem" below.

---

## MITM subsystem

Triggered when `pc.mitmActive()` returns true (CA is loaded **AND** runtime toggle is on). The whole purpose of MITM is to **see the URL path inside HTTPS**, so we can decide per-GET whether to range-split it.

### Step 1 — Wrap the CONNECT'd socket in a locally-served `http.Server`

[mitm.go](mitm.go) `InterceptHTTPS` does **not** write a response loop itself. Instead, it:

1. Builds an `http.Server` with a `TLSConfig.GetCertificate` callback that mints a fake cert on-demand via `Minter` ([mint.go](mint.go)).
2. Sets `NextProtos: []string{"h2", "http/1.1"}` — browsers negotiate **HTTP/2** with the proxy. This is critical: without h2, the browser would be limited to 6 HTTP/1.1 connections per origin, and one long-poll/SSE/XHR could starve the connection pool. h2 multiplexes hundreds of streams over one TCP, so no deadlock.
3. Feeds the already-CONNECT'd client socket via `oneConnListener` (returns the conn once, then blocks). `http.Server.ServeTLS` handles the TLS handshake, ALPN, and per-request concurrency for us.

### Step 2 — Per-request dispatch: `mitmHandler.ServeHTTP`

Every intercepted request lands here in its own goroutine. Two-way branch:

| Condition | Action |
|---|---|
| `Upgrade: websocket` / `Connection: upgrade` | `handleUpgrade` — hijack the raw TCP, dial upstream via one link, bidirectional splice |
| everything else | `forwardOrSplit` — single-link forward; on response, maybe abort and re-fetch in parallel (see below) |

### Step 3a — `handleUpgrade` (WebSockets)

`http.Hijacker.Hijack()` exposes the raw client TCP connection. We dial upstream fresh (can't reuse Transport, it won't relinquish the connection), forward the request verbatim, then bidirectionally splice client↔upstream. After upgrade, the wire is opaque protocol bytes (WebSocket frames / custom protocol) — raw TCP splice is the only correct handling. This path is **h1 only**; h2 WebSockets (RFC 8441) don't reach it because Go's stdlib doesn't dispatch Extended CONNECT to ServeHTTP by default.

### Step 3b — `forwardOrSplit` (default path for every non-upgrade request)

Clones the request, sends via `linkTransport(link)` (a cached per-link `http.Transport` bound to that link's LocalIP), then **inspects response headers** via `shouldSplit`:

- Method is GET, ≥ 2 healthy links, no `Content-Encoding`, not a streaming MIME type
- Either `200 OK` with `Content-Length ≥ 10 MB` and `Accept-Ranges: bytes`, OR `206 Partial Content` with a parseable `Content-Range` (range support is implicit on 206)
- Effective byte range is at least `rangeSplitThreshold` (10 MB)

If those all hold → `resp.Body.Close()`, release the link, hand off to `splitAcrossLinks`. Otherwise stream the body through normally. Detection is **free**: we only look at headers of a response we would have served anyway, no extra round-trip.

### Step 3c — `splitAcrossLinks` ([rangesplit.go](rangesplit.go))

This is where multi-link parallelism happens for large downloads.

**Chunk count** (`computeChunks`): size × links. 1 stream per link for <50 MB, 2 per link for <500 MB, 4 per link for ≥500 MB. Clamped to `[2, 16]`, each chunk constrained to ≥ 2 MB.

**Per-chunk bounded buffer** (`chunkBuf`, `bufferSlots`): each chunk gets its own buffered `chan []byte`. Capacity is `chunkSize/4` clamped to `[2, 16] MB`, in units of `readSliceSize` (64 KB). Fetcher pushes 64 KB slices, blocks when channel is full. Drain goroutine drains `chunkBuf[0]` fully, then `chunkBuf[1]`, etc., writing to the client in absolute byte order. **All in RAM, zero temp files.**

Why a bounded channel instead of `io.Pipe`? Pipe is unbuffered — would serialize all fetchers behind the slowest drain consumer. A bounded channel gives each chunk some breathing room (typically 2-16 MB) so fetchers can race ahead of drain while still imposing backpressure.

**Per-chunk retry with link-switching** (`fetchChunk` → `fetchChunkOnce`): each fetcher tracks bytes successfully pushed. On TCP/read failure, picks a different healthy link via `pickAlternative`, waits (exponential backoff 100→800 ms), and re-issues `Range: bytes=(start+pushed)-(end)` to resume from the exact last byte pushed. Up to `maxChunkAttempts` (5). The drainer never sees retries — bytes arrive in order.

**Response to client:** `200 OK` if client sent no Range header, `206 Partial Content` + `Content-Range: bytes <effStart>-<effEnd>/<total>` if client sent a Range (supports browser pause/resume natively).

---

## File layout

| File | Responsibility |
|---|---|
| [main.go](main.go) | CLI flags, startup, adapter scan loop, signal handling, TUI vs log-mode dispatch |
| [proxy.go](proxy.go) | SOCKS5 + HTTP proxy dispatcher, `chooseDialer`, tunnel splice, connection routing |
| [mitm.go](mitm.go) | `InterceptHTTPS` (h2+h1 server), `mitmHandler`, `forwardOrSplit`, `handleUpgrade`, `oneConnListener`, per-link `http.Transport` cache |
| [mitm_control.go](mitm_control.go) | `MITMController` (runtime on/off toggle), stdin keypress loop (`m`+Enter) |
| [rangesplit.go](rangesplit.go) | `shouldSplit` (response-header detection), `splitAcrossLinks`, `computeChunks`, `bufferSlots`, `chunkBuf` (bounded in-memory buffer), `fetchChunk` (with retry), `pickAlternative` |
| [balancer.go](balancer.go) | `Link` + `Balancer` (weighted round-robin `Pick`, `Upsert`, `HealthyLinks`, `SnapshotView`) |
| [ca.go](ca.go) | Root CA generation and on-disk caching |
| [ca_windows.go](ca_windows.go) | Windows-specific CA install (`certutil`), admin detection, UAC elevation, `fMinimizeConnections` registry fix |
| [ca_other.go](ca_other.go) | macOS/Linux CA install (`security add-trusted-cert`), stubs for non-Windows |
| [mint.go](mint.go) | Per-host leaf-cert minting from the root CA |
| [interfaces.go](interfaces.go) | `EnumerateAdapters`, per-platform adapter blacklist, `ProbeAdapter` |
| [tui.go](tui.go) | Live terminal UI — per-link table, rate calculation, recent connections, MITM toggle state |
| [stats.go](stats.go) | `RecentConns` ring buffer for the TUI |
| [console_windows.go](console_windows.go), [console_other.go](console_other.go) | VT processing enable on Windows, no-op elsewhere |

---

## Key invariants and gotchas

- **Per-socket routing** works because every outbound connection (tunnel and every chunk fetcher) creates its own `net.Dialer` with `LocalAddr` set. The OS picks the route matching that source IP. There is no global routing change.
- **`Balancer.Pick()` mutates** — it atomically increments `ActiveConns` and `TotalConns` on the chosen link. Every caller **must** decrement `ActiveConns` when done (`defer atomic.AddInt64(&link.ActiveConns, -1)`).
- **`linkTransport` cache is keyed by `*Link` pointer.** If a Link is recreated (different pointer, same name), the old transport leaks and a new one is built. `Balancer.Upsert` deliberately reuses the same pointer to avoid this.
- **MITM toggle is live, not a flag.** Default state: ON if CA is installed/loadable. User toggles via `m`+Enter in the TUI (reads `stdin` line-buffered — no raw-mode terminal needed).
- **Split gates are all on the response, not the request URL:** GET method, ≥2 healthy links, effective size ≥ 10 MB, `Accept-Ranges: bytes` (on 200) or 206 with valid `Content-Range`, no `Content-Encoding`, not a streaming content-type. No URL extension matching, no HEAD probes.
- **All chunk buffers live in RAM.** Max memory per download is `numChunks × bufferCap` — worst case 16 chunks × 16 MB = 256 MB during the peak of a very large transfer, typically much less. Buffers freed automatically when a chunk is fully drained or the context cancels.
- **HTTP/2 between browser↔proxy is non-negotiable** — without it, the MITM path deadlocks on busy sites. `NextProtos: ["h2", "http/1.1"]` lets Go's stdlib pick whichever the browser supports.
- **On macOS/Linux `ElevateForSetup` is a stub** — user runs `sudo mergenet --install-cert` manually; elevation is Windows-only.

---

## Known trade-offs

- **First split upgrades cost one aborted single-link transfer.** When `shouldSplit` fires, we close the original response body (wasting a few KB of already-transferred bytes) and launch N parallel Range requests. Much cheaper than a HEAD probe on every request.
- **RAM budget scales with chunk count and buffer size.** Typical: 4 chunks × 8 MB = 32 MB per concurrent download. Extreme: 16 × 16 MB = 256 MB. Fine for desktop use, worth noting for low-memory targets.
- **`handleUpgrade` hijacks and dials upstream fresh.** This doesn't reuse the Transport's connection pool. For WebSocket-heavy apps (Discord/Slack), this is fine — WS connections are long-lived.
- **CA private key is user-readable at `%APPDATA%\mergenet\ca-key.pem`.** Any process running as you can MITM your traffic while the CA is installed. `mergenet --uninstall-cert` removes it.
- **No per-host MITM disable list.** Some sites with custom TLS pinning (banking apps, some mobile-API endpoints) may reject the minted cert. Current workaround: press `m`+Enter to disable MITM globally.
- **Retry budget is bounded (5 attempts/chunk).** Beyond that the chunk fails and the whole download aborts — client sees a truncated body unless it retries with `Range:`. Adequate for flaky but functional links; won't help if a link is completely dead for minutes.

---

## Where to look when things break

| Symptom | Look at |
|---|---|
| Download uses only one interface | `rangesplit.go` → `shouldSplit` returned false. Check the `[mitm] MITM GET … -> NNN (len=…)` log line. Common reasons: `Content-Length` < 10 MB, missing `Accept-Ranges: bytes` on a 200, streaming content-type, <2 healthy links. |
| Downloads truncated mid-transfer | Check log for `chunk … failed (pushed=…/…)` lines. If 5 retries exhaust, whole download aborts. Consider raising `maxChunkAttempts` or investigating the flaky link. |
| Websites hang on load | Toggle MITM off (`m`+Enter). If they work → bug in `mitmHandler`/`forwardOrSplit`. If still broken → proxy.go dial path. |
| "Only 1 link detected" | `interfaces.go` blacklist, Windows `fMinimizeConnections` policy, adapter having a usable IPv4. |
| WebSocket-based sites (Discord, GitHub notifications) broken | `handleUpgrade` in mitm.go — the hijack + raw splice path. |
| `ResponseHeaderTimeout` warnings | `linkTransport` in mitm.go (currently 30s). |
| Browser download stalls in the middle | Client write failed → `drainTo` returned error → `splitAcrossLinks` called `cancel()` → all fetchers exited cleanly. Browser should show failed download; resume via `Range:` works. |
