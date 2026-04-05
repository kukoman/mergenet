# mergenet

Combine your internet interfaces (wifi + tether) to "increase" your download rate. Each TCP connection is round-robined across the links, and single-file HTTPS downloads get split into parallel chunks across both.

## Run it

Just build it and open as admin (needs to install certs first time), then you can only run it as regular user: ```mergenet.exe```

First run prompts UAC. It installs its own root CA and flips one registry key. Set the Windows proxy to `127.0.0.1:1080` (Settings → Network → Proxy → Manual). Done.

## What it changes on your machine

- **Root CA in Windows trust store** — so mergenet can intercept HTTPS and split big downloads across both links. Remove anytime with `mergenet.exe --uninstall-cert`.
- **`HKLM\...\WcmSvc\GroupPolicy\fMinimizeConnections = 0`** — Windows otherwise kills your WiFi the moment USB tether connects, leaving one link, defeating the whole point.

## Flags

```
--dry-run           list detected adapters and exit
--listen ADDR       proxy address (default 127.0.0.1:1080)
--no-mitm           disable HTTPS interception (kills single-file splitting)
--log               scrolling log instead of live TUI
--install-cert      install CA (admin) and exit
--uninstall-cert    remove CA (admin) and exit
```

## Build

Built and used on Windows. macOS is untested — it compiles, but I haven't run it there.

Windows:

```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o mergenet.exe .
```

macOS (unsigned, so strip quarantine before running):

```bash
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o mergenet-macos-arm64 .
chmod +x mergenet-macos-arm64
xattr -d com.apple.quarantine mergenet-macos-arm64
```

Or `make release` for all platforms.
