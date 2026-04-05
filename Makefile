.PHONY: build windows macos-arm64 macos-amd64 linux release test clean

# Single source of truth for the version string baked into local builds.
# (CI overrides this from the git tag via -X main.Version=...)
VERSION := $(shell sed -n 's/^var Version = "\(.*\)"/\1/p' main.go)
LDFLAGS := -s -w -X main.Version=$(VERSION)

# Default: primary target is Windows. `make` alone → mergenet.exe.
build: windows

# Primary platform.
windows:
	GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o mergenet.exe .

# Secondary platforms.
macos-arm64:
	GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o mergenet-v$(VERSION)-macos-arm64 .

macos-amd64:
	GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o mergenet-v$(VERSION)-macos-amd64 .

linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o mergenet-v$(VERSION)-linux-amd64 .

# Build all four into dist/ for a GitHub release.
release: clean
	mkdir -p dist
	GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o dist/mergenet-v$(VERSION)-windows-amd64.exe .
	GOOS=darwin  GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o dist/mergenet-v$(VERSION)-macos-arm64 .
	GOOS=darwin  GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o dist/mergenet-v$(VERSION)-macos-amd64 .
	GOOS=linux   GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o dist/mergenet-v$(VERSION)-linux-amd64 .

test:
	go test ./... -v

clean:
	rm -rf dist mergenet mergenet.exe mergenet-v*-macos-* mergenet-v*-linux-* mergenet-v*-windows-*
