.PHONY: build windows macos-arm64 macos-amd64 linux release test clean

# Default: primary target is Windows. `make` alone → mergenet.exe.
build: windows

# Primary platform.
windows:
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o mergenet.exe .

# Secondary platforms.
macos-arm64:
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o mergenet-macos-arm64 .

macos-amd64:
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o mergenet-macos-amd64 .

linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o mergenet-linux-amd64 .

# Build all four into dist/ for a GitHub release.
release: clean
	mkdir -p dist
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/mergenet-windows-amd64.exe .
	GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o dist/mergenet-macos-arm64 .
	GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o dist/mergenet-macos-amd64 .
	GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o dist/mergenet-linux-amd64 .

test:
	go test ./... -v

clean:
	rm -rf dist mergenet mergenet.exe mergenet-macos-* mergenet-linux-*
