package main

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestSocks5Greeting_NoAuth(t *testing.T) {
	// Client sends: VER=5, NMETHODS=1, METHODS=[0x00]
	input := []byte{0x05, 0x01, 0x00}
	r := bytes.NewReader(input)
	w := &bytes.Buffer{}
	err := socks5Greeting(r, w)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []byte{0x05, 0x00}
	if !bytes.Equal(w.Bytes(), expected) {
		t.Fatalf("expected %v, got %v", expected, w.Bytes())
	}
}

func TestSocks5Greeting_UserPassAlsoAcceptedAsNoAuth(t *testing.T) {
	// Client offers noauth + userpass; server must still pick noauth (0x00)
	input := []byte{0x05, 0x02, 0x00, 0x02}
	r := bytes.NewReader(input)
	w := &bytes.Buffer{}
	err := socks5Greeting(r, w)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(w.Bytes(), []byte{0x05, 0x00}) {
		t.Fatalf("expected noauth reply, got %v", w.Bytes())
	}
}

func TestSocks5Greeting_NoNoAuthOffered(t *testing.T) {
	// Client offers only userpass (0x02) — server must reply 0xFF
	input := []byte{0x05, 0x01, 0x02}
	r := bytes.NewReader(input)
	w := &bytes.Buffer{}
	err := socks5Greeting(r, w)
	if err == nil {
		t.Fatal("expected error when noauth not offered")
	}
	if !bytes.Equal(w.Bytes(), []byte{0x05, 0xFF}) {
		t.Fatalf("expected no-acceptable-methods reply, got %v", w.Bytes())
	}
}

func TestSocks5Greeting_WrongVersion(t *testing.T) {
	input := []byte{0x04, 0x01, 0x00}
	err := socks5Greeting(bytes.NewReader(input), &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error on wrong version")
	}
}

func TestSocks5ReadRequest_IPv4(t *testing.T) {
	// VER=5, CMD=1 (CONNECT), RSV=0, ATYP=1 (IPv4), 1.2.3.4:443
	input := []byte{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB}
	req, err := socks5ReadRequest(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Target != "1.2.3.4:443" {
		t.Fatalf("expected 1.2.3.4:443, got %q", req.Target)
	}
}

func TestSocks5ReadRequest_Domain(t *testing.T) {
	// VER=5, CMD=1, RSV=0, ATYP=3 (domain), len=11, "example.com", port 443
	domain := "example.com"
	input := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	input = append(input, []byte(domain)...)
	input = append(input, 0x01, 0xBB)
	req, err := socks5ReadRequest(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Target != "example.com:443" {
		t.Fatalf("expected example.com:443, got %q", req.Target)
	}
}

func TestSocks5ReadRequest_UnsupportedCmd(t *testing.T) {
	// CMD=2 (BIND) — unsupported
	input := []byte{0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB}
	_, err := socks5ReadRequest(bytes.NewReader(input))
	if err == nil {
		t.Fatal("expected error on BIND command")
	}
}

func TestSocks5ReadRequest_UnsupportedIPv6(t *testing.T) {
	// ATYP=4 (IPv6) — unsupported
	input := []byte{0x05, 0x01, 0x00, 0x04}
	input = append(input, make([]byte, 16)...)
	input = append(input, 0x01, 0xBB)
	_, err := socks5ReadRequest(bytes.NewReader(input))
	if err == nil {
		t.Fatal("expected error on IPv6 atyp")
	}
}

func TestProxyEndToEndViaLoopback(t *testing.T) {
	// 1. Start a fake upstream TCP server that echoes.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		c, err := upstream.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()

	// 2. Build a balancer with a single loopback link.
	b := NewBalancer()
	b.AddLink(&Link{Name: "loop", LocalIP: net.ParseIP("127.0.0.1"), Weight: 1, Healthy: true})

	// 3. Start proxy on ephemeral port.
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()
	stats := NewRecentConns(10)
	go ServeSOCKS5(proxyLn, &ProxyConfig{Balancer: b, Recent: stats})

	// 4. Connect as SOCKS5 client.
	c, err := net.Dial("tcp", proxyLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Greeting
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("greeting failed: %v", resp)
	}

	// CONNECT to upstream
	upAddr := upstream.Addr().(*net.TCPAddr)
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, upAddr.IP.To4()...)
	req = append(req, byte(upAddr.Port>>8), byte(upAddr.Port&0xff))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != repSuccess {
		t.Fatalf("connect failed, rep=%d", rep[1])
	}

	// Echo test
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("expected echo 'hello', got %q", buf)
	}
}

func TestProxyReturnsNetworkUnreachableWhenNoLinks(t *testing.T) {
	b := NewBalancer()
	proxyLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer proxyLn.Close()
	stats := NewRecentConns(10)
	go ServeSOCKS5(proxyLn, &ProxyConfig{Balancer: b, Recent: stats})

	c, err := net.Dial("tcp", proxyLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{0x05, 0x01, 0x00})
	io.ReadFull(c, make([]byte, 2))
	c.Write([]byte{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB})
	rep := make([]byte, 10)
	io.ReadFull(c, rep)
	if rep[1] != repNetworkUnreach {
		t.Fatalf("expected network unreachable, got %d", rep[1])
	}
}
