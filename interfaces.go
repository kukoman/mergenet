package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

var blacklistSubstrings = []string{
	// Windows
	"vethernet",
	"wsl",
	"loopback",
	"bluetooth",
	"vmware",
	"virtualbox",
	"hyper-v",
	"tailscale",
	"zerotier",
	"npcap",
	"tap-",
	// macOS: VPN/tunnels, AirDrop, low-latency WLAN, bridges, AP mode, 6to4/IPv6 tunnels
	"utun",
	"awdl",
	"llw",
	"anpi",
	"stf",
	"gif",
	"ap1",
	"bridge",
}

var blacklistExact = []string{
	"local area connection* 9",
	"local area connection* 10",
}

func IsBlacklistedAdapterName(name string) bool {
	n := strings.ToLower(name)
	for _, s := range blacklistSubstrings {
		if strings.Contains(n, s) {
			return true
		}
	}
	for _, e := range blacklistExact {
		if n == e {
			return true
		}
	}
	return false
}

func IsUsableIPv4(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	if ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || ip4.IsUnspecified() {
		return false
	}
	return true
}

type Adapter struct {
	Name    string
	IPv4    net.IP
	Up      bool
	Skipped string // reason, if filtered out
}

// EnumerateAdapters returns all interfaces with decisions about usability.
func EnumerateAdapters() ([]Adapter, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Adapter
	for _, iface := range ifaces {
		a := Adapter{Name: iface.Name, Up: iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagRunning != 0}
		if iface.Flags&net.FlagLoopback != 0 {
			a.Skipped = "loopback"
			out = append(out, a)
			continue
		}
		if IsBlacklistedAdapterName(iface.Name) {
			a.Skipped = "blacklisted"
			out = append(out, a)
			continue
		}
		if !a.Up {
			a.Skipped = "disconnected"
			out = append(out, a)
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			a.Skipped = fmt.Sprintf("addrs error: %v", err)
			out = append(out, a)
			continue
		}
		var v4 net.IP
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ip4 := ipnet.IP.To4(); ip4 != nil && IsUsableIPv4(ip4.String()) {
				v4 = ip4
				break
			}
		}
		if v4 == nil {
			a.Skipped = "no usable IPv4"
			out = append(out, a)
			continue
		}
		a.IPv4 = v4
		out = append(out, a)
	}
	return out, nil
}

// ProbeAdapter does a TCP dial to probeTarget bound to localIP, returning latency or error.
func ProbeAdapter(localIP net.IP, probeTarget string, timeout time.Duration) (time.Duration, error) {
	d := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: localIP},
		Timeout:   timeout,
	}
	start := time.Now()
	conn, err := d.Dial("tcp", probeTarget)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(start), nil
}
