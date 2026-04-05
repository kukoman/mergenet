package main

import "testing"

func TestIsBlacklistedAdapterName(t *testing.T) {
	cases := []struct {
		name  string
		block bool
	}{
		{"WiFi", false},
		{"Ethernet", false},
		{"Ethernet 3", false},
		{"vEthernet (WSL)", true},
		{"vEthernet (Hyper-V firewall)", true},
		{"Bluetooth Network Connection", true},
		{"Local Area Connection* 9", true},
		{"Local Area Connection* 10", true},
		{"Loopback Pseudo-Interface 1", true},
		{"VMware Network Adapter VMnet1", true},
		{"VirtualBox Host-Only Network", true},
		{"Tailscale", true},
		{"ZeroTier One", true},
		{"TAP-Windows Adapter V9", true},
		{"Npcap Loopback Adapter", true},
		{"Wi-Fi", false},
		{"wifi", false},
	}
	for _, c := range cases {
		if got := IsBlacklistedAdapterName(c.name); got != c.block {
			t.Errorf("IsBlacklistedAdapterName(%q) = %v, want %v", c.name, got, c.block)
		}
	}
}

func TestIsUsableIPv4(t *testing.T) {
	cases := []struct {
		ip     string
		usable bool
	}{
		{"192.168.1.31", true},
		{"10.117.166.57", true},
		{"172.16.0.5", true},
		{"8.8.8.8", true},
		{"127.0.0.1", false},
		{"169.254.1.1", false},
		{"0.0.0.0", false},
	}
	for _, c := range cases {
		if got := IsUsableIPv4(c.ip); got != c.usable {
			t.Errorf("IsUsableIPv4(%q) = %v, want %v", c.ip, got, c.usable)
		}
	}
}

func TestEnumerateAdaptersReturnsEntries(t *testing.T) {
	adapters, err := EnumerateAdapters()
	if err != nil {
		t.Fatalf("EnumerateAdapters: %v", err)
	}
	if len(adapters) == 0 {
		t.Fatal("expected at least one adapter")
	}
	// At least one adapter should be present (loopback exists everywhere)
	foundLoop := false
	for _, a := range adapters {
		if a.Skipped == "loopback" {
			foundLoop = true
			break
		}
	}
	if !foundLoop {
		t.Fatal("expected loopback adapter in enumeration")
	}
}
