package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"time"
)

// Minter caches per-host leaf certificates signed by our CA.
type Minter struct {
	ca    *CA
	mu    sync.RWMutex
	cache map[string]*tls.Certificate
}

func NewMinter(ca *CA) *Minter {
	return &Minter{ca: ca, cache: map[string]*tls.Certificate{}}
}

// Get returns a TLS certificate for host, minting it on first request.
func (m *Minter) Get(host string) (*tls.Certificate, error) {
	m.mu.RLock()
	if c, ok := m.cache[host]; ok {
		m.mu.RUnlock()
		return c, nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.cache[host]; ok {
		return c, nil
	}
	cert, err := m.mint(host)
	if err != nil {
		return nil, err
	}
	m.cache[host] = cert
	return cert, nil
}

func (m *Minter) mint(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"mergenet"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(398 * 24 * time.Hour), // within browser cert-lifetime limits
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.ca.Cert, &key.PublicKey, m.ca.Key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, m.ca.Cert.Raw},
		PrivateKey:  key,
		Leaf:        nil,
	}, nil
}
