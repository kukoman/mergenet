package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMitmTLSErrorFallback(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}
	_, err := client.Get(ts.URL)
	
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	
	var certErr x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var certInv x509.CertificateInvalidError
	
	isCertErr := errors.As(err, &certErr) || errors.As(err, &hostErr) || errors.As(err, &certInv)
	t.Logf("err: %v (isCertErr=%v)", err, isCertErr)
}
