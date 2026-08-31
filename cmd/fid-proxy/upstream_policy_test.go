package main

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestValidateUpstreamBaseURL(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "anthropic", raw: "https://api.anthropic.com", want: "https://api.anthropic.com"},
		{name: "openai", raw: "https://api.openai.com:443/", want: "https://api.openai.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := validateUpstreamBaseURL(tt.raw)
			if err != nil {
				t.Fatalf("validateUpstreamBaseURL(%q): %v", tt.raw, err)
			}
			if got := u.String(); got != tt.want {
				t.Fatalf("canonical URL = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateUpstreamBaseURLRejectsUntrustedForms(t *testing.T) {
	for _, raw := range []string{
		"http://api.anthropic.com",             // TLS downgrade
		"https://evil.example",                 // wrong host
		"https://api.anthropic.com:8443",       // non-standard port
		"https://secret@api.anthropic.com",     // credentials in URL
		"https://api.anthropic.com/v1",         // endpoint override
		"https://api.anthropic.com?redirect=1", // query override
		"https://api.anthropic.com#fragment",   // fragment
		"https://api.anthropic.com:",           // malformed empty port
		"https://api.anthropic.com.",           // alternate DNS spelling
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := validateUpstreamBaseURL(raw); err == nil {
				t.Fatalf("validateUpstreamBaseURL(%q) unexpectedly succeeded", raw)
			}
		})
	}
}

func TestForwardRejectsHTTPBeforeSending(t *testing.T) {
	_, err := (&server{}).forward("http://api.anthropic.com", "sk-secret", "anthropic", upstreamReq{})
	if err == nil {
		t.Fatal("HTTP provider URL was accepted")
	}
	if strings.Contains(err.Error(), "sk-secret") {
		t.Fatalf("validation error leaked the provider key: %v", err)
	}
}

func TestProviderHTTPClientHardening(t *testing.T) {
	c := newProviderHTTPClient()
	transport, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("provider transport type = %T, want *http.Transport", c.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("provider transport inherits an environment proxy")
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("provider transport has no explicit TLS configuration")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("provider transport disables TLS certificate verification")
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("provider TLS minimum = %#x, want TLS 1.2 or newer", transport.TLSClientConfig.MinVersion)
	}
}

func TestProviderHTTPClientRejectsRedirects(t *testing.T) {
	var targetHit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHit.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	_, err := newProviderHTTPClient().Get(redirect.URL)
	if err == nil {
		t.Fatal("provider client followed a redirect")
	}
	if !errors.Is(err, http.ErrUseLastResponse) && !strings.Contains(err.Error(), "redirects are disabled") {
		t.Fatalf("unexpected redirect error: %v", err)
	}
	if targetHit.Load() {
		t.Fatal("provider client sent the redirected request")
	}
}

func TestProviderHTTPClientRejectsUntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	_, err := newProviderHTTPClient().Get(server.URL)
	if err == nil {
		t.Fatal("provider client accepted a certificate outside the trusted CA roots")
	}
}
