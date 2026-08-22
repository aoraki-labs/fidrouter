package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"fidrouter/pkg/token"
)

// TestT7ResolveCapability covers the folded-exchange logic: a real capability token is
// accepted as-is; a raw gateway key is exchanged via cp-adapter for one; and with no
// cp-adapter configured a raw key is refused.
func TestT7ResolveCapability(t *testing.T) {
	cpPub, cpPriv, _ := ed25519.GenerateKey(rand.Reader)
	good, _ := token.Mint(cpPriv, token.Claims{Tenant: "u_x", Models: []string{"m"}, Exp: time.Now().Add(time.Hour).Unix()})

	// stub cp-adapter: any /exchange returns a freshly minted capability token
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/exchange" {
			w.WriteHeader(404)
			return
		}
		tok, _ := token.Mint(cpPriv, token.Claims{Tenant: "u_from_key", Models: []string{"m"}, Exp: time.Now().Add(time.Hour).Unix()})
		_ = json.NewEncoder(w).Encode(map[string]string{"capability_token": tok})
	}))
	defer stub.Close()

	s := &server{cpPub: cpPub, http: &http.Client{Timeout: 5 * time.Second}, cpAdapterURL: stub.URL}

	// 1) an existing capability token passes through unchanged
	if got, err := s.resolveCapability(good); err != nil || got != good {
		t.Fatalf("capability passthrough: got=%q err=%v", got, err)
	}
	// 2) a raw key is exchanged, and the resulting token verifies to the exchanged tenant
	claims, err := s.authClaims("sk-raw-user-key")
	if err != nil {
		t.Fatalf("exchange path failed: %v", err)
	}
	if claims.Tenant != "u_from_key" {
		t.Fatalf("expected exchanged tenant, got %q", claims.Tenant)
	}
	// 3) with no cp-adapter, a raw key is refused (can't fabricate authz)
	s2 := &server{cpPub: cpPub, http: &http.Client{}}
	if _, err := s2.resolveCapability("sk-raw"); err == nil {
		t.Fatal("expected refusal when no cp-adapter is configured")
	}
}
