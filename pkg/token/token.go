// Package token is the capability token: how the control plane (New API) tells
// the enclave "this tenant may use these models, up to this quota" WITHOUT the
// enclave ever touching the user database. It is a tiny Ed25519-signed JWT-like
// blob: base64url(claims).base64url(sig). The enclave pins the control-plane
// public key (CPK) and verifies signature + expiry only.
package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type Claims struct {
	Tenant   string   `json:"tenant"`   // downstream customer id
	Pool     string   `json:"pool"`     // upstream account pool this tenant maps to ("shared" or a dedicated id)
	Models   []string `json:"models"`   // model allowlist
	MaxTok   int64    `json:"max_tok"`  // remaining quota (advisory in mock)
	Exp      int64    `json:"exp"`      // unix expiry
	Isolated bool     `json:"isolated"` // if true, no cross-tenant cache sharing allowed
}

func Mint(cpPriv ed25519.PrivateKey, c Claims) (string, error) {
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(cpPriv, body)
	return b64(body) + "." + b64(sig), nil
}

func Verify(cpPub ed25519.PublicKey, tok string) (Claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 2 {
		return Claims{}, errors.New("token: malformed")
	}
	body, err := unb64(parts[0])
	if err != nil {
		return Claims{}, err
	}
	sig, err := unb64(parts[1])
	if err != nil {
		return Claims{}, err
	}
	if !ed25519.Verify(cpPub, body, sig) {
		return Claims{}, errors.New("token: bad signature")
	}
	var c Claims
	if err := json.Unmarshal(body, &c); err != nil {
		return Claims{}, err
	}
	if c.Exp != 0 && time.Now().Unix() > c.Exp {
		return Claims{}, errors.New("token: expired")
	}
	return c, nil
}

func (c Claims) AllowsModel(model string) bool {
	for _, m := range c.Models {
		if m == model || m == "*" {
			return true
		}
	}
	return false
}

func b64(b []byte) string            { return base64.RawURLEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
