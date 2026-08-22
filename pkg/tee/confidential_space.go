package tee

// ConfidentialSpaceAttester runs INSIDE a GCP Confidential Space container. Its
// attestation is a signed OIDC token whose `submods.container.image_digest`
// claim is the digest of THIS container image — so the measurement covers OUR
// code, not just the base VM (the gap that plain MRTD/configfs-TSM had).
//
// The token is fetched from the container_launcher over a Unix socket:
//   POST unix:/run/container_launcher/teeserver.sock  http://localhost/v1/token
//   body {"audience","token_type":"OIDC","nonces":[<hex bind>]}
// We put bind = SHA256(nonce || ephemeral_pub || identity_pub) in `nonces`, so
// it surfaces in the token's `eat_nonce` claim and anchors the channel + receipt
// keys to the attested image. Trust root = Google (/v1/token) or Intel Trust
// Authority (/v1/intel/token) — configurable.
//
// Only works inside Confidential Space (the socket exists there). Measurement()
// = the image_digest read from a boot token.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"fidrouter/pkg/enc"
)

const csSocket = "/run/container_launcher/teeserver.sock"

type ConfidentialSpace struct {
	idPriv      ed25519.PrivateKey
	audience    string
	endpoint    string // "/v1/token" (Google) or "/v1/intel/token" (Intel Trust Authority)
	measurement string // image_digest
	tlsPub      []byte // RA-TLS: DER SPKI of the in-enclave TLS cert key (bound into eat_nonce)
	hc          *http.Client

	mu   sync.Mutex
	sess map[string]sessionEntry
}

func NewConfidentialSpace(idPriv ed25519.PrivateKey, audience, endpoint string) (*ConfidentialSpace, error) {
	if endpoint == "" {
		endpoint = "/v1/token"
	}
	c := &ConfidentialSpace{
		idPriv: idPriv, audience: audience, endpoint: endpoint,
		sess: make(map[string]sessionEntry),
		hc: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", csSocket)
			},
		}},
	}
	tok, err := c.fetchToken([]string{"fidr-boot"})
	if err != nil {
		return nil, err
	}
	dg, err := imageDigestFromToken(tok)
	if err != nil {
		return nil, err
	}
	c.measurement = dg
	return c, nil
}

func (c *ConfidentialSpace) Platform() string               { return "gcp-cs" }
func (c *ConfidentialSpace) Measurement() string            { return c.measurement }
func (c *ConfidentialSpace) IdentityPub() ed25519.PublicKey { return c.idPriv.Public().(ed25519.PublicKey) }
func (c *ConfidentialSpace) Sign(msg []byte) []byte         { return ed25519.Sign(c.idPriv, msg) }
func (c *ConfidentialSpace) SetTLSPub(spki []byte)          { c.tlsPub = spki }

func (c *ConfidentialSpace) Attest(nonce []byte) (Quote, error) {
	priv, err := enc.NewX25519()
	if err != nil {
		return Quote{}, err
	}
	ephPub := priv.PublicKey().Bytes()
	idPub := c.IdentityPub()

	h := sha256.New()
	h.Write(nonce)
	h.Write(ephPub)
	h.Write(idPub)
	if len(c.tlsPub) > 0 { // RA-TLS: bind the TLS cert public key into eat_nonce
		h.Write(c.tlsPub)
	}
	bind := hex.EncodeToString(h.Sum(nil)) // 64 chars, within the 10-74 nonce range

	tok, err := c.fetchToken([]string{bind})
	if err != nil {
		return Quote{}, err
	}

	sid := make([]byte, 16)
	if _, err := rand.Read(sid); err != nil {
		return Quote{}, err
	}
	session := hex.EncodeToString(sid)
	c.mu.Lock()
	c.gcLocked()
	c.sess[session] = sessionEntry{priv: priv, exp: time.Now().Add(2 * time.Minute)}
	c.mu.Unlock()

	return Quote{
		Platform: "gcp-cs", Measurement: c.measurement, Session: session,
		Nonce: nonce, EphemeralPub: ephPub, IdentityPub: idPub, TLSPub: c.tlsPub, RawQuote: []byte(tok),
	}, nil
}

func (c *ConfidentialSpace) SessionKey(session string, clientPub []byte) ([]byte, error) {
	c.mu.Lock()
	e, ok := c.sess[session]
	c.mu.Unlock()
	if !ok || time.Now().After(e.exp) {
		return nil, errors.New("cs: unknown or expired session")
	}
	return enc.SharedKey(e.priv, clientPub, "fid-e2e-v1")
}

func (c *ConfidentialSpace) fetchToken(nonces []string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"audience": c.audience, "token_type": "OIDC", "nonces": nonces,
	})
	req, _ := http.NewRequest("POST", "http://localhost"+c.endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", errors.New("cs teeserver: " + resp.Status + " " + string(b[:min(len(b), 200)]))
	}
	return strings.TrimSpace(string(b)), nil
}

func (c *ConfidentialSpace) gcLocked() {
	now := time.Now()
	for k, v := range c.sess {
		if now.After(v.exp) {
			delete(c.sess, k)
		}
	}
}

// imageDigestFromToken pulls submods.container.image_digest out of a JWT payload.
func imageDigestFromToken(tok string) (string, error) {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return "", errors.New("cs: malformed token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var claims struct {
		Submods struct {
			Container struct {
				ImageDigest string `json:"image_digest"`
			} `json:"container"`
		} `json:"submods"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", err
	}
	if claims.Submods.Container.ImageDigest == "" {
		return "", errors.New("cs: token has no submods.container.image_digest")
	}
	return claims.Submods.Container.ImageDigest, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
