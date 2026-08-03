// Package tee is THE mockable underlying layer #1: remote attestation.
//
// Attester is the interface the rest of fid-router codes against. Today the
// only implementation is Mock (below). In production you add an Aliyun-DCAP or
// dstack implementation that returns a real Intel TDX quote (MRTD/RTMR) — and
// NOTHING else in the codebase changes.
//
// What a Quote promises the client:
//   - Measurement: the code identity (mock: sha256 of the build string; real:
//     MRTD/RTMR). The client pins this to a published reproducible-build value.
//   - EphemeralPub: an X25519 public key generated *inside the enclave* for
//     this session; the client seals its prompt to it, so plaintext only opens
//     inside the attested code.
//   - ReportData = H(nonce || EphemeralPub): binds freshness (anti-replay) and
//     the channel key into the signed quote.
//   - Sig: signed by the enclave identity key (mock: a fixed Ed25519 key whose
//     pub is pinned by the client; real: chains to the Intel root via DCAP).
package tee

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"fidrouter/internal/enc"
)

type Quote struct {
	Platform     string `json:"platform"`
	Measurement  string `json:"measurement"`
	Session      string `json:"session"`
	Nonce        []byte `json:"nonce"`
	EphemeralPub []byte `json:"ephemeral_pub"`
	ReportData   string `json:"report_data"`
	IdentityPub  []byte `json:"identity_pub"`
	Sig          []byte `json:"sig"`
	RawQuote     []byte `json:"raw_quote,omitempty"` // real TDX quote (DCAP-verifiable); empty for mock
}

// Attester is the mockable TEE boundary.
type Attester interface {
	Platform() string
	Measurement() string
	IdentityPub() ed25519.PublicKey
	// Attest opens a session bound to nonce and returns a signed quote.
	Attest(nonce []byte) (Quote, error)
	// SessionKey re-derives the symmetric channel key for a live session using
	// the client's public key. The enclave-side private key never leaves here.
	SessionKey(session string, clientPub []byte) ([]byte, error)
	// Sign lets the data plane sign receipts with the enclave identity key.
	Sign(msg []byte) []byte
}

// MeasurementOf is the (mock) code measurement for a given build string.
// tamper=true simulates someone slipping a logger into the build: the
// measurement changes, so client attestation and KMS key-release both fail.
func MeasurementOf(version string, tamper bool) string {
	v := version
	if tamper {
		v += "+silent-logger"
	}
	sum := sha256.Sum256([]byte("MRTD:" + v))
	return hex.EncodeToString(sum[:])
}

type sessionEntry struct {
	priv *ecdh.PrivateKey
	exp  time.Time
}

// Mock is an in-process attester. NO disk, sessions expire — consistent with
// the enclave's structural no-log posture.
type Mock struct {
	platform    string
	measurement string
	idPriv      ed25519.PrivateKey

	mu   sync.Mutex
	sess map[string]sessionEntry
}

func NewMock(version string, idPriv ed25519.PrivateKey, tamper bool) *Mock {
	return &Mock{
		platform:    "mock-tee",
		measurement: MeasurementOf(version, tamper),
		idPriv:      idPriv,
		sess:        make(map[string]sessionEntry),
	}
}

func (m *Mock) Platform() string               { return m.platform }
func (m *Mock) Measurement() string            { return m.measurement }
func (m *Mock) IdentityPub() ed25519.PublicKey { return m.idPriv.Public().(ed25519.PublicKey) }
func (m *Mock) Sign(msg []byte) []byte         { return ed25519.Sign(m.idPriv, msg) }

func (m *Mock) Attest(nonce []byte) (Quote, error) {
	priv, err := enc.NewX25519()
	if err != nil {
		return Quote{}, err
	}
	ephPub := priv.PublicKey().Bytes()

	sid := make([]byte, 16)
	if _, err := rand.Read(sid); err != nil {
		return Quote{}, err
	}
	session := hex.EncodeToString(sid)

	m.mu.Lock()
	m.gcLocked()
	m.sess[session] = sessionEntry{priv: priv, exp: time.Now().Add(2 * time.Minute)}
	m.mu.Unlock()

	rd := sha256.Sum256(append(append([]byte{}, nonce...), ephPub...))
	reportData := hex.EncodeToString(rd[:])

	// signed body = measurement || report_data || ephemeral_pub
	body := append([]byte(m.measurement+reportData), ephPub...)
	return Quote{
		Platform:     m.platform,
		Measurement:  m.measurement,
		Session:      session,
		Nonce:        nonce,
		EphemeralPub: ephPub,
		ReportData:   reportData,
		IdentityPub:  m.IdentityPub(),
		Sig:          ed25519.Sign(m.idPriv, body),
	}, nil
}

func (m *Mock) SessionKey(session string, clientPub []byte) ([]byte, error) {
	m.mu.Lock()
	e, ok := m.sess[session]
	m.mu.Unlock()
	if !ok || time.Now().After(e.exp) {
		return nil, errors.New("tee: unknown or expired session")
	}
	return enc.SharedKey(e.priv, clientPub, "fid-e2e-v1")
}

func (m *Mock) gcLocked() {
	now := time.Now()
	for k, v := range m.sess {
		if now.After(v.exp) {
			delete(m.sess, k)
		}
	}
}
