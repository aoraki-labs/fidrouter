// Package delegation lets ONE shared enclave serve MANY relay operators without any of them
// — or us — becoming an authority over the others.
//
// The problem it solves: an enclave that trusts a single control-plane key means whoever
// holds that key can mint a token for any tenant, and therefore spend any upstream key
// sealed into that enclave. On a multi-operator enclave that is not a policy question, it is
// a broken authority model.
//
// The fix: the enclave bakes only a ROOT public key. Each operator holds their OWN signing
// seed and gets a delegation:
//
//	root signs    { relay_id, partner_cp_pub, cp_adapter_url, not_after }
//	partner signs the same bytes with partner_cp_pub
//
// Both signatures are required. Root alone cannot point an operator's traffic at a different
// adapter or swap their key, because the partner's counter-signature would not verify — so
// even we cannot redirect where a user's gateway key gets sent. The partner alone cannot
// enrol themselves, because root's signature gates who may operate at all.
//
// A delegation is self-authenticating, so it is PUSHED to the enclave and needs no trusted
// transport and no outbound fetch. It lives in memory only: after a restart it must be
// re-pushed, exactly like sealed BYOK.
package delegation

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Payload is the signed part. Field order here IS the canonical signing order — changing it
// invalidates every existing delegation, so don't reorder without a version bump.
type Payload struct {
	RelayID      string `json:"relay_id"`
	PartnerCPPub []byte `json:"partner_cp_pub"`
	CPAdapterURL string `json:"cp_adapter_url"`
	NotAfter     int64  `json:"not_after"`
}

// Delegation is the wire form: payload + both signatures.
type Delegation struct {
	Payload
	RootSig    []byte `json:"root_sig"`
	PartnerSig []byte `json:"partner_sig"`
}

// SigningBytes is what both signatures cover. Marshalling a struct with fixed field order
// gives deterministic bytes; we deliberately do NOT sign the outer envelope, so a delegation
// can be re-wrapped without invalidating it.
func (p Payload) SigningBytes() ([]byte, error) { return json.Marshal(p) }

var (
	ErrRootSig    = errors.New("delegation: root signature invalid (not issued by the baked root key)")
	ErrPartnerSig = errors.New("delegation: partner counter-signature invalid — the operator did not agree to this adapter URL/key")
	ErrExpired    = errors.New("delegation: expired")
	ErrShape      = errors.New("delegation: malformed")
)

// Verify checks a delegation against the enclave's baked root key. Order matters only for
// error clarity; every check is mandatory.
func Verify(rootPub ed25519.PublicKey, d *Delegation, now time.Time) error {
	if d == nil || d.RelayID == "" || strings.ContainsAny(d.RelayID, "/?# ") {
		return ErrShape
	}
	if len(d.PartnerCPPub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: partner_cp_pub must be %d bytes", ErrShape, ed25519.PublicKeySize)
	}
	if !strings.HasPrefix(d.CPAdapterURL, "http://") && !strings.HasPrefix(d.CPAdapterURL, "https://") {
		return fmt.Errorf("%w: cp_adapter_url must be http(s)", ErrShape)
	}
	msg, err := d.Payload.SigningBytes()
	if err != nil {
		return err
	}
	if len(rootPub) != ed25519.PublicKeySize || !ed25519.Verify(rootPub, msg, d.RootSig) {
		return ErrRootSig
	}
	if !ed25519.Verify(ed25519.PublicKey(d.PartnerCPPub), msg, d.PartnerSig) {
		return ErrPartnerSig
	}
	if d.NotAfter > 0 && now.Unix() > d.NotAfter {
		return ErrExpired
	}
	return nil
}

// Store holds verified delegations by relay id. In memory only — a delegation is a
// capability grant, and losing them on restart is the safe direction.
type Store struct {
	mu      sync.RWMutex
	rootPub ed25519.PublicKey
	byID    map[string]*Delegation
}

func NewStore(rootPub ed25519.PublicKey) *Store {
	return &Store{rootPub: rootPub, byID: map[string]*Delegation{}}
}

// Put verifies then stores. A delegation that doesn't verify is never retained.
func (s *Store) Put(d *Delegation) error {
	if len(s.rootPub) != ed25519.PublicKeySize {
		return errors.New("delegation: this enclave has no root CP key configured")
	}
	if err := Verify(s.rootPub, d, time.Now()); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[d.RelayID] = d
	return nil
}

// Get returns a still-valid delegation, or nil. Expiry is re-checked on read so a delegation
// that lapses while cached stops being usable without needing a sweeper.
func (s *Store) Get(relayID string) *Delegation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d := s.byID[relayID]
	if d == nil {
		return nil
	}
	if d.NotAfter > 0 && time.Now().Unix() > d.NotAfter {
		return nil
	}
	return d
}

func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

// Sign is a helper for whoever issues delegations (the platform) and for the partner's
// counter-signature. Kept here so issuer and verifier can never drift apart.
func Sign(seed ed25519.PrivateKey, p Payload) ([]byte, error) {
	msg, err := p.SigningBytes()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(seed, msg), nil
}
