package delegation

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func mk(t *testing.T) (root ed25519.PrivateKey, partner ed25519.PrivateKey, d *Delegation) {
	t.Helper()
	_, root, _ = ed25519.GenerateKey(rand.Reader)
	partnerPub, partnerPriv, _ := ed25519.GenerateKey(rand.Reader)
	p := Payload{RelayID: "r_abc", PartnerCPPub: partnerPub,
		CPAdapterURL: "https://adapter.partner.example", NotAfter: time.Now().Add(time.Hour).Unix()}
	rs, err := Sign(root, p)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := Sign(partnerPriv, p)
	if err != nil {
		t.Fatal(err)
	}
	return root, partnerPriv, &Delegation{Payload: p, RootSig: rs, PartnerSig: ps}
}

func TestValidDelegation(t *testing.T) {
	root, _, d := mk(t)
	if err := Verify(root.Public().(ed25519.PublicKey), d, time.Now()); err != nil {
		t.Fatalf("valid delegation rejected: %v", err)
	}
}

// The whole point of the counter-signature: holding the root key must NOT let us move an
// operator's traffic to an adapter we control, or swap in a key we hold.
func TestRootAloneCannotRedirect(t *testing.T) {
	root, _, d := mk(t)
	rootPub := root.Public().(ed25519.PublicKey)

	evil := *d
	evil.CPAdapterURL = "https://adapter.attacker.example"
	rs, _ := Sign(root, evil.Payload) // re-sign as root, but we cannot forge the partner sig
	evil.RootSig = rs
	if err := Verify(rootPub, &evil, time.Now()); !errors.Is(err, ErrPartnerSig) {
		t.Fatalf("redirected adapter URL accepted (err=%v) — root must not be able to redirect", err)
	}

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	swap := *d
	swap.PartnerCPPub = otherPub
	rs2, _ := Sign(root, swap.Payload)
	swap.RootSig = rs2
	if err := Verify(rootPub, &swap, time.Now()); !errors.Is(err, ErrPartnerSig) {
		t.Fatalf("swapped partner key accepted (err=%v)", err)
	}
}

// And the reverse: an operator cannot enrol themselves without root.
func TestPartnerAloneCannotEnrol(t *testing.T) {
	root, partner, d := mk(t)
	self := *d
	ps, _ := Sign(partner, self.Payload)
	self.PartnerSig = ps
	self.RootSig = ps // garbage as a root signature
	if err := Verify(root.Public().(ed25519.PublicKey), &self, time.Now()); !errors.Is(err, ErrRootSig) {
		t.Fatalf("self-enrolment accepted (err=%v)", err)
	}
}

func TestExpiryAndShape(t *testing.T) {
	root, partnerPriv, d := mk(t)
	rootPub := root.Public().(ed25519.PublicKey)

	old := *d
	old.NotAfter = time.Now().Add(-time.Minute).Unix()
	old.RootSig, _ = Sign(root, old.Payload)
	old.PartnerSig, _ = Sign(partnerPriv, old.Payload)
	if err := Verify(rootPub, &old, time.Now()); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired delegation accepted (err=%v)", err)
	}

	for _, bad := range []func(x *Delegation){
		func(x *Delegation) { x.RelayID = "" },
		func(x *Delegation) { x.RelayID = "a/b" }, // would let a relay id escape into the path
		func(x *Delegation) { x.CPAdapterURL = "file:///etc/passwd" },
		func(x *Delegation) { x.PartnerCPPub = []byte("short") },
	} {
		x := *d
		bad(&x)
		x.RootSig, _ = Sign(root, x.Payload)
		x.PartnerSig, _ = Sign(partnerPriv, x.Payload)
		if err := Verify(rootPub, &x, time.Now()); err == nil {
			t.Fatalf("malformed delegation accepted: %+v", x.Payload)
		}
	}
}

func TestStoreRejectsInvalidAndExpiresOnRead(t *testing.T) {
	root, partnerPriv, d := mk(t)
	s := NewStore(root.Public().(ed25519.PublicKey))

	bad := *d
	bad.PartnerSig = make([]byte, ed25519.SignatureSize)
	if err := s.Put(&bad); err == nil || s.Len() != 0 {
		t.Fatal("store retained an unverifiable delegation")
	}
	if err := s.Put(d); err != nil {
		t.Fatalf("valid Put failed: %v", err)
	}
	if s.Get("r_abc") == nil {
		t.Fatal("Get returned nil for a stored delegation")
	}
	if s.Get("r_nope") != nil {
		t.Fatal("Get invented a delegation")
	}

	// lapses while cached → must stop being usable without a sweeper
	exp := *d
	exp.NotAfter = time.Now().Add(-time.Second).Unix()
	exp.RootSig, _ = Sign(root, exp.Payload)
	exp.PartnerSig, _ = Sign(partnerPriv, exp.Payload)
	s.mu.Lock()
	s.byID["r_abc"] = &exp
	s.mu.Unlock()
	if s.Get("r_abc") != nil {
		t.Fatal("expired-in-cache delegation still served")
	}
}
