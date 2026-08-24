package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"fidrouter/internal/kms"
	"fidrouter/internal/routing"
	"fidrouter/pkg/delegation"
	"fidrouter/pkg/tee"
	"fidrouter/pkg/token"
)

func mintFor(t *testing.T, priv ed25519.PrivateKey, tenant string) string {
	t.Helper()
	tok, err := token.Mint(priv, token.Claims{Tenant: tenant, Models: []string{"m"},
		Exp: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// The property that makes a SHARED enclave safe for multiple relay operators: an upstream key
// is readable only by whoever provisioned it. Before the provisioner namespacing, any holder
// of the one CP seed could mint a token and spend every operator's sealed key.
func TestUpstreamKeyIsolatedPerProvisioner(t *testing.T) {
	aPub, _, _ := ed25519.GenerateKey(rand.Reader)
	bPub, _, _ := ed25519.GenerateKey(rand.Reader)

	// resolveKey consults the KMS first (empty result = fall through to the sealed-BYOK
	// RAM store), so give it a passthrough KMS and a mock attester.
	_, idPriv, _ := ed25519.GenerateKey(rand.Reader)
	s := &server{byok: map[string]string{}, km: kms.Passthrough{},
		at: tee.NewMock("test", idPriv, false)}
	// Operator A seals a key for the shared account name; B seals its own under the SAME name.
	s.byok[byokKey(aPub, "byok-anthropic")] = "sk-ant-A"
	s.byok[byokKey(bPub, "byok-anthropic")] = "sk-ant-B"

	acct := &routing.Account{ID: "byok-anthropic"}
	for _, tc := range []struct {
		who  ed25519.PublicKey
		want string
	}{{aPub, "sk-ant-A"}, {bPub, "sk-ant-B"}} {
		got, err := s.resolveKey(acct, tc.who)
		if err != nil {
			t.Fatalf("provisioner could not read its own key: %v", err)
		}
		if string(got) != tc.want {
			t.Fatalf("got %q want %q — operators are NOT isolated", got, tc.want)
		}
	}

	// A third key (e.g. someone who obtained a delegation but never provisioned this account,
	// including us holding the root) must get nothing at all.
	cPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if got, err := s.resolveKey(acct, cPub); err == nil {
		t.Fatalf("a non-provisioner read %q — this is the cross-operator spend bug", got)
	}
}

// A relay id the enclave has no delegation for must be refused outright: falling back to the
// baked key would silently serve one operator's traffic under another's identity.
func TestUnknownRelayRefused(t *testing.T) {
	rootPub, _, _ := ed25519.GenerateKey(rand.Reader)
	s := &server{cpPub: rootPub, dels: delegation.NewStore(rootPub)}
	if _, _, err := s.authClaims("sk-anything", "r_never_enrolled"); err == nil {
		t.Fatal("unknown relay id was accepted")
	}
	if _, err := s.resolveCapability("sk-anything", "r_never_enrolled"); err == nil {
		t.Fatal("unknown relay id resolved an exchange target")
	}
}

// With a delegation installed, the exchange target and the accepted signer both come from the
// delegation — not from whatever we baked in.
func TestDelegationDrivesTargetAndSigner(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	pPub, pPriv, _ := ed25519.GenerateKey(rand.Reader)
	pay := delegation.Payload{RelayID: "r_x", PartnerCPPub: pPub,
		CPAdapterURL: "https://adapter.partner.example", NotAfter: 0}
	rs, _ := delegation.Sign(rootPriv, pay)
	ps, _ := delegation.Sign(pPriv, pay)

	s := &server{cpPub: rootPub, cpAdapterURL: "https://ours.example",
		dels: delegation.NewStore(rootPub),
		// a root-signed token is NOT a valid capability token here, so it falls through to
		// the exchange; give it a client so that attempt errors instead of panicking
		http: &http.Client{Timeout: 2 * time.Second}}
	if err := s.dels.Put(&delegation.Delegation{Payload: pay, RootSig: rs, PartnerSig: ps}); err != nil {
		t.Fatalf("put: %v", err)
	}
	d := s.dels.Get("r_x")
	if d == nil || d.CPAdapterURL != "https://adapter.partner.example" {
		t.Fatal("delegation not usable")
	}
	// A token signed by the PARTNER key must be accepted under that relay id...
	tokPartner := mintFor(t, pPriv, "u_p")
	if c, signer, err := s.authClaims(tokPartner, "r_x"); err != nil {
		t.Fatalf("partner-signed token rejected: %v", err)
	} else if c.Tenant != "u_p" || string(signer) != string(pPub) {
		t.Fatalf("wrong claims/signer: %+v %x", c, signer)
	}
	// ...while one signed by the ROOT key must NOT be, or root would be able to act as the
	// operator and then read keys provisioned under the operator's key.
	tokRoot := mintFor(t, rootPriv, "u_root")
	if _, _, err := s.authClaims(tokRoot, "r_x"); err == nil {
		t.Fatal("root-signed token accepted under a partner's relay id")
	}
}
