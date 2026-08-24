package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fidrouter/internal/kms"
	"fidrouter/internal/routing"
	"fidrouter/pkg/delegation"
	"fidrouter/pkg/enc"
	"fidrouter/pkg/tee"
	"fidrouter/pkg/token"
)

// Inject a key through the REAL /byok handler and then read it back through resolveKey.
//
// This exists because a unit test that pre-populated the byok map passed while the shipped
// code was broken: the read side was namespaced by the provisioning key and the write side
// was not, so a key could be injected and then never resolved. Round-tripping through the
// handler is the only way that mismatch shows up.
func TestByokInjectThenResolve(t *testing.T) {
	cpPub, cpPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, idPriv, _ := ed25519.GenerateKey(rand.Reader)
	sealPriv, err := enc.NewX25519()
	if err != nil {
		t.Fatal(err)
	}
	s := &server{
		cpPub: cpPub, km: kms.Passthrough{}, at: tee.NewMock("test", idPriv, false),
		byok: map[string]string{}, sealPriv: sealPriv, sealPub: sealPriv.PublicKey().Bytes(),
	}

	const upstream = "sk-ant-the-real-key"
	tok, err := token.Mint(cpPriv, token.Claims{Tenant: "u_1", Models: []string{"m"},
		Exp: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}

	// seal exactly like a browser / ctl would: eph_pub || AES-GCM(shared, key)
	eph, err := enc.NewX25519()
	if err != nil {
		t.Fatal(err)
	}
	shared, err := enc.SharedKey(eph, s.sealPub, "fid-byok-v1")
	if err != nil {
		t.Fatal(err)
	}
	ct, err := enc.Seal(shared, []byte(upstream), []byte("fid-byok-v1"))
	if err != nil {
		t.Fatal(err)
	}
	sealed := "sealed:" + base64.StdEncoding.EncodeToString(append(eph.PublicKey().Bytes(), ct...))

	body, _ := json.Marshal(map[string]string{"token": tok, "account": "byok-anthropic", "sealed": sealed})
	rec := httptest.NewRecorder()
	s.handleByok(rec, httptest.NewRequest("POST", "/byok", strings.NewReader(string(body))))
	if rec.Code != http.StatusOK {
		t.Fatalf("/byok returned %d: %s", rec.Code, rec.Body.String())
	}

	// the whole point: the key just injected must be resolvable by the same CP key
	got, err := s.resolveKey(&routing.Account{ID: "byok-anthropic"}, cpPub)
	if err != nil {
		t.Fatalf("injected key could not be resolved (write/read namespaces disagree): %v", err)
	}
	if string(got) != upstream {
		t.Fatalf("resolved %q, want %q", got, upstream)
	}

	// ...and by nobody else
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := s.resolveKey(&routing.Account{ID: "byok-anthropic"}, other); err == nil {
		t.Fatal("a different CP key resolved someone else's injected upstream key")
	}
}

// A delegated operator signs with their OWN key, so /byok must accept that rather than only
// the baked key — otherwise BYOK is impossible for every operator except us.
func TestByokAcceptsDelegatedOperator(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	pPub, pPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, idPriv, _ := ed25519.GenerateKey(rand.Reader)
	sealPriv, _ := enc.NewX25519()

	s := &server{cpPub: rootPub, km: kms.Passthrough{}, at: tee.NewMock("t", idPriv, false),
		byok: map[string]string{}, sealPriv: sealPriv, sealPub: sealPriv.PublicKey().Bytes(),
		dels: newStoreWith(t, rootPub, rootPriv, pPub, pPriv)}

	tok, _ := token.Mint(pPriv, token.Claims{Tenant: "u_p", Models: []string{"m"},
		Exp: time.Now().Add(time.Hour).Unix()})
	eph, _ := enc.NewX25519()
	shared, _ := enc.SharedKey(eph, s.sealPub, "fid-byok-v1")
	ct, _ := enc.Seal(shared, []byte("sk-partner-upstream"), []byte("fid-byok-v1"))
	sealed := "sealed:" + base64.StdEncoding.EncodeToString(append(eph.PublicKey().Bytes(), ct...))
	body, _ := json.Marshal(map[string]string{"token": tok, "account": "acct", "sealed": sealed})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/r/r_x/byok", strings.NewReader(string(body)))
	relayRouter(http.HandlerFunc(s.handleByok)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delegated operator could not inject: %d %s", rec.Code, rec.Body.String())
	}
	if got, err := s.resolveKey(&routing.Account{ID: "acct"}, pPub); err != nil ||
		string(got) != "sk-partner-upstream" {
		t.Fatalf("delegated operator cannot read its own key: %q %v", got, err)
	}
	// and OUR root key must not be able to read it
	if _, err := s.resolveKey(&routing.Account{ID: "acct"}, rootPub); err == nil {
		t.Fatal("root read an operator's sealed key")
	}
}

// newStoreWith builds a delegation store containing one valid delegation for the partner.
func newStoreWith(t *testing.T, rootPub ed25519.PublicKey, rootPriv ed25519.PrivateKey,
	pPub ed25519.PublicKey, pPriv ed25519.PrivateKey) *delegation.Store {
	t.Helper()
	pay := delegation.Payload{RelayID: "r_x", PartnerCPPub: pPub,
		CPAdapterURL: "https://adapter.partner.example"}
	rs, _ := delegation.Sign(rootPriv, pay)
	ps, _ := delegation.Sign(pPriv, pay)
	st := delegation.NewStore(rootPub)
	if err := st.Put(&delegation.Delegation{Payload: pay, RootSig: rs, PartnerSig: ps}); err != nil {
		t.Fatal(err)
	}
	return st
}
