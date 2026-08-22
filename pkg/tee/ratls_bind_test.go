package tee

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"fidrouter/pkg/ratls"
)

// TestRATLSBinding proves the RA-TLS retrofit: SetTLSPub folds the TLS cert
// public key into the attestation bind (report_data), and the quote carries it.
func TestRATLSBinding(t *testing.T) {
	_, idPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, spki, err := ratls.Generate([]string{"enclave.fidcore.xyz", "34.158.56.83"})
	if err != nil || len(spki) == 0 {
		t.Fatalf("ratls.Generate: %v (spki=%d)", err, len(spki))
	}
	nonce := []byte("nonce-abc")

	// Without a TLS binding: report_data = H(nonce || ephemeral_pub), no TLSPub.
	q, err := NewMock("v1", idPriv, false).Attest(nonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(q.TLSPub) != 0 {
		t.Fatal("did not expect a TLS binding")
	}
	base := sha256.Sum256(append(append([]byte{}, nonce...), q.EphemeralPub...))
	if q.ReportData != hex.EncodeToString(base[:]) {
		t.Fatal("unbound report_data mismatch")
	}

	// With a TLS binding: report_data folds in the SPKI, and the quote exposes it.
	m := NewMock("v1", idPriv, false)
	m.SetTLSPub(spki)
	q2, err := m.Attest(nonce)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(q2.TLSPub) != hex.EncodeToString(spki) {
		t.Fatal("quote missing bound TLS pubkey")
	}
	in := append(append([]byte{}, nonce...), q2.EphemeralPub...)
	in = append(in, spki...)
	want := sha256.Sum256(in)
	if q2.ReportData != hex.EncodeToString(want[:]) {
		t.Fatal("bound report_data does not match H(nonce||eph||tls)")
	}
	if q2.ReportData == q.ReportData {
		t.Fatal("binding a TLS key must change report_data")
	}
}
