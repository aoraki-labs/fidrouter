// Package ratls generates the in-enclave TLS certificate for RA-TLS.
//
// The private key is created inside the enclave and never leaves its memory (no
// disk, no env). The certificate's public key (its SubjectPublicKeyInfo) is
// returned so the attester can BIND it into the remote-attestation quote — a
// verifier that pins the measurement then knows the TLS peer it's talking to is
// the attested, no-log build. This moves the confidentiality guarantee into the
// transport, so a stock HTTPS client benefits without our E2EE handshake.
//
// T9 (attestation-CA): the attestation binds the *key*, not the certificate. So the
// enclave can also serve a **publicly-trusted certificate over that same key**: it emits a
// CSR (GET /tls-csr), something outside runs ACME for the domain, and the signed chain is
// injected back (POST /tls-cert) — see Holder.InstallChain, which refuses any chain whose
// public key isn't the enclave's own. Then a stock client validates via the CA while a
// verifying client still validates via the attestation binding. Both are looking at the
// same attested key; neither trusts the other's path.
package ratls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// Holder owns the enclave's TLS key and whichever certificate is currently served.
// Use GetCertificate with tls.Config so an injected CA chain takes effect immediately,
// without dropping the listener.
type Holder struct {
	mu       sync.RWMutex
	key      *ecdsa.PrivateKey
	cert     tls.Certificate
	spki     []byte
	hosts    []string
	caSigned bool
}

// Generate creates a fresh per-boot key (forward secrecy: a leaked key is useless after
// restart) and a self-signed certificate over it.
func Generate(hosts []string) (tls.Certificate, []byte, error) {
	h, err := New(hosts, nil)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return h.Certificate(), h.SPKI(), nil
}

// New builds a Holder. If seed is nil the key is random per boot. If seed is non-nil the
// key is DERIVED from it, so it is stable across restarts — which is what makes a
// CA-issued certificate reusable (ACME rate limits make per-boot issuance impractical).
// The seed never leaves the enclave either way; stability is the only difference.
func New(hosts []string, seed []byte) (*Holder, error) {
	var (
		key *ecdsa.PrivateKey
		err error
	)
	if len(seed) == 0 {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		key, err = deriveP256(seed)
	}
	if err != nil {
		return nil, err
	}
	h := &Holder{key: key, hosts: hosts}
	if h.spki, err = x509.MarshalPKIXPublicKey(&key.PublicKey); err != nil {
		return nil, err
	}
	if h.cert, err = selfSigned(key, hosts); err != nil {
		return nil, err
	}
	return h, nil
}

// deriveP256 turns a seed into a deterministic P-256 key. Domain-separated so the TLS key
// is never the identity key even when both come from the same seed.
func deriveP256(seed []byte) (*ecdsa.PrivateKey, error) {
	n := elliptic.P256().Params().N
	for i := byte(0); i < 32; i++ {
		sum := sha512.Sum512(append(append([]byte("fid-ratls-tls-key-v1"), seed...), i))
		d := new(big.Int).SetBytes(sum[:32])
		// require 0 < d < N
		if d.Sign() == 0 || d.Cmp(n) >= 0 {
			continue
		}
		key := new(ecdsa.PrivateKey)
		key.Curve = elliptic.P256()
		key.D = d
		key.PublicKey.X, key.PublicKey.Y = elliptic.P256().ScalarBaseMult(d.Bytes())
		return key, nil
	}
	return nil, errors.New("ratls: could not derive a valid P-256 key from seed")
}

func selfSigned(key *ecdsa.PrivateKey, hosts []string) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "fidrouter-enclave"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	applyHosts(tmpl, hosts)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func applyHosts(tmpl *x509.Certificate, hosts []string) {
	for _, h := range hosts {
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
}

// SPKI is the DER SubjectPublicKeyInfo bound into the attestation.
func (h *Holder) SPKI() []byte { return h.spki }

// Certificate returns the certificate currently served.
func (h *Holder) Certificate() tls.Certificate {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cert
}

// CASigned reports whether a publicly-trusted chain has been installed.
func (h *Holder) CASigned() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.caSigned
}

// GetCertificate is the tls.Config hook, so InstallChain takes effect on the next handshake.
func (h *Holder) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	c := h.cert
	return &c, nil
}

// CSRPEM returns a PEM CertificateRequest for the enclave's key, for an ACME client running
// outside. It proves possession of the key without revealing it.
func (h *Holder) CSRPEM() ([]byte, error) {
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: firstDNS(h.hosts)}}
	for _, s := range h.hosts {
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, s)
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, h.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func firstDNS(hosts []string) string {
	for _, h := range hosts {
		if h != "" && net.ParseIP(h) == nil {
			return h
		}
	}
	return "fidrouter-enclave"
}

// InstallChain swaps in an externally-issued (e.g. ACME) certificate chain for the SAME
// in-enclave key. It REFUSES a chain whose leaf public key isn't ours — that check is what
// makes this endpoint safe to expose: nobody can install a certificate for a key they
// control, so nobody can impersonate the enclave through it. The attestation binding is
// unaffected, because the bound value is the key, not the certificate.
func (h *Holder) InstallChain(chainPEM []byte) error {
	var certs [][]byte
	rest := chainPEM
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			certs = append(certs, blk.Bytes)
		}
	}
	if len(certs) == 0 {
		return errors.New("no CERTIFICATE block in the supplied PEM")
	}
	leaf, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return fmt.Errorf("parse leaf: %w", err)
	}
	leafSPKI, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return fmt.Errorf("leaf public key: %w", err)
	}
	if string(leafSPKI) != string(h.spki) {
		return errors.New("refusing chain: its public key is not this enclave's attested TLS key")
	}
	if time.Now().After(leaf.NotAfter) {
		return errors.New("refusing chain: leaf certificate has expired")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cert = tls.Certificate{Certificate: certs, PrivateKey: h.key, Leaf: leaf}
	h.caSigned = true
	return nil
}
