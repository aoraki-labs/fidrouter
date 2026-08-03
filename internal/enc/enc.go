// Package enc holds the minimal, stdlib-only crypto used across fidrouter.
// It is deliberately tiny: X25519 ECDH -> SHA-256 KDF -> AES-256-GCM.
// This is a faithful (if minimal) stand-in for the HPKE/RA-TLS layer that a
// production build would use; the shape of the API does not change when the
// mock TEE is swapped for real Intel TDX attestation.
package enc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// NewX25519 generates an ephemeral X25519 keypair.
func NewX25519() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }

// SharedKey performs ECDH(priv, peerPub) and derives a 32-byte AES key bound to `info`.
func SharedKey(priv *ecdh.PrivateKey, peerPub []byte, info string) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(shared)
	h.Write([]byte(info))
	return h.Sum(nil), nil
}

// Seal encrypts plaintext with AES-256-GCM (nonce prepended), authenticating aad.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return append(nonce, g.Seal(nil, nonce, plaintext, aad)...), nil
}

// Open reverses Seal.
func Open(key, blob, aad []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < g.NonceSize() {
		return nil, errors.New("enc: ciphertext too short")
	}
	nonce, ct := blob[:g.NonceSize()], blob[g.NonceSize():]
	return g.Open(nil, nonce, ct, aad)
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
