// Package kms is THE mockable underlying layer #2: attestation-gated key release.
//
// KeyProvider is the interface. Mock (below) holds the master key locally and
// releases an upstream API key ONLY if the caller's measurement equals the
// measurement the key was sealed to. In production you swap Mock for Aliyun KMS
// (Secure Key Release) / dstack-kms: the master NEVER touches the enclave disk,
// and release is gated on a real remote-attestation quote — same interface.
//
// This is what makes BYOK safe and "managed key" operator-blind: the sealed
// upstream key can only be opened by the exact attested no-log build.
package kms

import (
	"errors"

	"fidrouter/internal/enc"
)

// KeyProvider releases plaintext upstream keys to an attested caller.
type KeyProvider interface {
	// Seal wraps a plaintext upstream key so only `measurement` can open it.
	Seal(plaintextKey []byte, measurement string) ([]byte, error)
	// Unseal releases the key iff callerMeasurement matches. Runs "inside" the
	// KMS trust domain; the returned key lives only in enclave RAM.
	Unseal(sealed []byte, callerMeasurement string) ([]byte, error)
}

// Passthrough is a NO-OP provider for demo/plaintext-pool mode: the "sealed"
// bytes are already the plaintext key. NOT for production.
type Passthrough struct{}

func (Passthrough) Seal(k []byte, _ string) ([]byte, error)   { return k, nil }
func (Passthrough) Unseal(s []byte, _ string) ([]byte, error) { return s, nil }

// Mock keeps the master key in-process. Documented limitation: a real KMS keeps
// the master in an HSM and gates Unseal on a verified TDX quote, not a string.
type Mock struct {
	master              []byte // 32 bytes
	expectedMeasurement string
}

func NewMock(master []byte, expectedMeasurement string) *Mock {
	return &Mock{master: master, expectedMeasurement: expectedMeasurement}
}

func (m *Mock) Seal(plaintextKey []byte, measurement string) ([]byte, error) {
	// aad binds the ciphertext to the target measurement.
	return enc.Seal(m.master, plaintextKey, []byte(measurement))
}

func (m *Mock) Unseal(sealed []byte, callerMeasurement string) ([]byte, error) {
	if callerMeasurement != m.expectedMeasurement {
		return nil, errors.New("kms: attestation gate REFUSED — measurement mismatch (tampered/unknown build)")
	}
	return enc.Open(m.master, sealed, []byte(callerMeasurement))
}
