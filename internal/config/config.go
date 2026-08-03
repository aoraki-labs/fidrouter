// Package config holds the shared build version and the on-disk key/pool
// material used to wire the mock up. In production these live in New API's DB
// (sealed) + the KMS/HSM, not flat files — this is a local demo convenience.
package config

const ProxyVersion = "fid-proxy-mock-v0.1.0"

// Keys is the control material produced by `ctl init`.
type Keys struct {
	IdentitySeed        []byte `json:"identity_seed"`         // enclave identity Ed25519 (mock: on disk; real: KMS-sealed)
	IdentityPub         []byte `json:"identity_pub"`          // pinned by clients
	CPSeed              []byte `json:"cp_seed"`               // control-plane (New API) signing key
	CPPub               []byte `json:"cp_pub"`                // pinned by the enclave to verify capability tokens
	KMSMaster           []byte `json:"kms_master"`            // mock KMS master (real: HSM-resident)
	ExpectedMeasurement string `json:"expected_measurement"` // measurement KMS releases keys to
}

// PublicConfig is the ONLY key material safe to bake into the measured image:
// the control-plane PUBLIC key (to verify capability tokens) + the expected
// measurement. No private seeds — those are injected at boot (env now,
// attestation-gated Secret Manager next), so the open-source image has no secret
// and its measurement is reproducible.
type PublicConfig struct {
	CPPub               []byte `json:"cp_pub"`
	ExpectedMeasurement string `json:"expected_measurement"`
}

// PlainAccount is an upstream account with a plaintext key (input to sealing).
// BaseURL set => forward real OpenAI-compatible requests there; empty => mock.
type PlainAccount struct {
	ID        string `json:"id"`
	Provider  string `json:"provider"`
	Key       string `json:"key"`
	BaseURL   string `json:"base_url,omitempty"`
	TPMBudget int    `json:"tpm_budget"`
}

// PlainPools: poolID -> accounts (managed-key mode: WE own these keys).
type PlainPools struct {
	Pools map[string][]PlainAccount `json:"pools"`
}

// SealedAccount is what the control plane actually stores: ciphertext only.
type SealedAccount struct {
	ID        string `json:"id"`
	Provider  string `json:"provider"`
	BaseURL   string `json:"base_url,omitempty"`
	Sealed    []byte `json:"sealed"`
	TPMBudget int    `json:"tpm_budget"`
}

type SealedPools struct {
	Pools map[string][]SealedAccount `json:"pools"`
}
