// Package receipt is the tamper-evident audit record the enclave emits per
// request. CRUCIAL: it carries only HASHES + counts + routing metadata, never
// prompt/response content. The client (and a transparency log, later) verifies
// the signature and that model==requested — catching silent model downgrades.
package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type Receipt struct {
	TsUnix        int64  `json:"ts_unix"`
	Tenant        string `json:"tenant"`
	Model         string `json:"model"`     // model ACTUALLY sent upstream
	Account       string `json:"account"`   // upstream account id it was routed to
	ReqHash       string `json:"req_hash"`  // sha256 of plaintext request (content NOT stored)
	RespHash      string `json:"resp_hash"` // sha256 of plaintext response
	PromptTok     int    `json:"prompt_tokens"`
	CompletionTok int    `json:"completion_tokens"`
	CacheHit      bool   `json:"cache_hit"`
	Measurement   string `json:"measurement"` // binds receipt to the attested build
}

type Signed struct {
	Receipt Receipt `json:"receipt"`
	Sig     []byte  `json:"sig"`
}

func Hash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Sign serializes the receipt deterministically and signs it with `signer`
// (the enclave identity key, via tee.Attester.Sign).
func Sign(r Receipt, signer func([]byte) []byte) (Signed, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return Signed{}, err
	}
	return Signed{Receipt: r, Sig: signer(body)}, nil
}

func Verify(pub ed25519.PublicKey, s Signed) bool {
	body, err := json.Marshal(s.Receipt)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, body, s.Sig)
}
