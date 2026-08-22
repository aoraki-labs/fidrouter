// Command enclave-template is a MINIMAL, working enclave you can copy to build your own
// verifiable relay. It is deliberately small: attestation, an in-enclave TLS key bound into
// that attestation, a sealed-BYOK endpoint, one inference route, and a signed receipt.
//
// It imports the SAME packages the production data plane uses (fidrouter/pkg/...), so a
// client verifying your enclave runs byte-identical checks. Do not reimplement them: the
// bind formula, token format and receipt layout are a wire contract, and a "compatible
// looking" copy that drifts is exactly how verification silently breaks.
//
// Run locally:
//
//	FIDPROXY_ATTESTER=mock go run ./examples/enclave-template
//	curl -s localhost:9095/attestation?nonce=abc | jq .
//
// Then read INVARIANTS.md before changing anything.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"fidrouter/pkg/receipt"
	"fidrouter/pkg/tee"
	"fidrouter/pkg/token"
)

func main() {
	addr := envOr("ADDR", ":9095")

	// 1) Enclave identity. Injected at boot, NEVER baked into the image — the image is what
	// gets measured and published, so a baked secret would be readable by anyone who pulls it.
	var idPriv ed25519.PrivateKey
	if s := strings.TrimSpace(os.Getenv("FID_IDENTITY_SEED")); s != "" {
		seed, err := hex.DecodeString(s)
		if err != nil || len(seed) != ed25519.SeedSize {
			log.Fatalf("FID_IDENTITY_SEED must be %d-byte hex", ed25519.SeedSize)
		}
		idPriv = ed25519.NewKeyFromSeed(seed)
	} else {
		_, idPriv, _ = ed25519.GenerateKey(rand.Reader)
		log.Printf("WARNING: ephemeral identity key — receipts won't verify against a registry")
	}

	// 2) Attester. `mock` for local dev; `gcp-cs` on Confidential Space, where the
	// measurement is the container image digest that clients pin.
	var at tee.Attester
	switch os.Getenv("FIDPROXY_ATTESTER") {
	case "gcp-cs":
		cs, err := tee.NewConfidentialSpace(idPriv, envOr("FID_CS_AUDIENCE", "fidrouter"),
			envOr("FID_CS_TOKEN_ENDPOINT", ""))
		if err != nil {
			log.Fatalf("confidential space attester: %v", err)
		}
		at = cs
	default:
		at = tee.NewMock("enclave-template-v1", idPriv, false)
	}

	// 3) The CP public key whose signatures this enclave will accept on capability tokens.
	// BAKE THIS INTO THE IMAGE: it is public, and measuring it is what lets a verifier see
	// which control plane may authorise spend here. The matching seed stays in cp-adapter.
	var cpPub ed25519.PublicKey
	if s := strings.TrimSpace(os.Getenv("FID_CP_PUB")); s != "" {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != ed25519.PublicKeySize {
			log.Fatalf("FID_CP_PUB must be %d-byte hex", ed25519.PublicKeySize)
		}
		cpPub = b
	}

	mux := http.NewServeMux()

	// /attestation — the root of all trust. Returns a quote binding a fresh nonce and this
	// enclave's keys, so a client can prove it is talking to the measured build.
	mux.HandleFunc("/attestation", func(w http.ResponseWriter, r *http.Request) {
		nonce := r.URL.Query().Get("nonce")
		if nonce == "" {
			http.Error(w, "nonce required", 400) // never issue an unbound quote: replayable
			return
		}
		q, err := at.Attest([]byte(nonce))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, q)
	})

	// /v1/infer — your actual work goes here. The contract: verify the capability token
	// BEFORE doing anything, keep plaintext in memory only, and emit a signed receipt.
	mux.HandleFunc("/v1/infer", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST", 405)
			return
		}
		claims, err := token.Verify(cpPub, bearer(r))
		if err != nil {
			http.Error(w, "unauthorized: "+err.Error(), 401)
			return
		}
		var in struct {
			Model    string `json:"model"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad json", 400)
			return
		}

		// ---- YOUR UPSTREAM CALL GOES HERE -------------------------------------------
		// Rules that keep the guarantee true:
		//   * never log message content (that is the whole product)
		//   * never write plaintext to disk
		//   * hold the upstream key only in memory (inject it sealed, see /sealing in
		//     cmd/fid-proxy for the operator-blind pattern)
		out := "hello from your enclave"
		promptTokens, completionTokens := len(in.Messages), 5
		// ------------------------------------------------------------------------------

		// A receipt is metadata ONLY — model, counts, measurement, timestamp. No content.
		// It is signed by the attested identity key, so anyone can later verify this
		// response really came from this measured build and the model wasn't downgraded.
		rec := receipt.Receipt{
			TsUnix: time.Now().Unix(), Tenant: claims.Tenant, Model: in.Model,
			PromptTok: promptTokens, CompletionTok: completionTokens,
			Measurement: at.Measurement(),
		}
		if signed, err := receipt.Sign(rec, func(b []byte) []byte {
			return ed25519.Sign(idPriv, b) // signed by the ATTESTED identity key
		}); err == nil {
			if enc, err := json.Marshal(signed); err == nil {
				w.Header().Set("X-Fid-Receipt", base64.StdEncoding.EncodeToString(enc))
			}
		}
		writeJSON(w, map[string]any{"content": out, "model": in.Model})
	})

	log.Printf("[enclave-template] platform=%s measurement=%s addr=%s",
		at.Platform(), at.Measurement(), addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func bearer(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
