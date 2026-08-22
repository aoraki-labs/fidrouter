// client is the reference VERIFIER — the logic your drop-in SDK will ship. It
// refuses to send a prompt until it has cryptographically verified the enclave:
//  1. fetch /attestation with a fresh nonce,
//  2. measurement == pinned reproducible-build value,
//  3. identity pubkey == pinned value, quote signature valid,
//  4. report_data == H(nonce || ephemeral_pub)  (freshness + key binding),
//     -> any failure = FAIL-CLOSED (never send).
//
// Only then does it seal the prompt to the attested key and send it, and it
// verifies the signed receipt (incl. model == requested → no silent downgrade).
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"fidrouter/pkg/enc"
	"fidrouter/pkg/receipt"
	"fidrouter/pkg/tee"
	"fidrouter/pkg/wire"
)

func main() {
	proxy := flag.String("proxy", "http://127.0.0.1:9090", "")
	tok := flag.String("token", "", "capability token")
	model := flag.String("model", "gpt-4o", "")
	prefix := flag.String("prefix", "You are a helpful assistant. [long stable system prompt]", "cacheable prefix")
	suffix := flag.String("suffix", "hello", "variable tail")
	pinMeas := flag.String("pin-measurement", "", "pinned measurement (hex)")
	pinIdPub := flag.String("pin-idpub", "", "pinned identity pubkey (hex)")
	flag.Parse()

	pinPub, _ := hex.DecodeString(*pinIdPub)

	// 1) attestation with fresh nonce (sent as hex; both sides hash the hex bytes)
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	nonceHex := hex.EncodeToString(raw)
	q, err := fetchQuote(*proxy, nonceHex)
	if err != nil {
		failClosed("attestation fetch failed: " + err.Error())
	}

	// 2-4) VERIFY before trusting the channel
	if *pinMeas != "" && q.Measurement != *pinMeas {
		failClosed(fmt.Sprintf("measurement mismatch\n  got:    %s\n  pinned: %s\n  (build is not the audited no-log code — refusing)", q.Measurement, *pinMeas))
	}
	if len(pinPub) > 0 && !bytes.Equal(q.IdentityPub, pinPub) {
		failClosed("identity pubkey mismatch (not the enclave we trust)")
	}
	body := append([]byte(q.Measurement+q.ReportData), q.EphemeralPub...)
	if !ed25519.Verify(ed25519.PublicKey(q.IdentityPub), body, q.Sig) {
		failClosed("quote signature invalid")
	}
	if !bytes.Equal(q.Nonce, []byte(nonceHex)) {
		failClosed("enclave did not echo our nonce (possible replay)")
	}
	rdIn := append(append([]byte{}, q.Nonce...), q.EphemeralPub...)
	if len(q.TLSPub) > 0 { // RA-TLS: the TLS cert key is folded into the bind
		rdIn = append(rdIn, q.TLSPub...)
	}
	rd := sha256.Sum256(rdIn)
	if hex.EncodeToString(rd[:]) != q.ReportData {
		failClosed("report_data not bound to nonce+key (possible replay)")
	}
	fmt.Printf("✔ attestation OK  platform=%s measurement=%s…\n", q.Platform, q.Measurement[:16])

	// derive channel key and seal prompt to the attested ephemeral key
	cpriv, _ := enc.NewX25519()
	key, err := enc.SharedKey(cpriv, q.EphemeralPub, "fid-e2e-v1")
	if err != nil {
		failClosed(err.Error())
	}
	inner, _ := json.Marshal(wire.InnerPrompt{Model: *model, Prefix: *prefix, Suffix: *suffix})
	sealed, _ := enc.Seal(key, inner, []byte(q.Session))

	// send
	reqBody, _ := json.Marshal(wire.InferReq{
		Session: q.Session, ClientPub: cpriv.PublicKey().Bytes(), Token: *tok, Sealed: sealed,
	})
	resp, err := http.Post(*proxy+"/v1/infer", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		failClosed(err.Error())
	}
	defer resp.Body.Close()
	rawResp, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		fmt.Printf("✘ infer rejected (%d): %s\n", resp.StatusCode, string(rawResp))
		os.Exit(1)
	}
	var out wire.InferResp
	if err := json.Unmarshal(rawResp, &out); err != nil {
		failClosed("bad response: " + err.Error())
	}

	// verify receipt (signature, measurement binding, model == requested)
	if len(pinPub) > 0 && !receipt.Verify(ed25519.PublicKey(pinPub), out.Receipt) {
		failClosed("receipt signature invalid")
	}
	if *pinMeas != "" && out.Receipt.Receipt.Measurement != *pinMeas {
		failClosed("receipt measurement mismatch")
	}
	if out.Receipt.Receipt.Model != *model {
		failClosed(fmt.Sprintf("MODEL DOWNGRADE detected: asked %s, receipt says %s", *model, out.Receipt.Receipt.Model))
	}

	// open the sealed response
	plainResp, err := enc.Open(key, out.SealedResp, []byte(q.Session))
	if err != nil {
		failClosed("cannot open response: " + err.Error())
	}
	var ur wire.UpstreamResp
	_ = json.Unmarshal(plainResp, &ur)

	fmt.Printf("✔ receipt OK      account=%s affinity=%v CACHE_HIT=%v  model=%s ptok=%d ctok=%d\n",
		out.Route.Account, out.Route.Affinity, ur.CacheHit, out.Receipt.Receipt.Model,
		out.Receipt.Receipt.PromptTok, out.Receipt.Receipt.CompletionTok)
	fmt.Printf("  completion: %s\n", ur.Completion)
}

func fetchQuote(proxy, nonceHex string) (tee.Quote, error) {
	resp, err := http.Get(proxy + "/attestation?nonce=" + nonceHex)
	if err != nil {
		return tee.Quote{}, err
	}
	defer resp.Body.Close()
	var q tee.Quote
	if err := json.NewDecoder(resp.Body).Decode(&q); err != nil {
		return tee.Quote{}, err
	}
	return q, nil
}

func failClosed(msg string) {
	fmt.Println("✘ FAIL-CLOSED:", msg)
	os.Exit(1)
}
