// fid-proxy is the ENCLAVE DATA PLANE — the only component that ever sees a
// plaintext prompt, and only in RAM. It:
//   - serves /attestation (a signed quote binding a fresh channel key),
//   - on /v1/infer: verifies the capability token, opens the E2EE-sealed prompt,
//     affinity-routes to an upstream account, gets that account's key from the
//     (attestation-gated) KMS, forwards, and returns a signed receipt.
//
// STRUCTURAL NO-LOG: it writes NO request/response body anywhere. The only
// logs are metadata (tenant/model/account/cache/tokens). Run with FIDPROXY_TAMPER=1
// to simulate a logging build: the measurement changes, the KMS refuses to
// release keys, and clients fail-closed.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fidrouter/internal/config"
	"fidrouter/internal/kms"
	"fidrouter/internal/routing"
	"fidrouter/pkg/enc"
	"fidrouter/pkg/ratls"
	"fidrouter/pkg/receipt"
	"fidrouter/pkg/tee"
	"fidrouter/pkg/token"
	"fidrouter/pkg/wire"
)

type chatMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type upstreamReq struct {
	Model    string
	Messages []chatMsg
}

// tlsHolder owns the in-enclave TLS key + the certificate currently served. Package-level
// because RA-TLS is a process-wide property of the listener, not per-request state; nil when
// RA-TLS is off (plain HTTP), which the /tls-* handlers check.
var tlsHolder *ratls.Holder

type server struct {
	at           tee.Attester
	km           kms.KeyProvider
	rt           *routing.Router
	cpPub        ed25519.PublicKey
	upstream     string
	http         *http.Client
	meteringURL  string // if set, each signed receipt (metadata, NO content) is POSTed here
	verifyURL    string // shown on the root page so a human can go verify
	cpAdapterURL string // if set, a raw gateway key is exchanged here for a capability token (T7)

	// sealed BYOK (operator-blind): a per-boot X25519 keypair generated INSIDE
	// the enclave (RAM only, never persisted, operator never sees the private
	// half). Its public half is served at /sealing, SIGNED by the attested
	// identity key, so the key owner can encrypt their upstream key to exactly
	// this measured enclave. Ciphertext is submitted at runtime to /byok and the
	// plaintext lives only in RAM. On reboot the keypair changes → re-seal.
	sealPriv *ecdh.PrivateKey
	sealPub  []byte
	byokMu   sync.Mutex
	byok     map[string]string // accountID -> plaintext upstream key (RAM only)
}

func main() {
	home := os.Getenv("FID_HOME")
	if home == "" {
		home = "config"
	}
	// PUBLIC config (safe in the image): CP pubkey + expected measurement. Prefer
	// public.json (no secrets); fall back to keys.json for local/control-plane dev.
	var cpPubBytes []byte
	var expectedMeasurement string
	var kmsMaster []byte
	if b, err := os.ReadFile(filepath.Join(home, "public.json")); err == nil {
		var pc config.PublicConfig
		if err := json.Unmarshal(b, &pc); err != nil {
			log.Fatalf("fid-proxy: parse public.json: %v", err)
		}
		cpPubBytes = pc.CPPub
		expectedMeasurement = pc.ExpectedMeasurement
	} else {
		var keys config.Keys
		readJSON(filepath.Join(home, "keys.json"), &keys)
		cpPubBytes, expectedMeasurement, kmsMaster = keys.CPPub, keys.ExpectedMeasurement, keys.KMSMaster
	}

	// Identity private key — NEVER baked into the image. Injected at boot via
	// FID_IDENTITY_SEED (tee-env now; attestation-gated Secret Manager next =
	// operator-blind). Falls back to keys.json (local dev) or ephemeral.
	tamper := os.Getenv("FIDPROXY_TAMPER") == "1"
	var idPriv ed25519.PrivateKey
	if s := strings.TrimSpace(os.Getenv("FID_IDENTITY_SEED")); s != "" {
		seed, err := hex.DecodeString(s)
		if err != nil || len(seed) != ed25519.SeedSize {
			log.Fatalf("fid-proxy: FID_IDENTITY_SEED must be %d-byte hex", ed25519.SeedSize)
		}
		idPriv = ed25519.NewKeyFromSeed(seed)
	} else if b, err := os.ReadFile(filepath.Join(home, "keys.json")); err == nil {
		var keys config.Keys
		_ = json.Unmarshal(b, &keys)
		idPriv = ed25519.NewKeyFromSeed(keys.IdentitySeed)
	} else {
		_, idPriv, _ = ed25519.GenerateKey(rand.Reader)
		log.Printf("[fid-proxy] WARNING: ephemeral identity key (no FID_IDENTITY_SEED / keys.json)")
	}
	var at tee.Attester
	switch os.Getenv("FIDPROXY_ATTESTER") {
	case "tdx-configfs":
		t, err := tee.NewTdxConfigfs(idPriv)
		if err != nil {
			log.Fatalf("[fid-proxy] TDX attester init failed (need root + TDX guest): %v", err)
		}
		at = t
	case "gcp-cs": // GCP Confidential Space: measurement = container image_digest
		c, err := tee.NewConfidentialSpace(idPriv, envOr("FID_CS_AUDIENCE", "fidrouter"), os.Getenv("FID_CS_ENDPOINT"))
		if err != nil {
			log.Fatalf("[fid-proxy] Confidential Space attester init failed (must run inside CS): %v", err)
		}
		at = c
	default:
		at = tee.NewMock(config.ProxyVersion, idPriv, tamper)
	}
	if os.Getenv("FIDPROXY_MEASURE") == "1" { // print measurement (MRTD for TDX) and exit
		fmt.Println(at.Measurement())
		return
	}

	var km kms.KeyProvider
	pools := map[string][]*routing.Account{}
	if pt := os.Getenv("FIDPROXY_POOL_PLAINTEXT"); pt != "" {
		// demo mode: plaintext managed-key pool (decoupled from KMS/measurement sealing)
		var pp config.PlainPools
		readJSON(pt, &pp)
		for id, accts := range pp.Pools {
			for _, a := range accts {
				// A key of "env:NAME" is resolved from the environment at boot, so
				// the real BYOK key stays OUT of the image (registry) and OUT of git;
				// only a placeholder is baked in. The key is injected at VM launch via
				// Confidential Space `tee-env-NAME` metadata. The measured image_digest
				// is therefore independent of the key value.
				key := a.Key
				if strings.HasPrefix(key, "env:") {
					key = os.Getenv(strings.TrimPrefix(key, "env:"))
				}
				// "sealed-runtime": operator-blind BYOK. No key in config/image/env;
				// the key owner seals it to /sealing and submits ciphertext to /byok
				// at runtime. Sealed stays empty → resolveKey() reads the RAM store.
				if key == "sealed-runtime" {
					key = ""
				}
				pools[id] = append(pools[id], &routing.Account{
					ID: a.ID, Provider: a.Provider, BaseURL: a.BaseURL, Sealed: []byte(key), TPMBudget: a.TPMBudget,
				})
			}
		}
		km = kms.Passthrough{}
	} else {
		var pool config.SealedPools
		readJSON(filepath.Join(home, "pool.sealed.json"), &pool)
		km = kms.NewMock(kmsMaster, expectedMeasurement)
		for id, accts := range pool.Pools {
			for _, a := range accts {
				pools[id] = append(pools[id], &routing.Account{
					ID: a.ID, Provider: a.Provider, BaseURL: a.BaseURL, Sealed: a.Sealed, TPMBudget: a.TPMBudget,
				})
			}
		}
	}

	salt := make([]byte, 16)
	_, _ = rand.Read(salt)

	// per-boot sealing keypair (RAM only) for operator-blind BYOK
	sealPriv, err := enc.NewX25519()
	if err != nil {
		log.Fatalf("fid-proxy: sealing key: %v", err)
	}

	s := &server{
		at: at, km: km, rt: routing.New(salt, pools),
		cpPub:        ed25519.PublicKey(cpPubBytes),
		upstream:     envOr("UPSTREAM_URL", "http://127.0.0.1:9101/call"),
		http:         &http.Client{Timeout: 120 * time.Second}, // real Claude turns can run tens of seconds
		sealPriv:     sealPriv,
		sealPub:      sealPriv.PublicKey().Bytes(),
		byok:         map[string]string{},
		meteringURL:  os.Getenv("FIDPROXY_METERING_URL"),
		verifyURL:    os.Getenv("FIDPROXY_VERIFY_URL"),
		cpAdapterURL: os.Getenv("FIDPROXY_CP_ADAPTER_URL"),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/attestation", s.handleAttest)
	mux.HandleFunc("/sealing", s.handleSealing)                     // operator-blind BYOK: signed sealing pubkey
	mux.HandleFunc("/byok", s.handleByok)                           // submit a runtime-sealed upstream key
	mux.HandleFunc("/v1/infer", s.handleInfer)                      // sealed/attested path (verify SDK)
	mux.HandleFunc("/v1/chat/completions", s.handleChatCompletions) // OpenAI-compatible drop-in
	mux.HandleFunc("/v1/models", s.handleModels)
	mux.HandleFunc("/tls-csr", s.handleTLSCSR)   // T9: CSR for the attested in-enclave TLS key
	mux.HandleFunc("/tls-cert", s.handleTLSCert) // T9: install a CA-signed chain for that key

	// One managed enclave serves many relay operators, so a raw gateway key alone is not
	// enough to tell WHOSE gateway should validate it. Callers of a shared enclave therefore
	// address it as `/r/<relay-id>/v1/...`; the id is carried to the exchange so the control
	// plane knows which operator's gateway to check the key against. The id is a routing
	// label, not a secret and not authority: the key still has to validate, and the enclave
	// still verifies the returned capability token offline against its baked CP key.
	http.Handle("/r/", relayRouter(mux))
	http.Handle("/", mux)

	addr := envOr("FIDPROXY_ADDR", ":9090")

	// RA-TLS (opt-in via FIDPROXY_TLS=1): generate a per-boot TLS cert inside the
	// enclave, bind its public key into the attestation, and terminate TLS here —
	// so a stock HTTPS client that pins the measurement is talking to the attested
	// build. Default stays plain HTTP until the verifier learns the binding (T5).
	if os.Getenv("FIDPROXY_TLS") == "1" {
		hosts := strings.Split(envOr("FIDPROXY_TLS_HOSTS", "enclave.fidcore.xyz"), ",")
		// T9: with FIDPROXY_TLS_KEY_MODE=identity the TLS key is derived from the identity
		// seed, so it is STABLE across restarts and a publicly-trusted certificate issued
		// over it stays valid — per-boot keys would need a fresh ACME issuance on every
		// restart, which the rate limits don't allow. Default stays per-boot (a leaked TLS
		// key is useless after a restart); the key never leaves the enclave either way.
		var seed []byte
		if os.Getenv("FIDPROXY_TLS_KEY_MODE") == "identity" {
			if len(idPriv) == 0 {
				log.Fatalf("[fid-proxy] FIDPROXY_TLS_KEY_MODE=identity but no identity key available")
			}
			seed = idPriv.Seed() // domain-separated inside ratls; never the identity key itself
		}
		h, err := ratls.New(hosts, seed)
		if err != nil {
			log.Fatalf("[fid-proxy] ra-tls cert: %v", err)
		}
		tlsHolder = h
		at.SetTLSPub(h.SPKI())
		log.Printf("[fid-proxy] RA-TLS on: TLS pubkey (%d-byte SPKI) bound into attestation; key=%s platform=%s measurement=%s addr=%s",
			len(h.SPKI()), map[bool]string{true: "identity-derived", false: "per-boot"}[len(seed) > 0],
			at.Platform(), at.Measurement(), addr)
		srv := &http.Server{Addr: addr, TLSConfig: &tls.Config{
			GetCertificate: h.GetCertificate, MinVersion: tls.VersionTLS12}}
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}

	log.Printf("[fid-proxy] platform=%s measurement=%s tamper=%v addr=%s",
		at.Platform(), at.Measurement(), tamper, addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	verifyLink := ""
	if s.verifyURL != "" {
		verifyLink = fmt.Sprintf(`<p><a href="%s" style="color:#0d9488;font-weight:600">→ Verify this endpoint independently</a>
(checks the measurement below against the published open-source build, and fail-closes on mismatch).</p>`, s.verifyURL)
	}
	// This root page exists so a human who lands on the raw endpoint understands
	// what it is and where to go to VERIFY it — the machine-facing work happens at
	// /attestation. Humans should use the verify page (verifyLink); apps should use
	// the SDK. It is intentionally minimal: the enclave's job is to serve the API and
	// prove itself, not to host a UI.
	fmt.Fprintf(w, `<!doctype html><meta charset=utf-8><title>fidrouter data plane</title>
<body style="font-family:system-ui;max-width:660px;margin:56px auto;line-height:1.6;color:#0e1621;padding:0 18px">
<h2>fidrouter · verified no-log data plane</h2>
<p>This is the <b>API endpoint</b> that actually relays your prompts — the only
component that ever sees plaintext, and only in RAM. It runs inside a verified TEE
(<code>%s</code>) and is <b>operator-blind</b>: even we can't read your traffic or
extract your upstream key.</p>
<p>measurement: <code style="font-size:12px">%s</code></p>
%s
<p style="color:#5b6b7a;font-size:14px">Endpoints:</p>
<ul style="font-size:14px">
<li><code>GET  /attestation?nonce=…</code> — remote-attestation quote (bind a channel key)</li>
<li><code>GET  /sealing</code> — signed sealing pubkey (seal your upstream key to this enclave)</li>
<li><code>POST /byok</code> — submit a runtime-sealed upstream key (operator-blind BYOK)</li>
<li><code>POST /v1/infer</code> — sealed inference (native, E2EE)</li>
<li><code>POST /v1/chat/completions</code> — OpenAI-compatible; returns an <code>X-Fid-Receipt</code></li>
<li><code>GET  /v1/models</code></li>
</ul>
<p style="color:#5b6b7a;font-size:13px">Don't trust — verify. The SDK checks this
measurement against the published build and fail-closes on mismatch.</p>
</body>`, s.at.Platform(), s.at.Measurement(), verifyLink)
}

func (s *server) handleAttest(w http.ResponseWriter, r *http.Request) {
	nonce := []byte(r.URL.Query().Get("nonce"))
	if len(nonce) == 0 {
		http.Error(w, "nonce required", 400)
		return
	}
	q, err := s.at.Attest(nonce)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, q)
}

func (s *server) handleInfer(w http.ResponseWriter, r *http.Request) {
	var in wire.InferReq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	// 1) capability token (control plane authz) — enclave never touches user DB.
	//    T7: in.Token may be a raw gateway key; resolveCapability exchanges it in-enclave.
	claims, err := s.authClaims(in.Token, relayOf(r))
	if err != nil {
		http.Error(w, "unauthorized: "+err.Error(), 401)
		return
	}

	// 2) open the E2EE channel and decrypt the prompt IN RAM.
	key, err := s.at.SessionKey(in.Session, in.ClientPub)
	if err != nil {
		http.Error(w, "session: "+err.Error(), 400)
		return
	}
	plain, err := enc.Open(key, in.Sealed, []byte(in.Session))
	if err != nil {
		http.Error(w, "decrypt failed", 400)
		return
	}
	var p wire.InnerPrompt
	if err := json.Unmarshal(plain, &p); err != nil {
		http.Error(w, "bad prompt", 400)
		return
	}

	// 3) authorize model.
	if !claims.AllowsModel(p.Model) {
		http.Error(w, "model not allowed for tenant", 403)
		return
	}

	// 4) affinity route (fingerprint computed here, in-enclave; only the hash is used).
	needTok := len(p.Prefix)/4 + len(p.Suffix)/4
	fp := s.rt.Fingerprint(p.Model, p.Prefix, claims.Tenant, claims.Isolated)
	acct, affinity, ok := s.rt.Pick(claims.Pool, fp, needTok)
	if !ok {
		http.Error(w, "no upstream account in pool "+claims.Pool, 502)
		return
	}

	// 5) attestation-gated key release (fails if measurement != expected).
	upKey, err := s.resolveKey(acct)
	if err != nil {
		http.Error(w, "kms: "+err.Error(), 502)
		return
	}

	// 6) forward to upstream.
	msgs := []chatMsg{}
	if p.Prefix != "" {
		msgs = append(msgs, chatMsg{Role: "system", Content: p.Prefix})
	}
	msgs = append(msgs, chatMsg{Role: "user", Content: p.Suffix})
	ur, err := s.forward(acct.BaseURL, string(upKey), acct.Provider, upstreamReq{Model: p.Model, Messages: msgs})
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), 502)
		return
	}
	respBody, _ := json.Marshal(ur)

	// 7) signed receipt — hashes + counts only, NO content.
	rec := receipt.Receipt{
		TsUnix: time.Now().Unix(), Tenant: claims.Tenant, Model: p.Model, Account: acct.ID,
		ReqHash: receipt.Hash(plain), RespHash: receipt.Hash(respBody),
		PromptTok: ur.PromptTokens, CompletionTok: ur.CompletionTokens,
		CacheHit: ur.CacheHit, Measurement: s.at.Measurement(),
	}
	signed, _ := receipt.Sign(rec, s.at.Sign)
	s.emitMetering(signed)

	// 8) seal response back to the client (E2EE both ways).
	sealedResp, _ := enc.Seal(key, respBody, []byte(in.Session))
	writeJSON(w, wire.InferResp{
		SealedResp: sealedResp, Receipt: signed,
		Route: wire.RouteInfo{Account: acct.ID, Affinity: affinity, CacheHit: ur.CacheHit},
	})

	// 9) NO-LOG: metadata only. Never p.Prefix / p.Suffix / ur.Completion.
	log.Printf("[infer] tenant=%s pool=%s model=%s -> account=%s affinity=%v cache_hit=%v ptok=%d ctok=%d",
		claims.Tenant, claims.Pool, p.Model, acct.ID, affinity, ur.CacheHit, ur.PromptTokens, ur.CompletionTokens)
}

// allowedUpstreamHosts is part of the MEASURED code: the enclave will only ever
// forward to these real first-party provider endpoints, never to an arbitrary
// (possibly logging) middleman. Because this list is in the open-source, measured
// binary, "the upstream is really Anthropic/OpenAI, not another relay" is provable
// from the measurement + TLS, not merely promised. Adding a provider is a reviewed
// code change → new measurement → re-audit.
var allowedUpstreamHosts = map[string]bool{
	"api.anthropic.com": true,
	"api.openai.com":    true,
}

// forward dispatches by provider: Anthropic Messages API, OpenAI-compatible
// /v1/chat/completions (BYOK / managed real key), else the mock upstream.
func (s *server) forward(baseURL, apiKey, provider string, r upstreamReq) (wire.UpstreamResp, error) {
	if baseURL != "" {
		u, err := url.Parse(baseURL)
		if err != nil || !allowedUpstreamHosts[u.Host] {
			return wire.UpstreamResp{}, fmt.Errorf("upstream host %q not in measured allow-list (real providers only)", func() string {
				if u != nil {
					return u.Host
				}
				return baseURL
			}())
		}
	}
	if provider == "anthropic" {
		return s.forwardAnthropic(baseURL, apiKey, r)
	}
	if baseURL != "" {
		return s.forwardOpenAI(baseURL, apiKey, r)
	}
	// mock upstream still speaks the prefix/suffix shape: system->prefix, last turn->suffix.
	var prefix, suffix string
	for _, m := range r.Messages {
		if m.Role == "system" {
			prefix += m.Content
		} else {
			suffix = m.Content
		}
	}
	body, _ := json.Marshal(map[string]string{"model": r.Model, "prefix": prefix, "suffix": suffix})
	req, _ := http.NewRequest("POST", s.upstream, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiKey)
	resp, err := s.http.Do(req)
	if err != nil {
		return wire.UpstreamResp{}, err
	}
	defer resp.Body.Close()
	var out wire.UpstreamResp
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &out); err != nil {
		return wire.UpstreamResp{}, err
	}
	return out, nil
}

// forwardOpenAI calls a real OpenAI-compatible /v1/chat/completions endpoint
// (OpenAI, New API, most gateways). prefix->system, suffix->user.
func (s *server) forwardOpenAI(baseURL, apiKey string, r upstreamReq) (wire.UpstreamResp, error) {
	reqBody, _ := json.Marshal(map[string]any{"model": r.Model, "messages": r.Messages})
	req, _ := http.NewRequest("POST", strings.TrimRight(baseURL, "/")+"/v1/chat/completions", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := s.http.Do(req)
	if err != nil {
		return wire.UpstreamResp{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return wire.UpstreamResp{}, fmt.Errorf("upstream %d: %s", resp.StatusCode, string(b[:min(len(b), 200)]))
	}
	var oa struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens        int `json:"prompt_tokens"`
			CompletionTokens    int `json:"completion_tokens"`
			PromptTokensDetails struct {
				CachedTokens int `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(b, &oa); err != nil {
		return wire.UpstreamResp{}, err
	}
	content := ""
	if len(oa.Choices) > 0 {
		content = oa.Choices[0].Message.Content
	}
	return wire.UpstreamResp{
		Completion: content, CacheHit: oa.Usage.PromptTokensDetails.CachedTokens > 0,
		PromptTokens: oa.Usage.PromptTokens, CompletionTokens: oa.Usage.CompletionTokens,
	}, nil
}

// forwardAnthropic calls the native Anthropic Messages API (/v1/messages,
// x-api-key auth). This is the TEE-pure BYOK path for Claude: prompts flow only
// from this measured enclave straight to api.anthropic.com — never through the
// (unmeasured) control plane. prefix->system (top-level), suffix->user message.
func (s *server) forwardAnthropic(baseURL, apiKey string, r upstreamReq) (wire.UpstreamResp, error) {
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}
	var system string
	msgs := make([]map[string]string, 0, len(r.Messages))
	for _, m := range r.Messages {
		if m.Role == "system" { // Anthropic carries the system prompt top-level, not as a message
			if system != "" {
				system += "\n\n"
			}
			system += m.Content
			continue
		}
		role := m.Role
		if role != "assistant" {
			role = "user"
		}
		msgs = append(msgs, map[string]string{"role": role, "content": m.Content})
	}
	if len(msgs) == 0 {
		msgs = append(msgs, map[string]string{"role": "user", "content": ""})
	}
	body := map[string]any{"model": r.Model, "max_tokens": 4096, "messages": msgs}
	if system != "" {
		body["system"] = system
	}
	reqBody, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", strings.TrimRight(baseURL, "/")+"/v1/messages", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := s.http.Do(req)
	if err != nil {
		return wire.UpstreamResp{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return wire.UpstreamResp{}, fmt.Errorf("upstream %d: %s", resp.StatusCode, string(b[:min(len(b), 300)]))
	}
	var an struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens          int `json:"input_tokens"`
			OutputTokens         int `json:"output_tokens"`
			CacheReadInputTokens int `json:"cache_read_input_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(b, &an); err != nil {
		return wire.UpstreamResp{}, err
	}
	content := ""
	for _, c := range an.Content {
		if c.Type == "text" {
			content += c.Text
		}
	}
	return wire.UpstreamResp{
		Completion: content, CacheHit: an.Usage.CacheReadInputTokens > 0,
		PromptTokens: an.Usage.InputTokens, CompletionTokens: an.Usage.OutputTokens,
	}, nil
}

// --- OpenAI-COMPATIBLE front (compatible mode) --------------------------------
// Any OpenAI client works with just base_url + the capability token as api_key:
//   OpenAI(base_url="http://<enclave>:9090/v1", api_key="<capability token>")
// This path is plaintext-over-TLS (no client attestation / E2EE) — the "easy"
// tier. Trust is delivered OUT OF BAND (public verification page + open source +
// the X-Fid-Measurement response header). For cryptographic proof use the sealed
// /v1/infer path via the verify SDK. Structural no-log holds on BOTH paths:
// nothing here writes a prompt or completion — only metadata.

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[len("Bearer "):])
	}
	return ""
}

type ctxKey string

const relayCtxKey ctxKey = "fid-relay-id"

// relayRouter strips a `/r/<relay-id>` prefix, remembers the id on the request context, and
// hands the rest to the normal routes — so `/r/abc/v1/chat/completions` behaves exactly like
// `/v1/chat/completions`, just with the operator identified for key exchange.
func relayRouter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/r/")
		id, tail, _ := strings.Cut(rest, "/")
		if id == "" || len(id) > 64 || strings.ContainsAny(id, "/?#") {
			http.Error(w, "bad relay id", 400)
			return
		}
		r2 := r.Clone(context.WithValue(r.Context(), relayCtxKey, id))
		r2.URL.Path = "/" + tail
		next.ServeHTTP(w, r2)
	})
}

func relayOf(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v, ok := r.Context().Value(relayCtxKey).(string); ok {
		return v
	}
	return ""
}

// resolveCapability (T7) turns a presented credential into a CP capability token. If it
// already verifies as one, it's used as-is; otherwise — a raw gateway key (e.g. "sk-...") —
// the enclave exchanges it via cp-adapter internally. This folds the exchange server-side so
// a stock client just sends base_url + its own key (safe because the key only lands in the
// enclave: over RA-TLS TLS terminates here, and on the /v1/infer path it arrives E2EE-sealed).
func (s *server) resolveCapability(cred, relayID string) (string, error) {
	cred = strings.TrimSpace(cred)
	if cred == "" {
		return "", fmt.Errorf("missing credential")
	}
	if _, err := token.Verify(s.cpPub, cred); err == nil {
		return cred, nil // already a capability token
	}
	if s.cpAdapterURL == "" {
		return "", fmt.Errorf("not a capability token and no cp-adapter configured for exchange")
	}
	exReq := map[string]string{"key": cred}
	if relayID != "" {
		exReq["relay_id"] = relayID // which operator's gateway should validate this key
	}
	body, _ := json.Marshal(exReq)
	resp, err := s.http.Post(strings.TrimRight(s.cpAdapterURL, "/")+"/exchange", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("cp-adapter exchange: %s %s", resp.Status, string(b[:min(len(b), 160)]))
	}
	var ex struct {
		CapabilityToken string `json:"capability_token"`
	}
	if err := json.Unmarshal(b, &ex); err != nil || ex.CapabilityToken == "" {
		return "", fmt.Errorf("cp-adapter returned no capability_token")
	}
	return ex.CapabilityToken, nil
}

// authClaims resolves a credential (capability token OR raw gateway key) and verifies it.
func (s *server) authClaims(cred, relayID string) (token.Claims, error) {
	tok, err := s.resolveCapability(cred, relayID)
	if err != nil {
		return token.Claims{}, err
	}
	return token.Verify(s.cpPub, tok)
}

// handleTLSCSR (T9) returns a CSR for the enclave's attested TLS key so an ACME client
// running OUTSIDE can obtain a publicly-trusted certificate for it. Public information: a
// CSR reveals the public key (already in the attestation) and proves key possession.
func (s *server) handleTLSCSR(w http.ResponseWriter, r *http.Request) {
	if tlsHolder == nil {
		http.Error(w, "RA-TLS is not enabled on this enclave", 404)
		return
	}
	csr, err := tlsHolder.CSRPEM()
	if err != nil {
		http.Error(w, "csr: "+err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(csr)
}

// handleTLSCert (T9) installs an externally-issued certificate chain for the enclave's own
// TLS key, letting a stock HTTPS client validate via a public CA while a verifying client
// still checks the attestation binding. Safe by construction: InstallChain refuses any chain
// whose public key is not this enclave's attested key, so no one can install a certificate
// for a key they hold. A capability token is still required, to keep this operator-only.
func (s *server) handleTLSCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST a PEM chain", 405)
		return
	}
	if tlsHolder == nil {
		http.Error(w, "RA-TLS is not enabled on this enclave", 404)
		return
	}
	if _, err := s.authClaims(bearerToken(r), relayOf(r)); err != nil {
		http.Error(w, "unauthorized: "+err.Error(), 401)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read: "+err.Error(), 400)
		return
	}
	if err := tlsHolder.InstallChain(body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	log.Printf("[fid-proxy] T9: installed a CA-signed chain over the attested TLS key")
	writeJSON(w, map[string]any{"ok": true, "ca_signed": true})
}

func (s *server) handleModels(w http.ResponseWriter, r *http.Request) {
	claims, err := s.authClaims(bearerToken(r), relayOf(r))
	if err != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	data := make([]map[string]any, 0, len(claims.Models))
	for _, m := range claims.Models {
		data = append(data, map[string]any{"id": m, "object": "model", "owned_by": "fidrouter"})
	}
	writeJSON(w, map[string]any{"object": "list", "data": data})
}

func (s *server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	// T7: accepts a capability token OR a raw gateway key (exchanged in-enclave).
	claims, err := s.authClaims(bearerToken(r), relayOf(r))
	if err != nil {
		http.Error(w, "unauthorized: "+err.Error(), 401)
		return
	}
	var req struct {
		Model    string    `json:"model"`
		Messages []chatMsg `json:"messages"`
		Stream   bool      `json:"stream"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if req.Stream {
		http.Error(w, "streaming not supported yet on this endpoint; set stream=false", 400)
		return
	}
	if !claims.AllowsModel(req.Model) {
		http.Error(w, "model not allowed for tenant", 403)
		return
	}

	needTok := 0
	for _, m := range req.Messages {
		needTok += len(m.Content) / 4
	}
	// affinity fingerprint over the stable prefix (everything but the last turn),
	// computed here in-enclave; only the salted hash is used for routing.
	fp := s.rt.Fingerprint(req.Model, fpPrefix(req.Messages), claims.Tenant, claims.Isolated)
	acct, affinity, ok := s.rt.Pick(claims.Pool, fp, needTok)
	if !ok {
		http.Error(w, "no upstream account in pool "+claims.Pool, 502)
		return
	}
	upKey, err := s.resolveKey(acct)
	if err != nil {
		http.Error(w, "kms: "+err.Error(), 502)
		return
	}
	ur, err := s.forward(acct.BaseURL, string(upKey), acct.Provider, upstreamReq{Model: req.Model, Messages: req.Messages})
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), 502)
		return
	}

	idb := make([]byte, 12)
	_, _ = rand.Read(idb)
	// Signed receipt on the compatible path too — hashes + counts + model, NO
	// content. Any client can lodge it in the public explorer (transparency log)
	// to prove after the fact which measured build served it and that the model
	// wasn't silently downgraded. Emitted as a header so plain OpenAI clients get it.
	reqBytes, _ := json.Marshal(map[string]any{"model": req.Model, "messages": req.Messages})
	rec := receipt.Receipt{
		TsUnix: time.Now().Unix(), Tenant: claims.Tenant, Model: req.Model, Account: acct.ID,
		ReqHash: receipt.Hash(reqBytes), RespHash: receipt.Hash([]byte(ur.Completion)),
		PromptTok: ur.PromptTokens, CompletionTok: ur.CompletionTokens,
		CacheHit: ur.CacheHit, Measurement: s.at.Measurement(),
	}
	if signed, e := receipt.Sign(rec, s.at.Sign); e == nil {
		s.emitMetering(signed)
		if sb, e2 := json.Marshal(signed); e2 == nil {
			w.Header().Set("X-Fid-Receipt", base64.StdEncoding.EncodeToString(sb))
		}
	}
	// Trust signal even on the compatible path: which measured build served this.
	w.Header().Set("X-Fid-Measurement", s.at.Measurement())
	w.Header().Set("X-Fid-Account", acct.ID)
	w.Header().Set("X-Fid-Affinity", fmt.Sprintf("%v", affinity))
	w.Header().Set("X-Fid-Cache-Hit", fmt.Sprintf("%v", ur.CacheHit))
	writeJSON(w, map[string]any{
		"id":      "chatcmpl-" + hex.EncodeToString(idb),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   req.Model,
		"choices": []map[string]any{{
			"index":         0,
			"message":       map[string]string{"role": "assistant", "content": ur.Completion},
			"finish_reason": "stop",
		}},
		"usage": map[string]int{
			"prompt_tokens":     ur.PromptTokens,
			"completion_tokens": ur.CompletionTokens,
			"total_tokens":      ur.PromptTokens + ur.CompletionTokens,
		},
		"system_fingerprint": "fid:" + shortMeas(s.at.Measurement()),
	})

	// NO-LOG: metadata only. Never req.Messages / ur.Completion.
	log.Printf("[chat] tenant=%s pool=%s model=%s -> account=%s affinity=%v cache_hit=%v ptok=%d ctok=%d",
		claims.Tenant, claims.Pool, req.Model, acct.ID, affinity, ur.CacheHit, ur.PromptTokens, ur.CompletionTokens)
}

func fpPrefix(msgs []chatMsg) string {
	if len(msgs) <= 1 {
		return ""
	}
	var b strings.Builder
	for _, m := range msgs[:len(msgs)-1] {
		b.WriteString(m.Role)
		b.WriteString(":")
		b.WriteString(m.Content)
		b.WriteString("\n")
	}
	return b.String()
}

func shortMeas(s string) string {
	s = strings.TrimPrefix(s, "sha256:")
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// --- operator-blind sealed BYOK -----------------------------------------------

// resolveKey returns the upstream key for an account: from KMS/passthrough
// unseal, or — for "sealed-runtime" accounts (empty Sealed) — from the RAM BYOK
// store populated by /byok. The operator never has the plaintext.
func (s *server) resolveKey(acct *routing.Account) ([]byte, error) {
	k, err := s.km.Unseal(acct.Sealed, s.at.Measurement())
	if err != nil {
		return nil, err
	}
	if len(k) == 0 {
		s.byokMu.Lock()
		v := s.byok[acct.ID]
		s.byokMu.Unlock()
		if v == "" {
			return nil, fmt.Errorf("account %q has no upstream key yet — seal one to /sealing then POST /byok", acct.ID)
		}
		return []byte(v), nil
	}
	return k, nil
}

// handleSealing publishes the per-boot sealing public key, SIGNED by the attested
// identity key. Chain of trust: /attestation proves measurement + identity pub;
// this sig proves the sealing pub belongs to that same measured enclave. The key
// owner encrypts their upstream key to sealing_pub → only this enclave can open it.
func (s *server) handleSealing(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"sealing_pub":  base64.StdEncoding.EncodeToString(s.sealPub),
		"sig":          base64.StdEncoding.EncodeToString(s.at.Sign(s.sealPub)), // Sign(identity, sealing_pub)
		"identity_pub": base64.StdEncoding.EncodeToString(s.at.IdentityPub()),
		"measurement":  s.at.Measurement(),
		"info":         "fid-byok-v1",
	})
}

// handleByok accepts a runtime-sealed upstream key (ciphertext sealed to sealing_pub)
// and holds the plaintext in RAM only. Requires a CP-signed capability token as
// authority. On reboot the sealing key changes, so this must be re-submitted.
func (s *server) handleByok(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token   string `json:"token"`
		Account string `json:"account"`
		Sealed  string `json:"sealed"` // base64 of (client_eph_pub[32] || AES-GCM ciphertext)
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if _, err := token.Verify(s.cpPub, in.Token); err != nil {
		http.Error(w, "unauthorized: "+err.Error(), 401)
		return
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(in.Sealed, "sealed:"))
	if err != nil || len(blob) < 33 {
		http.Error(w, "bad sealed blob", 400)
		return
	}
	pt, err := s.unsealBYOK(blob)
	if err != nil {
		http.Error(w, "unseal failed (sealed to a different enclave/boot? re-fetch /sealing and re-seal): "+err.Error(), 400)
		return
	}
	s.byokMu.Lock()
	s.byok[in.Account] = string(pt)
	s.byokMu.Unlock()
	writeJSON(w, map[string]any{"ok": true, "account": in.Account})
	log.Printf("[byok] provisioned account=%s (%d bytes, RAM only)", in.Account, len(pt))
}

func (s *server) unsealBYOK(blob []byte) ([]byte, error) {
	key, err := enc.SharedKey(s.sealPriv, blob[:32], "fid-byok-v1")
	if err != nil {
		return nil, err
	}
	return enc.Open(key, blob[32:], []byte("fid-byok-v1"))
}

// emitMetering pushes the SIGNED receipt (metadata only — tenant/model/token
// counts, NO prompt/response content) to the configured metering webhook so the
// partner's control plane can attribute usage per user and bill. The receipt is
// Ed25519-signed by the enclave, so the recipient can verify it's genuine and
// unforgeable. Best-effort, async — never blocks or logs content.
func (s *server) emitMetering(signed receipt.Signed) {
	if s.meteringURL == "" {
		return
	}
	go func() {
		b, err := json.Marshal(signed)
		if err != nil {
			return
		}
		body, _ := json.Marshal(map[string]string{"receipt": base64.StdEncoding.EncodeToString(b)})
		req, err := http.NewRequest("POST", s.meteringURL, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if resp, err := s.http.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func readJSON(path string, v any) {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("fid-proxy: read %s: %v", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		log.Fatalf("fid-proxy: parse %s: %v", path, err)
	}
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
