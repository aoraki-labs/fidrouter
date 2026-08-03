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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fidrouter/internal/config"
	"fidrouter/internal/enc"
	"fidrouter/internal/kms"
	"fidrouter/internal/receipt"
	"fidrouter/internal/routing"
	"fidrouter/internal/tee"
	"fidrouter/internal/token"
	"fidrouter/internal/wire"
)

type chatMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type upstreamReq struct {
	Model    string
	Messages []chatMsg
}

type server struct {
	at        tee.Attester
	km        kms.KeyProvider
	rt        *routing.Router
	cpPub     ed25519.PublicKey
	upstream  string
	http      *http.Client
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
		c, err := tee.NewConfidentialSpace(idPriv, envOr("FID_CS_AUDIENCE", "fid-router"), os.Getenv("FID_CS_ENDPOINT"))
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

	s := &server{
		at: at, km: km, rt: routing.New(salt, pools),
		cpPub:    ed25519.PublicKey(cpPubBytes),
		upstream: envOr("UPSTREAM_URL", "http://127.0.0.1:9101/call"),
		http:     &http.Client{Timeout: 120 * time.Second}, // real Claude turns can run tens of seconds
	}

	http.HandleFunc("/", s.handleRoot)
	http.HandleFunc("/attestation", s.handleAttest)
	http.HandleFunc("/v1/infer", s.handleInfer)                     // sealed/attested path (verify SDK)
	http.HandleFunc("/v1/chat/completions", s.handleChatCompletions) // OpenAI-compatible drop-in
	http.HandleFunc("/v1/models", s.handleModels)

	addr := envOr("FIDPROXY_ADDR", ":9090")
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
	fmt.Fprintf(w, `<!doctype html><meta charset=utf-8><title>fid-router data plane</title>
<body style="font-family:system-ui;max-width:640px;margin:60px auto;line-height:1.6;color:#0e1621">
<h2>fid-router · verified no-log data plane</h2>
<p>This is an <b>API endpoint</b>, not a web app. It runs inside a verified TEE
(<code>%s</code>).</p>
<p>measurement: <code style="font-size:12px">%s</code></p>
<ul>
<li><code>GET /attestation?nonce=…</code> — remote-attestation quote</li>
<li><code>POST /v1/infer</code> — sealed inference (use the verify SDK)</li>
</ul>
<p style="color:#5b6b7a">Verify before you trust: the client SDK checks this
measurement against the published build and fail-closes on mismatch.</p>
</body>`, s.at.Platform(), s.at.Measurement())
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
	claims, err := token.Verify(s.cpPub, in.Token)
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
	upKey, err := s.km.Unseal(acct.Sealed, s.at.Measurement())
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

// forward dispatches by provider: Anthropic Messages API, OpenAI-compatible
// /v1/chat/completions (BYOK / managed real key), else the mock upstream.
func (s *server) forward(baseURL, apiKey, provider string, r upstreamReq) (wire.UpstreamResp, error) {
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

func (s *server) handleModels(w http.ResponseWriter, r *http.Request) {
	claims, err := token.Verify(s.cpPub, bearerToken(r))
	if err != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	data := make([]map[string]any, 0, len(claims.Models))
	for _, m := range claims.Models {
		data = append(data, map[string]any{"id": m, "object": "model", "owned_by": "fid-router"})
	}
	writeJSON(w, map[string]any{"object": "list", "data": data})
}

func (s *server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	claims, err := token.Verify(s.cpPub, bearerToken(r))
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
	upKey, err := s.km.Unseal(acct.Sealed, s.at.Measurement())
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
