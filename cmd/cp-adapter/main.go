// cp-adapter bridges an existing New API control plane to fid-router WITHOUT
// forking New API. A client presents its New API token; the adapter validates
// it against New API, then mints a fid-router capability JWT (signed by the CP
// key that fid-proxy pins) carrying the tenant, allowed models, pool and quota.
//
//	POST /exchange  {"api_token":"sk-...","pool":"shared"}  ->  {"token":"<capability JWT>"}
//
// Deploy anywhere that can reach New API (e.g. next to it on the AWS box, or a
// small VM). New API stays unchanged; this is the demo integration. (Production
// instead forks New API to mint the JWT + ciphertext channel keys + receipt
// billing directly.)
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"fidrouter/internal/config"
	"fidrouter/internal/token"
)

// New API on the AWS box uses a self-signed cert on an IP; skip verification for
// this control-plane call (the sensitive path — prompts — never goes here).
func insecureTransport() *http.Transport {
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
}

type exchangeReq struct {
	APIToken string `json:"api_token"`
	Pool     string `json:"pool"`
}

func main() {
	home := envOr("FID_HOME", "config")
	var keys config.Keys
	b, err := os.ReadFile(filepath.Join(home, "keys.json"))
	if err != nil {
		log.Fatalf("cp-adapter: read keys.json: %v", err)
	}
	if err := json.Unmarshal(b, &keys); err != nil {
		log.Fatal(err)
	}
	cpPriv := ed25519.NewKeyFromSeed(keys.CPSeed)

	newapi := envOr("NEWAPI_URL", "https://207.57.187.193")
	validatePath := envOr("NEWAPI_VALIDATE_PATH", "/v1/models")
	defaultPool := envOr("FID_DEFAULT_POOL", "shared")
	hc := &http.Client{Timeout: 15 * time.Second, Transport: insecureTransport()}

	http.HandleFunc("/exchange", func(w http.ResponseWriter, r *http.Request) {
		var in exchangeReq
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.APIToken == "" {
			http.Error(w, "api_token required", 400)
			return
		}
		// 1) validate the New API token + discover allowed models.
		models, ok := validate(hc, newapi+validatePath, in.APIToken)
		if !ok {
			http.Error(w, "invalid New API token", 401)
			return
		}
		// 2) mint a fid-router capability JWT. tenant = short hash of the token
		//    (stable per user, doesn't leak the token).
		h := sha256.Sum256([]byte(in.APIToken))
		pool := in.Pool
		if pool == "" {
			pool = defaultPool
		}
		tok, err := token.Mint(cpPriv, token.Claims{
			Tenant: "na-" + hex.EncodeToString(h[:6]), Pool: pool, Models: models,
			MaxTok: 1_000_000, Exp: time.Now().Unix() + 3600,
		})
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": tok})
	})

	addr := envOr("CP_ADAPTER_ADDR", ":9095")
	log.Printf("[cp-adapter] listening %s (New API=%s, validate=%s)", addr, newapi, validatePath)
	log.Fatal(http.ListenAndServe(addr, nil))
}

// validate calls New API's /v1/models with the token; 200 => valid, and we take
// the returned model ids as the allowlist (fallback ["*"] if unparsable).
func validate(hc *http.Client, url, apiToken string) ([]string, bool) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+apiToken)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, false
	}
	body, _ := io.ReadAll(resp.Body)
	var ml struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	models := []string{"*"}
	if json.Unmarshal(body, &ml) == nil && len(ml.Data) > 0 {
		models = models[:0]
		for _, m := range ml.Data {
			models = append(models, m.ID)
		}
	}
	return models, true
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
