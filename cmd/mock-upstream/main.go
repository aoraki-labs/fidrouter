// mock-upstream simulates a CLOSED provider (OpenAI/Anthropic). The point it
// demonstrates: prompt cache is scoped PER UPSTREAM ACCOUNT (per API key). Two
// different keys have two different caches — which is exactly why the relay
// must do affinity routing to land cache hits. It reports cache_hit so the demo
// can show affinity working.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
)

type req struct {
	Model  string `json:"model"`
	Prefix string `json:"prefix"` // the cacheable prefix (system prompt + stable context)
	Suffix string `json:"suffix"` // the variable tail
}

type resp struct {
	Completion       string `json:"completion"`
	CacheHit         bool   `json:"cache_hit"`
	PromptTokens     int    `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens"`
}

func main() {
	addr := ":9101"
	if v := os.Getenv("UPSTREAM_ADDR"); v != "" {
		addr = v
	}
	var mu sync.Mutex
	warm := map[string]bool{} // key = apiKey|model|H(prefix)

	http.HandleFunc("/call", func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("Authorization")
		var in req
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		h := sha256.Sum256([]byte(in.Prefix))
		ck := apiKey + "|" + in.Model + "|" + fmt.Sprintf("%x", h[:8])

		mu.Lock()
		hit := warm[ck]
		warm[ck] = true
		mu.Unlock()

		out := resp{
			Completion:       "echo(" + in.Suffix + ")",
			CacheHit:         hit,
			PromptTokens:     len(in.Prefix)/4 + len(in.Suffix)/4,
			CompletionTokens: 8,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	fmt.Println("[mock-upstream] listening", addr)
	_ = http.ListenAndServe(addr, nil)
}
