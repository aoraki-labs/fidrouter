// Package wire holds the request/response shapes shared by the proxy and client
// so they can never drift apart.
package wire

import "fidrouter/internal/receipt"

type InferReq struct {
	Session   string `json:"session"`
	ClientPub []byte `json:"client_pub"`
	Token     string `json:"token"`
	Sealed    []byte `json:"sealed"` // enc.Seal(key, InnerPrompt, aad=session)
}

type InnerPrompt struct {
	Model  string `json:"model"`
	Prefix string `json:"prefix"` // cacheable prefix
	Suffix string `json:"suffix"` // variable tail
}

type InferResp struct {
	SealedResp []byte         `json:"sealed_resp"`
	Receipt    receipt.Signed `json:"receipt"`
	Route      RouteInfo      `json:"route"`
}

type RouteInfo struct {
	Account  string `json:"account"`
	Affinity bool   `json:"affinity"`
	CacheHit bool   `json:"cache_hit"`
}

type UpstreamResp struct {
	Completion       string `json:"completion"`
	CacheHit         bool   `json:"cache_hit"`
	PromptTokens     int    `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens"`
}
