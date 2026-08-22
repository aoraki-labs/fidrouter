// Package routing implements cache-affinity routing.
//
// Topology (per the corrected model): downstream TENANTS (customers) map to an
// upstream ACCOUNT POOL. A pool may be shared by many tenants or dedicated to
// one. Upstream accounts are INDEPENDENT keys — each provider account has its
// OWN prompt cache — so to get a cache hit we must send the same cacheable
// prefix back to the same account. That is what affinity does.
//
// Mechanism: consistent-hash ranking of accounts by H(salt || scope || fp),
// pick the top account that still has rate-limit budget; if it is saturated,
// spill to the next (accepting a cache miss, never blocking). Cache is a
// best-effort optimization, not correctness.
package routing

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"sync"
)

type Account struct {
	ID        string
	Provider  string
	BaseURL   string // real upstream endpoint (empty => mock)
	Sealed    []byte // sealed upstream key (opened via kms just-in-time)
	TPMBudget int    // tokens-per-window budget (0 = unlimited)
}

type Router struct {
	mu    sync.Mutex
	salt  []byte                // per-boot; makes fp non-reversible across boots
	pools map[string][]*Account // poolID -> accounts
	used  map[string]int        // accountID -> tokens used this window
}

func New(salt []byte, pools map[string][]*Account) *Router {
	return &Router{salt: salt, pools: pools, used: map[string]int{}}
}

// Fingerprint is computed INSIDE the enclave over the cacheable prefix. Only
// this non-reversible value (salted per boot) is used for routing; the prefix
// plaintext never leaves. Isolated tenants get the tenant folded in so their
// requests never share an account slot decision with others (kills the
// cross-tenant cache-timing side channel on shared pools).
func (r *Router) Fingerprint(model, canonicalPrefix, tenant string, isolated bool) string {
	h := sha256.New()
	h.Write(r.salt)
	h.Write([]byte(model))
	if isolated {
		h.Write([]byte("tenant:" + tenant + "|"))
	}
	h.Write([]byte(canonicalPrefix))
	return string(h.Sum(nil))
}

// Pick returns the affinity account for (pool, fp), honoring rate-limit budget.
// affinity=true means we got the preferred (cache-warm) account; false means we
// had to spill (expect a cache miss).
func (r *Router) Pick(pool, fp string, needTok int) (acct *Account, affinity bool, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	accts := r.pools[pool]
	if len(accts) == 0 {
		return nil, false, false
	}

	// Rank deterministically by H(fp || accountID) — consistent hashing.
	ranked := make([]*Account, len(accts))
	copy(ranked, accts)
	sort.Slice(ranked, func(i, j int) bool {
		return score(fp, ranked[i].ID) < score(fp, ranked[j].ID)
	})

	for idx, a := range ranked {
		if a.TPMBudget == 0 || r.used[a.ID]+needTok <= a.TPMBudget {
			r.used[a.ID] += needTok
			return a, idx == 0, true
		}
	}
	// Everyone saturated: least-used, accept miss.
	least := ranked[0]
	for _, a := range ranked[1:] {
		if r.used[a.ID] < r.used[least.ID] {
			least = a
		}
	}
	r.used[least.ID] += needTok
	return least, false, true
}

func score(fp, id string) uint64 {
	h := sha256.Sum256(append([]byte(fp), id...))
	return binary.BigEndian.Uint64(h[:8])
}
