package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The relay prefix must be transparent to the routes behind it (so a Tier-0 user just sets
// base_url and changes nothing else) while making the operator id available for key exchange.
func TestRelayRouter(t *testing.T) {
	var gotPath, gotRelay string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotRelay = r.URL.Path, relayOf(r)
	})
	h := relayRouter(inner)

	for _, tc := range []struct{ url, wantPath, wantRelay string }{
		{"/r/r_ab12/v1/chat/completions", "/v1/chat/completions", "r_ab12"},
		{"/r/r_ab12/v1/models", "/v1/models", "r_ab12"},
		{"/r/solo", "/", "solo"}, // no tail
	} {
		gotPath, gotRelay = "", ""
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", tc.url, nil))
		if gotPath != tc.wantPath || gotRelay != tc.wantRelay {
			t.Fatalf("%s -> path=%q relay=%q; want path=%q relay=%q",
				tc.url, gotPath, gotRelay, tc.wantPath, tc.wantRelay)
		}
	}

	// A malformed id must be rejected outright rather than silently treated as "no relay",
	// which would send the key to the wrong (or default) gateway.
	for _, bad := range []string{"/r/", "/r//v1/models"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", bad, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s -> %d; want 400", bad, rec.Code)
		}
	}
}

// Without the prefix there must be no relay id at all — a shared enclave must not fall back
// to some default operator when the caller didn't name one.
func TestRelayAbsentByDefault(t *testing.T) {
	if got := relayOf(httptest.NewRequest("GET", "/v1/models", nil)); got != "" {
		t.Fatalf("relayOf = %q; want empty", got)
	}
	if got := relayOf(nil); got != "" {
		t.Fatalf("relayOf(nil) = %q; want empty", got)
	}
}
