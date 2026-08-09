# RA-TLS — attestation-bound TLS for the enclave

**Why.** Today the data plane serves plain HTTP on `:9090`; confidentiality comes from an
app-layer E2EE handshake to an attested ephemeral X25519 key (`internal/enc`, driven by
`cmd/client`). That guarantee only reaches clients that run *our* handshake — so a user with
a stock OpenAI client gets nothing. **RA-TLS binds the attestation to the TLS certificate**,
so a standard HTTPS client, once it pins the measurement (or trusts an attestation-CA), is
talking to the exact published, no-log build — no SDK swap. It also lets TLS terminate
*inside* the enclave, which lets us fold the key-exchange server-side (config collapses to
`base_url` + `api_key`). See `../platform/TRUST.md` for the product framing.

**Good news — the binding primitive already exists.** `internal/tee/confidential_space.go`
computes `bind = SHA256(nonce ‖ ephemeral_pub ‖ identity_pub)` and surfaces it in the CS
token's `eat_nonce`. RA-TLS reuses this exact mechanism, swapping in the **TLS public key**.
Low-risk retrofit.

## Current shape (for reference)
- `cmd/fid-proxy/main.go:210` — `FIDPROXY_ADDR` default `:9090`, plain `ListenAndServe`.
- `internal/tee/{tee.go,confidential_space.go,tdx.go}` — `Attest(nonce)` → `Quote{EphemeralPub,
  IdentityPub, ReportData/eat_nonce bind, RawQuote}`.
- `internal/enc`, `internal/wire` — app-layer E2EE + request/response types.
- `cmd/client/main.go` — fetches `/attestation`, pins measurement, does the handshake.

## Progress
**T1–T3 landed** (build + vet + unit test green in `golang:1.23`): per-boot in-enclave TLS
cert (`internal/ratls`), TLS pubkey bound into the attestation bind (`internal/tee` — Mock/CS/TDX,
`Quote.TLSPub`, opt-in), and HTTPS serving in `cmd/fid-proxy` gated by **`FIDPROXY_TLS=1`**.
The gate keeps the current plain-HTTP + app-layer-E2EE path as default.

**T5 landed too** — the verify SDK (`cli/fidrouter_cli/verify.py`, `sdk/python`, the platform's
vendored copy) and the Go `cmd/client` now (a) fold `tls_pub` into the recomputed bind and
(b) fetch the server's presented TLS cert and **fail closed if its key ≠ the attested
`tls_pub`** (MITM). For https the verifier trusts the attestation, not the CA (unverified TLS
context). Backward-compatible: plain-HTTP enclaves have no `tls_pub` → behaviour unchanged.
Proven end-to-end against the real binary (`FIDPROXY_TLS=1`, mock attester): positive verifies,
a mismatched cert is refused.

**Still gated OFF in prod.** Turning `FIDPROXY_TLS=1` on rebuilds the enclave ⇒ **new
measurement** ⇒ re-seal BYOK + registry update, and the released CLI wheel must be re-cut
(`cli-v0.1.1`) so users get the T5 verifier. Next: T4 (surface evidence) + T7 (fold exchange).

## Tasks (ordered; suggested path 1→2→3→5→7→6/8→9)

**T1 — In-enclave TLS keypair + self-signed cert at boot.**
Generate a per-boot TLS key (P-256/Ed25519), self-signed, `SAN=enclave.fidcore.xyz` (+ IP).
Private key in memory only, never persisted. New `internal/ratls`, wired from `cmd/fid-proxy`.

**T2 — Bind the TLS pubkey into attestation.**
Extend `bind` in `internal/tee/confidential_space.go` (+ `tdx.go`, `tee.go` Mock for parity):
`bind = SHA256(nonce ‖ tls_pub ‖ identity_pub)`. Reuse the existing `nonces`/`eat_nonce` path.

**T3 — Serve HTTPS, TLS terminates in-enclave.**
`cmd/fid-proxy/main.go` → `ListenAndServeTLS` with the T1 cert. No TLS-terminating proxy in
front (networking/firewall: expose the enclave TLS port directly). Keep a minimal HTTP path
for `/attestation` bootstrap if needed.

**T4 — Expose RA-TLS evidence to clients.**
(a) Embed the CS token / TDX quote in a custom X.509 extension (RA-TLS OID) so an aware
verifier reads it during the handshake. (b) `/attestation` also returns `tls_cert_fingerprint`
for out-of-band checks.

**T5 — Verifier checks the TLS-key ↔ attestation binding.**
Update `cmd/client`, the verify SDK (`../platform/vendor/fidrouter_verify.py` / `sdk/`), and
`../platform/app/services.py:verify_arbitrary`: on connect, read the presented cert, recompute
`bind`, confirm `eat_nonce` matches and `image_digest == pinned measurement`.

**T6 — Registry publishes the attested TLS anchor.**
Add the endpoint's current attested cert fingerprint to the registry; per-boot rotation means
the enclave re-publishes its fingerprint on boot.

**T7 — Fold the exchange server-side (unlocks `base_url` + key).**
With TLS terminating in-enclave, the enclave can accept the user's key: receive `Bearer`, call
cp-adapter internally to validate + mint the capability (or verify inline), then serve. New
cp-adapter client in `cmd/fid-proxy`.

**T8 — Cert rotation / lifecycle.**
Per-boot cert, short validity, publish-on-boot, client pin-invalidation handling.

**T9 — (optional) fidrouter attestation-CA.**
A service that verifies the quote↔tls-key binding and issues a standard CA-signed cert for
`enclave.fidcore.xyz`, transparency-logged — so stock clients need zero pin (trust tier 3).

**T10 — Compat, repro, tests.**
Keep app-layer E2EE (`internal/enc`) as fallback/defense-in-depth. Update `scripts/reproduce.sh`
→ new binary = **new measurement** (re-publish registry + re-seal BYOK). Add an e2e test that a
tampered TLS key fails the binding check.
