# enclave-template — build your own verifiable relay

A minimal, **compiling and running** enclave: attestation, offline capability-token checks,
signed receipts. Copy it, put your own upstream call in the marked block, ship it.

Anyone can add an enclave — us, or a partner who wants their own trust domain (their own
measurement, their own per-boot sealing key, attestation that doesn't depend on our infra).

## Try it in 30 seconds

```bash
FIDPROXY_ATTESTER=mock go run ./examples/enclave-template
curl -s 'localhost:9095/attestation?nonce=abc' | jq .
curl -s -o /dev/null -w '%{http_code}\n' 'localhost:9095/attestation'   # 400: nonce required
```

## Then, in order

1. **Read [INVARIANTS.md](INVARIANTS.md).** Eight rules. They are what a client's checks
   actually depend on; breaking one usually doesn't error, it just quietly stops proving
   anything.
2. **Put your upstream call** in the marked block in `main.go`. Keep plaintext in memory,
   emit the receipt.
3. **Build reproducibly + publish** — `Dockerfile` here, recipe in
   [`../../scripts/reproduce.sh`](../../scripts/reproduce.sh). Note the
   `allow_env_override` warning; it has bitten us in production.
4. **Deploy to Confidential Space** — see [`../../deploy/gcp/`](../../deploy/gcp/). You get a
   `base_url` and a `measurement`.
5. **Register it** at [app.fidcore.xyz](https://app.fidcore.xyz) → Endpoints → *Advanced*.
   Registration attests it live and publishes it to the neutral registry if it goes green.
   The attestation **is** the gate — there is no manual approval, and no way to publish
   something that doesn't attest.
6. **Have someone else verify you**: `fidrouter verify https://your-endpoint`. If you run
   the only verifier, you have proven nothing — see
   [`../../docs/VERIFICATION.md`](../../docs/VERIFICATION.md).

## What you inherit by importing `fidrouter/pkg/...`

| Package | You get |
|---|---|
| `pkg/tee` | Confidential Space / TDX attestation + the exact `report_data` binding clients recompute |
| `pkg/token` | Ed25519 capability tokens, verified **offline** against a baked CP public key |
| `pkg/receipt` | content-free signed receipts (anti-downgrade evidence) |
| `pkg/enc` | X25519 + AES-256-GCM used by E2EE and sealed BYOK |
| `pkg/ratls` | in-enclave TLS key bound into attestation; optional CA-signed cert over the same key |
| `pkg/wire` | request/response types of the sealed path |

These were moved out of `internal/` specifically so you can import them: an independent
implementation you can build yourself is worth more to the network than one only we can build.
