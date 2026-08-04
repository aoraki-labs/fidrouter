# fidrouter — verifiable, no-log LLM relay (the verifiable core)

**Don't trust a relay not to log your prompts — verify it.**

A relay sits between your app and an LLM provider. Normally you just have to trust
it. fidrouter runs the relay inside a hardware TEE (GCP Confidential Space / Intel
TDX) whose remote-attestation quote carries a **measurement** — the exact
fingerprint of the running code. Your client checks that measurement against the
**reproducible build of this repository** before sending anything, over an attested
end-to-end-encrypted channel, and **fails closed** on any mismatch.

> This repo is open **because that is the mechanism**. If the measured binary's
> source were secret, the attested measurement would prove nothing. So this repo
> contains exactly — and only — the parts whose openness makes verification real.

## What's in this repo (Apache-2.0) — and why each part must be open

| Part | What | Why it's open |
|---|---|---|
| `cmd/fid-proxy` + `internal/` | **The enclave data plane.** The only component that ever sees a plaintext prompt (in RAM); writes **no** request/response body anywhere. Serves OpenAI-compatible `/v1/chat/completions` + attested `/v1/infer`, and emits signed metadata receipts. | It's *the code being attested*. You verify this. |
| `sdk/python`, `sdk/ts` | **Verify SDK.** Attestation check, X25519+AES-GCM E2EE, Ed25519 receipt verification (anti-downgrade) — all fail-closed. `fid.OpenAI` is a drop-in for the OpenAI client that does all of this under the hood. | The verifier must be auditable too, or "verify" is just another "trust". |
| `deploy/gcp` + `scripts/reproduce.sh` | **Reproducible build + launch.** Rebuild this source → get the same image digest the enclave attests. | Reproducibility is what ties the measurement to *this* code. |
| `verify-page/` + `registry.json` | **Neutral verification page + registry** (measurement → this source + enclave pubkey). Runs on a host independent of any relay operator. | The trust anchor can't be controlled by the operator, and its checker must be open. Not `fid-proxy`, but core to "verify". |
| `cmd/ctl` (`seal-byok`) | **Client-side tooling** a key owner runs to seal their upstream key *to a specific attested enclave* (operator-blind BYOK). | The sealing party must be able to audit what they run. |
| `docs/WHITEPAPER.md`, `VERIFICATION.md`, `DESIGN.md` | Threat model, how-to-verify, and the product/architecture design. | — |

`cmd/client` + `cmd/mock-upstream` are a reference client and a local mock for the
`scripts/demo.sh` end-to-end.

## Companion repos
- **`fidrouter-cp-adapter`** (OPEN) — the control-plane bridge: turns a New API `sk-` into
  a capability token this enclave verifies. Open so any relay operator can integrate and
  audit it; you bundle it beside your own New API.
- **`fidrouter-platform`** (closed) — the product & operator plane, none of which affects
  verifiability: product frontend, partner console, dashboards, billing/reconciliation,
  and registry *authoring/ops* (the public `registry.json` is served from this repo's
  `registry/`; it's *authored* under review on the closed side, then committed here —
  git history is the transparency log).

**No secrets here either:** the enclave identity seed and the control-plane signing
key are injected/sealed at boot — never in the image. `.env` and `config/keys.json`
are git-ignored; the image ships only public config (`cp_pub`, expected measurement).

## The actual user flow (you never visit a second site)
You get an `sk-` from *your provider's* New API, exactly as today. Then:

```python
from fid import OpenAI                      # drop-in; verifies under the hood
client = OpenAI(api_key="sk-...",           # your New API key
                base_url="https://<relay>") # the SDK exchanges it for a capability
                                            # token, verifies the enclave, E2EE's the
resp = client.chat.completions.create(...)  # prompt — all automatic, fail-closed
```

The `sk-` → capability-token exchange and the metering all happen **behind** your
provider's control plane; there is no separate fidrouter login. The neutral verify
page is only for *auditing* an endpoint, not for getting access.

## Trust boundary
- **Proves:** this hop runs exactly this open code, in a real TEE, and keeps no logs.
- **Doesn't prove:** that the *upstream* provider doesn't log — that's the upstream's
  own policy/ZDR. In BYOK mode you supply the upstream key + endpoint, so you choose it.

## Status
Live on GCP Confidential Space; reproducible build + operator-blind sealed BYOK +
OpenAI-compatible endpoint + signed-receipt metering all working. See `docs/DESIGN.md`
for the full product/architecture picture and `docs/VERIFICATION.md` to verify a live
endpoint yourself.
