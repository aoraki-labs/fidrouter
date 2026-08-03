# fid-router — verifiable, no-log LLM relay (data plane + verify SDK)

The open, auditable **data plane** for a *verifiable* no-log LLM relay, plus the
client **verify SDK** and the **public verification** service.

The premise: don't ask users to *trust* a relay not to log their prompts — let
them **verify** it. The data plane runs inside a hardware TEE (GCP Confidential
Space / Intel TDX); its remote-attestation quote carries a **measurement** (the
running code's fingerprint). A client checks that measurement against the
reproducible build of *this* source before sending, over an attested
end-to-end-encrypted channel, and fails closed on mismatch.

> **This code being open + reproducibly built is the whole point.** If the
> measured binary's source were secret, the measurement would prove nothing.

## What's here (Apache-2.0)
- `cmd/fid-proxy` — the enclave data plane. The **only** component that ever sees a
  plaintext prompt (in RAM); it writes **no** request/response body anywhere.
  Speaks OpenAI-compatible `/v1/chat/completions` + a sealed/attested `/v1/infer`.
- `sdk/python`, `sdk/ts` — verify SDK: attestation check, X25519+AES-GCM E2EE,
  Ed25519 receipt verification (anti-downgrade), all fail-closed. `fid.OpenAI` is
  a drop-in for the OpenAI client that verifies under the hood.
- `deploy/gcp` — Confidential Space build/launch, the public **verification page**,
  and the **registry** (measurement → this source + enclave public key).

## What's deliberately NOT here
- **No private keys.** The enclave identity seed and the control-plane signing key
  are injected at boot / kept on the control plane — never baked into the image.
  The image ships only public config (`cp_pub`, expected measurement).
- **No credentials.** `.env` and `config/keys.json` are git-ignored.

## Trust boundary (what this can / cannot prove)
- **Can:** this hop runs exactly this open code, in a real TEE, and does not log.
- **Cannot:** that the *upstream* provider (OpenAI/Anthropic/…) doesn't log — that
  is the upstream's own policy/ZDR. In BYOK mode the customer supplies the upstream
  key and endpoint, so they choose and control the upstream.

## Status
PoC, running live on GCP Confidential Space. **In progress:** reproducible-build
pinning (deterministic `image_digest`) and operator-blind key management (upstream
key + identity seed via attestation-gated Secret Manager instead of injected env).
