# fidrouter — a verifiable, no-log LLM relay you don't have to trust

Every LLM relay today asks for the same thing: *trust us not to log your prompts.* You can't
check it. **fidrouter replaces that trust with proof.**

Each request is served inside a hardware TEE (Intel TDX / GCP Confidential Space) whose
remote-attestation quote carries a **measurement** — a cryptographic fingerprint of the exact
code running. That code is **open-source and reproducibly built**, so anyone can confirm the
relay you're talking to is the published, no-log build **before** sending a prompt. Every
response comes back with a **signed, content-free receipt** you can re-verify.

**Don't trust. Verify.**

## What's live today
- **A neutral verification network** — verify *any* relay's attestation against a public
  registry (`measurement → open source`), independent of the operator. No account needed.
- **A managed no-log relay** — Confidential Space (Intel TDX), operator-blind BYOK (your
  provider key is sealed to the attested enclave; we only ever hold ciphertext), serving
  Claude and OpenAI models.
- **Keep your own client** — point any OpenAI-compatible app/agent at the relay (`base_url` +
  key); verification rides along, no SDK swap.
- **Agent- & script-first** — a CLI (`fidrouter verify | endpoints | receipt | call`), an MCP
  server, and a drop-in SDK.
- **For partners** — open signup, foolproof onboarding, endpoints **auto-publish** once they
  attest green (no review queue), a dashboard built from unforgeable receipts.

## Try it in 30 seconds
```bash
pip install https://github.com/aoraki-labs/fidrouter/releases/download/cli-v0.1.1/fidrouter-0.1.1-py3-none-any.whl
fidrouter verify http://enclave.fidcore.xyz:9090      # → {"ok": true, "in_registry": true}
```
Or open **https://app.fidcore.xyz** → *Verify an endpoint*.

## Open source
- `github.com/aoraki-labs/fidrouter` — enclave data plane, verify SDK/CLI, reproducible
  build, the neutral registry, and the design docs (`docs/WHITEPAPER.md`, `docs/VERIFICATION.md`).
- `github.com/aoraki-labs/fidrouter-cp-adapter` — the key→token bridge operators run beside
  their gateway.

## On the roadmap (in the open)
- **RA-TLS** — bind the enclave's TLS key into attestation so a *stock* HTTPS client gets the
  guarantee with zero changes (`RATLS.md`, in progress).
- **A transparency-logged registry + independent verifiers** — so no single operator (us
  included) can forge the neutral trust anchor.

The whole point is a public good: a trust anchor for verifiable inference that anyone can
run, mirror, and check. Come verify us.
