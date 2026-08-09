# fidrouter — Verifiable no-log LLM relay (technical whitepaper / public version)

> Audience: developers, enterprise security evaluators, and partner relays who want to understand "why you can trust that a relay does not record my prompt."
> This document only covers the verifiability of **this one relay hop**; it does not promise end-to-end privacy (see §4 Honest boundary).

## 1. Problem
A token-aggregating relay (a "relay station") must, technically, terminate the user connection, obtain the **plaintext prompt**, and then inject the upstream provider's real key to forward it. The operator is therefore inherently able to read all plaintext. Existing solutions (including OpenRouter) rely on **policy/contract-based trust** — "we promise not to record," but it **cannot be proven**. Users can only choose to believe.

## 2. Approach: upgrade the first hop from "believe" to "verify"
fidrouter puts the relay's **data plane** inside an **Intel TDX confidential VM (enclave)**, and lets the user confirm, **before sending anything**, via **hardware remote attestation**:
- what is running is a piece of **open-source, reproducibly built** code;
- that this code **does not record, does not persist to disk, does not leak** the prompt;
- the prompt can only be decrypted **inside the attested enclave** — the operator, the host, and the database cannot read it.

The life of the plaintext: `user device (plaintext) → wire (E2EE sealed) → enclave RAM (plaintext, a single instant) → upstream (TLS)`. Except for that single instant inside the enclave, it is ciphertext throughout.

## 3. Architecture (three trust zones)
- **Client · verify SDK**: verify first, send later; fail-closed if it does not pass.
- **Enclave · data plane fid-proxy (open source, minimal, auditable)**: attested E2EE decryption, cache-affinity routing, signed receipts. **The only place that touches plaintext, and only in RAM.**
- **Outside the TEE · control plane (e.g. New API)**: users/billing/quota/backend, touches only metadata, **never terminates the prompt's TLS**.
- **KMS (attestation-gated)**: decryption of the upstream key is bound to the enclave measurement, so only attested code can obtain the plaintext key.

## 4. What it can prove / cannot prove (honest boundary)
- ✅ This relay of ours **does not record, does not retain, does not leak** your prompt, and what it runs really is that open-source code.
- ✅ The prompt can only be decrypted inside the attested enclave.
- ✅ **Routing authenticity**: the receipt proves the model actually served is the model you requested (prevents silent downgrade).
- ❌ It cannot prove how **closed-source upstreams like OpenAI/Anthropic** handle the plaintext once they receive it — they do not provide customer-verifiable proof.
- **Every privacy statement must carry a qualifier**: "This guarantee covers only this one relay hop; the prompt is delivered in plaintext to the upstream you chose, after which it is subject to that upstream's own ZDR / enterprise terms."

## 5. Why it must be open source (the precondition of verifiability)
Remote attestation only proves "running code == measurement X." If X corresponds to source code that is kept secret, the user cannot confirm it does not record — that is equivalent to no verification. Therefore:
- **Must be open source + reproducible build**: the data plane `fid-proxy`, the client verify SDK, and the build/measurement pipeline.
- **Need not be open source**: the control plane / billing / routing policy / backend (do not touch plaintext, not within the measurement).
- License **Apache-2.0**. Open-sourcing the data plane is the **precondition of trust**, not a concession; the moat is in the verification network and compliance, not in the proxy code.

## 6. Platform
The data plane only needs a **CPU TEE (Intel TDX)**, does not run inference, and needs no GPU. The trust root should be in **Intel (the CPU vendor)** rather than a cloud vendor — both GCP C3 TDX and Alibaba Cloud g8i TDX give a bare Intel-rooted DCAP quote; Azure by default wraps it into a Microsoft-signed MAA; AWS only has the AWS-rooted Nitro (and requires a vsock split). For domestic / no-cross-border use, use **Alibaba Cloud g8i** (the trust root is still Intel).

## 7. How to verify / how to trust
See [`VERIFICATION.md`](./VERIFICATION.md). The core: **verification is carried out by the user's side or can be independently cross-checked**, and never relies on the relay's self-description.
