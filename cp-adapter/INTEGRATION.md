# Integrate any gateway (New API / one-api / your own) with fidrouter

Offer your users a **verifiable, no-log** lane while your gateway stays the identity +
billing system and **never sees a prompt**. This works for any control plane that issues
API keys; New API / one-api specifics are called out.

## The model (read this first)
The verifiable lane must **not** relay through your gateway — if it did, your gateway would
see plaintext and break the no-log guarantee. So "using the verifiable lane" means: your
gateway issues the key, and the client goes **directly** to the enclave (E2EE). Your
gateway is the *issuer*, not the *proxy*.

```
user's key ──▶ your gateway (issue only)        cp-adapter: key → capability token
user ── E2EE prompt + token ──▶ ENCLAVE (attested, no-log) ──▶ provider
enclave ── signed receipt (metadata) ──▶ platform (usage) ──▶ your billing
```

## Steps
1. **Deploy the enclave.** Reproducibly build `github.com/aoraki-labs/fidrouter` and run it
   in a TEE (GCP Confidential Space today). You get `base_url` + a `measurement`.
2. **Generate a CP keypair.** The public half is baked into your enclave image
   (`config/public.json` → reproducible → your measurement); the seed stays with you.
3. **Bundle cp-adapter** (this repo) beside your gateway:
   ```
   CP_SEED_HEX=<your seed>  NEWAPI_BASE=https://your-gateway
   ENCLAVE_URL=<your enclave>  EXPECTED_MEASUREMENT=sha256:...
   python3 adapter.py            # POST /exchange {key} -> capability token
   ```
   It validates the user's key against your gateway out-of-band (for New API:
   `GET /v1/dashboard/billing/subscription`) — no request is relayed through the gateway.
4. **Register your endpoint** on the fidrouter platform (`cp_adapter_url` = your
   cp-adapter). It's live-attested; once green an admin publishes it to the neutral registry.
5. **Inject your upstream key** operator-blind (in-browser BYOK on the platform).
6. **Point metering** — set the enclave's `FIDPROXY_METERING_URL` at the platform `/ingest`.

## Surface it to your users (so they can opt in)
The verifiable lane is a **choice** — some users want it, some don't. Make it visible and
selectable:
- **A labeled model/group**, e.g. a `verified` group whose "how to use" tells users to
  point the drop-in SDK / `base_url` at the enclave (not your gateway's `/v1`).
- **A badge** on those models — `🛡 Verifiable · no-log (TEE-attested)`.
- **A "Verify" link** to the platform's public verify page so users can check the endpoint
  independently.

### New API / one-api, minimal (no source fork)
Use the built-ins — no UI patch needed:
- Create a **group** (e.g. `verified`) and name/describe it clearly.
- Use the **announcement** and **api_info / chats** settings to add the badge text + the
  "Verify" link + a one-line "how to use" pointing at the SDK/enclave.
- Users select the `verified` group (per token or per request) to opt into the lane.

Deeper (branded badge on model cards) means patching the New API frontend — note New API is
**AGPL-3.0**, so a modified, deployed fork must offer its source.

Part of **fidrouter** — https://github.com/aoraki-labs/fidrouter
