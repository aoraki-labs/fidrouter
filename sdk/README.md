# fidrouter verify SDK (Python + TS)

The **client-side verifier** — Level 1 of the trust ladder (see `docs/VERIFICATION.md`).
It refuses to send a prompt until it has cryptographically verified the enclave,
then seals the prompt to the attested key and verifies the signed receipt.
**This is the piece that must be open-source + reproducible** so users can audit it.

Both SDKs are byte-compatible with the Go data plane (`cmd/fid-proxy`), verified
by `scripts/test-sdk.sh`:
- channel key = `SHA256( X25519(client_priv, enclave_pub) || "fid-e2e-v1" )`
- sealing = AES-256-GCM, 12-byte nonce prepended, AAD = session bytes
- quote sig = Ed25519 over `(measurement||report_data as utf8) || ephemeral_pub`
- receipt sig = Ed25519 over Go's `json.Marshal(receipt)` (canonical field order)

## What it does (fail-closed)
1. `GET /attestation?nonce` → verify `measurement == pinned`, `identity_pub == pinned`,
   quote signature (→ Intel root in production), `report_data == H(nonce‖pub)`.
2. Any failure → **raise / throw, send nothing.**
3. Seal prompt (HPKE-style) to the attested key; POST `/v1/infer`.
4. Verify signed receipt: signature, measurement, and `model == requested` (anti-downgrade).
5. Open the sealed response.

## Python
```python
from fidrouter_verify import FidClient
c = FidClient(base_url="https://relay.example", token=TOKEN,
              pin_measurement=PIN_MEASUREMENT, pin_idpub_hex=PIN_IDPUB)
r = c.chat("gpt-4o", [{"role":"system","content":SYS},{"role":"user","content":"hi"}])
print(r.completion, r.cache_hit, r.model)   # raises FidVerificationError if untrusted
```
Deps: `cryptography`. Run: `sdk/python/example.py`.

## TypeScript / Node (ESM, no deps)
```js
import { FidClient } from "./fidrouter-verify.mjs";
const c = new FidClient({ baseUrl, token, pinMeasurement, pinIdpubHex });
const r = await c.chat({ model: "gpt-4o", messages: [...] });   // throws FidVerificationError if untrusted
```
Uses `node:crypto` (Node ≥ 18). Run: `node sdk/ts/example.mjs`.

## Drop-in mapping
`chat(model, messages)` splits messages into a **cacheable prefix** (all but last)
+ **variable suffix** (last message), matching the proxy's affinity-routing model.
A production build maps the full OpenAI/Anthropic request shape and honors
`cache_control` breakpoints.

## DCAP path (skeleton, ready for real TDX)
`dcap.py` / `dcap.mjs` verify a real Intel TDX quote. The SDK **dispatches by
`platform`**: `mock-tee` → the pinned-Ed25519 path above; anything else (e.g.
`aliyun-tdx`) → the DCAP path, which expects the endpoint to return a raw quote
(`raw_quote` b64) + `ephemeral_pub`.

Division of labor (deliberate): the DCAP module **parses** the quote (MRTD /
RTMRs / REPORT_DATA) and applies **policy** (measurement pinned to the published
reproducible build, `report_data == H(nonce‖pub)`, TCB status). The heavy crypto
(quote sig, QE report, PCK chain → Intel SGX Root CA, TCB via PCCS) is delegated
to a pluggable backend — **do not hand-roll ECDSA/X.509 in the SDK**:
- **`IntelTrustAuthorityBackend` → IMPLEMENTED** (Python + TS). Real ITA REST flow:
  `GET /appraisal/v1/nonce` → `POST /appraisal/v1/attest` (submit the TDX quote) →
  receive an attestation-token **JWT** → verify its **PS384/RS256** signature against
  ITA's JWKS (`GET {portal}/certs`, selected by `kid`, leaf from `x5c`) → read TDX/TCB
  claims (`tdx_mrtd`, `tdx_report_data`, `attester_tcb_status`, …) → **cross-check
  `tdx_mrtd` against the locally-parsed quote** so the token provably describes THIS
  quote. Configure with an ITA `api_key`. The JWS-verify crypto + JWKS(kid) lookup +
  tamper-rejection are unit-tested (`python3 sdk/python/dcap.py`; node self-test).
  Remaining TODO: pin/validate the `x5c` chain to the ITA root CA (defense in depth);
  live end-to-end needs a real ITA subscription + a real TDX quote.
- `QvlBackend` → Intel SGX DCAP Quote Verification Library (`sgx_qv_verify_quote`) + PCCS (offline; TODO bind the lib)
- `StubBackend` → DEV ONLY (parse, `verified=False`)

```python
from dcap import IntelTrustAuthorityBackend
FidClient(base_url=RELAY, token=T, pin_measurement=MEAS,
          dcap_backend=IntelTrustAuthorityBackend(api_key=ITA_KEY))
```
Byte-offset parsers + ITA JWS verify are unit-tested. TODO before production:
x5c-chain-to-root pinning, and source the receipt-signing pubkey from the
quote/registry (not a pin).

## Test
```bash
GO=/home/ubuntu/.local/go/bin/go bash scripts/test-sdk.sh   # both SDKs vs Go proxy + tamper check
```
