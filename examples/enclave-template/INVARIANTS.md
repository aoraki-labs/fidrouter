# Invariants — break these and your enclave stops being verifiable

This template is deliberately boring. The value isn't the code, it's the contract: a client
anywhere in the world runs a fixed set of checks, and your enclave has to satisfy them. If
you change something here, change it knowing which check it feeds.

## 1. Import `fidrouter/pkg/...` — don't reimplement it

`pkg/tee`, `pkg/token`, `pkg/receipt`, `pkg/enc`, `pkg/wire`, `pkg/ratls` are a **wire
contract**, not utilities. The verifier recomputes

```
report_data = SHA256(nonce ‖ ephemeral_pub ‖ identity_pub [‖ tls_pub])
```

byte for byte. A re-implementation that is one field or one order different fails closed —
or worse, *passes* today and silently diverges after an upstream change. Import the packages.

## 2. Never issue an unbound quote

`/attestation` must require a caller-supplied nonce. A quote without a fresh nonce is
replayable: an operator could capture one honest quote and serve it forever from an
unattested box.

## 3. Secrets are injected, never baked

The **image is what gets measured and published**. Anything baked into it is readable by
anyone who pulls it. So:

| Baked into the image (public, and measuring it is a feature) | Injected at boot (secret) |
|---|---|
| CP **public** key, metering URL, verify URL, TLS/RA-TLS config | identity seed, upstream provider key |

Baking the *public* config is deliberate: the measurement then proves where metering goes and
which control plane may authorise spend. Injecting is done with `tee-env-*` on Confidential
Space — **and only names listed in `tee.launch_policy.allow_env_override` are permitted. Any
other `tee-env-*` makes the launcher refuse to start the workload, so the VM boots and
immediately terminates.** (We lost a production window to exactly this.)

## 4. Verify the capability token before doing any work

`token.Verify(cpPub, …)` first. It is checked **offline** against the baked CP public key —
your enclave never calls the control plane to authorise a request, which is what keeps the
control plane out of the data path.

## 5. Receipts are metadata only

Model, token counts, measurement, timestamp, hashes. **Never content.** The receipt is signed
by the attested identity key, which is what lets a user prove after the fact that their
response came from the measured build and that the model wasn't silently downgraded.

## 6. No logging of content, no plaintext to disk

This is the entire product. Prompt plaintext lives in RAM for the duration of one request.
Don't add a debug log line "just for now" — the published image is the audit surface, and
someone will diff it.

## 7. Reproducible build, or none of the above matters

A verifier maps `measurement → source`. If your image isn't reproducible from published
source, the measurement proves only "some binary", not "this code". Keep the base pinned by
digest, build with `-trimpath -buildvcs=false -ldflags=-buildid=` and `SOURCE_DATE_EPOCH`,
and publish the recipe — see `../../scripts/reproduce.sh`.

## 8. Publish to the registry, and let someone else verify it

Register the endpoint so an **independent** verifier attests it. A relay that operates its own
verifier has proven nothing (same reason a TLS certificate means nothing if the server
validates it). See `../../docs/VERIFICATION.md` for the trust ladder.

## RA-TLS (optional but recommended)

`pkg/ratls` gives you an in-enclave TLS key whose public half is bound into the attestation
(`Attester.SetTLSPub`). Two things to know:

- The binding is on the **key**, not the certificate — so you can also serve a publicly
  trusted certificate over the same key (`Holder.CSRPEM` → ACME outside → `InstallChain`).
  Stock clients then validate via the CA; verifying clients still validate via attestation.
- `InstallChain` refuses a chain whose public key isn't yours. Keep that check.
