# cp-adapter — threat model

You are being asked to install this next to your gateway. That deserves a straight answer
about what it can and cannot do. This document is the answer; the code is ~250 lines of
Python in `adapter.py`, and it is open source (Apache-2.0) precisely so you don't have to
take our word for any of it.

## What cp-adapter is for

The enclave verifies capability tokens **offline**, against a CP public key baked into its
measured image. So something has to turn "a user of your gateway" into "a token the enclave
accepts", without the enclave ever touching your user database. That is cp-adapter's whole
job:

```
user's gateway key ──▶ cp-adapter ──▶ capability token (Ed25519, short-lived)
                         │
                         └── validates the key out-of-band against YOUR gateway
```

It runs on **your** infrastructure, holds **your** CP signing seed, and we never see either.

## What it can do (assume worst case if it were malicious or compromised)

Be clear-eyed — this is a privileged component:

1. **Mint capability tokens.** It holds the CP signing seed, so it can authorise inference
   spend against your account pool, for any tenant id it chooses.
2. **See gateway keys in transit.** Every `POST /exchange` carries a user's key. A malicious
   build could exfiltrate them.
3. **Whatever authority YOU give the validator.** How a key is checked is a pluggable
   validator you configure (`http`, `exec`, `newapi` — see
   [GATEWAY_INTEGRATION.md](../docs/GATEWAY_INTEGRATION.md)), so the privilege sits where you
   put it: a purpose-built `/fid/validate` endpoint answers one question and needs nothing
   else, while a script that reads your database has whatever access you grant it. cp-adapter
   itself no longer contains any code that reads a user table — the old
   `ALLOW_DB_GROUP_LOOKUP` path was removed for exactly this reason.
4. **Network position** next to your gateway.

Mitigations that are yours to apply: run it on the gateway host and bind it to localhost (or
put it behind your own TLS/auth); prefer the admin API over the DB read; rotate the CP
keypair (the enclave pins the public half, so rotation is a rebuild); revoke the admin token
at any time.

## What it cannot do — structurally, not by promise

1. **It never sees a prompt or a completion.** Inference does not pass through cp-adapter.
   It is touched **once** per credential to mint a token; the client (or the enclave, in the
   folded-exchange path) then talks straight to the enclave. There is no code path in
   `adapter.py` that carries message content — grep for it.
2. **It cannot read anything the enclave protects.** Your upstream provider key is sealed to
   the enclave's per-boot key; cp-adapter has no part in that flow and cannot decrypt it.
3. **It cannot forge attestation.** Measurement and quote verification happen on the
   *client* side against the public registry. A lying cp-adapter cannot make an unverified
   enclave look verified.
4. **It cannot leak the CP seed to us.** The seed is read from the environment and used only
   to sign token bytes. There is no outbound call to fidcore/aoraki infrastructure at all —
   `adapter.py` talks to exactly two places: your gateway, and whoever calls it.

## Trust summary

| Component | Whose machine | What it must be trusted with | Verifiable how |
|---|---|---|---|
| **enclave** (`cmd/fid-proxy`) | ours (or yours) | prompts | remote attestation + reproducible build — **verify, don't trust** |
| **cp-adapter** | **yours** | gateway keys, spend authorisation | open source, runs under your control, no outbound calls |
| **New API / your gateway** | yours | identity, billing | yours already |
| **platform** (`app.fidcore.xyz`) | ours | nothing secret — relays ciphertext | BYOK sealing is verified in-browser against the public registry |

The asymmetry is deliberate: the component that sees **prompts** is the one you can
cryptographically verify. The component that sees **credentials** is the one **you** own and
can read the source of.

## Known weaknesses (we would rather you hear them from us)

- **The `newapi` validator reads a dashboard endpoint**, which is a de-facto contract rather
  than an API, and without an admin token it reports the user's limit rather than the token's
  own remaining quota — so it can over-grant. Prefer the `http` validator where you control
  the gateway.
- **The CP seed is a hot key on disk/in env** on your host. Compromise of that host means an
  attacker can mint capability tokens until you rotate the keypair (which changes the
  enclave measurement). Long term this belongs in an HSM/KMS.
- **Tenant ids are derived from the key** (`sha256(key)[:16]`). Content-free, but stable —
  so usage is linkable per key across time. That is intentional for billing.
- **cp-adapter does not verify the enclave.** It reports `enclave_url` +
  `expected_measurement` to the client, and the *client* is responsible for verifying. Don't
  treat cp-adapter's word as attestation.
