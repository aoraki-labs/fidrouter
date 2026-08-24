# Integrating any gateway

fidrouter is not built around one gateway product. The enclave, the registry and the platform
know nothing about how your users are authenticated — that question is answered entirely by a
**validator** inside `cp-adapter`, which runs on *your* machine.

So integrating a gateway means answering one question, in whichever way suits you:

> Given a key one of my users presented, is it valid, and what may it do?

## The verdict

A validator returns this and nothing else:

```json
{
  "ok": true,
  "subject": "opaque-id-in-your-system",
  "remaining_usd": 12.5,
  "group": "enclave",
  "models": ["claude-opus-5"],
  "expires_at": 1789000000
}
```

| field | meaning |
|---|---|
| `ok` | **false** ⇒ refuse. Nothing is minted. Put a human-readable `reason` alongside it. |
| `subject` | An **opaque** id for the key/user in your system. It is hashed by cp-adapter into the tenant id (`u_…`), so **never put a name, email or anything identifying here** — tenant ids appear in signed receipts that get published. Omit it and the key itself is hashed instead. |
| `remaining_usd` | Remaining spend. **Omit it and cp-adapter refuses by default** (`QUOTA_UNKNOWN=refuse`) rather than minting an unbounded token; set `QUOTA_UNKNOWN=cap:5` to allow a bounded one instead. |
| `group` | Optional lane label. Required only if you run `ALLOWED_GROUPS` (see *Two lanes* below). |
| `models` | Optional allow-list, overriding the adapter default. |
| `expires_at` | Optional unix time; the capability token is shortened to match. |

### Refusal is not an outage

This distinction matters more than it looks:

- **Refusal** — your gateway says the key is bad. Normal. cp-adapter answers `401`.
- **Outage** — your gateway is unreachable or answers garbage. cp-adapter answers `503`,
  mints nothing, and does **not** cache the result. Alert on it.

If those were conflated, a gateway outage would look exactly like "every key is invalid" — or
worse, a misconfigured endpoint returning `200 OK` on everything would look like "every key is
valid". Hence: **refusals are `200` with `ok:false`, never `4xx`.**

## Pick a validator

### `http` — recommended for a gateway you can change

Implement one endpoint (~20 lines) and you are done:

```
POST /fid/validate
Authorization: Bearer <shared secret>          # optional, VALIDATOR_SECRET
Content-Type: application/json

{"key": "sk-..."}
→ 200 {"ok": true, "subject": "u/8812", "remaining_usd": 12.5, "group": "enclave"}
→ 200 {"ok": false, "reason": "quota exhausted"}
```

```bash
VALIDATOR=http
VALIDATOR_URL=https://your-gateway.internal/fid/validate
VALIDATOR_SECRET=…            # optional
```

This is the least-privilege option: the endpoint answers exactly one question, so cp-adapter
never needs broad credentials or database access.

### `exec` — for anything at all

Run a local command. stdin gets `{"key": "..."}`; stdout returns the verdict; a **non-zero
exit means outage**, not refusal.

```bash
VALIDATOR=exec
VALIDATOR_CMD=/opt/mygw/fid-validate
VALIDATOR_TIMEOUT=8
```

The key is passed on **stdin, never argv** — argv is readable by any local user via `/proc`.
Use this for a gateway you cannot modify, a direct database lookup, an LDAP call, whatever.
The privilege the script holds is entirely your choice, which is the point: we ship no
component that needs to read your user table.

### `newapi` — an unmodified New API

```bash
VALIDATOR=newapi
NEWAPI_BASE=http://127.0.0.1:4000
NEWAPI_ADMIN_TOKEN=…          # optional, see below
```

Works with a stock New API by reading `/v1/dashboard/billing/subscription`. Two honest
caveats:

1. That is a **dashboard** endpoint, not an auth API. Its response shape is a de-facto
   contract that can change between New API versions.
2. Without `NEWAPI_ADMIN_TOKEN` it reports the **user's** limit, not the token's own remaining
   quota — so a token with a tighter cap can be granted more than it should — and it cannot
   report `group` at all, so `ALLOWED_GROUPS` cannot be enforced.

For our own deployment we use `exec` with a small local script that reads the New API database
directly. That is *more* privilege, so it belongs in a script the operator owns rather than in
the component we ship — which is exactly why `ALLOW_DB_GROUP_LOOKUP` was removed from
cp-adapter itself.

## Two lanes (optional)

Many gateways want to sell both a normal lane and a verified (enclave) lane at different
prices. Gate the verified one by group:

```bash
ALLOWED_GROUPS=enclave
```

Only keys whose verdict carries a whitelisted `group` can mint a capability token. If the
group cannot be determined, cp-adapter **fails closed** — a gate that passes when it cannot
prove the answer is worse than no gate.

In New API the group comes from settings (*group ratio* + *user-selectable groups*) and needs
**no channel**. A channel would in fact be wrong: it would let your gateway *relay* that
lane and therefore see plaintext, which is the guarantee you are selling. The verified lane
deliberately has no relay path inside your gateway — its keys are exchanged by cp-adapter and
the client then talks straight to the attested enclave.

## What a validator can and cannot do

It is only ever *consulted*. It never signs anything, never sees a prompt, and never touches
the enclave. A buggy or hostile validator can grant access within **your own** system and
nothing more: it cannot forge a capability token (that needs your CP signing seed), cannot
read another operator's sealed upstream key (those are namespaced by the provisioning key),
and cannot make an unattested enclave look attested (clients verify that themselves).

See [`../cp-adapter/THREAT_MODEL.md`](../cp-adapter/THREAT_MODEL.md) for the full boundary.
