#!/usr/bin/env python3
"""cp-adapter — CLOSED control-plane glue between a New API instance and the
(open, verifiable) fidrouter enclave.

Why it exists: the enclave must NOT touch the user database, and New API must NOT
sit in the data path (it would see plaintext → breaks no-log). So this tiny
sidecar bridges them:

    client's New API `sk-` token  ──POST /exchange──▶  cp-adapter
        cp-adapter validates the sk- against New API (billing/subscription),
        derives a content-free tenant id, and MINTS a capability token
        (Ed25519, signed by the control-plane key the enclave pins)
    ◀── { capability_token, enclave_url, expected_measurement, verify_url }

Then the client goes DIRECT to the enclave (E2EE prompt + Bearer capability_token);
neither New API nor cp-adapter ever sees a prompt.

This file is CLOSED SOURCE (control plane). It depends only on the PUBLIC token
format — it does not embed any enclave secret. The one secret it holds is the
control-plane signing seed (CP_SEED_HEX), which is the private half of the cp_pub
the open image bakes in.

    CP_SEED_HEX=<hex ed25519 seed> NEWAPI_BASE=https://207.57.187.193 \
    ENCLAVE_URL=http://<ip>:9090 EXPECTED_MEASUREMENT=sha256:... \
    VERIFY_URL=https://verify.<ip>.sslip.io python3 adapter.py
"""
import hashlib
import json
import os
import ssl
import time
import urllib.request
from base64 import urlsafe_b64encode
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# --- config ---------------------------------------------------------------
NEWAPI_BASE = os.environ.get("NEWAPI_BASE", "https://207.57.187.193").rstrip("/")
ENCLAVE_URL = os.environ.get("ENCLAVE_URL", "")
EXPECTED_MEASUREMENT = os.environ.get("EXPECTED_MEASUREMENT", "")
VERIFY_URL = os.environ.get("VERIFY_URL", "")
DEFAULT_POOL = os.environ.get("POOL", "shared")
MODELS = [m for m in os.environ.get("MODELS", "claude-3,gpt-4o,claude-opus-5").split(",") if m]
TTL = int(os.environ.get("TTL", "3600"))
QUOTA_PER_USD = int(os.environ.get("QUOTA_PER_USD", "500000"))  # New API rc.21 unit

# --- verified-lane gating -------------------------------------------------
# A gateway can offer BOTH a plain lane and a verified (enclave) lane. Only keys whose
# New API *group* is in ALLOWED_GROUPS may be exchanged for a capability token, so the
# operator controls (and can price) which lane a key belongs to.
# Empty ALLOWED_GROUPS = no group restriction (any valid key), the previous behaviour.
ALLOWED_GROUPS = [g.strip() for g in os.environ.get("ALLOWED_GROUPS", "").split(",") if g.strip()]
# Group resolution. New API exposes no token-auth endpoint that reveals a key's group, so we
# need one of two privileged paths. PREFER the admin API: it is portable (works with a remote
# gateway), the credential is one the operator mints and can revoke, and it does not require
# cp-adapter to sit on the same host as the database.
# Which gateway, and how to ask it, lives entirely in validators.py — nothing else in the
# system knows what a "New API" is. See GATEWAY_INTEGRATION.md.
import validators as _v

VALIDATOR_KIND, _VALIDATE, _VCFG = _v.from_env()
QUOTA_UNKNOWN, QUOTA_CAP = _v.quota_policy()

_seed_hex = os.environ.get("CP_SEED_HEX", "")
if not _seed_hex:
    raise SystemExit("CP_SEED_HEX (control-plane ed25519 seed, hex) is required")
_CP = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(_seed_hex))

# New API uses a self-signed cert; verify by pin would be better, but for an
# internal control-plane hop we accept it explicitly (no user content flows here).
_TLS = ssl.create_default_context()
_TLS.check_hostname = False
_TLS.verify_mode = ssl.CERT_NONE


def _b64u(b: bytes) -> str:
    return urlsafe_b64encode(b).rstrip(b"=").decode()


def mint_capability(tenant: str, max_tok: int, models=None, ttl: int | None = None) -> str:
    """Mint the exact token the enclave verifies: base64url(json).base64url(sig),
    Ed25519 over the json bytes. Field order is irrelevant — the enclave verifies
    the signature over the bytes we send, then json-unmarshals them."""
    claims = {"tenant": tenant, "pool": DEFAULT_POOL, "models": models or MODELS,
              "max_tok": int(max_tok), "exp": int(time.time()) + (ttl or TTL),
              "isolated": False}
    body = json.dumps(claims, separators=(",", ":")).encode()
    sig = _CP.sign(body)
    return _b64u(body) + "." + _b64u(sig)


def tenant_for(subject: str) -> str:
    """Content-free, stable id for metering. Hashing happens HERE, in one place, so a
    custom validator cannot leak a username or email into signed receipts that get
    published. Defaults to the key, so existing tenant ids do not change; a validator that
    returns a stable subject additionally survives the user rotating their key."""
    return "u_" + hashlib.sha256(subject.encode()).hexdigest()[:16]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        if self.path != "/exchange":
            return self._send(404, {"error": "not found"})
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n)) if n else {}
        except Exception:
            return self._send(400, {"error": "bad json"})
        sk = (body.get("key") or "").strip()
        if not sk:
            return self._send(400, {"error": 'provide the user key as {"key":"..."}'})

        # 1) Ask the configured gateway. A refusal and an outage are different things: the
        #    first is a normal 401, the second is a 503 the operator should alert on — and
        #    neither ever results in a token.
        try:
            v = _VALIDATE(sk, _VCFG)
        except _v.ValidatorUnavailable as e:
            return self._send(503, {"error": f"gateway/validator unavailable: {e}",
                                    "validator": VALIDATOR_KIND})
        if not v.ok:
            return self._send(401, {"error": "the gateway rejected this key"
                                             + (f": {v.reason}" if v.reason else "")})

        # 2) Verified-lane gating, if the operator runs two lanes. Fail CLOSED: a gate that
        #    passes when it cannot prove the group is worse than no gate at all.
        if ALLOWED_GROUPS:
            if v.group is None:
                return self._send(503, {
                    "error": "cannot determine this key's group, refusing to mint "
                             "(fail-closed). Have the validator return `group`."})
            if v.group not in ALLOWED_GROUPS:
                return self._send(403, {
                    "error": f"key is in group '{v.group}', which is not enabled for the "
                             f"verified (enclave) lane. Allowed: {', '.join(ALLOWED_GROUPS)}.",
                    "group": v.group, "allowed_groups": ALLOWED_GROUPS})

        # 3) Unknown quota must never become an unlimited token.
        remaining = v.remaining_usd
        if remaining is None:
            if QUOTA_UNKNOWN == "refuse":
                return self._send(503, {
                    "error": "the gateway did not report remaining quota, refusing to mint. "
                             "Set QUOTA_UNKNOWN=cap:<usd> to allow a bounded token instead."})
            remaining = QUOTA_CAP

        tenant = tenant_for(v.subject or sk)
        ttl = TTL
        if v.expires_at:
            ttl = max(60, min(TTL, int(v.expires_at - time.time())))
        tok = mint_capability(tenant, max_tok=int(remaining * QUOTA_PER_USD),
                              models=(v.models or None), ttl=ttl)
        self._send(200, {
            "capability_token": tok,
            "tenant": tenant,
            "group": v.group,
            "enclave_url": ENCLAVE_URL,
            "expected_measurement": EXPECTED_MEASUREMENT,
            "verify_url": VERIFY_URL,
            "models": v.models or MODELS,
            "note": "verify the enclave (SDK) then call it DIRECTLY with this token; "
                    "cp-adapter and your gateway never see your prompt.",
        })

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"ok": True, "enclave": ENCLAVE_URL,
                                    "validator": VALIDATOR_KIND,
                                    "allowed_groups": ALLOWED_GROUPS,
                                    "quota_unknown": QUOTA_UNKNOWN})
        self._send(404, {"error": "not found"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8091"))
    # Bind loopback by default. cp-adapter answers "is this key valid" and mints spend
    # authority, so it should not be reachable from the internet just because the host has a
    # public IP. Set BIND=0.0.0.0 deliberately if the enclave (or clients) must reach it from
    # off-box, and put it behind TLS/an allowlist when you do.
    bind = os.environ.get("BIND", "127.0.0.1")
    print(f"cp-adapter on {bind}:{port}  newapi={NEWAPI_BASE}  enclave={ENCLAVE_URL}")
    ThreadingHTTPServer((bind, port), H).serve_forever()
