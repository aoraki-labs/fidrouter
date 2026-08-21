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
NEWAPI_ADMIN_TOKEN = os.environ.get("NEWAPI_ADMIN_TOKEN", "")
NEWAPI_ADMIN_USER_ID = os.environ.get("NEWAPI_ADMIN_USER_ID", "1")
# Reading the New API database is a FALLBACK and must be opted into explicitly, because that
# file contains every user's API key in plaintext — far more authority than "what group is
# this key in?" needs. Prefer NEWAPI_ADMIN_TOKEN. See THREAT_MODEL.md.
NEWAPI_DB = os.environ.get("NEWAPI_DB", "")
ALLOW_DB_GROUP_LOOKUP = os.environ.get("ALLOW_DB_GROUP_LOOKUP", "") == "1"

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


def mint_capability(tenant: str, max_tok: int) -> str:
    """Mint the exact token the enclave verifies: base64url(json).base64url(sig),
    Ed25519 over the json bytes. Field order is irrelevant — the enclave verifies
    the signature over the bytes we send, then json-unmarshals them."""
    claims = {"tenant": tenant, "pool": DEFAULT_POOL, "models": MODELS,
              "max_tok": int(max_tok), "exp": int(time.time()) + TTL, "isolated": False}
    body = json.dumps(claims, separators=(",", ":")).encode()
    sig = _CP.sign(body)
    return _b64u(body) + "." + _b64u(sig)


def validate_newapi_key(sk: str):
    """Validate a New API relay token out-of-band and read its remaining quota,
    WITHOUT relaying a real request through New API. Uses the token's own
    dashboard/billing endpoints (TokenAuth). Returns remaining USD or None."""
    req = urllib.request.Request(
        f"{NEWAPI_BASE}/v1/dashboard/billing/subscription",
        headers={"Authorization": f"Bearer {sk}"})
    try:
        with urllib.request.urlopen(req, timeout=8, context=_TLS) as r:
            data = json.loads(r.read())
    except Exception:
        return None
    # valid tokens return hard_limit_usd; invalid ones return an error object
    if "hard_limit_usd" not in data:
        return None
    return float(data.get("hard_limit_usd", 0))


def _group_via_admin_api(sk: str):
    """Resolve a key's group through the New API admin API (works with a remote gateway)."""
    req = urllib.request.Request(
        f"{NEWAPI_BASE}/api/token/?p=0&size=500",
        headers={"Authorization": f"Bearer {NEWAPI_ADMIN_TOKEN}",
                 "New-Api-User": str(NEWAPI_ADMIN_USER_ID)})
    with urllib.request.urlopen(req, timeout=8, context=_TLS) as r:
        data = json.loads(r.read())
    items = data.get("data")
    if isinstance(items, dict):  # some builds wrap the page as {items:[...]}
        items = items.get("items") or items.get("records") or []
    bare = sk[3:] if sk.startswith("sk-") else sk
    for it in items or []:
        if it.get("key") == bare:
            return (it.get("group") or "").strip(), it.get("user_id")
    return None, None


def _group_via_db(sk: str):
    """Resolve a key's group by reading the New API DB read-only (colocated deployment)."""
    import sqlite3
    bare = sk[3:] if sk.startswith("sk-") else sk
    con = sqlite3.connect(f"file:{NEWAPI_DB}?mode=ro", uri=True, timeout=5)
    try:
        row = con.execute(
            'select "group", user_id, status from tokens where key=? and (deleted_at is null)',
            (bare,)).fetchone()
        if not row:
            return None, None
        grp, uid, status = (row[0] or "").strip(), row[1], row[2]
        if status != 1:
            return None, uid  # disabled/expired token → refuse
        if not grp:  # empty token group means "inherit the user's group"
            urow = con.execute('select "group" from users where id=?', (uid,)).fetchone()
            grp = ((urow[0] if urow else "") or "").strip()
        return grp, uid
    finally:
        con.close()


def group_for(sk: str):
    """Resolve a key's group. Returns (group, user_id); group None = unresolvable (caller
    fails closed). Admin API first; the DB read is only used when explicitly enabled."""
    if NEWAPI_ADMIN_TOKEN:
        try:
            return _group_via_admin_api(sk)
        except Exception:  # noqa: BLE001 — fall through to the opt-in DB path
            pass
    if ALLOW_DB_GROUP_LOOKUP and NEWAPI_DB and os.path.exists(NEWAPI_DB):
        try:
            return _group_via_db(sk)
        except Exception:  # noqa: BLE001
            return None, None
    return None, None


def tenant_for(sk: str) -> str:
    """Content-free, stable per-token id. Lets metering attribute usage to *this*
    New API token without the enclave or console ever seeing the key itself."""
    return "u_" + hashlib.sha256(sk.encode()).hexdigest()[:16]


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
        if not sk.startswith("sk-"):
            return self._send(400, {"error": "provide New API key as {\"key\":\"sk-...\"}"})
        remaining_usd = validate_newapi_key(sk)
        if remaining_usd is None:
            return self._send(401, {"error": "New API rejected this key (invalid/expired/no quota)"})
        group = None
        if ALLOWED_GROUPS:
            # Verified lane is gated by group. Fail CLOSED: if we cannot prove which group
            # the key belongs to, we must not mint a token — a silent pass would make the
            # whole gate meaningless.
            group, _uid = group_for(sk)
            if group is None:
                return self._send(503, {
                    "error": "cannot resolve this key's group, refusing to mint (fail-closed). "
                             "Configure NEWAPI_ADMIN_TOKEN or NEWAPI_DB on cp-adapter."})
            if group not in ALLOWED_GROUPS:
                return self._send(403, {
                    "error": f"key is in group '{group}', which is not enabled for the verified "
                             f"(enclave) lane. Allowed: {', '.join(ALLOWED_GROUPS)}.",
                    "group": group, "allowed_groups": ALLOWED_GROUPS})
        tenant = tenant_for(sk)
        tok = mint_capability(tenant, max_tok=int(remaining_usd * QUOTA_PER_USD))
        self._send(200, {
            "capability_token": tok,
            "tenant": tenant,
            "group": group,
            "enclave_url": ENCLAVE_URL,
            "expected_measurement": EXPECTED_MEASUREMENT,
            "verify_url": VERIFY_URL,
            "models": MODELS,
            "note": "verify the enclave (SDK) then call it DIRECTLY with this token; "
                    "cp-adapter and New API never see your prompt.",
        })

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"ok": True, "newapi": NEWAPI_BASE, "enclave": ENCLAVE_URL,
                                    "allowed_groups": ALLOWED_GROUPS,
                                    "group_lookup": ("admin-api" if NEWAPI_ADMIN_TOKEN else
                                                     "db(opt-in)" if (ALLOW_DB_GROUP_LOOKUP and NEWAPI_DB)
                                                     else "none")})
        self._send(404, {"error": "not found"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8091"))
    print(f"cp-adapter on :{port}  newapi={NEWAPI_BASE}  enclave={ENCLAVE_URL}")
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
