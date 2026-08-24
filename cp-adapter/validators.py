"""Validators — the only place cp-adapter knows anything about a specific gateway.

fidrouter is meant to work with ANY gateway, so "is this key valid, and what may it do" is
answered by a pluggable validator rather than hard-coded against one product. Everything else
in cp-adapter (and the enclave, and the platform) only ever sees the Verdict below.

Three built-ins cover the space:

  newapi  read New API's dashboard/billing endpoint. Works with an unmodified New API, but it
          is a *dashboard* endpoint, not an auth API: its shape is a de-facto contract that
          can change between versions, and it reports the USER's limit rather than the token's
          own remaining quota. Give it an admin token to get the token's real quota + group.
  http    our documented contract, for any gateway willing to add ~20 lines:
              POST {gateway}/fid/validate  {"key": "..."}  ->  Verdict JSON
          Rejection is 200 with ok:false, NOT 4xx, so "the gateway says no" is distinguishable
          from "the gateway is broken" — the first is a normal refusal, the second must page
          someone and must never be cached.
  exec    run a local command: stdin gets {"key": ...}, stdout returns the Verdict. The
          universal escape hatch — any gateway, any database, any language, no code from us.
          The key goes on STDIN, never argv, because argv is world-readable via /proc.

A validator is only ever consulted. It never signs anything and never sees a prompt, so a
buggy or hostile one can grant access within that operator's own system and nothing more.
"""
import json
import os
import ssl
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field


class ValidatorUnavailable(Exception):
    """The gateway could not be reached / the validator failed. Distinct from a refusal:
    callers must fail closed AND surface this, because it is an outage, not a verdict."""


@dataclass
class Verdict:
    ok: bool
    subject: str = ""                       # opaque id in the operator's system (NOT a name/email)
    remaining_usd: float | None = None      # None = unknown -> policy decides, never "unlimited"
    group: str | None = None                # lane label, for verified-lane gating
    models: list[str] = field(default_factory=list)
    expires_at: int | None = None
    reason: str = ""

    @classmethod
    def from_json(cls, d: dict) -> "Verdict":
        if not isinstance(d, dict):
            raise ValidatorUnavailable("validator returned a non-object")
        if not d.get("ok"):
            return cls(ok=False, reason=str(d.get("reason", ""))[:200])
        rem = d.get("remaining_usd")
        models = d.get("models") or []
        return cls(
            ok=True,
            subject=str(d.get("subject") or ""),
            remaining_usd=(float(rem) if isinstance(rem, (int, float)) else None),
            group=(str(d["group"]) if d.get("group") not in (None, "") else None),
            models=[str(m) for m in models if str(m)],
            expires_at=(int(d["expires_at"]) if str(d.get("expires_at") or "").isdigit() else None),
        )


def _tls_ctx():
    # Partner gateways commonly run self-signed certs. This hop carries a credential but no
    # user content, and the operator chose the endpoint. TODO: honour a per-gateway cert pin.
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


# ---- newapi ---------------------------------------------------------------------------
def _newapi(key: str, cfg: dict) -> Verdict:
    base = cfg["base"].rstrip("/")
    req = urllib.request.Request(base + cfg.get("path", "/v1/dashboard/billing/subscription"),
                                 headers={"Authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(req, timeout=8, context=_tls_ctx()) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        # New API answers 401/403 for a bad token: that is a genuine refusal, not an outage.
        if e.code in (401, 403):
            return Verdict(ok=False, reason=f"gateway rejected the key ({e.code})")
        raise ValidatorUnavailable(f"gateway HTTP {e.code}") from e
    except Exception as e:  # noqa: BLE001
        raise ValidatorUnavailable(f"gateway unreachable: {e}") from e
    if "hard_limit_usd" not in data:
        return Verdict(ok=False, reason="gateway rejected the key")
    remaining = float(data.get("hard_limit_usd") or 0)
    group = None
    if cfg.get("admin_token"):
        # Optional and more precise: the token's OWN group and remaining quota. Requires a
        # broad admin credential, which is why it is opt-in rather than the default.
        try:
            areq = urllib.request.Request(
                f"{base}/api/token/?p=0&size=500",
                headers={"Authorization": f"Bearer {cfg['admin_token']}",
                         "New-Api-User": str(cfg.get("admin_user_id", "1"))})
            with urllib.request.urlopen(areq, timeout=8, context=_tls_ctx()) as r:
                items = json.loads(r.read()).get("data")
            if isinstance(items, dict):
                items = items.get("items") or items.get("records") or []
            bare = key[3:] if key.startswith("sk-") else key
            for it in items or []:
                if it.get("key") == bare:
                    group = (it.get("group") or "").strip() or None
                    if not it.get("unlimited_quota") and it.get("remain_quota") is not None:
                        per_usd = float(cfg.get("quota_per_usd", 500000)) or 500000.0
                        remaining = min(remaining, float(it["remain_quota"]) / per_usd)
                    break
        except Exception:  # noqa: BLE001 — admin lookup is best-effort; quota above still applies
            pass
    return Verdict(ok=True, subject=key, remaining_usd=remaining, group=group)


# ---- http (our documented contract) ---------------------------------------------------
def _http(key: str, cfg: dict) -> Verdict:
    url = cfg["url"]
    hdrs = {"Content-Type": "application/json"}
    if cfg.get("secret"):
        hdrs["Authorization"] = f"Bearer {cfg['secret']}"
    req = urllib.request.Request(url, data=json.dumps({"key": key}).encode(), headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=8, context=_tls_ctx()) as r:
            return Verdict.from_json(json.loads(r.read()))
    except urllib.error.HTTPError as e:
        # A conforming gateway signals refusal with 200 + ok:false. A 4xx/5xx here means the
        # endpoint is misconfigured or down, which must not be read as "key is invalid".
        raise ValidatorUnavailable(f"validator endpoint HTTP {e.code}") from e
    except Exception as e:  # noqa: BLE001
        raise ValidatorUnavailable(f"validator endpoint unreachable: {e}") from e


# ---- exec -----------------------------------------------------------------------------
def _exec(key: str, cfg: dict) -> Verdict:
    cmd = cfg["cmd"]
    try:
        p = subprocess.run(cmd if isinstance(cmd, list) else [cmd],
                           input=json.dumps({"key": key}).encode(),  # stdin, never argv
                           capture_output=True, timeout=float(cfg.get("timeout", 8)))
    except Exception as e:  # noqa: BLE001
        raise ValidatorUnavailable(f"validator command failed to run: {e}") from e
    if p.returncode != 0:
        raise ValidatorUnavailable(
            f"validator command exited {p.returncode}: {p.stderr.decode(errors='replace')[:160]}")
    try:
        return Verdict.from_json(json.loads(p.stdout or b"{}"))
    except ValidatorUnavailable:
        raise
    except Exception as e:  # noqa: BLE001
        raise ValidatorUnavailable(f"validator command returned unparseable output: {e}") from e


_KINDS = {"newapi": _newapi, "http": _http, "exec": _exec}


def from_env(env=None) -> tuple[str, callable, dict]:
    """Build the configured validator. Returns (kind, fn, cfg)."""
    e = env if env is not None else os.environ
    kind = (e.get("VALIDATOR") or "newapi").strip().lower()
    if kind not in _KINDS:
        raise SystemExit(f"VALIDATOR must be one of {', '.join(_KINDS)} (got {kind!r})")
    if kind == "newapi":
        base = e.get("NEWAPI_BASE") or ""
        if not base:
            raise SystemExit("VALIDATOR=newapi needs NEWAPI_BASE")
        cfg = {"base": base,
               "path": e.get("NEWAPI_VALIDATE_PATH", "/v1/dashboard/billing/subscription"),
               "admin_token": e.get("NEWAPI_ADMIN_TOKEN", ""),
               "admin_user_id": e.get("NEWAPI_ADMIN_USER_ID", "1"),
               "quota_per_usd": e.get("QUOTA_PER_USD", "500000")}
    elif kind == "http":
        url = e.get("VALIDATOR_URL") or ""
        if not url:
            raise SystemExit("VALIDATOR=http needs VALIDATOR_URL")
        cfg = {"url": url, "secret": e.get("VALIDATOR_SECRET", "")}
    else:
        cmd = e.get("VALIDATOR_CMD") or ""
        if not cmd:
            raise SystemExit("VALIDATOR=exec needs VALIDATOR_CMD")
        cfg = {"cmd": cmd, "timeout": e.get("VALIDATOR_TIMEOUT", "8")}
    return kind, _KINDS[kind], cfg


def quota_policy(env=None):
    """How to treat a verdict with unknown quota. Default refuse: minting an effectively
    unlimited token because we could not read a limit is the wrong direction to fail."""
    e = env if env is not None else os.environ
    raw = (e.get("QUOTA_UNKNOWN") or "refuse").strip().lower()
    if raw == "refuse":
        return ("refuse", 0.0)
    if raw.startswith("cap:"):
        try:
            return ("cap", float(raw.split(":", 1)[1]))
        except ValueError:
            pass
    raise SystemExit("QUOTA_UNKNOWN must be 'refuse' or 'cap:<usd>'")
