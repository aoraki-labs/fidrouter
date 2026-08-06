#!/usr/bin/env python3
"""fidrouter CLI — verify, use, and enable a verifiable no-log relay. Agent-friendly:
every command prints JSON on stdout and exits non-zero on failure.

  fidrouter verify <enclave-url>            # independently attest an endpoint
  fidrouter endpoints                        # list registered endpoints (from the registry)
  fidrouter receipt <X-Fid-Receipt>          # verify a signed receipt
  fidrouter call --endpoint 3 --key sk- --model claude-opus-5 --message "hi"
  fidrouter enable                           # print the one-line partner installer

Env: FIDROUTER_PLATFORM (default https://app.fidcore.xyz).
"""
import argparse
import json
import os
import sys
import urllib.request

from .verify import FidClient, verify_receipt

PLATFORM = os.environ.get("FIDROUTER_PLATFORM", "https://app.fidcore.xyz").rstrip("/")


def _get(url):
    with urllib.request.urlopen(url, timeout=20) as r:
        return json.loads(r.read())


def _post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def _registry():
    return _get(PLATFORM + "/api/registry")


def cmd_verify(a):
    """Independently attest an endpoint against the registry (fail-closed)."""
    reg = _registry()
    base = a.url.rstrip("/")
    meas = _get(base + "/attestation?nonce=fid").get("measurement", "")
    build = reg.get("builds", {}).get(meas)
    out = {"base_url": base, "measurement": meas, "in_registry": bool(build)}
    if build:
        try:
            FidClient(base_url=base, token="", pin_measurement=meas, cs_audience="fidrouter")._attest_and_verify()
            out["ok"] = True
        except Exception as e:  # noqa: BLE001
            out["ok"] = False
            out["detail"] = str(e)
    else:
        out["ok"] = False
        out["detail"] = "measurement not in the public registry"
    print(json.dumps(out, indent=2))
    sys.exit(0 if out.get("ok") else 1)


def cmd_endpoints(a):
    print(json.dumps(_registry().get("endpoints", []), indent=2))


def cmd_receipt(a):
    reg = _registry()
    import base64
    rec = json.loads(base64.b64decode(a.receipt))["receipt"]
    build = reg.get("builds", {}).get(rec.get("measurement", ""))
    if not build:
        print(json.dumps({"ok": False, "reason": "unknown measurement"})); sys.exit(1)
    v = verify_receipt(a.receipt, build["identity_pub_hex"])
    print(json.dumps({"ok": bool(v.get("signature_ok")), "receipt": rec}, indent=2))
    sys.exit(0 if v.get("signature_ok") else 1)


def cmd_call(a):
    """Exchange the key -> capability token, verify the enclave, then call it."""
    ex = _post(PLATFORM + "/api/exchange", {"endpoint": a.endpoint, "key": a.key})
    tok = ex.get("capability_token")
    if not tok:
        print(json.dumps({"ok": False, "error": ex.get("error", "exchange failed")})); sys.exit(1)
    base = ex["enclave_url"].rstrip("/")
    meas = ex.get("expected_measurement", "")
    try:  # fail-closed: verify before sending
        FidClient(base_url=base, token="", pin_measurement=meas, cs_audience="fidrouter")._attest_and_verify()
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": f"attestation failed: {e}"})); sys.exit(1)
    resp = _post(base + "/v1/chat/completions", {"model": a.model,
                 "messages": [{"role": "user", "content": a.message}]})
    print(resp["choices"][0]["message"]["content"] if "choices" in resp else json.dumps(resp))


def cmd_enable(a):
    print("curl -fsSL https://app.fidcore.xyz/enable.sh | bash")


def main():
    p = argparse.ArgumentParser(prog="fidrouter")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify"); v.add_argument("url"); v.set_defaults(f=cmd_verify)
    sub.add_parser("endpoints").set_defaults(f=cmd_endpoints)
    r = sub.add_parser("receipt"); r.add_argument("receipt"); r.set_defaults(f=cmd_receipt)
    c = sub.add_parser("call")
    c.add_argument("--endpoint", type=int, required=True); c.add_argument("--key", required=True)
    c.add_argument("--model", default="claude-opus-5"); c.add_argument("--message", required=True)
    c.set_defaults(f=cmd_call)
    sub.add_parser("enable").set_defaults(f=cmd_enable)
    a = p.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
