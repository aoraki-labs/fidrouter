"""fidrouter MCP server — lets an agent (Claude Code, etc.) discover, VERIFY, and USE a
verifiable no-log relay, plus get the one-line partner-enable command. Agent-first: the
human UI is optional; this is the programmatic surface.

Run:  pip install "mcp[cli]"  &&  python3 mcp/server.py
Register in Claude Code:  claude mcp add fidrouter -- python3 /path/to/mcp/server.py
Env:  FIDROUTER_PLATFORM (default https://app.fidcore.xyz)
"""
import base64
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "sdk", "python"))
from fidrouter_verify import FidClient, verify_receipt  # noqa: E402

from mcp.server.fastmcp import FastMCP  # noqa: E402

PLATFORM = os.environ.get("FIDROUTER_PLATFORM", "https://app.fidcore.xyz").rstrip("/")
mcp = FastMCP("fidrouter")


def _get(u):
    with urllib.request.urlopen(u, timeout=20) as r:
        return json.loads(r.read())


def _post(u, b):
    req = urllib.request.Request(u, data=json.dumps(b).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


@mcp.tool()
def list_endpoints() -> list:
    """List the verifiable relay endpoints registered in the neutral registry."""
    return _get(PLATFORM + "/api/registry").get("endpoints", [])


@mcp.tool()
def verify_endpoint(base_url: str) -> dict:
    """Independently attest a relay endpoint: read its measurement, confirm it's a published
    build in the registry, and verify the attestation. Returns {ok, measurement, in_registry, detail}."""
    reg = _get(PLATFORM + "/api/registry")
    base = base_url.rstrip("/")
    meas = _get(base + "/attestation?nonce=fid").get("measurement", "")
    build = reg.get("builds", {}).get(meas)
    if not build:
        return {"ok": False, "measurement": meas, "in_registry": False,
                "detail": "measurement not in the public registry"}
    try:
        FidClient(base_url=base, token="", pin_measurement=meas, cs_audience="fidrouter")._attest_and_verify()
        return {"ok": True, "measurement": meas, "in_registry": True,
                "detail": "attestation matches the published reproducible build"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "measurement": meas, "in_registry": True, "detail": str(e)}


@mcp.tool()
def verify_receipt_tool(receipt_b64: str) -> dict:
    """Verify a signed X-Fid-Receipt: signature by a registered enclave + no model downgrade."""
    reg = _get(PLATFORM + "/api/registry")
    rec = json.loads(base64.b64decode(receipt_b64))["receipt"]
    build = reg.get("builds", {}).get(rec.get("measurement", ""))
    if not build:
        return {"ok": False, "reason": "unknown measurement"}
    v = verify_receipt(receipt_b64, build["identity_pub_hex"])
    return {"ok": bool(v.get("signature_ok")), "receipt": rec}


@mcp.tool()
def call(endpoint_id: int, key: str, model: str, message: str) -> str:
    """Verified call: exchange your provider key for a capability token, attest the enclave
    (fail-closed), then run the completion inside the verified no-log enclave. Returns the reply."""
    ex = _post(PLATFORM + "/api/exchange", {"endpoint": endpoint_id, "key": key})
    tok = ex.get("capability_token")
    if not tok:
        return f"exchange failed: {ex.get('error')}"
    base = ex["enclave_url"].rstrip("/")
    FidClient(base_url=base, token="", pin_measurement=ex.get("expected_measurement", ""),
              cs_audience="fidrouter")._attest_and_verify()  # raises if unverified
    resp = _post(base + "/v1/chat/completions", {"model": model,
                 "messages": [{"role": "user", "content": message}]})
    return resp["choices"][0]["message"]["content"] if "choices" in resp else json.dumps(resp)


@mcp.tool()
def enable_command() -> str:
    """The one-line command a relay operator runs to enable a verifiable lane beside their gateway."""
    return "curl -fsSL https://app.fidcore.xyz/enable.sh | bash"


if __name__ == "__main__":
    mcp.run()
