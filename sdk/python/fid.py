"""fid — drop-in verified client for fidrouter.

    from fid import OpenAI                       # <- the ONLY line that changes
    client = OpenAI(api_key="<token>", base_url="http://<enclave>:9090")
    r = client.chat.completions.create(model="claude-opus-5",
                                       messages=[{"role":"user","content":"hi"}])
    print(r.choices[0].message.content)          # identical to the openai SDK
    print(r.fid.verified, r.fid.measurement)     # + proof extras

Same surface as `openai.OpenAI` for `chat.completions.create`, but every call is
attested end-to-end: the client fetches the enclave's remote-attestation quote,
checks its measurement against the EXPECTED value published by an INDEPENDENT
registry (not the operator), verifies the signature chain, seals the prompt to
the attested key, and verifies the signed receipt (anti-downgrade). If any step
fails it raises BEFORE sending — the prompt never leaves the machine (fail-closed).

The "extra info" verification needs beyond the api key — the expected measurement
— is fetched automatically from `verify_registry` (the public verification page),
so the caller still only provides {base_url, api_key}.
"""
from __future__ import annotations

import json
import urllib.request

from fidrouter_verify import FidClient, FidVerificationError  # noqa: F401 (re-exported)

__all__ = ["OpenAI", "FidVerificationError"]


class _Message:
    def __init__(self, content: str):
        self.role = "assistant"
        self.content = content


class _Choice:
    def __init__(self, content: str):
        self.index = 0
        self.message = _Message(content)
        self.finish_reason = "stop"


class _Usage:
    def __init__(self, p: int, c: int):
        self.prompt_tokens = p
        self.completion_tokens = c
        self.total_tokens = p + c


class _Fid:
    """fidrouter proof metadata attached to every response."""
    def __init__(self, res):
        self.verified = True          # reached here => attestation + receipt passed (else it raised)
        self.measurement = res.receipt.get("measurement", "")
        self.account = res.account
        self.cache_hit = res.cache_hit
        self.receipt = res.receipt    # signed; lodge in the explorer for an audit trail


class ChatCompletion:
    def __init__(self, res, model: str):
        self.object = "chat.completion"
        self.model = model
        self.choices = [_Choice(res.completion)]
        self.usage = _Usage(res.prompt_tokens, res.completion_tokens)
        self.fid = _Fid(res)


def _exchange(cp_adapter: str, api_token: str, pool: str) -> str:
    """Trade a New API token (sk-...) for a capability token via cp-adapter, so the
    user pastes their normal New API key and the SDK handles the rest."""
    body = json.dumps({"api_token": api_token, "pool": pool}).encode()
    req = urllib.request.Request(cp_adapter.rstrip("/") + "/exchange", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        tok = json.loads(r.read()).get("token")
    if not tok:
        raise FidVerificationError("cp-adapter did not return a capability token (bad New API key?)")
    return tok


def _resolve_expected(registry_url: str, base_url: str) -> str:
    """Fetch the EXPECTED measurement for base_url from the independent registry.
    This is the trust anchor — it must come from the neutral verifier, not the
    operator. No match => no published good build => refuse (fail-closed)."""
    url = registry_url.rstrip("/") + "/api/status"
    with urllib.request.urlopen(url, timeout=15) as r:
        rows = json.loads(r.read())
    want = base_url.rstrip("/")
    for e in rows:
        if e.get("base_url", "").rstrip("/") == want:
            m = e.get("expected") or e.get("measurement")
            if m:
                return m
    raise FidVerificationError(
        f"no published measurement for {base_url} in registry {registry_url} — refusing to send")


class _Completions:
    def __init__(self, client: "OpenAI"):
        self._client = client

    def create(self, model: str, messages: list, **_ignored) -> ChatCompletion:
        res = self._client._fid.chat(model, messages)  # attest+seal+verify inside, fail-closed
        return ChatCompletion(res, model)


class _Chat:
    def __init__(self, client: "OpenAI"):
        self.completions = _Completions(client)


class OpenAI:
    """Drop-in, verified. Provide {api_key, base_url}. The expected measurement is
    auto-fetched from `verify_registry` unless you pin it explicitly."""
    def __init__(self, api_key: str, base_url: str,
                 verify_registry: str = "", pin_measurement: str = "",
                 cs_audience: str = "fidrouter", cp_adapter: str = "", pool: str = "shared"):
        # If cp_adapter is set, api_key is a New API token (sk-...) → exchange it
        # for a capability token. Otherwise api_key is already a capability token.
        token = _exchange(cp_adapter, api_key, pool) if cp_adapter else api_key
        if not pin_measurement:
            if not verify_registry:
                raise FidVerificationError(
                    "pass verify_registry=<public verification page URL> (or pin_measurement=...) "
                    "so verification has an independent expected value")
            pin_measurement = _resolve_expected(verify_registry, base_url)
        self._fid = FidClient(base_url=base_url, token=token,
                              pin_measurement=pin_measurement, cs_audience=cs_audience)
        self.chat = _Chat(self)
