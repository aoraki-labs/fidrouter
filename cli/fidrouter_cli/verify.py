"""fidrouter verify SDK (Python) — the drop-in client that refuses to send a
prompt until it has cryptographically verified the enclave.

Byte-compatible with the Go data plane:
  channel key = SHA256( X25519(client_priv, enclave_pub) || b"fid-e2e-v1" )
  sealing     = AES-256-GCM, 12-byte nonce prepended, AAD = session bytes
  quote sig   = Ed25519 over (measurement||report_data as utf8) || ephemeral_pub
  receipt sig = Ed25519 over Go's json.Marshal(receipt) (canonical form below)

Deps: `cryptography`. Stdlib for HTTP/JSON/base64.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import urllib.request
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

INFO = b"fid-e2e-v1"
CS_ISS = "https://confidentialcomputing.googleapis.com"
CS_JWKS = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class FidVerificationError(Exception):
    """Raised whenever verification fails. The SDK is fail-closed: on this error
    NOTHING was sent (attestation stage) or the response is NOT trusted."""


@dataclass
class InferResult:
    completion: str
    cache_hit: bool
    account: str
    affinity: bool
    model: str
    prompt_tokens: int
    completion_tokens: int
    receipt: dict


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _jstr(s: str) -> str:
    # Match Go's json string encoding (HTML-escape on, as encoding/json default).
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '<':
            out.append('\\u003c')
        elif ch == '>':
            out.append('\\u003e')
        elif ch == '&':
            out.append('\\u0026')
        elif o < 0x20:
            out.append('\\u%04x' % o)
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def verify_receipt(receipt_b64: str, idpub_hex: str) -> dict:
    """PUBLIC: verify a signed receipt (base64 of the X-Fid-Receipt header / sealed
    receipt). `idpub_hex` is the enclave identity public key (published in the
    registry, keyed by measurement). Returns {ok, reason, receipt, signature_ok}.
    Anti-downgrade: read receipt['model'] and compare to what you requested."""
    try:
        signed = json.loads(base64.b64decode(receipt_b64))
        rec = signed["receipt"]
        sig = base64.b64decode(signed["sig"])
    except Exception as e:
        return {"ok": False, "reason": f"malformed receipt: {e}", "receipt": {}, "signature_ok": False}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(idpub_hex)).verify(sig, _canonical_receipt(rec))
        sig_ok = True
    except InvalidSignature:
        sig_ok = False
    return {"ok": sig_ok, "receipt": rec, "signature_ok": sig_ok,
            "reason": "signature valid — this receipt was signed by the registered enclave key"
                      if sig_ok else "signature invalid — not signed by the registered enclave key (forged/tampered)"}


def _canonical_receipt(r: dict) -> bytes:
    # Field order MUST match the Go struct receipt.Receipt.
    return (
        '{'
        f'"ts_unix":{int(r["ts_unix"])},'
        f'"tenant":{_jstr(r["tenant"])},'
        f'"model":{_jstr(r["model"])},'
        f'"account":{_jstr(r["account"])},'
        f'"req_hash":{_jstr(r["req_hash"])},'
        f'"resp_hash":{_jstr(r["resp_hash"])},'
        f'"prompt_tokens":{int(r["prompt_tokens"])},'
        f'"completion_tokens":{int(r["completion_tokens"])},'
        f'"cache_hit":{"true" if r["cache_hit"] else "false"},'
        f'"measurement":{_jstr(r["measurement"])}'
        '}'
    ).encode()


def _tls_ctx(url: str):
    """RA-TLS: for https we do NOT validate the CA — trust comes from the attestation
    (we match the presented cert's key against the attested tls_pub). Returns an
    unverified SSLContext for https, None for http."""
    if url.startswith("https://"):
        import ssl
        return ssl._create_unverified_context()
    return None


def _http_get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=20, context=_tls_ctx(url)) as resp:
        return json.loads(resp.read())


def _peer_spki(base_url: str):
    """RA-TLS: return the DER SubjectPublicKeyInfo of the server's TLS cert, or None
    if base_url isn't https. We do NOT trust the CA here — attestation is the trust
    anchor; we only need the presented key to compare against the attested one."""
    from urllib.parse import urlparse
    u = urlparse(base_url)
    if u.scheme != "https":
        return None
    import socket
    import ssl

    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    ctx = ssl._create_unverified_context()
    with socket.create_connection((u.hostname, u.port or 443), timeout=15) as sock:
        with ctx.wrap_socket(sock, server_hostname=u.hostname) as ss:
            der = ss.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der)
    return cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def _http_post(url: str, body: dict) -> tuple[int, bytes]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20, context=_tls_ctx(url)) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


class FidClient:
    def __init__(self, base_url: str, token: str, pin_measurement: str = "", pin_idpub_hex: str = "",
                 pccs_url: str = "", dcap_backend=None, dcap_allow_unverified: bool = False,
                 cs_audience: str = "fidrouter"):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.pin_measurement = pin_measurement  # TDX: MRTD; Confidential Space: container image_digest
        self.pin_idpub = bytes.fromhex(pin_idpub_hex) if pin_idpub_hex else b""
        # TDX/DCAP path config (used when the endpoint's platform != "mock-*")
        self.pccs_url = pccs_url
        self.dcap_backend = dcap_backend
        self.dcap_allow_unverified = dcap_allow_unverified
        self.cs_audience = cs_audience
        self._cs_jwks = None

    # --- core: verify enclave, seal prompt, send, verify receipt ---
    def infer(self, model: str, prefix: str, suffix: str) -> InferResult:
        q = self._attest_and_verify()  # fail-closed inside

        # derive channel key bound to the attested ephemeral key
        cpriv = X25519PrivateKey.generate()
        cpub = cpriv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        shared = cpriv.exchange(X25519PublicKey.from_public_bytes(q["ephemeral_pub"]))
        key = hashlib.sha256(shared + INFO).digest()

        session = q["session"]
        inner = json.dumps({"model": model, "prefix": prefix, "suffix": suffix}).encode()
        sealed = self._seal(key, inner, session.encode())

        status, raw = _http_post(self.base_url + "/v1/infer", {
            "session": session, "client_pub": _b64e(cpub), "token": self.token, "sealed": _b64e(sealed),
        })
        if status != 200:
            raise FidVerificationError(f"infer rejected ({status}): {raw[:200]!r}")
        out = json.loads(raw)

        # verify signed receipt: signature, measurement, and model==requested (anti-downgrade)
        rec = out["receipt"]["receipt"]
        sig = _b64d(out["receipt"]["sig"])
        idpub = self.pin_idpub or q["identity_pub"]
        try:
            Ed25519PublicKey.from_public_bytes(idpub).verify(sig, _canonical_receipt(rec))
        except InvalidSignature:
            raise FidVerificationError("receipt signature invalid")
        if self.pin_measurement and rec["measurement"] != self.pin_measurement:
            raise FidVerificationError("receipt measurement mismatch")
        if rec["model"] != model:
            raise FidVerificationError(f"MODEL DOWNGRADE: asked {model}, receipt says {rec['model']}")

        resp_plain = self._open(key, _b64d(out["sealed_resp"]), session.encode())
        ur = json.loads(resp_plain)
        return InferResult(
            completion=ur["completion"], cache_hit=ur["cache_hit"], model=rec["model"],
            account=out["route"]["account"], affinity=out["route"]["affinity"],
            prompt_tokens=ur["prompt_tokens"], completion_tokens=ur["completion_tokens"], receipt=rec,
        )

    # OpenAI-ish convenience: split messages into cacheable prefix + variable tail.
    def chat(self, model: str, messages: list[dict]) -> InferResult:
        prefix = "\n".join(f'{m["role"]}: {m["content"]}' for m in messages[:-1])
        suffix = messages[-1]["content"] if messages else ""
        return self.infer(model, prefix, suffix)

    # --- attestation (L1) ---
    def _attest_and_verify(self) -> dict:
        raw = secrets.token_bytes(16)
        nonce_hex = raw.hex()
        qj = _http_get(self.base_url + "/attestation?nonce=" + nonce_hex)
        # Dispatch by platform.
        plat = qj["platform"]
        if plat == "gcp-cs":                        # Confidential Space: Google-signed OIDC token
            return self._verify_cs(qj, nonce_hex)
        if not plat.startswith("mock"):             # raw TDX quote -> DCAP path
            return self._verify_tdx(qj, nonce_hex)
        q = {
            "platform": qj["platform"], "measurement": qj["measurement"], "session": qj["session"],
            "report_data": qj["report_data"],
            "nonce": _b64d(qj["nonce"]), "ephemeral_pub": _b64d(qj["ephemeral_pub"]),
            "identity_pub": _b64d(qj["identity_pub"]), "sig": _b64d(qj["sig"]),
        }
        if self.pin_measurement and q["measurement"] != self.pin_measurement:
            raise FidVerificationError(
                f"measurement mismatch\n  got:    {q['measurement']}\n  pinned: {self.pin_measurement}\n"
                "  (running build is not the audited no-log code — refusing)")
        if self.pin_idpub and q["identity_pub"] != self.pin_idpub:
            raise FidVerificationError("identity pubkey mismatch (not the enclave we trust)")
        body = (q["measurement"] + q["report_data"]).encode() + q["ephemeral_pub"]
        try:
            Ed25519PublicKey.from_public_bytes(q["identity_pub"]).verify(q["sig"], body)
        except InvalidSignature:
            raise FidVerificationError("quote signature invalid")
        if q["nonce"] != nonce_hex.encode():
            raise FidVerificationError("enclave did not echo our nonce (possible replay)")
        rd = hashlib.sha256(q["nonce"] + q["ephemeral_pub"] + self._tls_binding(qj)).hexdigest()
        if rd != q["report_data"]:
            raise FidVerificationError("report_data not bound to nonce+key (possible replay)")
        return q

    def _tls_binding(self, qj: dict) -> bytes:
        """RA-TLS: if the quote binds a TLS cert key (tls_pub), fold it into the bind AND
        require the cert the server actually presented (over https) to match it — else a
        proxy could relay a valid quote while terminating TLS itself (MITM). Returns the
        bound SPKI (b'' when the quote has no TLS binding, e.g. plain-HTTP enclaves)."""
        tp = qj.get("tls_pub")
        if not tp:
            return b""
        spki = _b64d(tp)
        peer = _peer_spki(self.base_url)
        if peer is not None and peer != spki:
            raise FidVerificationError(
                "RA-TLS: server TLS cert does not match the attested TLS key (possible MITM)")
        return spki

    def _verify_tdx(self, qj: dict, nonce_hex: str) -> dict:
        """Real-hardware path: verify an Intel TDX quote via DCAP (skeleton).
        Expects the endpoint to return {platform, raw_quote(b64), ephemeral_pub(b64),
        nonce(b64), session, receipt_pub(b64 optional)}."""
        from . import dcap  # local import so the mock path has no dcap dependency

        raw_quote = _b64d(qj["raw_quote"])
        eph = _b64d(qj["ephemeral_pub"])
        idpub = _b64d(qj["identity_pub"])
        nonce_echo = _b64d(qj["nonce"])
        if nonce_echo != nonce_hex.encode():
            raise FidVerificationError("enclave did not echo our nonce (possible replay)")
        # report_data (first 32B) binds nonce + channel key + receipt-signing key,
        # so DCAP-verifying the quote anchors ALL THREE to the attested measurement.
        expected_rd = hashlib.sha256(nonce_echo + eph + idpub + self._tls_binding(qj)).digest()
        backend = self.dcap_backend or (
            dcap.QvlBackend(self.pccs_url) if self.pccs_url else dcap.StubBackend())
        try:
            dcap.verify_tdx_quote(
                raw_quote, pinned_measurement=self.pin_measurement,
                expected_report_data=expected_rd, backend=backend,
                allow_unverified=self.dcap_allow_unverified)
        except dcap.DcapError as e:
            raise FidVerificationError(f"TDX quote verification failed: {e}")
        # receipt-signing pubkey is now bound into report_data (verified above).
        return {"session": qj["session"], "ephemeral_pub": eph, "identity_pub": idpub}

    def _verify_cs(self, qj: dict, nonce_hex: str) -> dict:
        """GCP Confidential Space path: verify the Google-signed OIDC attestation
        token — its `submods.container.image_digest` claim is OUR container's
        digest, so pinning it means the measurement covers our code."""
        token = _b64d(qj["raw_quote"]).decode()
        eph = _b64d(qj["ephemeral_pub"])
        idpub = _b64d(qj["identity_pub"])
        nonce_echo = _b64d(qj["nonce"])
        if nonce_echo != nonce_hex.encode():
            raise FidVerificationError("enclave did not echo our nonce (possible replay)")
        expected_bind = hashlib.sha256(nonce_echo + eph + idpub + self._tls_binding(qj)).hexdigest()

        claims = self._cs_verify_jwt(token)
        if claims.get("iss") != CS_ISS:
            raise FidVerificationError(f"CS token iss mismatch: {claims.get('iss')}")
        if claims.get("exp") and time.time() > claims["exp"]:
            raise FidVerificationError("CS token expired")
        if self.cs_audience and claims.get("aud") != self.cs_audience:
            raise FidVerificationError(f"CS token aud mismatch: {claims.get('aud')}")
        eat = claims.get("eat_nonce")
        eat = [eat] if isinstance(eat, str) else (eat or [])
        if expected_bind not in eat:
            raise FidVerificationError("eat_nonce not bound to nonce+keys (replay/mismatch)")
        digest = ((claims.get("submods") or {}).get("container") or {}).get("image_digest", "")
        if self.pin_measurement and digest != self.pin_measurement:
            raise FidVerificationError(
                f"image_digest mismatch\n  got:    {digest}\n  pinned: {self.pin_measurement}\n"
                "  (running container is not the audited no-log image — refusing)")
        if claims.get("swname") != "CONFIDENTIAL_SPACE":
            raise FidVerificationError(f"not Confidential Space (swname={claims.get('swname')})")
        return {"session": qj["session"], "ephemeral_pub": eph, "identity_pub": idpub}

    def _cs_verify_jwt(self, token: str) -> dict:
        h64, p64, s64 = token.split(".")
        header = json.loads(_b64url(h64))
        if header.get("alg") != "RS256":
            raise FidVerificationError(f"unexpected CS token alg {header.get('alg')}")
        if self._cs_jwks is None:
            self._cs_jwks = _http_get(CS_JWKS)
        jwk = next((k for k in self._cs_jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
        if jwk is None:
            raise FidVerificationError(f"CS JWKS has no key for kid={header.get('kid')}")
        n = int.from_bytes(_b64url(jwk["n"]), "big")
        e = int.from_bytes(_b64url(jwk["e"]), "big")
        try:
            RSAPublicNumbers(e, n).public_key().verify(
                _b64url(s64), (h64 + "." + p64).encode(), padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            raise FidVerificationError("CS token signature invalid")
        return json.loads(_b64url(p64))

    @staticmethod
    def _seal(key: bytes, pt: bytes, aad: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + AESGCM(key).encrypt(nonce, pt, aad)

    @staticmethod
    def _open(key: bytes, blob: bytes, aad: bytes) -> bytes:
        return AESGCM(key).decrypt(blob[:12], blob[12:], aad)
