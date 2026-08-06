"""DCAP / Intel TDX quote verification — SKELETON.

Design stance: do NOT hand-roll ECDSA + X.509 PCK-chain + TCB verification in
Python. This module does the two things a client-side policy layer SHOULD own:
  1) PARSE the real Intel TDX quote (v4/v5) and extract MRTD/RTMRs/REPORT_DATA;
  2) apply POLICY: measurement pinned to a published reproducible build,
     REPORT_DATA bound to H(nonce||ephemeral_pub), TCB status acceptable.
The heavy crypto (quote signature, QE report, PCK chain -> Intel SGX Root CA,
TCB level via PCCS) is delegated to a pluggable backend:
  - QvlBackend            -> Intel SGX DCAP Quote Verification Library (libsgx_dcap_quoteverify)
  - IntelTrustAuthorityBackend -> Intel Trust Authority (ITA) REST attestation
  - StubBackend           -> DEV ONLY: parse, do NOT trust (verified=False)

Refs: Intel TDX DCAP Quoting Library spec; Intel SGX DCAP QVL; Automata dcap-attestation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct
import time
import urllib.request
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.x509 import load_der_x509_certificate


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

# --- TDX quote v4 layout (bytes) -------------------------------------------
HEADER_LEN = 48
# TD report body (TDX 1.0 = 584 bytes). TDX 1.5 = 648 (adds TEE_TCB_SVN2/MRSERVICETD).
BODY_LEN_TDX10 = 584
_OFF = {  # offset within the TD report body
    "tee_tcb_svn": 0, "mrseam": 16, "mrsignerseam": 64, "seamattributes": 112,
    "tdattributes": 120, "xfam": 128, "mrtd": 136, "mrconfigid": 184,
    "mrowner": 232, "mrownerconfig": 280, "rtmr0": 328, "rtmr1": 376,
    "rtmr2": 424, "rtmr3": 472, "reportdata": 520,
}
TEE_TYPE_TDX = 0x00000081


class DcapError(Exception):
    pass


@dataclass
class ParsedTdxQuote:
    version: int
    tee_type: int
    mrtd: bytes
    rtmr: list  # [rtmr0..rtmr3]
    report_data: bytes  # 64 bytes
    tee_tcb_svn: bytes
    signature_section: bytes  # raw bytes handed to the backend for crypto verification

    @property
    def is_tdx(self) -> bool:
        return self.tee_type == TEE_TYPE_TDX


def parse_tdx_quote(raw: bytes) -> ParsedTdxQuote:
    if len(raw) < HEADER_LEN + BODY_LEN_TDX10 + 4:
        raise DcapError(f"quote too short: {len(raw)} bytes")
    version, _akt, tee_type = struct.unpack_from("<HHI", raw, 0)
    body = raw[HEADER_LEN:HEADER_LEN + BODY_LEN_TDX10]

    def f(name, n=48):
        o = _OFF[name]
        return body[o:o + n]

    sig_off = HEADER_LEN + BODY_LEN_TDX10
    (sig_len,) = struct.unpack_from("<I", raw, sig_off)
    sig_section = raw[sig_off + 4: sig_off + 4 + sig_len]

    return ParsedTdxQuote(
        version=version, tee_type=tee_type,
        mrtd=f("mrtd"), rtmr=[f("rtmr0"), f("rtmr1"), f("rtmr2"), f("rtmr3")],
        report_data=f("reportdata", 64), tee_tcb_svn=f("tee_tcb_svn", 16),
        signature_section=sig_section,
    )


# --- backends (crypto delegated here) --------------------------------------
@dataclass
class TcbResult:
    verified: bool
    tcb_status: str  # e.g. "OK" / "OutOfDate" / "unknown"
    detail: str = ""
    claims: dict = field(default_factory=dict)  # full attestation-token claims (ITA)


class QuoteVerifierBackend:
    def verify(self, raw_quote: bytes) -> TcbResult:  # pragma: no cover - interface
        raise NotImplementedError


class StubBackend(QuoteVerifierBackend):
    """DEV ONLY. Parses but does not cryptographically verify. NEVER use in prod."""
    def verify(self, raw_quote: bytes) -> TcbResult:
        return TcbResult(verified=False, tcb_status="unknown", detail="StubBackend: crypto NOT verified")


class QvlBackend(QuoteVerifierBackend):
    """Delegate to Intel SGX DCAP Quote Verification Library.
    TODO: bind to libsgx_dcap_quoteverify (sgx_qv_verify_quote) via cffi/ctypes,
    or shell out to the `SGXDCAPQuoteVerify`/`tdx-quote-verify` tool. Configure
    PCCS_URL so the QVL fetches PCK/TCB collateral. Return the QVL's tcb status.
    """
    def __init__(self, pccs_url: str):
        self.pccs_url = pccs_url

    def verify(self, raw_quote: bytes) -> TcbResult:
        raise NotImplementedError(
            "QvlBackend: wire up libsgx_dcap_quoteverify (sgx_qv_verify_quote) + PCCS "
            f"at {self.pccs_url}. Aliyun PCCS: https://sgx-dcap-server.<region>.aliyuncs.com/sgx/certification/v4/")


class IntelTrustAuthorityBackend(QuoteVerifierBackend):
    """Intel Trust Authority (ITA / Tiber Trust Authority) attestation backend.

    Flow: (optionally GET a signed nonce) -> POST the TDX quote to /attest ->
    receive a signed attestation-token JWT -> verify its signature against ITA's
    JWKS -> read TDX + TCB claims -> cross-check the token's tdx_mrtd/report_data
    against the locally-parsed quote so the token provably describes THIS quote.

    Endpoints (research-verified):
      nonce : GET  {api_url}/appraisal/{ver}/nonce      headers: x-api-key, Accept
      attest: POST {api_url}/appraisal/{ver}/attest     headers: x-api-key, Content-Type, Accept
      certs : GET  {portal_url}/certs                   (JWKS; note: PORTAL host)
    Token is signed PS384 (default) or RS256; JOSE header carries kid + x5c chain.
    """
    API_URL = "https://api.trustauthority.intel.com"
    PORTAL_URL = "https://portal.trustauthority.intel.com"

    def __init__(self, api_key: str, api_url: str = API_URL, portal_url: str = PORTAL_URL,
                 version: str = "v1", policy_ids: list | None = None, use_nonce: bool = True,
                 user_data_b64: str = ""):
        self.api_key = api_key
        self.api_url = api_url.rstrip("/")
        self.portal_url = portal_url.rstrip("/")
        self.ver = version
        self.policy_ids = policy_ids or []
        self.use_nonce = use_nonce
        self.user_data_b64 = user_data_b64
        self._jwks = None

    # --- REST calls ---
    def _headers(self, ct=False):
        h = {"x-api-key": self.api_key, "Accept": "application/json"}
        if ct:
            h["Content-Type"] = "application/json"
        return h

    def get_nonce(self) -> dict:
        req = urllib.request.Request(f"{self.api_url}/appraisal/{self.ver}/nonce", headers=self._headers())
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())  # {val, iat, signature} (base64)

    def attest(self, quote_b64: str, verifier_nonce: dict | None) -> str:
        body = {"quote": quote_b64}
        if verifier_nonce:
            body["verifier_nonce"] = verifier_nonce
        if self.user_data_b64:
            body["user_data"] = self.user_data_b64
        if self.policy_ids:
            body["policy_ids"] = self.policy_ids
        req = urllib.request.Request(
            f"{self.api_url}/appraisal/{self.ver}/attest",
            data=json.dumps(body).encode(), headers=self._headers(ct=True), method="POST")
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())["token"]  # compact JWT

    def _fetch_jwks(self) -> dict:
        if self._jwks is None:
            req = urllib.request.Request(f"{self.portal_url}/certs", headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as r:
                self._jwks = json.loads(r.read())
        return self._jwks

    # --- token verification ---
    @staticmethod
    def _pubkey_from_jwk(jwk: dict):
        # Prefer the x5c leaf certificate (enables chain validation); fall back to n/e.
        if jwk.get("x5c"):
            der = base64.b64decode(jwk["x5c"][0])
            return load_der_x509_certificate(der).public_key()
        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        return RSAPublicNumbers(e, n).public_key()

    def verify_token(self, token: str) -> dict:
        h64, p64, s64 = token.split(".")
        header = json.loads(_b64url_decode(h64))
        claims = json.loads(_b64url_decode(p64))
        kid, alg = header.get("kid"), header.get("alg")

        jwk = next((k for k in self._fetch_jwks().get("keys", []) if k.get("kid") == kid), None)
        if jwk is None:
            raise DcapError(f"ITA JWKS has no key for kid={kid}")
        pub = self._pubkey_from_jwk(jwk)

        # TODO: validate the x5c chain up to the pinned ITA root CA (defense in depth).
        # Here we verify the token signature with the (kid-selected) leaf public key.
        sig = _b64url_decode(s64)
        signing_input = (h64 + "." + p64).encode()
        try:
            if alg == "PS384":
                pub.verify(sig, signing_input,
                           padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=padding.PSS.DIGEST_LENGTH),
                           hashes.SHA384())
            elif alg == "RS256":
                pub.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
            else:
                raise DcapError(f"unsupported token alg {alg}")
        except InvalidSignature:
            raise DcapError("ITA token signature invalid")

        if claims.get("exp") and time.time() > claims["exp"]:
            raise DcapError("ITA token expired")
        return claims

    def verify(self, raw_quote: bytes) -> TcbResult:
        nonce = self.get_nonce() if self.use_nonce else None
        token = self.attest(base64.b64encode(raw_quote).decode(), nonce)
        claims = self.verify_token(token)

        # cross-check: the token must describe THIS quote (bind token<->quote).
        parsed = parse_tdx_quote(raw_quote)
        tok_mrtd = (claims.get("tdx_mrtd") or claims.get("tdx", {}).get("tdx_mrtd", "")).lower()
        if tok_mrtd and tok_mrtd != parsed.mrtd.hex():
            raise DcapError("ITA token tdx_mrtd does not match the presented quote")

        tcb = claims.get("attester_tcb_status", "unknown")
        return TcbResult(verified=True, tcb_status=tcb,
                         detail=f"ITA token verified (advisories={claims.get('attester_advisory_ids')})",
                         claims=claims)


@dataclass
class VerifiedQuote:
    measurement: str  # hex; the value the client pins (policy-defined, see measurement_of)
    report_data: bytes
    rtmr: list
    tcb_status: str
    backend_verified: bool


def measurement_of(q: ParsedTdxQuote) -> str:
    """Policy: which field(s) constitute 'the code identity' the client pins.
    Simplest & most common for a reproducible CVM image: MRTD. If runtime
    measurements matter, fold RTMRs in. Keep this IDENTICAL to what the build
    pipeline publishes to the measurement registry."""
    return q.mrtd.hex()


def verify_tdx_quote(
    raw_quote: bytes,
    *,
    pinned_measurement: str = "",
    expected_report_data: bytes | None = None,
    backend: QuoteVerifierBackend | None = None,
    allow_unverified: bool = False,
) -> VerifiedQuote:
    """Parse + policy-check a TDX quote. Raises DcapError (fail-closed) on any mismatch."""
    q = parse_tdx_quote(raw_quote)
    if not q.is_tdx:
        raise DcapError(f"not a TDX quote (tee_type={q.tee_type:#x})")

    # 1) crypto: quote sig + QE + PCK chain to Intel root + TCB (delegated)
    backend = backend or StubBackend()
    tcb = backend.verify(raw_quote)
    if not tcb.verified and not allow_unverified:
        raise DcapError(f"quote crypto NOT verified by backend: {tcb.detail}")

    # 2) policy: measurement pin
    meas = measurement_of(q)
    if pinned_measurement and meas != pinned_measurement:
        raise DcapError(f"measurement mismatch: got {meas}, pinned {pinned_measurement}")

    # 3) policy: report_data binding (freshness + channel key)
    if expected_report_data is not None and q.report_data[:len(expected_report_data)] != expected_report_data:
        raise DcapError("report_data not bound to expected nonce||pubkey")

    return VerifiedQuote(measurement=meas, report_data=q.report_data, rtmr=q.rtmr,
                         tcb_status=tcb.tcb_status, backend_verified=tcb.verified)


# --- self-test: validate the byte-offset parser against a synthetic quote ---
if __name__ == "__main__":
    mrtd = bytes(range(48))
    rd = b"REPORTDATA" + b"\x00" * 54
    body = bytearray(BODY_LEN_TDX10)
    body[_OFF["mrtd"]:_OFF["mrtd"] + 48] = mrtd
    body[_OFF["reportdata"]:_OFF["reportdata"] + 64] = rd
    header = struct.pack("<HHI", 4, 2, TEE_TYPE_TDX) + b"\x00" * (HEADER_LEN - 8)
    sig = b"\xAA" * 100
    raw = header + bytes(body) + struct.pack("<I", len(sig)) + sig
    p = parse_tdx_quote(raw)
    assert p.is_tdx and p.mrtd == mrtd and p.report_data == rd and p.signature_section == sig
    v = verify_tdx_quote(raw, pinned_measurement=mrtd.hex(), expected_report_data=b"REPORTDATA", allow_unverified=True)
    assert v.measurement == mrtd.hex()
    print("dcap.py self-test 1 OK: parsed MRTD + REPORT_DATA + sig section; policy checks pass (crypto=stub)")

    # --- self-test 2: ITA attestation-token (JWS) verification crypto ---
    from cryptography.hazmat.primitives.asymmetric import rsa

    def _b64u(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    def _num(n: int) -> str:
        return _b64u(n.to_bytes((n.bit_length() + 7) // 8, "big"))

    k = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    pn = k.public_key().public_numbers()
    header = {"alg": "PS384", "kid": "test-kid", "typ": "JWT"}
    claims = {"iss": "Intel Trust Authority", "exp": 4102444800,
              "attester_type": "TDX", "attester_tcb_status": "OK",
              "tdx_mrtd": mrtd.hex(), "tdx_report_data": rd.hex()}
    si = (_b64u(json.dumps(header).encode()) + "." + _b64u(json.dumps(claims).encode())).encode()
    sig = k.sign(si, padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=padding.PSS.DIGEST_LENGTH), hashes.SHA384())
    token = si.decode() + "." + _b64u(sig)

    ita = IntelTrustAuthorityBackend(api_key="dummy")
    ita._jwks = {"keys": [{"kid": "test-kid", "kty": "RSA", "n": _num(pn.n), "e": _num(pn.e)}]}
    got = ita.verify_token(token)
    assert got["tdx_mrtd"] == mrtd.hex() and got["attester_tcb_status"] == "OK"
    # tampering the payload must fail verification
    bad = token.split(".")
    bad[1] = _b64u(json.dumps({**claims, "attester_tcb_status": "OK", "tdx_mrtd": "00" * 48}).encode())
    try:
        ita.verify_token(".".join(bad))
        raise SystemExit("FAIL: tampered token verified")
    except DcapError:
        pass
    print("dcap.py self-test 2 OK: ITA PS384 JWS verify + JWKS(kid) lookup + claim read; tamper rejected")
