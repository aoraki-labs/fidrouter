// DCAP / Intel TDX quote verification — SKELETON (Node/TS), parity with sdk/python/dcap.py.
// Parses the TDX quote (MRTD/RTMRs/REPORT_DATA) + applies policy; delegates the
// crypto (quote sig, QE, PCK chain -> Intel root, TCB) to a pluggable backend
// (Intel QVL / Intel Trust Authority). Do NOT hand-roll ECDSA/X.509 here.
import crypto from "node:crypto";

const HEADER_LEN = 48;
const BODY_LEN_TDX10 = 584;
const OFF = { mrtd: 136, rtmr0: 328, rtmr1: 376, rtmr2: 424, rtmr3: 472, reportdata: 520 };
const TEE_TYPE_TDX = 0x00000081;

export class DcapError extends Error {}

export function parseTdxQuote(raw) {
  if (raw.length < HEADER_LEN + BODY_LEN_TDX10 + 4) throw new DcapError(`quote too short: ${raw.length}`);
  const version = raw.readUInt16LE(0);
  const teeType = raw.readUInt32LE(4);
  const body = raw.subarray(HEADER_LEN, HEADER_LEN + BODY_LEN_TDX10);
  const f = (o, n = 48) => body.subarray(o, o + n);
  const sigOff = HEADER_LEN + BODY_LEN_TDX10;
  const sigLen = raw.readUInt32LE(sigOff);
  return {
    version, teeType, isTdx: teeType === TEE_TYPE_TDX,
    mrtd: f(OFF.mrtd), rtmr: [f(OFF.rtmr0), f(OFF.rtmr1), f(OFF.rtmr2), f(OFF.rtmr3)],
    reportData: f(OFF.reportdata, 64),
    signatureSection: raw.subarray(sigOff + 4, sigOff + 4 + sigLen),
  };
}

// Backends — implement one of these for production.
export class StubBackend { // DEV ONLY: parse, do not trust
  async verify() { return { verified: false, tcbStatus: "unknown", detail: "StubBackend: crypto NOT verified" }; }
}
export class QvlBackend { // TODO: bind Intel SGX DCAP QVL (sgx_qv_verify_quote) + PCCS
  constructor(pccsUrl) { this.pccsUrl = pccsUrl; }
  async verify() { throw new DcapError(`QvlBackend TODO: wire libsgx_dcap_quoteverify + PCCS ${this.pccsUrl}`); }
}
// Intel Trust Authority (ITA) backend — real implementation.
//   nonce : GET  {apiUrl}/appraisal/{ver}/nonce   (x-api-key, Accept)
//   attest: POST {apiUrl}/appraisal/{ver}/attest  (x-api-key, Content-Type, Accept) -> {token}
//   certs : GET  {portalUrl}/certs                (JWKS; PORTAL host)
// token signed PS384 (default) or RS256; header carries kid + x5c.
export class IntelTrustAuthorityBackend {
  constructor({ apiKey, apiUrl = "https://api.trustauthority.intel.com",
                portalUrl = "https://portal.trustauthority.intel.com", version = "v1",
                policyIds = [], useNonce = true, userDataB64 = "" } = {}) {
    Object.assign(this, { apiKey, apiUrl: apiUrl.replace(/\/$/, ""), portalUrl: portalUrl.replace(/\/$/, ""),
      ver: version, policyIds, useNonce, userDataB64, _jwks: null });
  }
  _headers(ct) { const h = { "x-api-key": this.apiKey, Accept: "application/json" }; if (ct) h["Content-Type"] = "application/json"; return h; }

  async getNonce() {
    const r = await fetch(`${this.apiUrl}/appraisal/${this.ver}/nonce`, { headers: this._headers() });
    return r.json(); // {val, iat, signature}
  }
  async attest(quoteB64, verifierNonce) {
    const body = { quote: quoteB64 };
    if (verifierNonce) body.verifier_nonce = verifierNonce;
    if (this.userDataB64) body.user_data = this.userDataB64;
    if (this.policyIds.length) body.policy_ids = this.policyIds;
    const r = await fetch(`${this.apiUrl}/appraisal/${this.ver}/attest`,
      { method: "POST", headers: this._headers(true), body: JSON.stringify(body) });
    return (await r.json()).token;
  }
  async _fetchJwks() {
    if (!this._jwks) this._jwks = await (await fetch(`${this.portalUrl}/certs`, { headers: { Accept: "application/json" } })).json();
    return this._jwks;
  }
  _pubkeyFromJwk(jwk) {
    if (jwk.x5c?.length) return new crypto.X509Certificate(Buffer.from(jwk.x5c[0], "base64")).publicKey;
    return crypto.createPublicKey({ key: { kty: "RSA", n: jwk.n, e: jwk.e }, format: "jwk" });
  }
  async verifyToken(token) {
    const [h64, p64, s64] = token.split(".");
    const header = JSON.parse(Buffer.from(h64, "base64url"));
    const claims = JSON.parse(Buffer.from(p64, "base64url"));
    const jwks = await this._fetchJwks();
    const jwk = (jwks.keys || []).find((k) => k.kid === header.kid);
    if (!jwk) throw new DcapError(`ITA JWKS has no key for kid=${header.kid}`);
    const pub = this._pubkeyFromJwk(jwk);
    const si = Buffer.from(`${h64}.${p64}`);
    const sig = Buffer.from(s64, "base64url");
    let ok;
    if (header.alg === "PS384")
      ok = crypto.verify("sha384", si, { key: pub, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }, sig);
    else if (header.alg === "RS256") ok = crypto.verify("sha256", si, pub, sig);
    else throw new DcapError(`unsupported token alg ${header.alg}`);
    if (!ok) throw new DcapError("ITA token signature invalid");
    if (claims.exp && Date.now() / 1000 > claims.exp) throw new DcapError("ITA token expired");
    return claims;
  }
  async verify(rawQuote) {
    const nonce = this.useNonce ? await this.getNonce() : null;
    const token = await this.attest(Buffer.from(rawQuote).toString("base64"), nonce);
    const claims = await this.verifyToken(token);
    const parsed = parseTdxQuote(rawQuote);
    const tokMrtd = (claims.tdx_mrtd || "").toLowerCase();
    if (tokMrtd && tokMrtd !== Buffer.from(parsed.mrtd).toString("hex"))
      throw new DcapError("ITA token tdx_mrtd does not match the presented quote");
    return { verified: true, tcbStatus: claims.attester_tcb_status || "unknown", detail: "ITA token verified", claims };
  }
}

// Policy: which field is "the code identity" the client pins. Keep IDENTICAL to
// what the reproducible-build pipeline publishes. Simplest: MRTD.
export const measurementOf = (q) => Buffer.from(q.mrtd).toString("hex");

export async function verifyTdxQuote(raw, { pinnedMeasurement = "", expectedReportData = null, backend = null, allowUnverified = false } = {}) {
  const q = parseTdxQuote(raw);
  if (!q.isTdx) throw new DcapError(`not a TDX quote (tee_type=${q.teeType.toString(16)})`);
  const tcb = await (backend || new StubBackend()).verify(raw);
  if (!tcb.verified && !allowUnverified) throw new DcapError(`quote crypto NOT verified: ${tcb.detail}`);
  const meas = measurementOf(q);
  if (pinnedMeasurement && meas !== pinnedMeasurement) throw new DcapError(`measurement mismatch: ${meas} vs ${pinnedMeasurement}`);
  if (expectedReportData && !q.reportData.subarray(0, expectedReportData.length).equals(expectedReportData))
    throw new DcapError("report_data not bound to nonce||pubkey");
  return { measurement: meas, reportData: q.reportData, rtmr: q.rtmr, tcbStatus: tcb.tcbStatus, backendVerified: tcb.verified };
}
