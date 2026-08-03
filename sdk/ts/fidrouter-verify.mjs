// fid-router verify SDK (Node/TS, ESM) — drop-in client that refuses to send a
// prompt until it has cryptographically verified the enclave. No external deps
// (uses node:crypto). Byte-compatible with the Go data plane:
//   key    = SHA256( X25519(client_priv, enclave_pub) || "fid-e2e-v1" )
//   seal   = AES-256-GCM, 12-byte iv prepended, AAD = session bytes
//   quote  = Ed25519 over (measurement||report_data utf8) || ephemeral_pub
//   receipt= Ed25519 over Go json.Marshal(receipt) (canonical form below)
import crypto from "node:crypto";

const INFO = Buffer.from("fid-e2e-v1");

export class FidVerificationError extends Error {}

const x25519PubFromRaw = (raw) =>
  crypto.createPublicKey({ key: { kty: "OKP", crv: "X25519", x: raw.toString("base64url") }, format: "jwk" });
const ed25519PubFromRaw = (raw) =>
  crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") }, format: "jwk" });

function jstr(s) {
  let out = '"';
  for (const ch of s) {
    const o = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "<") out += "\\u003c";
    else if (ch === ">") out += "\\u003e";
    else if (ch === "&") out += "\\u0026";
    else if (o < 0x20) out += "\\u" + o.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

// Field order MUST match the Go struct receipt.Receipt.
function canonicalReceipt(r) {
  return Buffer.from(
    "{" +
      `"ts_unix":${r.ts_unix},` +
      `"tenant":${jstr(r.tenant)},` +
      `"model":${jstr(r.model)},` +
      `"account":${jstr(r.account)},` +
      `"req_hash":${jstr(r.req_hash)},` +
      `"resp_hash":${jstr(r.resp_hash)},` +
      `"prompt_tokens":${r.prompt_tokens},` +
      `"completion_tokens":${r.completion_tokens},` +
      `"cache_hit":${r.cache_hit ? "true" : "false"},` +
      `"measurement":${jstr(r.measurement)}` +
      "}"
  );
}

function seal(key, pt, aad) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(pt), c.final()]);
  return Buffer.concat([iv, ct, c.getAuthTag()]);
}
function open_(key, blob, aad) {
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(blob.length - 16);
  const ct = blob.subarray(12, blob.length - 16);
  const d = crypto.createDecipheriv("aes-256-gcm", key, iv);
  d.setAAD(aad);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

export class FidClient {
  constructor({ baseUrl = "http://127.0.0.1:9090", token, pinMeasurement = "", pinIdpubHex = "" }) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.token = token;
    this.pinMeasurement = pinMeasurement;
    this.pinIdpub = pinIdpubHex ? Buffer.from(pinIdpubHex, "hex") : null;
  }

  async infer({ model, prefix, suffix }) {
    const q = await this._attestAndVerify(); // fail-closed inside

    const eph = crypto.generateKeyPairSync("x25519");
    const cpub = Buffer.from(eph.publicKey.export({ format: "jwk" }).x, "base64url");
    const shared = crypto.diffieHellman({
      privateKey: eph.privateKey,
      publicKey: x25519PubFromRaw(q.ephemeral_pub),
    });
    const key = crypto.createHash("sha256").update(shared).update(INFO).digest();

    const inner = Buffer.from(JSON.stringify({ model, prefix, suffix }));
    const sealed = seal(key, inner, Buffer.from(q.session));

    const res = await fetch(this.baseUrl + "/v1/infer", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session: q.session, client_pub: cpub.toString("base64"),
        token: this.token, sealed: sealed.toString("base64"),
      }),
    });
    const raw = Buffer.from(await res.arrayBuffer());
    if (res.status !== 200) throw new FidVerificationError(`infer rejected (${res.status}): ${raw.toString().slice(0, 200)}`);
    const out = JSON.parse(raw.toString());

    const rec = out.receipt.receipt;
    const sig = Buffer.from(out.receipt.sig, "base64");
    const idpub = this.pinIdpub || q.identity_pub;
    if (!crypto.verify(null, canonicalReceipt(rec), ed25519PubFromRaw(idpub), sig))
      throw new FidVerificationError("receipt signature invalid");
    if (this.pinMeasurement && rec.measurement !== this.pinMeasurement)
      throw new FidVerificationError("receipt measurement mismatch");
    if (rec.model !== model)
      throw new FidVerificationError(`MODEL DOWNGRADE: asked ${model}, receipt says ${rec.model}`);

    const respPlain = open_(key, Buffer.from(out.sealed_resp, "base64"), Buffer.from(q.session));
    const ur = JSON.parse(respPlain.toString());
    return {
      completion: ur.completion, cacheHit: ur.cache_hit, model: rec.model,
      account: out.route.account, affinity: out.route.affinity,
      promptTokens: ur.prompt_tokens, completionTokens: ur.completion_tokens, receipt: rec,
    };
  }

  // OpenAI-ish convenience: split messages into cacheable prefix + variable tail.
  async chat({ model, messages }) {
    const prefix = messages.slice(0, -1).map((m) => `${m.role}: ${m.content}`).join("\n");
    const suffix = messages.length ? messages[messages.length - 1].content : "";
    return this.infer({ model, prefix, suffix });
  }

  async _attestAndVerify() {
    const raw = crypto.randomBytes(16);
    const nonceHex = raw.toString("hex");
    const res = await fetch(this.baseUrl + "/attestation?nonce=" + nonceHex);
    const j = await res.json();
    const q = {
      platform: j.platform, measurement: j.measurement, session: j.session, report_data: j.report_data,
      nonce: Buffer.from(j.nonce, "base64"), ephemeral_pub: Buffer.from(j.ephemeral_pub, "base64"),
      identity_pub: Buffer.from(j.identity_pub, "base64"), sig: Buffer.from(j.sig, "base64"),
    };
    if (this.pinMeasurement && q.measurement !== this.pinMeasurement)
      throw new FidVerificationError(
        `measurement mismatch\n  got:    ${q.measurement}\n  pinned: ${this.pinMeasurement}\n  (build is not the audited no-log code — refusing)`);
    if (this.pinIdpub && !q.identity_pub.equals(this.pinIdpub))
      throw new FidVerificationError("identity pubkey mismatch (not the enclave we trust)");
    const body = Buffer.concat([Buffer.from(q.measurement + q.report_data), q.ephemeral_pub]);
    if (!crypto.verify(null, body, ed25519PubFromRaw(q.identity_pub), q.sig))
      throw new FidVerificationError("quote signature invalid");
    if (!q.nonce.equals(Buffer.from(nonceHex)))
      throw new FidVerificationError("enclave did not echo our nonce (possible replay)");
    const rd = crypto.createHash("sha256").update(q.nonce).update(q.ephemeral_pub).digest("hex");
    if (rd !== q.report_data)
      throw new FidVerificationError("report_data not bound to nonce+key (possible replay)");
    return q;
  }
}
