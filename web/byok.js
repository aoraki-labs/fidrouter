// static/byok.js — in-browser, operator-blind BYOK sealing (WebCrypto only).
//
// Byte-exact to `ctl seal-byok` / internal/enc:
//   key    = SHA-256( X25519(eph_priv, sealing_pub) || "fid-byok-v1" )
//   sealed = "sealed:" + base64( eph_pub(32) || iv(12) || AES-256-GCM(key, plaintext, iv, aad="fid-byok-v1") )
// The plaintext upstream key NEVER leaves the browser un-sealed; the platform only ever
// relays ciphertext + the (signed) sealing key. Every step is fail-closed.
const INFO = "fid-byok-v1";
const enc = new TextEncoder();
const subtle = () => globalThis.crypto.subtle;

const b64 = (u8) => btoa(String.fromCharCode(...u8));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hexToBytes = (h) => new Uint8Array((h.match(/.{1,2}/g) || []).map((x) => parseInt(x, 16)));
const bytesToHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");
function concat(...arrs) {
  const n = arrs.reduce((a, b) => a + b.length, 0);
  const o = new Uint8Array(n);
  let i = 0;
  for (const a of arrs) { o.set(a, i); i += a.length; }
  return o;
}

async function sha256(u8) { return new Uint8Array(await subtle().digest("SHA-256", u8)); }

async function ed25519Verify(pubRaw, sig, msg) {
  const k = await subtle().importKey("raw", pubRaw, { name: "Ed25519" }, false, ["verify"]);
  return subtle().verify({ name: "Ed25519" }, k, sig, msg);
}

// Seal `upstreamKey` (string) to `sealingPubRaw` (32 raw bytes). Pure — unit-testable.
export async function sealKey(sealingPubRaw, upstreamKey) {
  const eph = await subtle().generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const ephPub = new Uint8Array(await subtle().exportKey("raw", eph.publicKey));
  const peer = await subtle().importKey("raw", sealingPubRaw, { name: "X25519" }, false, []);
  const shared = new Uint8Array(await subtle().deriveBits({ name: "X25519", public: peer }, eph.privateKey, 256));
  const key = await sha256(concat(shared, enc.encode(INFO)));
  const aes = await subtle().importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle().encrypt(
    { name: "AES-GCM", iv, additionalData: enc.encode(INFO), tagLength: 128 }, aes, enc.encode(upstreamKey)));
  return "sealed:" + b64(concat(ephPub, iv, ct));
}

// Verify the enclave's per-boot sealing key is signed by the pinned identity key.
export async function verifiedSealingKey(sealingResp, pinnedIdpubHex) {
  const sealingPub = unb64(sealingResp.sealing_pub);
  const sig = unb64(sealingResp.sig);
  const ok = await ed25519Verify(hexToBytes(pinnedIdpubHex), sig, sealingPub);
  if (!ok) throw new Error("sealing key signature invalid — not signed by the attested enclave identity");
  return sealingPub;
}

// Full fail-closed flow via the platform's enclave proxy. Returns the enclave's /byok result.
// onStep(name, ok) lets the UI show the green checklist.
export async function sealAndInject({ endpointId, account, token, upstreamKey, onStep = () => {} }) {
  // 1) pin the trust root from the PUBLIC registry (measurement -> idpub)
  const reg = await (await fetch("/api/registry", { cache: "no-store" })).json();
  const eps = await (await fetch("/api/partner/endpoints", { cache: "no-store" })).json();
  const ep = eps.find((e) => e.id === endpointId);
  if (!ep) throw new Error("endpoint not found");
  const build = reg.builds[ep.expected_measurement];
  if (!build || !build.identity_pub_hex) throw new Error("endpoint's build not in the public registry — refusing to seal");
  onStep("pinned", true);

  // 2) independent live attestation (server-side, against the registry)
  const ver = await (await fetch("/api/verify", { cache: "no-store" })).json();
  const v = ver.find((x) => x.base_url === ep.base_url);
  if (!v || !v.ok) throw new Error("endpoint does not currently attest green — refusing to seal");
  onStep("attested", true);

  // 3) fetch the per-boot sealing key and verify its signature under the pinned idpub
  const sealingResp = await (await fetch(`/api/enclave/sealing?endpoint=${endpointId}`, { cache: "no-store" })).json();
  if (sealingResp.error) throw new Error(sealingResp.error);
  const sealingPub = await verifiedSealingKey(sealingResp, build.identity_pub_hex);
  onStep("sealing_verified", true);

  // 4) seal (plaintext read only now) and submit ciphertext
  const sealed = await sealKey(sealingPub, upstreamKey);
  onStep("sealed", true);
  const res = await fetch("/api/enclave/byok", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": window.__csrf || "" },
    body: JSON.stringify({ endpoint: endpointId, account, token, sealed }),
  });
  const out = await res.json();
  if (!res.ok || out.ok === false) throw new Error(out.error || "enclave rejected /byok");
  onStep("injected", true);
  return out;
}

export const _internal = { sealKey, hexToBytes, bytesToHex, b64, unb64 };
