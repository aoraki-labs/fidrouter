#!/usr/bin/env python3
"""PUBLIC request explorer — the per-request transparency log (身份 B).

Each request the enclave serves comes with a SIGNED RECEIPT (X-Fid-Receipt header
/ sealed response): hashes + counts + model + measurement, NO content. This
service:
  - VERIFIES a pasted receipt: Ed25519 signature by the enclave identity key
    (published in the registry, keyed by measurement) + measurement is a known
    open-source build. Anti-downgrade: the receipt records the model actually
    served — compare it to what you asked for.
  - LOGS submitted receipts into an append-only HASH-CHAINED log (tamper-evident:
    entry_hash = SHA256(prev_hash || receipt)), so there's a public, ordered
    record anyone can audit.

Independent of the relay/operator by design. No secret, no api key needed.

    python3 explorer/server.py            # http://localhost:8081
    PORT=8081 python3 explorer/server.py
"""
import hashlib
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import base64

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "sdk", "python"))
from fidrouter_verify import _canonical_receipt  # reuse exact Go-compatible canonical form
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

REGISTRY = json.load(open(os.environ.get("REGISTRY_PATH",
                      os.path.join(HERE, "..", "verify-page", "registry.json"))))
LOG_PATH = os.environ.get("LOG_PATH", os.path.join(HERE, "log.jsonl"))
GENESIS = "0" * 64


def idpub_for(measurement: str):
    b = REGISTRY.get("builds", {}).get(measurement)
    if not b or not b.get("identity_pub_hex"):
        return None
    return bytes.fromhex(b["identity_pub_hex"])


def verify_receipt(receipt_b64: str) -> dict:
    """Decode + verify a base64(X-Fid-Receipt) blob. Returns a verdict dict."""
    try:
        signed = json.loads(base64.b64decode(receipt_b64))
        rec = signed["receipt"]
        sig = base64.b64decode(signed["sig"])
    except Exception as e:
        return {"ok": False, "reason": f"malformed receipt: {e}"}
    meas = rec.get("measurement", "")
    idpub = idpub_for(meas)
    known = idpub is not None
    build = REGISTRY.get("builds", {}).get(meas, {})
    if not known:
        return {"ok": False, "reason": "measurement not in registry (unknown/unpublished build)",
                "receipt": rec, "checks": {"signature": False, "measurement_known": False}, "build": {}}
    try:
        Ed25519PublicKey.from_public_bytes(idpub).verify(sig, _canonical_receipt(rec))
        sig_ok = True
    except InvalidSignature:
        sig_ok = False
    ok = sig_ok and known
    return {
        "ok": ok,
        "reason": "verified: signed by the registered enclave key, measurement is a known open-source build"
                  if ok else "signature invalid for the registered enclave key",
        "receipt": rec,
        "checks": {"signature": sig_ok, "measurement_known": known},
        "build": {"source": build.get("source"), "reproducible_build": build.get("reproducible_build")},
    }


# ---- append-only hash-chained log -------------------------------------------
def load_log() -> list:
    if not os.path.exists(LOG_PATH):
        return []
    out = []
    for line in open(LOG_PATH):
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def log_root(entries: list) -> str:
    return entries[-1]["hash"] if entries else GENESIS


def append_log(receipt_b64: str, rec: dict) -> dict:
    entries = load_log()
    for e in entries:  # dedupe identical receipts
        if e["receipt_b64"] == receipt_b64:
            return {"index": e["index"], "entry_hash": e["hash"], "root": log_root(entries), "duplicate": True}
    prev = log_root(entries)
    h = hashlib.sha256((prev + receipt_b64).encode()).hexdigest()
    entry = {"index": len(entries), "prev": prev, "hash": h, "receipt_b64": receipt_b64,
             "rec": rec, "submitted_at": int(time.time())}
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return {"index": entry["index"], "entry_hash": h, "root": h, "duplicate": False}


PAGE = r"""<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>fidrouter · 请求回执浏览器</title>
<style>
:root{--bg:#f6f8fa;--panel:#fff;--ink:#0b1220;--muted:#5b6b7a;--line:#e3e8ee;--accent:#0d9488;
--ok:#16a34a;--ok-bg:#e9f7ef;--bad:#dc2626;--bad-bg:#fdecec;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;}
@media (prefers-color-scheme:dark){:root{--bg:#0b0f14;--panel:#121821;--ink:#e8eef5;--muted:#8797a8;--line:#212a35;
--accent:#2dd4bf;--ok:#34d399;--ok-bg:#0f2b20;--bad:#f87171;--bad-bg:#2a1414;}}
:root[data-theme="dark"]{--bg:#0b0f14;--panel:#121821;--ink:#e8eef5;--muted:#8797a8;--line:#212a35;--accent:#2dd4bf;--ok:#34d399;--ok-bg:#0f2b20;--bad:#f87171;--bad-bg:#2a1414;}
:root[data-theme="light"]{--bg:#f6f8fa;--panel:#fff;--ink:#0b1220;--muted:#5b6b7a;--line:#e3e8ee;--accent:#0d9488;--ok:#16a34a;--ok-bg:#e9f7ef;--bad:#dc2626;--bad-bg:#fdecec;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:880px;margin:0 auto;padding:38px 20px 80px}
header{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
h1{font-size:22px;margin:0;letter-spacing:-.01em}h2{font-size:15px;margin:26px 0 8px;color:var(--muted);font-weight:600}
.tag{font-size:12px;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:2px 10px}
a{color:var(--accent)}.lead{color:var(--muted);max-width:64ch;margin:10px 0 0}
textarea{width:100%;height:96px;background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:10px;padding:12px;font-family:var(--mono);font-size:12px;margin-top:6px}
button{font:inherit;background:var(--accent);color:#04211f;border:0;border-radius:8px;padding:8px 16px;cursor:pointer;font-weight:650}
button.ghost{background:var(--panel);color:var(--ink);border:1px solid var(--line);font-weight:500}
.row{display:flex;gap:8px;margin-top:8px;flex-wrap:wrap}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:12px 0}
.pill{font-size:12px;font-weight:700;border-radius:999px;padding:4px 12px}.pill.ok{background:var(--ok-bg);color:var(--ok)}.pill.bad{background:var(--bad-bg);color:var(--bad)}
.top{display:flex;align-items:center;justify-content:space-between;gap:12px}
.rows{margin-top:12px;display:grid;grid-template-columns:auto 1fr;gap:5px 16px;font-size:13px}.k{color:var(--muted)}.mono{font-family:var(--mono);font-size:12px;word-break:break-all}
.detail{margin-top:10px;font-size:12.5px;color:var(--muted);border-top:1px dashed var(--line);padding-top:9px}.detail.bad{color:var(--bad)}
table{width:100%;border-collapse:collapse;font-size:12.5px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:600}
td.mono,th.mono{font-family:var(--mono)}.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:12px}
.root{font-size:12px;color:var(--muted);margin:6px 0 0}.foot{margin-top:22px;font-size:12px;color:var(--muted)}
</style></head><body><div class="wrap">
<header><h1>fidrouter · 请求回执浏览器</h1><span class="tag">透明日志 · 独立于中转运营方</span></header>
<p class="lead">每次请求,中转都签发一张<b>回执</b>(只含 hash+计数+模型+度量值,<b>无内容</b>)。把回执粘进来 → 现场验签名 + 核度量值,证明这条请求确实由那份<b>开源无日志代码</b>服务、<b>模型没被偷偷降级</b>。也可写入下方<b>不可篡改的追加日志</b>留痕。<a href="#" id="verlink">← 验端点(机器)在验证页</a></p>
<h2>验证一张回执</h2>
<textarea id="rin" placeholder="粘贴响应头 X-Fid-Receipt 的值(base64)…"></textarea>
<div class="row"><button id="verify">验证</button><button class="ghost" id="submit" disabled>写入透明日志</button></div>
<div id="result"></div>
<h2>透明日志(最近)</h2><div class="root" id="root"></div>
<div class="scroll"><table><thead><tr><th>#</th><th>时间</th><th>模型</th><th class="mono">度量值</th><th class="mono">entry_hash</th></tr></thead><tbody id="log"></tbody></table></div>
<p class="foot">校验用的"期望代码"(度量值→开源构建 + enclave 公钥)来自中立注册表 <code>verify-page/registry.json</code>,不由运营方即时提供。日志为哈希链:<code>hash = SHA256(prev ‖ receipt)</code>。</p>
</div>
<script>
let lastValid=null;
function esc(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function shortH(h){h=(h||'').replace('sha256:','');return h?h.slice(0,14)+'…':'—'}
function tstr(u){return u?new Date(u*1000).toLocaleString():'—'}
async function verify(){
  const v=document.getElementById('rin').value.trim(); if(!v)return;
  const r=await fetch('/api/verify',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({receipt_b64:v})});
  const d=await r.json(); render(d,v);
}
function render(d,v){
  const rec=d.receipt||{}, ok=d.ok===true;
  document.getElementById('submit').disabled=!ok; lastValid=ok?v:null;
  const ch=d.checks||{};
  document.getElementById('result').innerHTML=`<div class="card"><div class="top"><b>回执验证</b>${ok?'<span class="pill ok">✓ VERIFIED</span>':'<span class="pill bad">✗ 不可信</span>'}</div>
  <div class="rows">
    <div class="k">签名(enclave 身份钥)</div><div>${ch.signature?'✓ 有效':'✗ 无效'}</div>
    <div class="k">度量值∈开源注册表</div><div>${ch.measurement_known?'✓ 是':'✗ 否(未知构建)'}</div>
    <div class="k">模型(实际服务)</div><div><b>${esc(rec.model||'—')}</b>  <span class="k">← 和你请求的比对=防降级</span></div>
    <div class="k">度量值</div><div class="mono">${shortH(rec.measurement)}</div>
    <div class="k">时间</div><div>${tstr(rec.ts_unix)}</div>
    <div class="k">tokens</div><div>in ${rec.prompt_tokens||0} / out ${rec.completion_tokens||0} · cache_hit ${rec.cache_hit}</div>
    <div class="k">req_hash</div><div class="mono">${shortH(rec.req_hash)}</div>
    <div class="k">resp_hash</div><div class="mono">${shortH(rec.resp_hash)}</div>
    <div class="k">开源构建</div><div>${esc((d.build||{}).source||'—')}</div>
  </div><div class="detail ${ok?'':'bad'}">${esc(d.reason||'')}</div></div>`;
}
async function submit(){
  if(!lastValid)return;
  await fetch('/submit',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({receipt_b64:lastValid})});
  loadLog();
}
async function loadLog(){
  const r=await fetch('/api/log?n=50',{cache:'no-store'}); const d=await r.json();
  document.getElementById('root').textContent='log root: '+shortH(d.root)+'  ·  '+d.entries.length+' 条';
  document.getElementById('log').innerHTML=d.entries.slice().reverse().map(e=>`<tr><td>${e.index}</td><td>${tstr(e.submitted_at)}</td><td>${esc((e.rec||{}).model||'')}</td><td class="mono">${shortH((e.rec||{}).measurement)}</td><td class="mono">${shortH(e.hash)}</td></tr>`).join('')||'<tr><td colspan="5" style="color:var(--muted)">暂无</td></tr>';
}
document.getElementById('verify').onclick=verify;
document.getElementById('submit').onclick=submit;
loadLog(); setInterval(loadLog,15000);
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, "application/json", json.dumps(obj).encode())

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n))
        except Exception:
            return {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            self._send(200, "text/html; charset=utf-8", PAGE.encode())
        elif u.path == "/api/log":
            n = int((parse_qs(u.query).get("n") or ["50"])[0])
            entries = load_log()
            self._json(200, {"root": log_root(entries), "entries": entries[-n:]})
        else:
            self._send(404, "text/plain", b"not found")

    def do_POST(self):
        u = urlparse(self.path)
        b = self._body()
        rb = (b.get("receipt_b64") or "").strip()
        if not rb:
            self._json(400, {"ok": False, "reason": "receipt_b64 required"})
            return
        v = verify_receipt(rb)
        if u.path == "/api/verify":
            self._json(200, v)
        elif u.path == "/submit":
            if not v["ok"]:
                self._json(400, {"ok": False, "reason": "refusing to log an unverified receipt: " + v["reason"]})
                return
            self._json(200, {"ok": True, **append_log(rb, v["receipt"])})
        else:
            self._send(404, "text/plain", b"not found")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8081"))
    print(f"fidrouter request explorer on http://0.0.0.0:{port}  (log: {LOG_PATH})")
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
