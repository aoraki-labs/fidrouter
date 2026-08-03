#!/usr/bin/env python3
"""PUBLIC trust page — the neutral verifier (身份 B), independent of any operator.

ONE page, two things a non-technical person can do without any account or key:
  ① 这台中转可信吗 — live-check each registered endpoint's attestation against the
     published open-source build (machine/code check; continuous).
  ② 验一张回执     — paste a request receipt → verify it was signed by the enclave
     key + the model wasn't downgraded (single-request check; on demand).

No public feed of requests: receipts are checked on demand, never listed — a
privacy product must not expose who-asked-what.

    python3 verify-page/server.py            # http://localhost:8080
"""
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "sdk", "python"))
from fidrouter_verify import FidClient, FidVerificationError, verify_receipt  # noqa: E402

REGISTRY = json.load(open(os.environ.get("REGISTRY_PATH", os.path.join(HERE, "registry.json"))))


def check(ep: dict) -> dict:
    """① Live-verify one endpoint's attestation against its published measurement."""
    t0 = time.time()
    out = {"name": ep["name"], "platform": ep.get("platform", ""), "base_url": ep["base_url"],
           "expected": ep["expected_measurement"],
           "build": REGISTRY["builds"].get(ep["expected_measurement"], {})}
    try:
        c = FidClient(base_url=ep["base_url"], token="", pin_measurement=ep["expected_measurement"],
                      cs_audience=ep.get("cs_audience", "fidrouter"))
        c._attest_and_verify()
        out.update(ok=True, detail="现场校验通过 · 度量值 == 公开构建")
    except FidVerificationError as e:
        out.update(ok=False, detail=str(e))
    except Exception as e:
        out.update(ok=False, detail=f"unreachable: {type(e).__name__}: {e}")
    out["checked_ms"] = int((time.time() - t0) * 1000)
    return out


def check_receipt(receipt_b64: str) -> dict:
    """② Verify a pasted receipt: decode → find the enclave key for its measurement
    in the registry → verify signature. measurement_known guards unpublished builds."""
    try:
        rec = json.loads(__import__("base64").b64decode(receipt_b64))["receipt"]
    except Exception as e:
        return {"ok": False, "reason": f"回执格式错误: {e}", "receipt": {}}
    meas = rec.get("measurement", "")
    build = REGISTRY.get("builds", {}).get(meas)
    if not build or not build.get("identity_pub_hex"):
        return {"ok": False, "reason": "这条回执的度量值不在注册表(未知/未发布的构建)",
                "receipt": rec, "measurement_known": False, "build": {}}
    v = verify_receipt(receipt_b64, build["identity_pub_hex"])
    v["measurement_known"] = True
    v["build"] = {"source": build.get("source"), "reproducible_build": build.get("reproducible_build")}
    v["ok"] = v["signature_ok"]  # both signature + known-measurement hold here
    if v["ok"]:
        v["reason"] = "通过:这条回执由注册表登记的 enclave 私钥签发,度量值是已发布的开源构建"
    return v


def badge_svg(ok) -> bytes:
    label, color = ("verifying…", "#6b7280")
    if ok is True:
        label, color = ("verified", "#16a34a")
    elif ok is False:
        label, color = ("failed", "#dc2626")
    w = 132
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img">'
            f'<rect rx="3" width="{w}" height="20" fill="#24292f"/>'
            f'<rect rx="3" x="66" width="{w-66}" height="20" fill="{color}"/>'
            f'<g fill="#fff" font-family="Verdana,sans-serif" font-size="11" text-anchor="middle">'
            f'<text x="33" y="14">fidrouter</text><text x="{66+(w-66)//2}" y="14">{label}</text></g></svg>').encode()


PAGE = r"""<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>fidrouter · 验证</title>
<style>
:root{--bg:#f6f8fa;--panel:#fff;--ink:#0b1220;--muted:#5b6b7a;--line:#e3e8ee;--accent:#0d9488;
--ok:#16a34a;--ok-bg:#e9f7ef;--bad:#dc2626;--bad-bg:#fdecec;--mono:ui-monospace,Menlo,Consolas,monospace;}
@media (prefers-color-scheme:dark){:root{--bg:#0b0f14;--panel:#121821;--ink:#e8eef5;--muted:#8797a8;--line:#212a35;--accent:#2dd4bf;--ok:#34d399;--ok-bg:#0f2b20;--bad:#f87171;--bad-bg:#2a1414;}}
:root[data-theme="dark"]{--bg:#0b0f14;--panel:#121821;--ink:#e8eef5;--muted:#8797a8;--line:#212a35;--accent:#2dd4bf;--ok:#34d399;--ok-bg:#0f2b20;--bad:#f87171;--bad-bg:#2a1414;}
:root[data-theme="light"]{--bg:#f6f8fa;--panel:#fff;--ink:#0b1220;--muted:#5b6b7a;--line:#e3e8ee;--accent:#0d9488;--ok:#16a34a;--ok-bg:#e9f7ef;--bad:#dc2626;--bad-bg:#fdecec;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:820px;margin:0 auto;padding:38px 20px 80px}
h1{font-size:22px;margin:0}.tag{font-size:12px;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:2px 10px;margin-left:10px}
.lead{color:var(--muted);max-width:60ch;margin:10px 0 0}
.tabs{display:flex;gap:8px;margin:22px 0 4px}
.tab{font:inherit;background:transparent;color:var(--muted);border:0;border-bottom:2px solid transparent;padding:8px 4px;cursor:pointer}
.tab.on{color:var(--ink);border-bottom-color:var(--accent);font-weight:650}
.pane{display:none}.pane.on{display:block}
.bar{display:flex;gap:10px;align-items:center;margin:14px 0 6px}
button.act{background:var(--accent);color:#04211f;border:0;border-radius:8px;padding:8px 16px;cursor:pointer;font-weight:650}
button.ghost{background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:7px 14px;cursor:pointer}
.updated{font-size:12px;color:var(--muted)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:12px 0}
.top{display:flex;align-items:center;justify-content:space-between;gap:12px}
.name{font-weight:650}.plat{font-size:12px;color:var(--muted);margin-top:2px}
.pill{font-size:12px;font-weight:700;border-radius:999px;padding:4px 12px;white-space:nowrap}
.pill.ok{background:var(--ok-bg);color:var(--ok)}.pill.bad{background:var(--bad-bg);color:var(--bad)}
.rows{margin-top:12px;display:grid;grid-template-columns:auto 1fr;gap:5px 16px;font-size:13px}.k{color:var(--muted)}
.mono{font-family:var(--mono);font-size:12px;word-break:break-all}
.detail{margin-top:10px;font-size:12.5px;color:var(--muted);border-top:1px dashed var(--line);padding-top:9px}.detail.bad{color:var(--bad)}
textarea{width:100%;height:90px;background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:10px;padding:12px;font-family:var(--mono);font-size:12px}
.how{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin-top:26px;font-size:13.5px;color:var(--muted)}.how b{color:var(--ink)}
a{color:var(--accent)}.foot{margin-top:20px;font-size:12px;color:var(--muted)}
</style></head><body><div class="wrap">
<h1 style="display:inline">fidrouter · 验证</h1><span class="tag">中立信任锚 · 不属于任何中转运营方</span>
<p class="lead">这里让你<b>自己核实</b>,不用信运营方的口头承诺,也不用写代码、不用账号。</p>

<div class="tabs">
  <button class="tab on" data-t="m">① 这台中转可信吗</button>
  <button class="tab" data-t="r">② 验一张回执</button>
</div>

<div class="pane on" id="pane-m">
  <div class="bar"><button class="ghost" id="refresh">重新验证</button><span class="updated" id="updated"></span></div>
  <div id="cards"></div>
</div>

<div class="pane" id="pane-r">
  <p class="lead" style="margin:12px 0 6px">你每次用这台中转,响应里会带一张<b>回执</b>(只有指纹和计数,没有你的内容)。粘进来,就能证明这条请求确实由可信代码处理、<b>模型没被偷偷换成便宜的</b>。</p>
  <textarea id="rin" placeholder="粘贴响应头 X-Fid-Receipt 的值…"></textarea>
  <div class="bar"><button class="act" id="chk">验证这张回执</button></div>
  <div id="rres"></div>
</div>

<div class="how">
<b>为什么可以信任它</b>
<ol style="margin:8px 0 0;padding-left:20px">
<li>这台机器出示一张<b>由芯片硬件签发的证明</b>——证明它跑在"上了锁、连机房管理员也打不开看内存"的环境里,不是普通服务器装样子。</li>
<li>证明里带着<b>运行代码的指纹</b>。把它和<b>公开源代码</b>的指纹对一对:一致,就说明它跑的正是任何人都能审计、确认"不记录你数据"的那份代码。</li>
<li>对不上 → <b>红灯</b>,客户端<b>拒绝发送</b>,你的内容根本出不了你的电脑。</li>
</ol>
<div style="margin-top:10px">绿灯 = 三步全部通过。<a href="__SOURCE__" id="src">查看源代码(开源,可复现构建,任何人可复核)</a></div>
</div>
<p class="foot">本页由中立方运营,独立于中转运营方——被验证方无法篡改验证结果。</p>
</div>
<script>
function esc(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function short(h){h=(h||'').replace('sha256:','');return h?('sha256:'+h.slice(0,16)+'…'):'—'}
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('on',x===b));
  document.querySelectorAll('.pane').forEach(p=>p.classList.toggle('on',p.id==='pane-'+b.dataset.t));
});
// ① machine
const cards=document.getElementById('cards'),upd=document.getElementById('updated');
async function load(){
  upd.textContent='验证中…';cards.style.opacity=.5;
  try{const j=await (await fetch('/api/status',{cache:'no-store'})).json();
    cards.innerHTML=j.map(e=>{const ok=e.ok===true,b=e.build||{};
      return `<div class="card"><div class="top"><div><div class="name">${esc(e.name)}</div><div class="plat">${esc(e.platform)}</div></div>${ok?'<span class="pill ok">✓ 可信</span>':'<span class="pill bad">✗ 不可信</span>'}</div>
      <div class="rows"><div class="k">端点</div><div class="mono">${esc(e.base_url)}</div>
      <div class="k">运行代码指纹</div><div class="mono">${short(e.expected)}</div>
      <div class="k">公开代码</div><div>${esc(b.source||'—')}</div>
      <div class="k">用时</div><div>${e.checked_ms}ms</div></div>
      <div class="detail ${ok?'':'bad'}">${esc(e.detail)}</div></div>`;}).join('');
    upd.textContent='最后验证 '+new Date().toLocaleTimeString();}
  catch(e){upd.textContent='加载失败'} cards.style.opacity=1;
}
document.getElementById('refresh').onclick=load;load();setInterval(load,20000);
// ② receipt
document.getElementById('chk').onclick=async()=>{
  const v=document.getElementById('rin').value.trim();if(!v)return;
  const d=await (await fetch('/api/check-receipt',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({receipt_b64:v})})).json();
  const rec=d.receipt||{},ok=d.ok===true;
  document.getElementById('rres').innerHTML=`<div class="card"><div class="top"><b>回执验证</b>${ok?'<span class="pill ok">✓ 可信</span>':'<span class="pill bad">✗ 不可信</span>'}</div>
  <div class="rows"><div class="k">签名(enclave 私钥)</div><div>${d.signature_ok?'✓ 有效':'✗ 无效'}</div>
  <div class="k">度量值∈开源注册表</div><div>${d.measurement_known?'✓ 是':'✗ 否'}</div>
  <div class="k">实际服务的模型</div><div><b>${esc(rec.model||'—')}</b> <span class="k">← 和你请求的比对 = 防降级</span></div>
  <div class="k">运行代码指纹</div><div class="mono">${short(rec.measurement)}</div>
  <div class="k">tokens</div><div>in ${rec.prompt_tokens||0} / out ${rec.completion_tokens||0}</div></div>
  <div class="detail ${ok?'':'bad'}">${esc(d.reason||'')}</div></div>`;
};
(function(){var a=document.getElementById('src');if(a&&(a.getAttribute('href')==='__SOURCE__'||!a.getAttribute('href'))){a.textContent='源代码即将公开(开源 + 可复现构建)';a.removeAttribute('href');a.style.color='var(--muted)';}})();
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def _send(self, code, ctype, body):
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            return json.loads(self.rfile.read(n)) if n > 0 else {}
        except Exception:
            return {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        if u.path == "/":
            page = PAGE.replace("__SOURCE__", REGISTRY.get("source_url", ""))
            self._send(200, "text/html; charset=utf-8", page.encode())
        elif u.path == "/api/status":
            self._send(200, "application/json", json.dumps([check(e) for e in REGISTRY["endpoints"]]).encode())
        elif u.path == "/api/expected":
            name = (q.get("target") or [""])[0]
            for e in REGISTRY["endpoints"]:
                if e["name"] == name or not name:
                    self._send(200, "application/json",
                               json.dumps({"target": e["name"], "expected_measurement": e["expected_measurement"]}).encode()); return
            self._send(404, "application/json", b'{"error":"unknown target"}')
        elif u.path == "/badge":
            ok = None
            for e in REGISTRY["endpoints"]:
                ok = check(e)["ok"]; break
            self._send(200, "image/svg+xml", badge_svg(ok))
        else:
            self._send(404, "text/plain", b"not found")

    def do_POST(self):
        if urlparse(self.path).path == "/api/check-receipt":
            rb = (self._body().get("receipt_b64") or "").strip()
            if not rb:
                self._send(400, "application/json", b'{"ok":false,"reason":"receipt_b64 required"}'); return
            self._send(200, "application/json", json.dumps(check_receipt(rb)).encode())
        else:
            self._send(404, "text/plain", b"not found")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"fidrouter trust page on http://0.0.0.0:{port}  ({len(REGISTRY['endpoints'])} endpoint(s))")
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
