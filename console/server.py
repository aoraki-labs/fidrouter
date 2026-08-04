#!/usr/bin/env python3
"""Partner console — the control-plane side a relay operator sees.

Receives the enclave's SIGNED metering receipts (metadata only: tenant/user,
model, token counts — NO prompt/response content), VERIFIES each one is genuinely
signed by the registered enclave (so usage numbers are unforgeable — not even we
can inflate them), aggregates per user for billing/dashboards, and renders the
product docs. This is the partner's control plane: it never sees content.

    python3 console/server.py            # http://localhost:8082
"""
import base64
import json
import os
import sys
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "sdk", "python"))
from fidrouter_verify import verify_receipt  # noqa: E402

REGISTRY = json.load(open(os.environ.get("REGISTRY_PATH",
                      os.path.join(HERE, "..", "verify-page", "registry.json"))))
DOCS = open(os.environ.get("DOCS_PATH", os.path.join(HERE, "..", "docs", "DESIGN.md"))).read()

# in-memory usage aggregates keyed by tenant (would be a DB in production)
USAGE = defaultdict(lambda: {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0,
                             "models": set(), "last_ts": 0})


def idpub_for(measurement: str):
    b = REGISTRY.get("builds", {}).get(measurement)
    return b.get("identity_pub_hex") if b else None


def ingest(receipt_b64: str) -> dict:
    """Verify the signed receipt against the registered enclave key, then count it.
    Rejects anything not signed by a known enclave → usage can't be forged."""
    try:
        rec = json.loads(base64.b64decode(receipt_b64))["receipt"]
    except Exception as e:
        return {"ok": False, "reason": f"malformed: {e}"}
    idhex = idpub_for(rec.get("measurement", ""))
    if not idhex:
        return {"ok": False, "reason": "unknown enclave measurement (not in registry)"}
    v = verify_receipt(receipt_b64, idhex)
    if not v["signature_ok"]:
        return {"ok": False, "reason": "receipt signature invalid (forged?)"}
    u = USAGE[rec.get("tenant", "?")]
    u["requests"] += 1
    u["prompt_tokens"] += int(rec.get("prompt_tokens", 0))
    u["completion_tokens"] += int(rec.get("completion_tokens", 0))
    u["models"].add(rec.get("model", "?"))
    u["last_ts"] = int(rec.get("ts_unix", 0)) or int(time.time())
    return {"ok": True, "tenant": rec.get("tenant")}


def usage_json():
    return [{"tenant": t, "requests": u["requests"], "prompt_tokens": u["prompt_tokens"],
             "completion_tokens": u["completion_tokens"], "models": sorted(u["models"]),
             "last_ts": u["last_ts"]} for t, u in sorted(USAGE.items())]


PAGE = r"""<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>fidrouter · 合作方控制台</title>
<style>
:root{--bg:#f6f8fa;--panel:#fff;--ink:#0b1220;--muted:#5b6b7a;--line:#e3e8ee;--accent:#0d9488;--ok:#16a34a;--mono:ui-monospace,Menlo,Consolas,monospace;}
@media (prefers-color-scheme:dark){:root{--bg:#0b0f14;--panel:#121821;--ink:#e8eef5;--muted:#8797a8;--line:#212a35;--accent:#2dd4bf;--ok:#34d399;}}
:root[data-theme="dark"]{--bg:#0b0f14;--panel:#121821;--ink:#e8eef5;--muted:#8797a8;--line:#212a35;--accent:#2dd4bf;--ok:#34d399;}
:root[data-theme="light"]{--bg:#f6f8fa;--panel:#fff;--ink:#0b1220;--muted:#5b6b7a;--line:#e3e8ee;--accent:#0d9488;--ok:#16a34a;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.65 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:34px 20px 80px}
h1{font-size:22px;margin:0}.tag{font-size:12px;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:2px 10px;margin-left:10px}
.lead{color:var(--muted);max-width:64ch;margin:10px 0 0}
.tabs{display:flex;gap:6px;margin:22px 0 8px;flex-wrap:wrap}
.tab{font:inherit;background:transparent;color:var(--muted);border:0;border-bottom:2px solid transparent;padding:8px 4px;cursor:pointer}
.tab.on{color:var(--ink);border-bottom-color:var(--accent);font-weight:650}
.pane{display:none}.pane.on{display:block}
.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:12px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:600}
td.n{text-align:right;font-variant-numeric:tabular-nums;font-family:var(--mono)}
.muted{color:var(--muted)}.updated{font-size:12px;color:var(--muted);margin:8px 0}
.doc{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:8px 22px 20px}
.doc h1{font-size:22px;margin:22px 0 8px}.doc h2{font-size:18px;margin:26px 0 8px;border-top:1px solid var(--line);padding-top:18px}
.doc h3{font-size:15px;margin:18px 0 6px}.doc h4{font-size:14px;margin:14px 0 4px;color:var(--muted)}
.doc code{background:var(--bg);border:1px solid var(--line);border-radius:5px;padding:1px 5px;font-family:var(--mono);font-size:12.5px}
.doc pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:12px;overflow-x:auto}.doc pre code{border:0;background:0;padding:0}
.doc table{margin:8px 0}.doc blockquote{border-left:3px solid var(--accent);margin:10px 0;padding:2px 14px;color:var(--muted)}
.doc ul,.doc ol{padding-left:22px}
a{color:var(--accent)}
</style></head><body><div class="wrap">
<h1 style="display:inline">fidrouter · 合作方控制台</h1><span class="tag">控制面 · 只见元数据,永不见内容</span>
<p class="lead">你的用户请求直连可信 enclave(无日志),enclave 把<b>签名计量</b>(用户/模型/token 数,<b>无 prompt 内容</b>)回传到这里。计量每条都验签,<b>不可伪造</b> —— 连我们都改不了你的用量数。</p>
<div class="tabs"><button class="tab on" data-t="u">用量</button><button class="tab" data-t="d">产品文档</button></div>
<div class="pane on" id="pane-u">
  <div class="updated" id="updated"></div>
  <div class="scroll"><table><thead><tr><th>用户/租户</th><th class="n">请求数</th><th class="n">输入 token</th><th class="n">输出 token</th><th>模型</th><th>最近</th></tr></thead><tbody id="rows"></tbody></table></div>
  <p class="muted" style="font-size:12px;margin-top:10px">按用户聚合,用于你自己的计费/看板。要接你的 New API,把计量回调指到 <code>/ingest</code> 即可。</p>
</div>
<div class="pane" id="pane-d"><div class="doc" id="doc"></div></div>
</div>
<script>
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('on',x===b));
  document.querySelectorAll('.pane').forEach(p=>p.classList.toggle('on',p.id==='pane-'+b.dataset.t));
});
function esc(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function tstr(u){return u?new Date(u*1000).toLocaleString():'—'}
async function loadUsage(){
  const j=await (await fetch('/api/usage',{cache:'no-store'})).json();
  document.getElementById('updated').textContent='最后更新 '+new Date().toLocaleTimeString()+' · '+j.length+' 个用户';
  document.getElementById('rows').innerHTML=j.map(r=>`<tr><td>${esc(r.tenant)}</td><td class="n">${r.requests}</td><td class="n">${r.prompt_tokens}</td><td class="n">${r.completion_tokens}</td><td>${r.models.map(esc).join(', ')}</td><td>${tstr(r.last_ts)}</td></tr>`).join('')||'<tr><td colspan="6" class="muted">暂无用量(发一条请求试试)</td></tr>';
}
loadUsage(); setInterval(loadUsage,5000);
// minimal markdown -> html for the product docs
function md(src){
  const lines=src.split('\n'); let out=[],i=0;
  function inline(t){return esc(t).replace(/`([^`]+)`/g,'<code>$1</code>').replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>').replace(/\[([^\]]+)\]\(([^)]+)\)/g,'<a href="$2">$1</a>');}
  while(i<lines.length){
    let l=lines[i];
    if(/^```/.test(l)){let b=[];i++;while(i<lines.length&&!/^```/.test(lines[i])){b.push(esc(lines[i]));i++;}i++;out.push('<pre><code>'+b.join('\n')+'</code></pre>');continue;}
    let h=l.match(/^(#{1,4})\s+(.*)/); if(h){out.push('<h'+h[1].length+'>'+inline(h[2])+'</h'+h[1].length+'>');i++;continue;}
    if(/^\s*\|/.test(l)){let rows=[];while(i<lines.length&&/^\s*\|/.test(lines[i])){rows.push(lines[i]);i++;}
      let cells=r=>r.split('|').slice(1,-1).map(c=>c.trim());
      let head=cells(rows[0]);let body=rows.slice(2);
      out.push('<div class="scroll"><table><thead><tr>'+head.map(c=>'<th>'+inline(c)+'</th>').join('')+'</tr></thead><tbody>'+body.map(r=>'<tr>'+cells(r).map(c=>'<td>'+inline(c)+'</td>').join('')+'</tr>').join('')+'</tbody></table></div>');continue;}
    if(/^>\s?/.test(l)){out.push('<blockquote>'+inline(l.replace(/^>\s?/,''))+'</blockquote>');i++;continue;}
    if(/^\s*[-*]\s+/.test(l)){let items=[];while(i<lines.length&&/^\s*[-*]\s+/.test(lines[i])){items.push('<li>'+inline(lines[i].replace(/^\s*[-*]\s+/,''))+'</li>');i++;}out.push('<ul>'+items.join('')+'</ul>');continue;}
    if(l.trim()===''){out.push('');i++;continue;}
    out.push('<p>'+inline(l)+'</p>');i++;
  }
  return out.join('\n');
}
fetch('/api/docs').then(r=>r.text()).then(t=>{document.getElementById('doc').innerHTML=md(t);});
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def _send(self, code, ctype, body):
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(body)

    def log_message(self, *a):
        pass

    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/":
            self._send(200, "text/html; charset=utf-8", PAGE.encode())
        elif p == "/api/usage":
            self._send(200, "application/json", json.dumps(usage_json()).encode())
        elif p == "/api/docs":
            self._send(200, "text/plain; charset=utf-8", DOCS.encode())
        else:
            self._send(404, "text/plain", b"not found")

    def do_POST(self):
        if urlparse(self.path).path == "/ingest":
            n = int(self.headers.get("Content-Length", "0") or "0")
            try:
                body = json.loads(self.rfile.read(n)) if n > 0 else {}
            except Exception:
                body = {}
            r = ingest((body.get("receipt") or "").strip())
            self._send(200 if r["ok"] else 400, "application/json", json.dumps(r).encode())
        else:
            self._send(404, "text/plain", b"not found")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8082"))
    print(f"fidrouter partner console on http://0.0.0.0:{port}")
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
