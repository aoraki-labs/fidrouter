// Tiny local web server for testing a fidrouter endpoint from a browser.
// The browser talks to THIS server (same origin) which runs the TS verify SDK
// and does the attestation + E2EE + receipt check in Node. (A pure-browser page
// can't be a Claude artifact — artifact CSP forbids fetching your relay host.)
//   node web/server.mjs          # then open http://127.0.0.1:8088
import http from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { FidClient, FidVerificationError } from "../sdk/ts/fidrouter-verify.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.WEB_PORT || 8088;

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && (req.url === "/" || req.url.startsWith("/index.html"))) {
      const html = await readFile(path.join(__dirname, "index.html"));
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(html);
    }
    if (req.method === "POST" && req.url === "/api/infer") {
      let body = "";
      for await (const c of req) body += c;
      const inp = JSON.parse(body);
      const client = new FidClient({
        baseUrl: inp.baseUrl, token: inp.token,
        pinMeasurement: inp.pinMeasurement || "", pinIdpubHex: inp.pinIdpub || "",
      });
      try {
        const r = await client.infer({ model: inp.model, prefix: inp.prefix, suffix: inp.suffix });
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ ok: true, result: r }));
      } catch (e) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({
          ok: false, failClosed: e instanceof FidVerificationError, error: String(e.message || e),
        }));
      }
    }
    res.writeHead(404);
    res.end("not found");
  } catch (e) {
    res.writeHead(500);
    res.end(String(e));
  }
});
server.listen(PORT, () => console.log(`[web] fidrouter test UI on http://127.0.0.1:${PORT}`));
