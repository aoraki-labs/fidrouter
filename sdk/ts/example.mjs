// Example: verify a fidrouter endpoint and send two prompts with the SAME
// cacheable prefix (2nd should be a cache hit via affinity routing).
//   PIN_MEASUREMENT=.. PIN_IDPUB=.. FID_TOKEN=.. node example.mjs
import { FidClient, FidVerificationError } from "./fidrouter-verify.mjs";

const client = new FidClient({
  baseUrl: process.env.FID_PROXY || "http://127.0.0.1:9090",
  token: process.env.FID_TOKEN,
  pinMeasurement: process.env.PIN_MEASUREMENT || "",
  pinIdpubHex: process.env.PIN_IDPUB || "",
});

const PREFIX = "You are ACME's support bot. [500 tokens of stable policy/context ...]";
try {
  let i = 0;
  for (const q of ["question one", "question two"]) {
    i++;
    const r = await client.chat({
      model: "gpt-4o",
      messages: [
        { role: "system", content: PREFIX },
        { role: "user", content: q },
      ],
    });
    console.log(`[ts #${i}] ✔ verified  account=${r.account} affinity=${r.affinity} ` +
      `CACHE_HIT=${r.cacheHit} model=${r.model} ptok=${r.promptTokens} -> ${r.completion}`);
  }
} catch (e) {
  if (e instanceof FidVerificationError) { console.log("[ts] ✘ FAIL-CLOSED:", e.message); process.exit(1); }
  throw e;
}
