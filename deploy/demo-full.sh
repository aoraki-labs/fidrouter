#!/usr/bin/env bash
# FULL customer demo chain:
#   New API (control plane, AWS) --token--> cp-adapter --capability JWT-->
#   client verify SDK --attest+seal--> fid-proxy in GCP Confidential Space
#
# Prereq: a New API USER token (create in New API: 令牌/Tokens -> 新建 -> copy sk-...).
#   NEWAPI_TOKEN=sk-xxxx bash deploy/demo-full.sh
set -uo pipefail
cd "$(dirname "$0")/.."
: "${NEWAPI_TOKEN:?set NEWAPI_TOKEN to a New API user token (sk-...)}"
NEWAPI_URL=${NEWAPI_URL:-https://207.57.187.193}
CS_IP=${CS_IP:-34.158.56.83}
DIGEST=${DIGEST:-sha256:dbccae5713b9b0a817af87281bde7fc57cb05ef557e684527b8567d4b6cf2be3}
# Real Claude via BYOK. Override MODEL=claude-haiku-4-5 for a ~cheap/fast pipe test.
MODEL=${MODEL:-claude-opus-5}
export FID_HOME=config

echo "== 1) start cp-adapter (bridges New API -> fid-router capability token) =="
pkill -f 'dist/cp-adapter' 2>/dev/null || true; sleep 1
NEWAPI_URL="$NEWAPI_URL" ./dist/cp-adapter >/tmp/cp-adapter.log 2>&1 &
sleep 2

echo "== 2) exchange the New API token for a capability JWT =="
CAP=$(curl -s -X POST http://127.0.0.1:9095/exchange \
      -H 'Content-Type: application/json' \
      -d "{\"api_token\":\"$NEWAPI_TOKEN\",\"pool\":\"shared\"}" \
      | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))")
if [ -z "$CAP" ]; then echo "  exchange failed (invalid token?)"; cat /tmp/cp-adapter.log; exit 1; fi
echo "  capability JWT: ${CAP:0:32}…"

echo "== 3) client verifies Confidential Space (measurement=our image) and sends =="
CAP="$CAP" DIGEST="$DIGEST" CS_IP="$CS_IP" MODEL="$MODEL" python3 - <<'PY'
import os, sys
sys.path.insert(0, "sdk/python")
from fidrouter_verify import FidClient, FidVerificationError
c = FidClient(base_url=f"http://{os.environ['CS_IP']}:9090", token=os.environ["CAP"],
              pin_measurement=os.environ["DIGEST"], cs_audience="fid-router")
try:
    for i, q in enumerate(["refund policy?", "shipping time?"], 1):
        r = c.chat(os.environ["MODEL"], [{"role":"system","content":"ACME support [stable ctx]"},
                                         {"role":"user","content":q}])
        print(f"  #{i} ✔ verified (Confidential Space, measurement=our image) "
              f"account={r.account} cache_hit={r.cache_hit} model={r.model} -> {r.completion}")
except FidVerificationError as e:
    print("  ✘ FAIL-CLOSED:", e)
PY
pkill -f 'dist/cp-adapter' 2>/dev/null || true
echo "== done =="
