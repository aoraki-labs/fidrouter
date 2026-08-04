#!/usr/bin/env bash
# Local end-to-end for the metering webhook + partner console.
# mock enclave --(signed receipt, metadata only)--> console /ingest --> per-user usage
# NB: no `set -e` — we background the enclave/console/upstream, and errexit trips
# on their async signals. Failures here are surfaced by the /api/usage output.
set -uo pipefail
cd "$(dirname "$0")/.."
export GOFLAGS=-mod=mod GOTOOLCHAIN=local CGO_ENABLED=0
GO=${GO:-/home/ubuntu/.local/go/bin/go}
PROXY=http://127.0.0.1:9090
CONSOLE=http://127.0.0.1:8082
TMP=$(mktemp -d)
# self-contained key material in a temp home (do NOT touch the repo's config/):
# init generates a fresh keys.json (cp_pub + kms_master + measurement all agree);
# drop public.json so the enclave uses that keys.json rather than a stale pinned one.
export FID_HOME="$TMP/home"; mkdir -p "$FID_HOME"
# a mock pool (empty base_url -> internal mock upstream at UPSTREAM_URL); this test
# exercises the metering path, not a real provider.
cat > "$FID_HOME/pool.plain.json" <<'JSON'
{"pools":{"shared":[
  {"id":"acct-a","provider":"openai","key":"mock-key-a","base_url":"","tpm_budget":100000},
  {"id":"acct-b","provider":"openai","key":"mock-key-b","base_url":"","tpm_budget":100000}]}}
JSON

cleanup(){ pkill -f "$TMP/mock-upstream" 2>/dev/null||true; pkill -f "$TMP/fid-proxy" 2>/dev/null||true; [ -n "${CONSOLE_PID:-}" ] && kill "$CONSOLE_PID" 2>/dev/null||true; rm -rf "$TMP"; }
trap cleanup EXIT; cleanup 2>/dev/null||true

$GO build -o "$TMP/fid-proxy" ./cmd/fid-proxy
$GO build -o "$TMP/mock-upstream" ./cmd/mock-upstream
$GO build -o "$TMP/ctl" ./cmd/ctl
$GO build -o "$TMP/client" ./cmd/client
"$TMP/ctl" init >/dev/null; "$TMP/ctl" seal-pool >/dev/null; source "$FID_HOME/pins.sh"

# temp registry: register the MOCK measurement -> mock identity pubkey, so the
# console will accept (verify) receipts from this local mock enclave.
MEAS=$(FIDPROXY_MEASURE=1 "$TMP/fid-proxy")
IDPUB_HEX=$(python3 -c 'import json,base64,os;k=json.load(open(os.environ["FID_HOME"]+"/keys.json"));print(base64.b64decode(k["identity_pub"]).hex())')
python3 - "$TMP/registry.json" "$MEAS" "$IDPUB_HEX" <<'PY'
import json,sys
path,meas,idpub=sys.argv[1],sys.argv[2],sys.argv[3]
json.dump({"builds":{meas:{"identity_pub_hex":idpub}}},open(path,"w"))
print("registered measurement",meas[:24],"idpub",idpub[:16])
PY

echo "== start console (metering sink) =="
REGISTRY_PATH="$TMP/registry.json" PORT=8082 python3 console/server.py >"$TMP/console.log" 2>&1 &
CONSOLE_PID=$!
echo "== start mock upstream + enclave (metering -> console) =="
"$TMP/mock-upstream" >/tmp/fid-upstream.met.log 2>&1 &
FIDPROXY_METERING_URL="$CONSOLE/ingest" FIDPROXY_VERIFY_URL="https://verify.example" \
  "$TMP/fid-proxy" >/tmp/fid-proxy.met.log 2>&1 &
sleep 4

mint(){ "$TMP/ctl" mint "$@"; }
run(){ "$TMP/client" -token "$1" -model "$2" -prefix "$3" -suffix "$4" \
        -pin-measurement "$PIN_MEASUREMENT" -pin-idpub "$PIN_IDPUB" >/dev/null; }

T1=$(mint -tenant acme  -pool shared -models gpt-4o,claude-3)
T2=$(mint -tenant globex -pool shared -models gpt-4o)
run "$T1" gpt-4o   "ctx" "q1"; run "$T1" gpt-4o "ctx" "q2"; run "$T1" claude-3 "ctx" "q3"
run "$T2" gpt-4o   "ctx" "q1"
sleep 2

echo; echo "== console /api/usage (per-user, from verified signed receipts) =="
curl -s "$CONSOLE/api/usage" | python3 -m json.tool
echo; echo "== reject test: forged receipt (bad sig) must be refused =="
curl -s -X POST "$CONSOLE/ingest" -H 'content-type: application/json' \
  -d '{"receipt":"eyJyZWNlaXB0Ijp7Im1lYXN1cmVtZW50IjoiZm9yZ2VkIn19"}'
echo