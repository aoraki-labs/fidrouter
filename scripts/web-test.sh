#!/usr/bin/env bash
# Boots the mock stack + web UI, exercises POST /api/infer (miss->hit) and a
# tamper case, then tears everything down — all in one foreground run.
set -uo pipefail
cd "$(dirname "$0")/.."
export GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS=-mod=mod
export GOPATH=/home/ubuntu/.local/gopath GOCACHE=/home/ubuntu/.local/gocache
GO=${GO:-/home/ubuntu/.local/go/bin/go}
export FID_HOME=config

cleanup(){ pkill -f 'exe/mock-upstream' 2>/dev/null||true; pkill -f 'exe/fid-proxy' 2>/dev/null||true; pkill -f 'web/server.mjs' 2>/dev/null||true; }
trap cleanup EXIT; cleanup; sleep 1

$GO build ./...
$GO run ./cmd/ctl init >/dev/null; $GO run ./cmd/ctl seal-pool >/dev/null; source config/pins.sh
$GO run ./cmd/mock-upstream >/tmp/up.log 2>&1 &
$GO run ./cmd/fid-proxy     >/tmp/px.log 2>&1 &
node web/server.mjs         >/tmp/web.log 2>&1 &
sleep 4
TOK=$($GO run ./cmd/ctl mint -tenant cust1 -pool shared -models gpt-4o)

call(){ curl -s -X POST http://127.0.0.1:8088/api/infer -H 'Content-Type: application/json' \
  -d "{\"baseUrl\":\"http://127.0.0.1:9090\",\"token\":\"$TOK\",\"pinMeasurement\":\"$1\",\"pinIdpub\":\"$PIN_IDPUB\",\"model\":\"gpt-4o\",\"prefix\":\"stable ctx\",\"suffix\":\"$2\"}"; }

echo "== call 1 (expect miss) =="; call "$PIN_MEASUREMENT" q1 | python3 -c "import sys,json;d=json.load(sys.stdin);print('ok=',d['ok'],'cacheHit=',d['result']['cacheHit'],'account=',d['result']['account'],'model=',d['result']['model'])"
echo "== call 2 same prefix (expect HIT) =="; call "$PIN_MEASUREMENT" q2 | python3 -c "import sys,json;d=json.load(sys.stdin);print('ok=',d['ok'],'cacheHit=',d['result']['cacheHit'])"
echo "== tamper: wrong pinned measurement (expect fail-closed) =="; call deadbeef q3 | python3 -c "import sys,json;d=json.load(sys.stdin);print('ok=',d['ok'],'failClosed=',d.get('failClosed'),'err=',(d.get('error') or '')[:56])"
echo "== web.log =="; tail -2 /tmp/web.log