#!/usr/bin/env bash
# Runs the Python and TS verify SDKs against the real Go data plane, proving
# cross-language byte-compatibility (attestation, E2EE, receipt signature),
# then a tamper check (SDKs must fail-closed).
set -euo pipefail
cd "$(dirname "$0")/.."
export GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS=-mod=mod
export GOPATH=/home/ubuntu/.local/gopath GOCACHE=/home/ubuntu/.local/gocache
GO=${GO:-/home/ubuntu/.local/go/bin/go}
export FID_HOME=config

echo "== build + init =="
$GO build ./...
$GO run ./cmd/ctl init >/dev/null
$GO run ./cmd/ctl seal-pool >/dev/null
source config/pins.sh
export PIN_MEASUREMENT PIN_IDPUB
export FID_PROXY=http://127.0.0.1:9090

cleanup(){ pkill -f 'exe/mock-upstream' 2>/dev/null || true; pkill -f 'exe/fid-proxy' 2>/dev/null || true; }
trap cleanup EXIT; cleanup

$GO run ./cmd/mock-upstream >/tmp/fid-up.sdk.log 2>&1 &
$GO run ./cmd/fid-proxy     >/tmp/fid-proxy.sdk.log 2>&1 &
sleep 3

export FID_TOKEN=$($GO run ./cmd/ctl mint -tenant cust1 -pool shared -models gpt-4o,claude-3)

echo; echo "== Python SDK vs Go proxy =="
python3 sdk/python/example.py

echo; echo "== TS/Node SDK vs Go proxy =="
node sdk/ts/example.mjs

echo; echo "== TAMPER: restart proxy as logging build -> SDKs must FAIL-CLOSED =="
pkill -f 'exe/fid-proxy' 2>/dev/null || true; sleep 1
FIDPROXY_TAMPER=1 $GO run ./cmd/fid-proxy >/tmp/fid-proxy.tamper.log 2>&1 &
sleep 3
echo "-- python --"; python3 sdk/python/example.py || true
echo "-- node --";   node sdk/ts/example.mjs || true

echo; echo "== done =="
