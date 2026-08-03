#!/usr/bin/env bash
# End-to-end local demo of the fid-router verifiable no-log relay (mocked TEE).
# Shows: attestation + fail-closed, E2EE prompt, affinity routing -> cache hits,
# shared vs dedicated pools, signed receipts + downgrade detection, and NO-LOG.
set -euo pipefail

cd "$(dirname "$0")/.."
export GOFLAGS=-mod=mod GOTOOLCHAIN=local CGO_ENABLED=0
GO=${GO:-/home/ubuntu/.local/go/bin/go}
export FID_HOME=config
PROXY=http://127.0.0.1:9090
LOG=/tmp/fid-proxy.demo.log

echo "== build =="
$GO build ./...

echo "== ctl init + seal managed-key pool =="
$GO run ./cmd/ctl init
$GO run ./cmd/ctl seal-pool
source config/pins.sh

cleanup() { pkill -f 'exe/mock-upstream' 2>/dev/null || true; pkill -f 'exe/fid-proxy' 2>/dev/null || true; }
trap cleanup EXIT
cleanup

echo "== start mock upstream + fid-proxy =="
$GO run ./cmd/mock-upstream >/tmp/fid-upstream.demo.log 2>&1 &
$GO run ./cmd/fid-proxy      >"$LOG" 2>&1 &
sleep 3

mint() { $GO run ./cmd/ctl mint "$@"; }
run()  { $GO run ./cmd/client -token "$1" -model "$2" -prefix "$3" -suffix "$4" \
             -pin-measurement "$PIN_MEASUREMENT" -pin-idpub "$PIN_IDPUB"; }

T_CUST1=$(mint -tenant cust1 -pool shared   -models gpt-4o,claude-3)
T_CUST2=$(mint -tenant cust2 -pool shared   -models gpt-4o)
T_VIP=$(  mint -tenant vip   -pool cust-vip -models gpt-4o -isolated)

PFX="You are ACME's support bot. [500 tokens of stable policy/context ...]"

echo; echo "== 1) cust1 sends the SAME prefix 3x -> affinity pins one account -> cache warms =="
run "$T_CUST1" gpt-4o "$PFX" "question one"
run "$T_CUST1" gpt-4o "$PFX" "question two"
run "$T_CUST1" gpt-4o "$PFX" "question three"

echo; echo "== 2) cust2 (shares the pool) sends the SAME prefix -> lands same account -> instant HIT =="
echo "   (this cross-tenant cache reuse is the efficiency win AND the side channel; use -isolated to forbid it)"
run "$T_CUST2" gpt-4o "$PFX" "different question"

echo; echo "== 3) vip on its DEDICATED pool (isolated) — separate cache, first call is a miss =="
run "$T_VIP" gpt-4o "$PFX" "vip question"

echo; echo "== 4) receipt binds the model ACTUALLY used; client checks model==requested =="
echo "   (no downgrade happens here, but if the proxy served a cheaper model the receipt check would FAIL-CLOSED)"
run "$T_CUST1" claude-3 "$PFX" "cust1 asks claude" || true

echo; echo "== 5) NO-LOG check: does the proxy log contain any prompt text? =="
if grep -qiE 'ACME|question|policy|completion|echo\(' "$LOG"; then
  echo "  !! found prompt/response content in logs (BAD)"; else
  echo "  OK: proxy logs contain only metadata (tenant/model/account/cache/tokens). Sample:";
  grep '\[infer\]' "$LOG" | tail -3 | sed 's/^/     /'
fi

echo; echo "== 6) TAMPER: restart proxy as a 'logging build' -> measurement changes -> client FAIL-CLOSED =="
pkill -f 'exe/fid-proxy' 2>/dev/null || true; sleep 1
FIDPROXY_TAMPER=1 $GO run ./cmd/fid-proxy >/tmp/fid-proxy.tamper.log 2>&1 &
sleep 3
run "$T_CUST1" gpt-4o "$PFX" "should be refused" || echo "   (refused as expected)"

echo; echo "== done =="
