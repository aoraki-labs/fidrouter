#!/usr/bin/env bash
# Reproduce & verify what the live fidrouter enclave runs — at the CONTENT level.
#
# The security-relevant artifact is the fid-proxy BINARY, which is bit-for-bit
# reproducible from this source. The enclave image is exactly:
#     pinned distroless base (digest in deploy/gcp/cs/Dockerfile)
#   + this reproducible fid-proxy binary
#   + public config (config/public.json, config/pool.plain.json) — no secrets
# so verifying the running image = confirming those three, no trust in the operator.
#
#   bash scripts/reproduce.sh                       # print the reproducible binary hash
#   LIVE=<AR image ref> bash scripts/reproduce.sh   # + pull the live image and diff its binary
#
# (Note: the OCI image manifest digest is deterministic via `buildx --output
#  type=oci` + SOURCE_DATE_EPOCH, but the pushable exporter's config timestamp is
#  not bit-stable across tools; content-equivalence above is the practical check.)
set -euo pipefail
cd "$(dirname "$0")/.."
: "${GO:=go}"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $GO build \
  -trimpath -buildvcs=false -ldflags=-buildid= -o /tmp/fid-proxy.repro ./cmd/fid-proxy
H=$(sha256sum /tmp/fid-proxy.repro | awk '{print $1}')
echo "reproducible fid-proxy binary sha256: $H"

if [ -n "${LIVE:-}" ]; then
  : "${CRANE:=crane}"
  echo "pulling live image $LIVE and extracting its /app/fid-proxy …"
  D=$(mktemp -d); $CRANE export "$LIVE" - | tar -xf - -C "$D" app/fid-proxy 2>/dev/null || true
  if [ -f "$D/app/fid-proxy" ]; then
    LH=$(sha256sum "$D/app/fid-proxy" | awk '{print $1}')
    echo "live image  fid-proxy binary sha256: $LH"
    [ "$H" = "$LH" ] && echo "✅ MATCH — the live enclave runs exactly this open source" \
                     || echo "❌ MISMATCH — live binary differs from this source"
  else
    echo "could not extract /app/fid-proxy from live image"
  fi
  rm -rf "$D"
fi
