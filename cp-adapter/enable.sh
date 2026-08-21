#!/usr/bin/env bash
# fidrouter — one-line partner enable. Bundles cp-adapter beside your gateway.
#   curl -fsSL https://app.fidcore.xyz/enable.sh | bash          # interactive
# Agent/non-interactive: set NEWAPI_BASE, ENCLAVE_URL, EXPECTED_MEASUREMENT in the env.
set -euo pipefail
ask(){ # ask VAR "prompt" [default]
  local cur="${!1:-}"; [ -n "$cur" ] && return
  local v; printf "%s%s: " "$2" "${3:+ [$3]}" >/dev/tty; read -r v </dev/tty || true
  eval "$1=\"${v:-$3}\""; }
ask NEWAPI_BASE "Your gateway base URL"
ask ENCLAVE_URL "Your enclave URL" "http://your-enclave:9090"
ask EXPECTED_MEASUREMENT "Enclave measurement (sha256:...)"
VERIFY_URL="${VERIFY_URL:-https://app.fidcore.xyz}"; MODELS="${MODELS:-claude-opus-5,claude-sonnet-5,claude-haiku-4-5-20251001}"
PORT="${PORT:-8091}"; DIR="${DIR:-/opt/cp-adapter}"
RAW="https://raw.githubusercontent.com/aoraki-labs/fidrouter-cp-adapter/main/adapter.py"
[ -n "$NEWAPI_BASE" ] && [ -n "$EXPECTED_MEASUREMENT" ] || { echo "need gateway URL + measurement"; exit 1; }

echo "[fidrouter] installing cp-adapter → $DIR"
python3 -c "import cryptography" 2>/dev/null || python3 -m pip install --quiet cryptography
sudo mkdir -p "$DIR"; sudo curl -fsSL "$RAW" -o "$DIR/adapter.py"
if [ -z "${CP_SEED_HEX:-}" ]; then
  read -r CP_SEED_HEX CP_PUB < <(python3 - <<'PY'
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K
from cryptography.hazmat.primitives import serialization as s
k=K.generate();r=lambda o:o(s.Encoding.Raw,*(([s.PrivateFormat.Raw,s.NoEncryption()]) if o==k.private_bytes else [s.PublicFormat.Raw]))
print(k.private_bytes(s.Encoding.Raw,s.PrivateFormat.Raw,s.NoEncryption()).hex(),k.public_key().public_bytes(s.Encoding.Raw,s.PublicFormat.Raw).hex())
PY
)
  echo "[fidrouter] generated CP keypair — bake this cp_pub into your enclave, then rebuild:"
  echo "            cp_pub = $CP_PUB"
fi
sudo tee "$DIR/cpadapter.env" >/dev/null <<EOF
CP_SEED_HEX=$CP_SEED_HEX
NEWAPI_BASE=$NEWAPI_BASE
ENCLAVE_URL=$ENCLAVE_URL
EXPECTED_MEASUREMENT=$EXPECTED_MEASUREMENT
VERIFY_URL=$VERIFY_URL
MODELS=$MODELS
PORT=$PORT
EOF
sudo chmod 600 "$DIR/cpadapter.env"
if command -v systemctl >/dev/null; then
  sudo tee /etc/systemd/system/cpadapter.service >/dev/null <<EOF
[Unit]
Description=fidrouter cp-adapter
After=network-online.target
[Service]
EnvironmentFile=$DIR/cpadapter.env
ExecStart=$(command -v python3) $DIR/adapter.py
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload && sudo systemctl enable --now cpadapter
  sleep 2; curl -fsS "http://127.0.0.1:$PORT/healthz" && echo
else
  echo "[fidrouter] run: env \$(cat $DIR/cpadapter.env|xargs) python3 $DIR/adapter.py"
fi
echo "[fidrouter] up on :$PORT. Next → register your endpoint at $VERIFY_URL (base_url=$ENCLAVE_URL, measurement=$EXPECTED_MEASUREMENT, cp_adapter_url=http://<this-host>:$PORT), then BYOK."
