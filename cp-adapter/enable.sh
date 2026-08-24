#!/usr/bin/env bash
# fidrouter — install cp-adapter beside your gateway.
#
# You are being asked to pipe a script into a shell on your own production host, so it should
# tell you exactly what it will do and touch as little as possible. It:
#   * installs into ONE directory (default /opt/cp-adapter) and its own venv — it does NOT
#     install anything into your system Python
#   * downloads adapter.py PINNED to a commit and verifies its sha256 before running it
#   * runs as a dedicated non-root user, bound to 127.0.0.1
#   * does not read, modify, proxy or restart your gateway. It never sees a prompt.
#
# Read it first, or have it print its plan and exit:
#   curl -fsSL https://app.fidcore.xyz/enable.sh | bash -s -- --dry-run
#
# Normal install (interactive):
#   curl -fsSL https://app.fidcore.xyz/enable.sh | bash
#
# Non-interactive: set NEWAPI_BASE (and optionally ENCLAVE_URL / EXPECTED_MEASUREMENT).
#
# This file is published at github.com/aoraki-labs/fidrouter/blob/main/cp-adapter/enable.sh
# and what app.fidcore.xyz serves is byte-identical — diff them if you like:
#   diff <(curl -fsSL https://app.fidcore.xyz/enable.sh) enable.sh
set -euo pipefail

# ---- pinned artifact ------------------------------------------------------------------
# Pinned to a COMMIT, not a branch: a branch means "whatever was there the second you ran
# this". The checksum is verified before the file is ever executed.
PIN_COMMIT="${PIN_COMMIT:-047286594f0cf3551ca1d0da3eb05a2e8c80d4a1}"
PIN_SHA256_VALIDATORS="${PIN_SHA256_VALIDATORS:-03b0cb32842bc91a6679c19fcb03dab4f10e0e31d0cc62ebb0d60dd3a700f86c}"
PIN_SHA256="${PIN_SHA256:-27d914d335d24979ecb32ee7cd425756640a9c5a783730d09fa08799ad9257b1}"
RAW_BASE="https://raw.githubusercontent.com/aoraki-labs/fidrouter/${PIN_COMMIT}/cp-adapter"
RAW="$RAW_BASE/adapter.py"
PLATFORM="${PLATFORM:-https://app.fidcore.xyz}"

DIR="${DIR:-/opt/cp-adapter}"
PORT="${PORT:-8091}"
BIND="${BIND:-127.0.0.1}"
SVC_USER="${SVC_USER:-cpadapter}"
DRY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run|--print-only) DRY=1 ;;
    --dir)  DIR="$2"; shift ;;
    --port) PORT="$2"; shift ;;
    --bind) BIND="$2"; shift ;;
    --user) SVC_USER="$2"; shift ;;
    --validator) VALIDATOR="$2"; shift ;;
    -h|--help) sed -n '2,25p' "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

say(){ printf '[fidrouter] %s\n' "$*"; }
ask(){ # ask VAR "prompt" [default]
  local cur="${!1:-}"; [ -n "$cur" ] && return
  local def="${3:-}" v
  # Must work both interactively and under `curl | bash` (where stdin is the script, so we
  # read from the terminal) AND fully unattended (cron/CI/agent: no terminal at all, so take
  # the default rather than dying on /dev/tty). Note /dev/tty can exist yet not be openable,
  # so test by actually opening it.
  if ! { : >/dev/tty; } 2>/dev/null; then eval "$1=\"$def\""; return; fi
  printf '%s%s: ' "$2" "${def:+ [$def]}" >/dev/tty
  read -r v </dev/tty || true
  eval "$1=\"${v:-$def}\""
}

# ---- the managed enclave's CURRENT measurement comes from the public registry ----------
# Never hard-code it: the measurement changes every time the enclave is rebuilt, and a stale
# default would make you pin a build that is no longer running — your endpoint would simply
# fail attestation. If the registry is unreachable we ask rather than guess.
fetch_managed(){
  command -v python3 >/dev/null || return 0
  curl -fsSL --max-time 10 "$PLATFORM/api/registry" 2>/dev/null | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
for e in d.get("endpoints") or []:
    print(e.get("base_url",""), e.get("expected_measurement",""))
    break' 2>/dev/null || true
}

read -r REG_URL REG_MEAS <<<"$(fetch_managed)" || true
ask NEWAPI_BASE "Your gateway base URL (e.g. https://gateway.example.com)"
ask ENCLAVE_URL "Enclave URL" "${REG_URL:-}"
ask EXPECTED_MEASUREMENT "Enclave measurement (sha256:...)" "${REG_MEAS:-}"
# How your gateway is asked "is this key valid" — newapi | http | exec.
# See docs/GATEWAY_INTEGRATION.md. Defaults to newapi, which works unmodified.
VALIDATOR="${VALIDATOR:-newapi}"
VERIFY_URL="${VERIFY_URL:-$PLATFORM}"
MODELS="${MODELS:-claude-opus-5,claude-sonnet-5,claude-haiku-4-5-20251001}"

[ -n "${NEWAPI_BASE:-}" ] || { echo "need your gateway base URL" >&2; exit 1; }
[ -n "${EXPECTED_MEASUREMENT:-}" ] || {
  echo "need the enclave measurement (registry unreachable — pass EXPECTED_MEASUREMENT=)" >&2; exit 1; }

cat <<PLAN
[fidrouter] plan
  install dir      : $DIR            (created; nothing else on this host is modified)
  python           : $DIR/venv       (private venv — your system Python is untouched)
  files            : $RAW_BASE/{adapter.py,validators.py}
                     each sha256-verified before it is installed or run
  service          : /etc/systemd/system/cpadapter.service, enabled at boot
  runs as          : user "$SVC_USER" (created if missing), NOT root
  listens on       : $BIND:$PORT     (loopback by default — not reachable off-box)
  gateway          : $NEWAPI_BASE    (read-only: validates a key, reads remaining quota)
  validator        : $VALIDATOR       (how your gateway is asked; see GATEWAY_INTEGRATION.md)
  enclave          : $ENCLAVE_URL
  measurement      : $EXPECTED_MEASUREMENT
  CP keypair       : generated LOCALLY; the seed is written to $DIR/cpadapter.env (0600,
                     owned by $SVC_USER) and is never transmitted anywhere
  NOT touched      : your gateway's config, data or process; no DB writes; no traffic proxied
PLAN

if [ "$DRY" = 1 ]; then say "dry run — nothing was changed."; exit 0; fi
[ "$(id -u)" = 0 ] || command -v sudo >/dev/null || { echo "need root or sudo" >&2; exit 1; }
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"

say "installing → $DIR"
$SUDO mkdir -p "$DIR"

# dedicated service account: a component holding a signing seed should not run as root
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
  $SUDO useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null \
    || $SUDO adduser --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null \
    || { echo "could not create user $SVC_USER" >&2; exit 1; }
fi

# private venv — keeps 'cryptography' out of your system Python entirely
if [ ! -x "$DIR/venv/bin/python" ]; then
  say "creating venv (system Python untouched)"
  $SUDO python3 -m venv "$DIR/venv" || {
    echo "python3-venv is missing — install it (e.g. apt-get install python3-venv)" >&2; exit 1; }
fi
$SUDO "$DIR/venv/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1 || true
$SUDO "$DIR/venv/bin/pip" install --quiet cryptography

# fetch pinned adapter to a temp file, verify, and only then install it
TMPD="$(mktemp -d)"; trap 'rm -rf "$TMPD"' EXIT
fetch_verify(){ # fetch_verify <file> <expected-sha256>
  say "downloading pinned $1"
  curl -fsSL --max-time 30 "$RAW_BASE/$1" -o "$TMPD/$1"
  local got; got="$(sha256sum "$TMPD/$1" | cut -d' ' -f1)"
  if [ "$got" != "$2" ]; then
    echo "[fidrouter] ABORT: checksum mismatch for $1" >&2
    echo "            expected $2" >&2
    echo "            got      $got" >&2
    exit 1
  fi
  say "  checksum ok"
}
fetch_verify adapter.py    "$PIN_SHA256"
fetch_verify validators.py "$PIN_SHA256_VALIDATORS"
$SUDO install -m 0644 "$TMPD/adapter.py"    "$DIR/adapter.py"
$SUDO install -m 0644 "$TMPD/validators.py" "$DIR/validators.py"

if [ -z "${CP_SEED_HEX:-}" ]; then
  # The seed is generated HERE, on your machine, and never leaves it. Only the public half
  # is something you share (it gets baked into / registered with the enclave).
  read -r CP_SEED_HEX CP_PUB < <("$DIR/venv/bin/python" - <<'PY'
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K
from cryptography.hazmat.primitives import serialization as s
k = K.generate()
print(k.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption()).hex(),
      k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw).hex())
PY
)
  say "generated CP keypair locally — share only the PUBLIC half:"
  say "  cp_pub = $CP_PUB"
fi

$SUDO tee "$DIR/cpadapter.env" >/dev/null <<EOF
CP_SEED_HEX=$CP_SEED_HEX
NEWAPI_BASE=$NEWAPI_BASE
ENCLAVE_URL=$ENCLAVE_URL
EXPECTED_MEASUREMENT=$EXPECTED_MEASUREMENT
VERIFY_URL=$VERIFY_URL
MODELS=$MODELS
VALIDATOR=$VALIDATOR
PORT=$PORT
BIND=$BIND
EOF
$SUDO chmod 600 "$DIR/cpadapter.env"
$SUDO chown -R "$SVC_USER":"$SVC_USER" "$DIR"

if command -v systemctl >/dev/null; then
  $SUDO tee /etc/systemd/system/cpadapter.service >/dev/null <<EOF
[Unit]
Description=fidrouter cp-adapter
After=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
EnvironmentFile=$DIR/cpadapter.env
ExecStart=$DIR/venv/bin/python $DIR/adapter.py
Restart=always
RestartSec=3
# least privilege: it needs the network and its own directory, nothing else
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$DIR
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
EOF
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now cpadapter
  sleep 2
  if curl -fsS "http://127.0.0.1:$PORT/healthz"; then echo; say "healthy"; else
    say "not healthy yet — check: journalctl -u cpadapter -n 50"; fi
else
  say "no systemd here. Run it with:"
  say "  sudo -u $SVC_USER env \$(cat $DIR/cpadapter.env | xargs) $DIR/venv/bin/python $DIR/adapter.py"
fi

cat <<NEXT
[fidrouter] cp-adapter is up on $BIND:$PORT

Next:
  1. Register your endpoint at $VERIFY_URL
       base_url        = $ENCLAVE_URL
       measurement     = $EXPECTED_MEASUREMENT
       cp_adapter_url  = http://<this-host>:$PORT
  2. Inject your upstream provider key (BYOK) — sealed in your browser, we only get ciphertext.

To remove everything this installed:
  sudo systemctl disable --now cpadapter
  sudo rm -f /etc/systemd/system/cpadapter.service && sudo systemctl daemon-reload
  sudo rm -rf $DIR && sudo userdel $SVC_USER
NEXT
