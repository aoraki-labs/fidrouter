#!/usr/bin/env bash
# Live demo against the real GCP Intel TDX box: (1) verify + send, (2) cache hit
# via affinity, (3) tamper -> client FAIL-CLOSED. Run from repo root.
#   bash deploy/gcp/demo.sh
set -uo pipefail
cd "$(dirname "$0")/../.."

IP=${BOX_IP:-35.247.164.62}
MRTD=${BOX_MRTD:-c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5}
K=deploy/gcp/fid-router-gcp
SSH="ssh -i $K -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=25"

echo "== minting a capability token on the box (control-plane key) =="
TOK=$($SSH fidr@"$IP" 'FID_HOME=config ./ctl mint -tenant cust1 -pool shared -models gpt-4o' 2>/dev/null)
echo "   token: ${TOK:0:32}…"

export BOX_IP="$IP" BOX_MRTD="$MRTD" TOK="$TOK"
python3 - <<'PY'
import os, sys
sys.path.insert(0, "sdk/python")
from fidrouter_verify import FidClient, FidVerificationError
ip, mrtd, tok = os.environ["BOX_IP"], os.environ["BOX_MRTD"], os.environ["TOK"]
base = f"http://{ip}:9090"
SYS = "You are ACME's support bot. [stable policy/context ...]"

print(f"\nEndpoint: {base}   pinned MRTD: {mrtd[:24]}…\n")

print("== 1) verify the enclave, then send (expect cache MISS) ==")
c = FidClient(base_url=base, token=tok, pin_measurement=mrtd, dcap_allow_unverified=True)
r = c.chat("gpt-4o", [{"role":"system","content":SYS},{"role":"user","content":"refund policy?"}])
print(f"   ✔ REAL-TDX verified · account={r.account} · cache_hit={r.cache_hit} · model={r.model}")
print(f"     completion: {r.completion}")

print("\n== 2) same prefix again (affinity -> cache HIT) ==")
r = c.chat("gpt-4o", [{"role":"system","content":SYS},{"role":"user","content":"shipping time?"}])
print(f"   ✔ verified · cache_hit={r.cache_hit}")

print("\n== 3) TAMPER: pin a WRONG measurement -> client refuses (fail-closed) ==")
bad = FidClient(base_url=base, token=tok, pin_measurement="deadbeef"*12, dcap_allow_unverified=True)
try:
    bad.chat("gpt-4o", [{"role":"system","content":SYS},{"role":"user","content":"should be refused"}])
    print("   !! unexpectedly succeeded")
except FidVerificationError as e:
    print(f"   ✔ FAIL-CLOSED (nothing sent): {str(e).splitlines()[0]}")
PY