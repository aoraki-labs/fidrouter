#!/usr/bin/env bash
# Use the LIVE verified no-log enclave as the first internal customer.
#   1) mint a capability token (control-plane authz, no prompt ever touches it)
#   2) client SDK verifies the enclave measurement (fail-closed) + opens attested E2EE
#   3) send a prompt to REAL Claude via BYOK, straight from the measured enclave
#      to api.anthropic.com — never through the (unmeasured) control plane.
#
#   deploy/gcp/use.sh "your question here"
#   MODEL=claude-opus-5 deploy/gcp/use.sh "..."   # default is cheap claude-haiku-4-5
set -uo pipefail
cd "$(dirname "$0")/../.."
export FID_HOME=config
IP=${CS_IP:-34.21.247.73}
DIGEST=${DIGEST:-sha256:ed7aadcd07e28decc13c8662b09530e7d128d94c91dc35211ce341ff8b883593}
MODEL=${MODEL:-claude-haiku-4-5}
PROMPT=${1:-"In one sentence, what is a typical refund policy?"}

CAP=$(./dist/ctl mint -tenant internal-1 -pool shared \
      -models claude-opus-5,claude-haiku-4-5,claude-opus-4-8 -ttl 86400)

CAP="$CAP" IP="$IP" DIGEST="$DIGEST" MODEL="$MODEL" PROMPT="$PROMPT" python3 - <<'PY'
import os, sys
sys.path.insert(0, "sdk/python")
from fidrouter_verify import FidClient, FidVerificationError
c = FidClient(base_url=f"http://{os.environ['IP']}:9090", token=os.environ["CAP"],
              pin_measurement=os.environ["DIGEST"], cs_audience="fidrouter")
try:
    r = c.chat(os.environ["MODEL"],
               [{"role": "system", "content": "You are a helpful assistant. Be concise."},
                {"role": "user", "content": os.environ["PROMPT"]}])
    print(f"verified ✔  measurement pinned + attested E2EE  (model={r.model} account={r.account})")
    print(r.completion)
except FidVerificationError as e:
    print("FAIL-CLOSED (attestation mismatch — would not send):", e)
PY
