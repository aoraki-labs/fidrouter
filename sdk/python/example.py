"""Example: verify a fidrouter endpoint and send two prompts with the SAME
cacheable prefix (2nd should be a cache hit via affinity routing).

  PIN_MEASUREMENT=.. PIN_IDPUB=.. FID_TOKEN=.. python3 example.py
"""
import os
import sys

from fidrouter_verify import FidClient, FidVerificationError

client = FidClient(
    base_url=os.environ.get("FID_PROXY", "http://127.0.0.1:9090"),
    token=os.environ["FID_TOKEN"],
    pin_measurement=os.environ.get("PIN_MEASUREMENT", ""),
    pin_idpub_hex=os.environ.get("PIN_IDPUB", ""),
)

PREFIX = "You are ACME's support bot. [500 tokens of stable policy/context ...]"
try:
    for i, q in enumerate(["question one", "question two"], 1):
        r = client.chat("gpt-4o", [
            {"role": "system", "content": PREFIX},
            {"role": "user", "content": q},
        ])
        print(f"[py #{i}] ✔ verified  account={r.account} affinity={r.affinity} "
              f"CACHE_HIT={r.cache_hit} model={r.model} ptok={r.prompt_tokens} -> {r.completion}")
except FidVerificationError as e:
    print("[py] ✘ FAIL-CLOSED:", e)
    sys.exit(1)
