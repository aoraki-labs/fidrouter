#!/usr/bin/env python3
"""RA-TLS cutover: recreate fid-proxy-cs on the new image (already built+pushed) with
RA-TLS on. Reuses cs_provision's launch body. Upstream key injected via tee-env (our own
managed relay). Identity seed preserved so idpub/registry entry stay valid."""
import base64
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gcp

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..")
REPO, IMAGE = "fidrouter", "fid-proxy"
NEW_DIGEST = "sha256:8d306d528fe5cd4e1b2da6a58cdfff2840705f452420707545c931d7948b4456"

p, z, r = gcp.project(), gcp.zone(), gcp.region()
ar_host = f"{r}-docker.pkg.dev"
img = f"{ar_host}/{p}/{REPO}/{IMAGE}:deleg2"

# --- secrets from local config (never printed) ---
k = json.load(open(os.path.join(ROOT, "config", "keys.json")))
seed_hex = base64.b64decode(k["identity_seed"]).hex()
anthropic = ""
for line in open(os.path.join(ROOT, ".env")):
    if line.startswith("ANTHROPIC_API_KEY="):
        anthropic = line.split("=", 1)[1].strip().strip('"').strip("'")
        break
if not anthropic:
    raise SystemExit("ANTHROPIC_API_KEY not found in .env")

# ONLY these two may be supplied as tee-env: the image's Confidential Space launch policy
# (`tee.launch_policy.allow_env_override`) allows exactly FID_ANTHROPIC_KEY + FID_IDENTITY_SEED.
# Supplying anything else makes the hardened launcher REFUSE to start the workload, so the
# container never runs and the VM terminates (learned the hard way). Everything else about
# RA-TLS is baked into the image, where the measurement proves it.
tee_env = [
    {"key": "tee-env-FID_IDENTITY_SEED", "value": seed_hex},
    {"key": "tee-env-FID_ANTHROPIC_KEY", "value": anthropic},
]
print("tee-env keys:", [e["key"] for e in tee_env])

# --- delete existing, wait ---
try:
    gcp.delete(f"/projects/{p}/zones/{z}/instances/fid-proxy-cs")
    print("deleting existing fid-proxy-cs …")
    for _ in range(40):
        time.sleep(4)
        try:
            gcp.get(f"/projects/{p}/zones/{z}/instances/fid-proxy-cs")
        except gcp.GcpError:
            print("  deleted."); break
except gcp.GcpError as e:
    if "not found" not in (e.body or "").lower() and "notFound" not in (e.body or ""):
        print("delete:", e)

cs_image = gcp.get("/projects/confidential-space-images/global/images/family/confidential-space")["selfLink"]
try:
    enc_ip = gcp.get(f"/projects/{p}/regions/{r}/addresses/fid-proxy-ip")["address"]
except gcp.GcpError:
    enc_ip = None
accessconf = {"type": "ONE_TO_ONE_NAT", "name": "External NAT"}
if enc_ip:
    accessconf["natIP"] = enc_ip
    print("pinning static IP", enc_ip)

body = {
    "name": "fid-proxy-cs",
    "machineType": f"projects/{p}/zones/{z}/machineTypes/c3-standard-4",
    "confidentialInstanceConfig": {"confidentialInstanceType": "TDX"},
    "shieldedInstanceConfig": {"enableSecureBoot": True},
    "scheduling": {"onHostMaintenance": "TERMINATE"},
    "disks": [{"boot": True, "autoDelete": True,
               "initializeParams": {"sourceImage": cs_image, "diskSizeGb": "20"}}],
    "networkInterfaces": [{"network": f"projects/{p}/global/networks/fid-router-net",
                           "accessConfigs": [accessconf]}],
    "metadata": {"items": [
        {"key": "tee-image-reference", "value": f"{ar_host}/{p}/{REPO}/{IMAGE}@{NEW_DIGEST}"},
        {"key": "tee-restart-policy", "value": "Never"},
        *tee_env,
    ]},
    "serviceAccounts": [{"email": "default", "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}],
}
op = gcp.post(f"/projects/{p}/zones/{z}/instances", body)
print("launch op:", op.get("name"))
time.sleep(20)
inst = gcp.get(f"/projects/{p}/zones/{z}/instances/fid-proxy-cs")
ip = inst["networkInterfaces"][0].get("accessConfigs", [{}])[0].get("natIP")
json.dump({"image": img, "digest": NEW_DIGEST, "ip": ip},
          open(os.path.join(HERE, "cs_state.json"), "w"), indent=2)
print(f"CS VM fid-proxy-cs status={inst.get('status')} ip={ip}")
print("pin_measurement (new) =", NEW_DIGEST)
