"""Relaunch fid-proxy-cs with the EXISTING image digest (no rebuild) and corrected
metadata (no tee-container-log-redirect). Used after the launcher rejected the
hardened image for requesting log redirection.
"""
import base64
import json
import time

import gcp

DIGEST = "sha256:08b44d2113a530a71563c28a9a97d49b401bef7dad889695b33fc2b8a2818d0d"


def main():
    p, z = gcp.project(), gcp.zone()
    ar = f"{gcp.region()}-docker.pkg.dev"
    k = json.load(open("../../config/keys.json"))
    seed_hex = base64.b64decode(k["identity_seed"]).hex()
    try:
        gcp.delete(f"/projects/{p}/zones/{z}/instances/fid-proxy-cs")
        print("deleting old VM...")
        for _ in range(40):
            time.sleep(4)
            try:
                gcp.get(f"/projects/{p}/zones/{z}/instances/fid-proxy-cs")
            except gcp.GcpError:
                break
    except gcp.GcpError as e:
        print("delete:", e)
    cs_image = gcp.get("/projects/confidential-space-images/global/images/family/confidential-space")["selfLink"]
    body = {
        "name": "fid-proxy-cs",
        "machineType": f"projects/{p}/zones/{z}/machineTypes/c3-standard-4",
        "confidentialInstanceConfig": {"confidentialInstanceType": "TDX"},
        "shieldedInstanceConfig": {"enableSecureBoot": True},
        "scheduling": {"onHostMaintenance": "TERMINATE"},
        "disks": [{"boot": True, "autoDelete": True, "initializeParams": {"sourceImage": cs_image, "diskSizeGb": "20"}}],
        "networkInterfaces": [{"network": f"projects/{p}/global/networks/fid-router-net",
                               "accessConfigs": [{"type": "ONE_TO_ONE_NAT", "name": "External NAT"}]}],
        "metadata": {"items": [
            {"key": "tee-image-reference", "value": f"{ar}/{p}/fidrouter/fid-proxy@{DIGEST}"},
            {"key": "tee-restart-policy", "value": "Never"},
            {"key": "tee-env-FID_IDENTITY_SEED", "value": seed_hex},
        ]},
        "serviceAccounts": [{"email": "default", "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}],
    }
    op = gcp.post(f"/projects/{p}/zones/{z}/instances", body)
    print("launch op:", op.get("name"))
    time.sleep(18)
    inst = gcp.get(f"/projects/{p}/zones/{z}/instances/fid-proxy-cs")
    ip = inst["networkInterfaces"][0].get("accessConfigs", [{}])[0].get("natIP")
    json.dump({"image": f"{ar}/{p}/fidrouter/fid-proxy:latest", "digest": DIGEST, "ip": ip},
              open("cs_state.json", "w"), indent=2)
    print("status:", inst.get("status"), "ip:", ip)


if __name__ == "__main__":
    main()
