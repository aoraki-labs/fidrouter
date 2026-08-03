"""Build + push the fid-proxy Confidential Space image, then launch a
Confidential Space VM whose attestation covers the image digest.

Prereqs (one-time, needs an operator with rights):
  - SA must have roles/artifactregistry.admin (create repo + push) — the current
    fid-router-provisioner SA does NOT yet; grant it, or create the repo manually.
  - docker available locally (it is).

Flow:
  1. stage build context (dist binaries + config + Dockerfile + entrypoint)
  2. ensure Artifact Registry repo
  3. docker login (oauth2accesstoken) + build + push -> image digest
  4. launch Confidential Space VM (metadata tee-image-reference) on C3/TDX
  5. print IMAGE_DIGEST (client pin_measurement) + VM IP

Run (dry-run prints the plan):  python3 deploy/gcp/cs_provision.py [--yes] [--debug-image]
"""
import argparse
import json
import os
import shutil
import subprocess
import time

import gcp

HERE = os.path.dirname(__file__)
REPO = "fid-router"
IMAGE = "fid-proxy"
DOCKER = ["sudo", "-n", "docker"]  # docker daemon needs root in this env


def sh(*a, **k):
    print("+", " ".join(a))
    return subprocess.run(a, check=True, **k)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--debug-image", action="store_true", help="use confidential-space-debug (SSH+stdout)")
    ap.add_argument("--ssh-cidr", default="0.0.0.0/0")
    args = ap.parse_args()
    p, z, r = gcp.project(), gcp.zone(), gcp.region()
    ar_host = f"{r}-docker.pkg.dev"
    img = f"{ar_host}/{p}/{REPO}/{IMAGE}:latest"
    fam = "confidential-space-debug" if args.debug_image else "confidential-space"

    print(f"plan: build {img}; launch CS VM (c3-standard-4, TDX, image-family={fam}) in {z}")
    if not args.yes:
        print("DRY-RUN. Re-run with --yes. NOTE: needs roles/artifactregistry.admin on the SA.")
        return

    # 1) stage build context
    ctx = os.path.join(HERE, "cs", "_ctx")
    shutil.rmtree(ctx, ignore_errors=True)
    os.makedirs(ctx)
    root = os.path.join(HERE, "..", "..")
    for f in ("dist/fid-proxy", "dist/mock-upstream"):
        shutil.copy(os.path.join(root, f), ctx)
    shutil.copy(os.path.join(HERE, "cs", "entrypoint.sh"), ctx)
    shutil.copy(os.path.join(HERE, "cs", "Dockerfile"), ctx)
    # NEVER bake private keys into the image: keys.json (identity/CP/KMS seeds) is
    # excluded; the image ships only public.json (cp_pub + expected measurement).
    shutil.copytree(os.path.join(root, "config"), os.path.join(ctx, "config"),
                    ignore=shutil.ignore_patterns("*.sealed.json", "keys.json"))

    # 2) ensure Artifact Registry repo (needs artifactregistry.admin)
    try:
        gcp.post(f"https://artifactregistry.googleapis.com/v1/projects/{p}/locations/{r}/repositories?repositoryId={REPO}",
                 {"format": "DOCKER"})
        print("created AR repo", REPO)
    except gcp.GcpError as e:
        print("AR repo:", "exists" if "ALREADY_EXISTS" in (e.body or "") else f"ERROR {e}")

    # 3) docker login + build + push
    tok = gcp.token()
    sh(*DOCKER, "login", "-u", "oauth2accesstoken", "-p", tok, ar_host)
    sh(*DOCKER, "build", "-t", img, ctx)
    sh(*DOCKER, "push", img)
    out = subprocess.run([*DOCKER, "inspect", "--format={{index .RepoDigests 0}}", img],
                         check=True, capture_output=True, text=True).stdout.strip()
    digest = out.split("@")[-1]  # sha256:...
    print("IMAGE_DIGEST =", digest)

    # 3b) BYOK upstream key: injected via CS `tee-env-*` metadata, NOT baked into
    # the image. Keeps the measured image_digest independent of the key, and keeps
    # the key out of the Artifact Registry image and out of git. Operator-visible
    # (VM metadata) for now; operator-blind BYOK (KMS + Workload Identity Pool
    # gated on image_digest) is the production upgrade.
    tee_env = []
    up_key = os.environ.get("FID_ANTHROPIC_KEY", "")
    if up_key:
        tee_env.append({"key": "tee-env-FID_ANTHROPIC_KEY", "value": up_key})
        print("injecting upstream key via tee-env-FID_ANTHROPIC_KEY (not baked into image)")
    else:
        print("WARNING: FID_ANTHROPIC_KEY not set — upstream calls will fail.")
    # Identity seed injected at boot too (kept stable across redeploys so the
    # published idpub / registry entry stays valid). tee-env now; Secret Manager next.
    seed_hex = os.environ.get("FID_IDENTITY_SEED", "")
    if not seed_hex:
        try:
            import base64 as _b64
            k = json.load(open(os.path.join(HERE, "..", "..", "config", "keys.json")))
            seed_hex = _b64.b64decode(k["identity_seed"]).hex()
        except Exception as e:
            print("WARNING: no FID_IDENTITY_SEED and cannot read keys.json:", e)
    if seed_hex:
        tee_env.append({"key": "tee-env-FID_IDENTITY_SEED", "value": seed_hex})
        print("injecting identity seed via tee-env-FID_IDENTITY_SEED (not baked into image)")

    # 4) launch Confidential Space VM (delete a prior one first — image ref is immutable)
    try:
        gcp.delete(f"/projects/{p}/zones/{z}/instances/fid-proxy-cs")
        print("deleting existing fid-proxy-cs …")
        for _ in range(30):
            time.sleep(4)
            try:
                gcp.get(f"/projects/{p}/zones/{z}/instances/fid-proxy-cs")
            except gcp.GcpError:
                break
    except gcp.GcpError as e:
        if "not found" not in (e.body or "").lower() and "notFound" not in (e.body or ""):
            print("delete fid-proxy-cs:", e)

    cs_image = gcp.get(f"/projects/confidential-space-images/global/images/family/{fam}")["selfLink"]
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
            {"key": "tee-image-reference", "value": f"{ar_host}/{p}/{REPO}/{IMAGE}@{digest}"},
            {"key": "tee-restart-policy", "value": "Never"},
            {"key": "tee-container-log-redirect", "value": "true"},
            *tee_env,
        ]},
        "serviceAccounts": [{"email": "default", "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}],
    }
    op = gcp.post(f"/projects/{p}/zones/{z}/instances", body)
    print("launch op:", op.get("name"))
    time.sleep(20)
    inst = gcp.get(f"/projects/{p}/zones/{z}/instances/fid-proxy-cs")
    ip = inst["networkInterfaces"][0].get("accessConfigs", [{}])[0].get("natIP")
    json.dump({"image": img, "digest": digest, "ip": ip}, open(os.path.join(HERE, "cs_state.json"), "w"), indent=2)
    print(f"\nCS VM fid-proxy-cs status={inst.get('status')} ip={ip}")
    print(f"client pin_measurement (image_digest) = {digest}")


if __name__ == "__main__":
    main()
