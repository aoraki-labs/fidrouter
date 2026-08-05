# GCP Confidential Space — reproducible build + launch

Stdlib-only (no gcloud SDK). `gcp.py` reads `GCP_PROJECT_ID`, `GCP_ZONE`,
`GOOGLE_APPLICATION_CREDENTIALS` from the repo `.env`, signs a service-account JWT →
OAuth token → Compute/Artifact Registry REST.

The enclave runs on **GCP Confidential Space** (Intel TDX). What Confidential Space
attests is the **container image digest** (`submods.container.image_digest`) — so the
whole point is that anyone can rebuild this source and get the *same* digest.

## Build + launch
```bash
python3 deploy/gcp/cs_provision.py --yes
```
This: builds the `fid-proxy` binary reproducibly (`-trimpath -buildvcs=false
-ldflags=-buildid= CGO_ENABLED=0`), builds + pushes the pinned distroless image with
`buildx` + `SOURCE_DATE_EPOCH` (deterministic), and launches a `c3-standard-4` TDX
Confidential VM whose attestation covers that digest. Prints the `IMAGE_DIGEST`
(= the measurement clients pin) and the VM IP; writes `cs_state.json`.

The identity seed is injected at boot via `tee-env-FID_IDENTITY_SEED` (kept stable
across redeploys so the published idpub stays valid). The upstream key is **not** baked
or injected — it's sealed at runtime (operator-blind BYOK, `ctl seal-byok`).

## Relaunch without rebuilding
`python3 deploy/gcp/relaunch_cs.py` re-creates the VM from an existing image digest
(e.g. after a VM stop, or to change VM metadata) — no rebuild.

## Verify it's running this source
```bash
bash scripts/reproduce.sh                 # rebuild the binary, print its sha256
LIVE=<image-ref> bash scripts/reproduce.sh  # + pull the live image, diff /app/fid-proxy
```
Then the **verify SDK** live-checks the endpoint's attestation against the registry
(`sdk/python`, `sdk/ts`) and fail-closes on mismatch. See `docs/VERIFICATION.md`.

## Note on the attester backends
Live uses `FIDPROXY_ATTESTER=gcp-cs` (Google-signed OIDC over the CS teeserver socket).
The code also carries a raw-TDX attester (`internal/tee/tdx.go`, `FIDPROXY_ATTESTER=
tdx-configfs`) + DCAP quote verification in the SDK (`sdk/*/dcap.*`) for self-hosted
Intel TDX — an alternative backend, not used by the GCP deployment.
