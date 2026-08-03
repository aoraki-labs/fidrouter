# GCP C3 Intel TDX — provision & end-to-end runbook

Stdlib-only (no gcloud SDK). Reads `GCP_PROJECT_ID`, `GCP_ZONE`,
`GOOGLE_APPLICATION_CREDENTIALS` from the repo `.env`. `gcp.py` signs a
service-account JWT → OAuth token → Compute REST API.

## Why GCP (vs Aliyun)
Aliyun TDX was blocked by account gray-list/real-name + g8i out of stock overseas.
GCP C3 gives **real Intel TDX** immediately: verified — the guest boots as a real
Trust Domain (`tdx_guest` flag, `/dev/tdx_guest`, `/sys/kernel/config/tsm/report`).

## Provision (billable)
```bash
python3 deploy/gcp/preflight.py                       # creds + Compute API + C3 + quota
python3 deploy/gcp/provision.py --yes --ssh-cidr <your-ip>/32   # auto VPC + firewall + C3 TDX VM
```
Writes `state.json`, SSH key `deploy/gcp/fid-router-gcp`, user `fidr`, public IP.

## Deploy fid-proxy (real TDX attester) + verify end-to-end
Build linux/amd64: `GOOS=linux GOARCH=amd64 go build -o dist/<c> ./cmd/<c>` for
`fid-proxy mock-upstream ctl`, then `scp` them + `config/pool.plain.json` to the box.

On the box (the proxy needs root for configfs-TSM):
```bash
export FID_HOME=config
./ctl init
MRTD=$(sudo env FIDPROXY_ATTESTER=tdx-configfs FIDPROXY_MEASURE=1 FID_HOME=config ./fid-proxy)
./ctl remeasure "$MRTD"        # seal the managed-key pool to the REAL MRTD
./ctl seal-pool
nohup ./mock-upstream >up.log 2>&1 </dev/null &
sudo env FIDPROXY_ATTESTER=tdx-configfs FID_HOME=config \
     UPSTREAM_URL=http://127.0.0.1:9101/call FIDPROXY_ADDR=:9090 \
     nohup ./fid-proxy >px.log 2>&1 </dev/null &
./ctl mint -tenant cust1 -pool shared -models gpt-4o    # -> capability token
```
Open the proxy port: firewall rule `tcp:9090` from your IP (see provision + the
`fidr-allow-proxy` rule we add).

From your machine (the verify SDK), point at the box with `pin_measurement=$MRTD`:
```python
from fidrouter_verify import FidClient
c = FidClient(base_url="http://<box-ip>:9090", token=TOKEN,
              pin_measurement=MRTD, dcap_allow_unverified=True)  # see note
r = c.chat("gpt-4o", [{"role":"system","content":SYS},{"role":"user","content":"hi"}])
```
The `TdxConfigfsAttester` produces a real quote whose `report_data` binds
`SHA256(nonce ‖ ephemeral_pub ‖ identity_pub)`, so verifying the quote anchors the
channel key AND the receipt key to the attested MRTD.

## What is real vs. the last stub
Real: TDX Trust Domain, genuine quote (configfs-TSM), measurement pin, report_data
binding, attested E2EE, enclave-signed receipt (anti-downgrade), affinity cache.
Stub: `dcap_allow_unverified=True` skips the **ECDSA + PCK-chain-to-Intel-root**
check. Harden by installing Intel QVL on a verifier (`libsgx-dcap-quote-verify` +
the TDX quote-verify sample) or using the `IntelTrustAuthorityBackend` (needs an
ITA subscription). Also still mock: KMS (MockKMS gates on measurement locally;
swap for GCP Cloud KMS / Confidential Space); managed upstream (mock-upstream).

## Teardown (stop billing)
```bash
# delete the instance + firewalls + network (or just stop the instance)
python3 - <<'PY'
import gcp, json
st=json.load(open("deploy/gcp/state.json")); p=gcp.project(); z=gcp.zone()
gcp.api("DELETE", f"/projects/{p}/zones/{z}/instances/{st['instance']}")
PY
```
