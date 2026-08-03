# Aliyun provisioning for fidrouter (P0)

Stdlib-only (no SDK). Reads `ALIYUN_ACCESS_KEY_ID/SECRET` from the repo `.env`.

## What you (🧑) must do first
The `.env` key must be **active** and the RAM user must have these policies
(or an equivalent scoped custom policy):

| Permission | Why |
|---|---|
| `AliyunECSFullAccess` (or scoped) | create the g8i (TDX) instance, security group, key pair |
| `AliyunVPCFullAccess` (or scoped) | create VPC + vSwitch |
| `AliyunKMSFullAccess` (or scoped) | attestation-gated key release for sealed upstream keys (P1) |

Create/enable in RAM console → attach policies → put the AccessKey in `.env`.
The current `.env` key returns **`Forbidden.AccessKeyDisabled`** — it is
disabled and cannot create anything until enabled/replaced.

## Usage
```bash
python3 deploy/aliyun/preflight.py                     # read-only: creds + perms + g8i stock
python3 deploy/aliyun/provision.py                     # DRY-RUN plan (creates nothing)
python3 deploy/aliyun/provision.py --yes               # actually create (BILLABLE)
python3 deploy/aliyun/provision.py --yes --type ecs.g8i.large --ssh-cidr <your-ip>/32
```
`provision.py` writes `state.json` + `fid-router-key.pem` (chmod 600). It refuses
to run if identity check fails or if `state.json` already exists (`--force` to override).

## After the instance is up (P0, per CHECKLIST.md)
1. SSH in with `fid-router-key.pem`.
2. Install the TDX guest bits: `tdx_guest` kernel module + Intel DCAP, point
   `/etc/sgx_default_qcnl.conf` `PCCS_URL` at the region PCCS
   (`https://sgx-dcap-server.cn-hangzhou.aliyuncs.com/sgx/certification/v4/`).
3. Generate + DCAP-verify a TDX quote; confirm MRTD/RTMR are stable across reboot.
4. Then swap the PoC's `internal/tee` mock for the real `AliyunTDXAttester`.

## Security
- `.env` currently also holds a disabled key **and** plaintext panel/root creds.
  Rotate all of them; keep `.env` out of version control; prefer STS/short-lived
  creds for a RAM user scoped to just ECS/VPC/KMS.
- `provision.py` opens 22 to `--ssh-cidr` (default `0.0.0.0/0` — set to your IP).
