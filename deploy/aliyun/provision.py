"""Provision the fid-router P0 environment on Aliyun (VPC + vSwitch + security
group + key pair + one g8i instance for the TDX data plane).

SAFETY: default is a DRY-RUN that only prints the plan. It creates real,
BILLABLE resources only with --yes. It refuses to run if preflight fails, and
refuses to double-provision if state.json already exists (use --force).

  python3 deploy/aliyun/provision.py                 # dry-run plan
  python3 deploy/aliyun/provision.py --yes            # actually create
  python3 deploy/aliyun/provision.py --yes --type ecs.g8i.large --zone cn-hangzhou-k

NOTE: untested end-to-end until an ACTIVE key exists. TDX guest enablement
(tdx_guest module + DCAP/PCCS) is a post-boot step; see CHECKLIST.md. Verify
exact RunInstances params against api.aliyun.com if a call is rejected.
"""
import argparse
import json
import os
import sys
import time

import acs

STATE = os.path.join(os.path.dirname(__file__), "state.json")


def pick_zone(region, itype, want=None):
    d = acs.ecs("DescribeAvailableResource", {
        "RegionId": region, "DestinationResource": "InstanceType",
        "InstanceChargeType": "PostPaid", "InstanceType": itype,
    }, region)
    zones = [z["ZoneId"] for z in d.get("AvailableZones", {}).get("AvailableZone", [])
             if z.get("StatusCategory") == "WithStock"]
    if want:
        return want if want in zones else None
    return zones[0] if zones else None


def latest_image(region, itype, uefi=False):
    d = acs.ecs("DescribeImages", {
        "RegionId": region, "OSType": "linux", "ImageOwnerAlias": "system",
        "InstanceType": itype, "Status": "Available", "PageSize": "50",
    }, region)
    imgs = d.get("Images", {}).get("Image", [])
    pool = [i for i in imgs if i.get("Platform", "").lower().startswith("aliyun")] or imgs
    if uefi:  # TDX requires a UEFI image
        pool = [i for i in pool if i.get("BootMode") in ("UEFI", "UEFI-Preferred")] or pool
    return pool[0]["ImageId"] if pool else None


def wait_vpc(region, vpc_id):
    for _ in range(30):
        d = acs.vpc("DescribeVpcs", {"RegionId": region, "VpcId": vpc_id}, region)
        vs = d.get("Vpcs", {}).get("Vpc", [])
        if vs and vs[0].get("Status") == "Available":
            return
        time.sleep(3)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", default="cn-hangzhou")
    ap.add_argument("--type", default="ecs.g8i.xlarge")
    ap.add_argument("--zone", default=None)
    ap.add_argument("--ssh-cidr", default="0.0.0.0/0", help="restrict to your IP/32 in production")
    ap.add_argument("--yes", action="store_true", help="actually create billable resources")
    ap.add_argument("--force", action="store_true", help="provision even if state.json exists")
    ap.add_argument("--tdx", action="store_true", help="create an Intel TDX confidential VM (needs >=xlarge + UEFI image)")
    args = ap.parse_args()
    r = args.region

    if os.path.exists(STATE) and not args.force:
        print(f"state.json exists ({STATE}); refusing to double-provision. Use --force to override.")
        sys.exit(1)

    # gate on identity (proves key is active) before doing anything
    try:
        ident = acs.sts_identity()
        print(f"identity: account={ident.get('AccountId')} arn={ident.get('Arn')}")
    except acs.AcsError as e:
        print(f"cannot authenticate ({e.code}): {e.body[:200]}")
        print("Fix the .env key (enable it + attach ECS/VPC/KMS policies), then retry.")
        sys.exit(1)

    zone = pick_zone(r, args.type, args.zone)
    image = latest_image(r, args.type, uefi=args.tdx)
    if args.tdx and args.type.endswith(".large"):
        print("WARNING: TDX requires >= xlarge; .large will be rejected.")
    plan = {
        "region": r, "zone": zone, "instance_type": args.type, "image": image,
        "confidential_computing": "TDX" if args.tdx else "off",
        "vpc_cidr": "172.16.0.0/16", "vswitch_cidr": "172.16.0.0/24",
        "open_ports": ["443/0.0.0.0/0", f"22/{args.ssh_cidr}"],
        "charge": "PostPaid (hourly, BILLABLE)",
    }
    print("== plan ==")
    print(json.dumps(plan, indent=2, ensure_ascii=False))
    if not zone:
        print("no zone with stock for this type; try --type ecs.g8i.large or another --zone")
        sys.exit(1)
    if not args.yes:
        print("\nDRY-RUN. Re-run with --yes to create these BILLABLE resources.")
        sys.exit(0)

    print("\n== creating (billable) ==")
    st = {"plan": plan}

    v = acs.vpc("CreateVpc", {"RegionId": r, "CidrBlock": "172.16.0.0/16",
                              "VpcName": "fid-router-vpc"}, r)
    st["vpc_id"] = v["VpcId"]; print("VpcId", v["VpcId"]); wait_vpc(r, v["VpcId"])

    sw = acs.vpc("CreateVSwitch", {"RegionId": r, "VpcId": v["VpcId"], "ZoneId": zone,
                                   "CidrBlock": "172.16.0.0/24", "VSwitchName": "fid-router-sw"}, r)
    st["vswitch_id"] = sw["VSwitchId"]; print("VSwitchId", sw["VSwitchId"]); time.sleep(4)

    sg = acs.ecs("CreateSecurityGroup", {"RegionId": r, "VpcId": v["VpcId"],
                                         "SecurityGroupName": "fid-router-sg"}, r)
    st["sg_id"] = sg["SecurityGroupId"]; print("SecurityGroupId", sg["SecurityGroupId"])
    for port, cidr in [("443/443", "0.0.0.0/0"), ("22/22", args.ssh_cidr)]:
        acs.ecs("AuthorizeSecurityGroup", {"RegionId": r, "SecurityGroupId": sg["SecurityGroupId"],
                "IpProtocol": "tcp", "PortRange": port, "SourceCidrIp": cidr, "Policy": "accept"}, r)

    kp = acs.ecs("CreateKeyPair", {"RegionId": r, "KeyPairName": "fid-router-key"}, r)
    pem = os.path.join(os.path.dirname(__file__), "fid-router-key.pem")
    with open(pem, "w") as f:
        f.write(kp["PrivateKeyBody"])
    os.chmod(pem, 0o600)
    st["key_pair"] = "fid-router-key"; st["pem"] = pem; print("KeyPair saved ->", pem)

    run_params = {
        "RegionId": r, "ZoneId": zone, "ImageId": image, "InstanceType": args.type,
        "SecurityGroupId": sg["SecurityGroupId"], "VSwitchId": sw["VSwitchId"],
        "InstanceChargeType": "PostPaid", "InternetMaxBandwidthOut": "5",
        "KeyPairName": "fid-router-key", "Amount": "1",
        "SystemDisk.Category": "cloud_essd", "InstanceName": "fid-proxy-tdx",
    }
    if args.tdx:
        run_params["SecurityOptions.ConfidentialComputingMode"] = "TDX"
    run = acs.ecs("RunInstances", run_params, r)
    iid = run["InstanceIdSets"]["InstanceIdSet"][0]
    st["instance_id"] = iid; print("InstanceId", iid)

    with open(STATE, "w") as f:
        json.dump(st, f, indent=2)
    print(f"\nstate -> {STATE}")
    print("next: wait for Running, get public IP (DescribeInstances), ssh in, install tdx_guest+DCAP (CHECKLIST P0).")


if __name__ == "__main__":
    main()
