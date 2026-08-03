"""Read-only preflight: verifies the .env credential works and has the ECS/VPC/
KMS permissions + g8i(TDX) availability needed to provision the P0 environment.
Creates nothing. Run this first; provision.py runs it automatically too.

  python3 deploy/aliyun/preflight.py [--region cn-hangzhou] [--type ecs.g8i.xlarge]
"""
import argparse
import sys

import acs


def check(label, fn):
    try:
        fn()
        print(f"  [ok]   {label}")
        return True
    except acs.AcsError as e:
        print(f"  [FAIL] {label}: {e.code} — {e.body[:160]}")
        return False
    except Exception as e:  # noqa
        print(f"  [FAIL] {label}: {e}")
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", default="cn-hangzhou")
    ap.add_argument("--type", default="ecs.g8i.xlarge")
    args = ap.parse_args()
    r = args.region
    ok = True

    print("== identity ==")
    def _id():
        d = acs.sts_identity()
        print(f"         account={d.get('AccountId')} arn={d.get('Arn')}")
    ok &= check("STS GetCallerIdentity (key is active)", _id)

    print("== permissions ==")
    ok &= check("ECS DescribeRegions", lambda: acs.ecs("DescribeRegions", {"RegionId": r}, r))
    ok &= check("VPC DescribeVpcs", lambda: acs.vpc("DescribeVpcs", {"RegionId": r, "PageSize": "1"}, r))
    ok &= check("KMS ListKeys", lambda: acs.kms("ListKeys", {"RegionId": r}, r))

    print(f"== g8i / TDX availability for {args.type} in {r} ==")
    def _avail():
        d = acs.ecs("DescribeAvailableResource", {
            "RegionId": r, "DestinationResource": "InstanceType",
            "InstanceChargeType": "PostPaid", "InstanceType": args.type,
        }, r)
        zones = d.get("AvailableZones", {}).get("AvailableZone", [])
        usable = [z["ZoneId"] for z in zones if z.get("StatusCategory") == "WithStock"]
        print(f"         zones with stock: {usable or 'NONE (try another zone/type)'}")
        if not usable:
            raise acs.AcsError("NoStock", 200, "no zone has stock for this type")
    ok &= check(f"{args.type} has stock", _avail)

    print()
    if ok:
        print("PREFLIGHT PASSED — safe to run: python3 deploy/aliyun/provision.py --yes")
        sys.exit(0)
    else:
        print("PREFLIGHT FAILED — fix the [FAIL] items above before provisioning.")
        print("Most common: the .env AccessKey is disabled, or the RAM user lacks ECS/VPC/KMS policies.")
        sys.exit(1)


if __name__ == "__main__":
    main()
