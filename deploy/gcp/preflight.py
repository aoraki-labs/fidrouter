"""Read-only GCP preflight: verifies the SA credential works and the project has
Compute API + a C3 machine type + C3 CPU quota to launch an Intel TDX
Confidential VM. Creates nothing.

  python3 deploy/gcp/preflight.py [--type c3-standard-4]
"""
import argparse
import sys

import gcp


def check(label, fn):
    try:
        fn()
        print(f"  [ok]   {label}")
        return True
    except gcp.GcpError as e:
        print(f"  [FAIL] {label}: {e} — {e.body[:160]}")
        return False
    except Exception as e:  # noqa
        print(f"  [FAIL] {label}: {e}")
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--type", default="c3-standard-4")
    args = ap.parse_args()
    p, z, r = gcp.project(), gcp.zone(), gcp.region()
    ok = True

    print(f"project={p} zone={z} region={r}")
    print("== identity / token ==")
    def _tok():
        gcp.token()
        print(f"         SA={gcp._sa().get('client_email')}")
    ok &= check("SA JWT -> OAuth access token", _tok)

    print("== compute API + project ==")
    ok &= check("GET project (Compute Engine API enabled)", lambda: gcp.get(f"/projects/{p}"))

    print(f"== C3 machine type {args.type} in {z} ==")
    def _mt():
        gcp.get(f"/projects/{p}/zones/{z}/machineTypes/{args.type}")
    ok &= check(f"{args.type} exists in {z}", _mt)

    print(f"== C3 CPU quota in {r} ==")
    def _q():
        reg = gcp.get(f"/projects/{p}/regions/{r}")
        quotas = {q["metric"]: q for q in reg.get("quotas", [])}
        c3 = quotas.get("C3_CPUS") or quotas.get("CPUS")
        if not c3:
            raise gcp.GcpError("no C3_CPUS/CPUS quota entry")
        print(f"         C3_CPUS: limit={c3['limit']} usage={c3['usage']}"
              if 'C3_CPUS' in quotas else f"         CPUS: limit={c3['limit']} usage={c3['usage']} (no C3-specific quota shown)")
        if c3["limit"] < 4:
            raise gcp.GcpError(f"quota too low (limit={c3['limit']}); request C3 CPUs quota in {r}")
    ok &= check("C3 CPU quota >= 4", _q)

    print()
    if ok:
        print("PREFLIGHT PASSED — ready to provision a C3 Intel TDX confidential VM.")
        sys.exit(0)
    print("PREFLIGHT FAILED — fix the [FAIL] items above.")
    print("Common: enable Compute Engine API; grant the SA roles/compute.admin + iam.serviceAccountUser; request C3 CPUs quota.")
    sys.exit(1)


if __name__ == "__main__":
    main()
