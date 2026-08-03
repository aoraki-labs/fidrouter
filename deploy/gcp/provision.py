"""Provision a GCP C3 **Intel TDX Confidential VM** for the fid-router data plane
(auto VPC + firewall + instance). Mirrors deploy/aliyun/provision.py.

SAFETY: dry-run by default (prints the plan, creates nothing). Creates real,
BILLABLE resources only with --yes. Refuses to double-provision if state.json
exists (use --force).

  python3 deploy/gcp/provision.py                       # dry-run plan
  python3 deploy/gcp/provision.py --yes --ssh-cidr <ip>/32
"""
import argparse
import json
import os
import subprocess
import time

import gcp

STATE = os.path.join(os.path.dirname(__file__), "state.json")
NET = "fid-router-net"
IMAGE = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts-amd64"  # supports Confidential VM / TDX


def wait_op(op):
    link = op.get("selfLink")
    if not link:
        return op
    for _ in range(60):
        o = gcp.api("GET", link)
        if o.get("status") == "DONE":
            if o.get("error"):
                raise gcp.GcpError("operation error: " + json.dumps(o["error"])[:300])
            return o
        time.sleep(4)
    raise gcp.GcpError("operation timed out: " + link)


def ensure_sshkey():
    priv = os.path.join(os.path.dirname(__file__), "fid-router-gcp")
    if not os.path.exists(priv):
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", priv, "-N", "", "-q", "-C", "fidr"], check=True)
        os.chmod(priv, 0o600)
    pub = open(priv + ".pub").read().strip()
    return priv, pub


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--machine-type", default="c3-standard-4")
    ap.add_argument("--tdx", action="store_true", default=True)
    ap.add_argument("--no-tdx", dest="tdx", action="store_false")
    ap.add_argument("--ssh-cidr", default="0.0.0.0/0", help="restrict 22 to your IP/32 in production")
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    p, z, r = gcp.project(), gcp.zone(), gcp.region()
    if os.path.exists(STATE) and not args.force:
        print(f"state.json exists ({STATE}); refusing to double-provision. Use --force."); return

    # sanity: token works
    gcp.token()
    plan = {
        "project": p, "zone": z, "machine_type": args.machine_type,
        "confidential": "TDX" if args.tdx else "off", "image": IMAGE, "network": NET,
        "open_ports": ["443/0.0.0.0/0", f"22/{args.ssh_cidr}"],
        "charge": "per-second, BILLABLE",
    }
    print("== plan =="); print(json.dumps(plan, indent=2))
    if not args.yes:
        print("\nDRY-RUN. Re-run with --yes to create these BILLABLE resources."); return

    print("\n== creating (billable) ==")
    st = {"plan": plan}
    priv, pub = ensure_sshkey()
    st["ssh_key"] = priv

    # 1) auto-mode VPC (creates a subnet in every region)
    try:
        wait_op(gcp.post(f"/projects/{p}/global/networks",
                         {"name": NET, "autoCreateSubnetworks": True}))
        print("network", NET)
    except gcp.GcpError as e:
        if "already exists" not in (e.body or ""):
            raise
        print("network", NET, "(exists)")
    time.sleep(5)

    # 2) firewall rules
    for name, ports, src in [("fidr-allow-ssh", ["22"], args.ssh_cidr), ("fidr-allow-443", ["443"], "0.0.0.0/0")]:
        try:
            gcp.post(f"/projects/{p}/global/firewalls", {
                "name": name, "network": f"projects/{p}/global/networks/{NET}",
                "direction": "INGRESS", "sourceRanges": [src],
                "allowed": [{"IPProtocol": "tcp", "ports": ports}],
            })
            print("firewall", name)
        except gcp.GcpError as e:
            if "already exists" not in (e.body or ""):
                raise

    # 3) the C3 TDX confidential VM
    body = {
        "name": "fid-proxy-tdx",
        "machineType": f"projects/{p}/zones/{z}/machineTypes/{args.machine_type}",
        "disks": [{"boot": True, "autoDelete": True,
                   "initializeParams": {"sourceImage": IMAGE, "diskSizeGb": "20"}}],
        "networkInterfaces": [{
            "network": f"projects/{p}/global/networks/{NET}",
            "accessConfigs": [{"type": "ONE_TO_ONE_NAT", "name": "External NAT"}],
        }],
        "scheduling": {"onHostMaintenance": "TERMINATE"},  # required for Confidential VM
        "metadata": {"items": [{"key": "ssh-keys", "value": "fidr:" + pub}]},
    }
    if args.tdx:
        body["confidentialInstanceConfig"] = {"confidentialInstanceType": "TDX"}
    op = gcp.post(f"/projects/{p}/zones/{z}/instances", body)
    wait_op(op)
    inst = gcp.get(f"/projects/{p}/zones/{z}/instances/fid-proxy-tdx")
    ip = inst["networkInterfaces"][0].get("accessConfigs", [{}])[0].get("natIP")
    st["instance"] = "fid-proxy-tdx"; st["ip"] = ip; st["user"] = "fidr"
    json.dump(st, open(STATE, "w"), indent=2)
    print(f"instance fid-proxy-tdx  status={inst.get('status')}  ip={ip}")
    print(f"ssh -i {priv} fidr@{ip}")
    print(f"state -> {STATE}")


if __name__ == "__main__":
    main()
