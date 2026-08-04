"""Deploy the PUBLIC verification page to its OWN small VM — deliberately a
separate host from the relay/enclave, because the trust anchor must be
independent of the operator. e2-micro, files embedded via startup-script
(no SSH needed), served by systemd on :8080.

  python3 deploy/gcp/verify_provision.py --yes     # create/replace
  python3 deploy/gcp/verify_provision.py --destroy
"""
import argparse
import base64
import json
import os
import time

import gcp

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..", "..")
NAME = "fid-verify"


def b64(path):
    return base64.b64encode(open(path, "rb").read()).decode()


def startup_script(ip):
    files = {
        "/opt/vp/verify-page/server.py": os.path.join(ROOT, "verify-page", "server.py"),
        "/opt/vp/verify-page/registry.json": os.path.join(ROOT, "verify-page", "registry.json"),
        "/opt/vp/sdk/python/fidrouter_verify.py": os.path.join(ROOT, "sdk", "python", "fidrouter_verify.py"),
        # partner console: metering ingest (verifies signed receipts) + usage board + embedded docs
        "/opt/vp/console/server.py": os.path.join(ROOT, "console", "server.py"),
        "/opt/vp/docs/DESIGN.md": os.path.join(ROOT, "docs", "DESIGN.md"),
    }
    lines = [
        "#!/bin/bash", "set -e",
        "export DEBIAN_FRONTEND=noninteractive",
        "apt-get update -y", "apt-get install -y python3-pip",
        "pip3 install --break-system-packages cryptography || pip3 install cryptography",
        "mkdir -p /opt/vp/verify-page /opt/vp/explorer /opt/vp/sdk/python /opt/vp/console /opt/vp/docs",
    ]
    for dst, src in files.items():
        lines.append(f"base64 -d > {dst} <<'B64'\n{b64(src)}\nB64")
    lines += [
        "cat > /etc/systemd/system/vp.service <<'EOF'",
        "[Unit]", "Description=fidrouter public verification", "After=network-online.target",
        "[Service]",
        "Environment=PORT=8080",
        "WorkingDirectory=/opt/vp/verify-page",
        "ExecStart=/usr/bin/python3 /opt/vp/verify-page/server.py",
        "Restart=always", "RestartSec=3",
        "[Install]", "WantedBy=multi-user.target",
        "EOF",
        "systemctl daemon-reload", "systemctl enable --now vp",
        # partner console on :8082 (metering ingest + usage board + docs)
        "cat > /etc/systemd/system/console.service <<'EOF'",
        "[Unit]", "Description=fidrouter partner console", "After=network-online.target",
        "[Service]",
        "Environment=PORT=8082",
        "Environment=REGISTRY_PATH=/opt/vp/verify-page/registry.json",
        "Environment=DOCS_PATH=/opt/vp/docs/DESIGN.md",
        "WorkingDirectory=/opt/vp/console",
        "ExecStart=/usr/bin/python3 /opt/vp/console/server.py",
        "Restart=always", "RestartSec=3",
        "[Install]", "WantedBy=multi-user.target",
        "EOF",
        "systemctl daemon-reload", "systemctl enable --now console",
    ]
    # HTTPS via Caddy auto-TLS. Domain later: use sslip.io (public wildcard DNS
    # that resolves <ip-dashed>.sslip.io -> ip), so Let's Encrypt issues a REAL
    # trusted cert with no domain ownership. Static IP keeps the hostname stable.
    dash = ip.replace(".", "-")
    hv = f"verify.{dash}.sslip.io"
    hc = f"console.{dash}.sslip.io"
    lines += [
        "curl -fsSL https://github.com/caddyserver/caddy/releases/download/v2.8.4/caddy_2.8.4_linux_amd64.tar.gz | tar -xz -C /usr/local/bin caddy",
        "chmod +x /usr/local/bin/caddy",
        "id caddy >/dev/null 2>&1 || useradd --system --home /var/lib/caddy --create-home --shell /usr/sbin/nologin caddy",
        "mkdir -p /etc/caddy /var/lib/caddy && chown caddy:caddy /var/lib/caddy",
        "cat > /etc/caddy/Caddyfile <<EOF",
        f"{hv} {{",
        "  reverse_proxy localhost:8080",
        "}",
        f"{hc} {{",
        "  reverse_proxy localhost:8082",
        "}",
        "EOF",
        "cat > /etc/systemd/system/caddy.service <<'EOF'",
        "[Unit]", "Description=Caddy (auto-HTTPS)", "After=network-online.target",
        "[Service]", "User=caddy",
        "Environment=XDG_DATA_HOME=/var/lib/caddy", "Environment=XDG_CONFIG_HOME=/var/lib/caddy",
        "ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile",
        "AmbientCapabilities=CAP_NET_BIND_SERVICE", "Restart=always", "RestartSec=3",
        "[Install]", "WantedBy=multi-user.target",
        "EOF",
        "systemctl daemon-reload", "systemctl enable --now caddy",
    ]
    return "\n".join(lines) + "\n"


def ensure_firewall(p):
    # Separate idempotent rules per port (firewall PATCH on an existing rule is
    # unreliable; creating a distinct rule always works and no-ops if present).
    for name, port in (("fidr-allow-verify", "8080"), ("fidr-allow-explorer", "8081"),
                       ("fidr-allow-console", "8082"),
                       ("fidr-allow-web-80", "80"), ("fidr-allow-web-443", "443")):
        try:
            gcp.post(f"/projects/{p}/global/firewalls", {
                "name": name, "network": f"projects/{p}/global/networks/fid-router-net",
                "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": [port]}],
            })
            print(f"created firewall {name} (:{port})")
        except gcp.GcpError as e:
            print(f"firewall {name}:", "exists" if "ALREADY_EXISTS" in (e.body or "") else e)


def ensure_static_ip(p, r) -> str:
    """Reserve a regional static external IP so the sslip.io hostname (and thus
    the HTTPS cert + trust URL) stays stable across redeploys."""
    name = "fid-verify-ip"
    try:
        gcp.post(f"/projects/{p}/regions/{r}/addresses", {"name": name})
        print("reserved static IP", name)
    except gcp.GcpError as e:
        print("static IP:", "exists" if "ALREADY_EXISTS" in (e.body or "") else e)
    for _ in range(20):
        a = gcp.get(f"/projects/{p}/regions/{r}/addresses/{name}")
        if a.get("address"):
            return a["address"]
        time.sleep(2)
    raise gcp.GcpError("static IP not ready")


def destroy(p, z):
    try:
        gcp.delete(f"/projects/{p}/zones/{z}/instances/{NAME}")
        print("deleting", NAME)
    except gcp.GcpError as e:
        print("destroy:", e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--destroy", action="store_true")
    args = ap.parse_args()
    p, z, r = gcp.project(), gcp.zone(), gcp.region()
    if args.destroy:
        destroy(p, z)
        return
    if not args.yes:
        print("DRY-RUN. Re-run with --yes to create the e2-micro verification host.")
        return

    ensure_firewall(p)
    ip = ensure_static_ip(p, r)
    print("static IP =", ip)
    destroy(p, z)  # replace if exists
    for _ in range(45):  # wait for the async delete to actually finish
        time.sleep(4)
        try:
            gcp.get(f"/projects/{p}/zones/{z}/instances/{NAME}")
        except gcp.GcpError:
            break
    img = gcp.get("/projects/debian-cloud/global/images/family/debian-12")["selfLink"]
    body = {
        "name": NAME,
        "machineType": f"projects/{p}/zones/{z}/machineTypes/e2-micro",
        "disks": [{"boot": True, "autoDelete": True, "initializeParams": {"sourceImage": img, "diskSizeGb": "10"}}],
        "networkInterfaces": [{"network": f"projects/{p}/global/networks/fid-router-net",
                               "accessConfigs": [{"type": "ONE_TO_ONE_NAT", "name": "External NAT", "natIP": ip}]}],
        "metadata": {"items": [{"key": "startup-script", "value": startup_script(ip)}]},
    }
    op = gcp.post(f"/projects/{p}/zones/{z}/instances", body)
    print("launch op:", op.get("name"))
    time.sleep(18)
    inst = gcp.get(f"/projects/{p}/zones/{z}/instances/{NAME}")
    ip = inst["networkInterfaces"][0].get("accessConfigs", [{}])[0].get("natIP")
    dash = (ip or "").replace(".", "-")
    json.dump({"ip": ip, "verify_https": f"https://verify.{dash}.sslip.io",
               "console_https": f"https://console.{dash}.sslip.io"},
              open(os.path.join(HERE, "verify_state.json"), "w"))
    print(f"\n{NAME} status={inst.get('status')} ip={ip}")
    print("give it ~2-3 min for pip + caddy install + Let's Encrypt issuance, then:")
    print(f"  trust page (HTTPS):    https://verify.{dash}.sslip.io")
    print(f"  partner console:       https://console.{dash}.sslip.io")
    print(f"  (plain http fallback:  http://{ip}:8080  /  http://{ip}:8082)")


if __name__ == "__main__":
    main()
