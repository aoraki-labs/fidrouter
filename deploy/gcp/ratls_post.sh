#!/usr/bin/env bash
# RA-TLS post-cutover: run this AFTER ratls_relaunch.py has recreated fid-proxy-cs on the
# new measurement and it has booted. It flips the platform + cp-adapter to the new
# measurement + https. Safe to re-run (idempotent-ish). NOT destructive to the enclave.
#
#   bash ratls_post.sh
#
set -euo pipefail
KEY=/home/ubuntu/toma/awskey-high-privilege-admin-20260801
BOX=ubuntu@52.15.198.116
SSH="ssh -o StrictHostKeyChecking=no -i $KEY $BOX"
NEW_MEAS="sha256:165d65794a4bd7c9a8d98ed46276e486cd3f790b25e01476f460695756e03946"
IDPUB="f8546d03ebc1aac4c974fdeb4d34662b26ce818539070e5a0e936a608cb35f95"
ENCLAVE_HTTPS="https://enclave.fidcore.xyz:9090"

echo "== 1) confirm the enclave attests the NEW measurement over https (self-signed → -k) =="
GOT=$(curl -sk --max-time 12 "$ENCLAVE_HTTPS/attestation?nonce=ratlspost" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("measurement",""))' 2>/dev/null || true)
echo "   enclave reports: ${GOT:-<none>}"
if [ "$GOT" != "$NEW_MEAS" ]; then
  echo "   !! enclave is NOT on the new measurement yet (got '$GOT'). Run ratls_relaunch.py first and wait for boot. Aborting."
  exit 1
fi

echo "== 2) platform DB: add Build + point claude-official at new measurement + https =="
$SSH "python3 - <<PY
import sqlite3
db=sqlite3.connect('/home/ubuntu/fidcore-platform-data/fidrouter.db')
db.execute('''INSERT OR REPLACE INTO builds(measurement,name,source,reproducible_build,identity_pub_hex,source_url,published_at)
             VALUES(?,?,?,?,?,?,?)''',
  ('$NEW_MEAS','fidrouter data plane (RA-TLS, reproducible, sealed BYOK, metering)',
   'cmd/fid-proxy (Apache-2.0)','bash scripts/reproduce.sh (binary bit-reproducible)',
   '$IDPUB','https://github.com/aoraki-labs/fidrouter','2026-08-19'))
db.execute('update endpoints set expected_measurement=?, base_url=? where id=3',('$NEW_MEAS','$ENCLAVE_HTTPS'))
db.commit()
for r in db.execute('select id,name,status,base_url,expected_measurement from endpoints'):
    print(tuple(r))
PY"

echo "== 3) cp-adapter: bump EXPECTED_MEASUREMENT + ENCLAVE_URL=https, restart =="
$SSH "sed -i 's#^export EXPECTED_MEASUREMENT=.*#export EXPECTED_MEASUREMENT=$NEW_MEAS#' /home/ubuntu/cp-adapter/start.sh
sed -i 's#^export ENCLAVE_URL=.*#export ENCLAVE_URL=$ENCLAVE_HTTPS#' /home/ubuntu/cp-adapter/start.sh
pm2 restart cp-adapter >/dev/null 2>&1
sleep 2; curl -s http://127.0.0.1:8091/healthz"
echo

echo "== 4) restart platform so /api/verify re-checks, then verify green =="
$SSH "cd /home/ubuntu/fidcore-platform && pm2 restart fidcore-platform >/dev/null 2>&1; sleep 3"
echo "   /api/verify:"
curl -s https://app.fidcore.xyz/api/verify | python3 -c 'import sys,json;[print(" ",e["name"],e["ok"],e.get("detail","")[:70]) for e in json.load(sys.stdin)]'

echo "== DONE. Remember to also update repo registry.json + config/keys.json expected_measurement to $NEW_MEAS and commit. =="
