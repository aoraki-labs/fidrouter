"""Minimal, dependency-free Aliyun RPC API client (HMAC-SHA1 signing).

Why hand-rolled: aliyunsdkcore in this env pulls a broken vendored pyOpenSSL.
Signing is the stable public contract, so we sign with stdlib only. Reads
credentials from the repo .env; NEVER prints the secret.
"""
import base64
import hashlib
import hmac
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import os

_ENV_CACHE = None


def load_env(path=None):
    global _ENV_CACHE
    if _ENV_CACHE is not None:
        return _ENV_CACHE
    if path is None:
        path = os.path.join(os.path.dirname(__file__), "..", "..", ".env")
    env = {}
    with open(path) as f:
        for line in f:
            m = re.match(r"\s*([A-Za-z0-9_]+)\s*=\s*(.+?)\s*$", line)
            if m:
                env[m.group(1)] = m.group(2)
    _ENV_CACHE = env
    return env


def _enc(s):
    return urllib.parse.quote(str(s), safe="")


class AcsError(Exception):
    def __init__(self, code, http, body):
        self.code, self.http, self.body = code, http, body
        super().__init__(f"{code} (HTTP {http}): {body[:300]}")


def call(domain, version, action, params=None, region="cn-hangzhou", method="GET"):
    """Call an Aliyun RPC API. Returns parsed JSON dict. Raises AcsError on non-200."""
    env = load_env()
    ak = env.get("ALIYUN_ACCESS_KEY_ID")
    sk = env.get("ALIYUN_ACCESS_KEY_SECRET")
    if not ak or not sk:
        raise AcsError("NoCredentials", 0, "ALIYUN_ACCESS_KEY_ID/SECRET missing in .env")

    p = {
        "Format": "JSON", "Version": version, "AccessKeyId": ak,
        "SignatureMethod": "HMAC-SHA1", "SignatureVersion": "1.0",
        "SignatureNonce": uuid.uuid4().hex,
        "Timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "Action": action,
    }
    if params:
        p.update({k: v for k, v in params.items() if v is not None})

    q = "&".join(f"{_enc(k)}={_enc(p[k])}" for k in sorted(p))
    sts = f"{method}&{_enc('/')}&{_enc(q)}"
    sig = base64.b64encode(hmac.new((sk + "&").encode(), sts.encode(), hashlib.sha1).digest()).decode()
    url = f"https://{domain}/?{q}&Signature={_enc(sig)}"

    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            code = json.loads(body).get("Code", f"HTTP{e.code}")
        except Exception:
            code = f"HTTP{e.code}"
        raise AcsError(code, e.code, body)


# thin product wrappers ------------------------------------------------------
def ecs(action, params=None, region="cn-hangzhou"):
    return call(f"ecs.{region}.aliyuncs.com", "2014-05-26", action, params, region)


def vpc(action, params=None, region="cn-hangzhou"):
    return call("vpc.aliyuncs.com", "2016-04-28", action, params, region)


def kms(action, params=None, region="cn-hangzhou"):
    return call(f"kms.{region}.aliyuncs.com", "2016-01-20", action, params, region)


def sts_identity():
    return call("sts.aliyuncs.com", "2015-04-01", "GetCallerIdentity")
