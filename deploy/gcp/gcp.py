"""Minimal, dependency-free Google Cloud client (service-account JWT -> OAuth2
access token -> Compute REST API). Mirrors deploy/aliyun/acs.py. Reads config
from the repo .env; never prints the private key.

Auth: sign a JWT with the SA private key (RS256), exchange at the token endpoint
for a Bearer access token, call https://compute.googleapis.com/compute/v1/...
"""
import base64
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

COMPUTE = "https://compute.googleapis.com/compute/v1"
_ENV = None
_SA = None
_TOKEN = None  # (access_token, expiry)


def load_env(path=None):
    global _ENV
    if _ENV is not None:
        return _ENV
    if path is None:
        path = os.path.join(os.path.dirname(__file__), "..", "..", ".env")
    env = {}
    with open(path) as f:
        for line in f:
            m = re.match(r"\s*([A-Za-z0-9_]+)\s*=\s*(.+?)\s*$", line)
            if m:
                env[m.group(1)] = m.group(2)
    _ENV = env
    return env


def _clean(v):  # strip inline "# ..." comments (GCP_ZONE has one)
    return v.split("#")[0].strip()


def project():
    return _clean(load_env()["GCP_PROJECT_ID"])


def zone():
    return _clean(load_env()["GCP_ZONE"])


def region():
    return zone().rsplit("-", 1)[0]


def _sa():
    global _SA
    if _SA is None:
        env = load_env()
        path = env.get("GOOGLE_APPLICATION_CREDENTIALS")
        if path and os.path.exists(path):
            _SA = json.load(open(path))
        elif env.get("GCP_SA_JSON"):
            _SA = json.loads(env["GCP_SA_JSON"])
        else:
            raise GcpError("no SA credentials (GOOGLE_APPLICATION_CREDENTIALS / GCP_SA_JSON)")
    return _SA


class GcpError(Exception):
    def __init__(self, msg, http=0, body=""):
        self.http, self.body = http, body
        super().__init__(msg)


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def token():
    global _TOKEN
    if _TOKEN and _TOKEN[1] - 60 > time.time():
        return _TOKEN[0]
    sa = _sa()
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    if sa.get("private_key_id"):
        header["kid"] = sa["private_key_id"]
    claims = {
        "iss": sa["client_email"],
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "aud": sa.get("token_uri", "https://oauth2.googleapis.com/token"),
        "iat": now, "exp": now + 3600,
    }
    si = (_b64u(json.dumps(header).encode()) + "." + _b64u(json.dumps(claims).encode())).encode()
    key = serialization.load_pem_private_key(sa["private_key"].encode(), password=None)
    sig = key.sign(si, padding.PKCS1v15(), hashes.SHA256())
    assertion = si.decode() + "." + _b64u(sig)
    data = urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion,
    }).encode()
    try:
        with urllib.request.urlopen(sa.get("token_uri", "https://oauth2.googleapis.com/token"), data=data, timeout=30) as r:
            j = json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise GcpError("token exchange failed", e.code, e.read().decode())
    _TOKEN = (j["access_token"], now + int(j.get("expires_in", 3600)))
    return _TOKEN[0]


def api(method, url, body=None):
    """Call a Compute (or full-URL) API. `url` may be a path under COMPUTE or absolute."""
    if url.startswith("/"):
        url = COMPUTE + url
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + token(),
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            code = json.loads(body).get("error", {}).get("message", f"HTTP{e.code}")
        except Exception:
            code = f"HTTP{e.code}"
        raise GcpError(code, e.code, body)


def get(path):
    return api("GET", path)


def post(path, body):
    return api("POST", path, body)


def delete(path):
    return api("DELETE", path)
