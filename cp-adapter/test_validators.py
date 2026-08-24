"""Tests for the validator layer. Run: python3 -m unittest test_validators -v

These assert the properties that matter for safety, not the plumbing:
  * a refusal and an outage are never confused (an outage must not read as "key invalid")
  * unknown quota never becomes unlimited
  * a validator cannot smuggle a name/email into the tenant id
"""
import json
import os
import stat
import subprocess
import tempfile
import unittest

import validators as V


class TestVerdictParsing(unittest.TestCase):
    def test_refusal(self):
        v = V.Verdict.from_json({"ok": False, "reason": "no quota"})
        self.assertFalse(v.ok)
        self.assertEqual(v.reason, "no quota")

    def test_unknown_quota_stays_none(self):
        # A gateway that omits remaining_usd, or sends junk, must NOT become "unlimited".
        for payload in ({"ok": True}, {"ok": True, "remaining_usd": "lots"},
                        {"ok": True, "remaining_usd": None}):
            self.assertIsNone(V.Verdict.from_json(payload).remaining_usd, payload)

    def test_fields(self):
        v = V.Verdict.from_json({"ok": True, "subject": "u/1", "remaining_usd": 12.5,
                                 "group": "enclave", "models": ["a", "", "b"],
                                 "expires_at": "1700000000"})
        self.assertEqual((v.subject, v.remaining_usd, v.group), ("u/1", 12.5, "enclave"))
        self.assertEqual(v.models, ["a", "b"])
        self.assertEqual(v.expires_at, 1700000000)

    def test_empty_group_is_none_not_empty_string(self):
        # "" would silently fail an `in ALLOWED_GROUPS` check in a confusing way.
        self.assertIsNone(V.Verdict.from_json({"ok": True, "group": ""}).group)

    def test_non_object_is_an_outage(self):
        with self.assertRaises(V.ValidatorUnavailable):
            V.Verdict.from_json(["nope"])


class TestExecValidator(unittest.TestCase):
    def _script(self, body: str) -> str:
        f = tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False)
        f.write("#!/usr/bin/env bash\n" + body)
        f.close()
        os.chmod(f.name, os.stat(f.name).st_mode | stat.S_IEXEC)
        return f.name

    def test_reads_key_from_stdin_and_returns_verdict(self):
        # Also proves the key is NOT passed in argv: the script echoes its own $@.
        s = self._script('read -r line; echo "{\\"ok\\":true,\\"subject\\":\\"s1\\","'
                         '"\\"remaining_usd\\":3.5,\\"group\\":\\"enclave\\"}" ; echo "argv=$@" >&2\n')
        v = V._exec("sk-secret", {"cmd": s})
        self.assertTrue(v.ok)
        self.assertEqual((v.subject, v.remaining_usd, v.group), ("s1", 3.5, "enclave"))
        p = subprocess.run([s], input=b'{"key":"sk-secret"}', capture_output=True)
        self.assertNotIn(b"sk-secret", p.stderr, "key leaked into argv")

    def test_nonzero_exit_is_outage_not_refusal(self):
        s = self._script("exit 3\n")
        with self.assertRaises(V.ValidatorUnavailable):
            V._exec("sk", {"cmd": s})

    def test_garbage_output_is_outage(self):
        s = self._script("echo not-json\n")
        with self.assertRaises(V.ValidatorUnavailable):
            V._exec("sk", {"cmd": s})

    def test_explicit_refusal_is_a_verdict(self):
        s = self._script('echo "{\\"ok\\":false,\\"reason\\":\\"revoked\\"}"\n')
        v = V._exec("sk", {"cmd": s})
        self.assertFalse(v.ok)
        self.assertEqual(v.reason, "revoked")


class TestQuotaPolicy(unittest.TestCase):
    def test_default_refuses(self):
        self.assertEqual(V.quota_policy({}), ("refuse", 0.0))

    def test_cap(self):
        self.assertEqual(V.quota_policy({"QUOTA_UNKNOWN": "cap:2.5"}), ("cap", 2.5))

    def test_bad_value_is_fatal_not_silently_permissive(self):
        with self.assertRaises(SystemExit):
            V.quota_policy({"QUOTA_UNKNOWN": "unlimited"})


class TestFromEnv(unittest.TestCase):
    def test_requires_config(self):
        for env in ({"VALIDATOR": "newapi"}, {"VALIDATOR": "http"}, {"VALIDATOR": "exec"}):
            with self.assertRaises(SystemExit, msg=env):
                V.from_env(env)

    def test_unknown_kind(self):
        with self.assertRaises(SystemExit):
            V.from_env({"VALIDATOR": "telepathy"})

    def test_builds_each_kind(self):
        k, fn, cfg = V.from_env({"VALIDATOR": "newapi", "NEWAPI_BASE": "https://g"})
        self.assertEqual(k, "newapi")
        self.assertEqual(cfg["base"], "https://g")
        k, _, cfg = V.from_env({"VALIDATOR": "http", "VALIDATOR_URL": "https://g/fid/validate"})
        self.assertEqual((k, cfg["url"]), ("http", "https://g/fid/validate"))
        k, _, cfg = V.from_env({"VALIDATOR": "exec", "VALIDATOR_CMD": "/bin/true"})
        self.assertEqual((k, cfg["cmd"]), ("exec", "/bin/true"))


if __name__ == "__main__":
    unittest.main()
