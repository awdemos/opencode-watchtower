"""Tests for the guard orchestrator."""
import unittest
import os
import tempfile
import json

from watchtower.guard import Guard
from watchtower.schema import Identity, Intent, Resource


class TestGuard(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.policy_path = os.path.join(self.tmpdir, "policy.json")
        policy = {
            "policies": [
                {
                    "name": "allow-tmp-read",
                    "priority": 100,
                    "match": {"domain": "filesystem", "operation": "read"},
                    "condition": "target.path.startswith('/tmp/')",
                    "action": "allow",
                    "risk_level": "low",
                },
                {
                    "name": "deny-system",
                    "priority": 50,
                    "match": {"domain": "filesystem", "operation": "delete"},
                    "condition": "target.path.startswith('/etc/')",
                    "action": "deny",
                    "risk_level": "critical",
                },
                {
                    "name": "default-deny",
                    "priority": 0,
                    "condition": "True",
                    "action": "deny",
                },
            ]
        }
        with open(self.policy_path, "w") as f:
            json.dump(policy, f)

    def tearDown(self):
        for f in os.listdir(self.tmpdir):
            os.unlink(os.path.join(self.tmpdir, f))
        os.rmdir(self.tmpdir)

    def test_allow_action(self):
        guard = Guard(self.policy_path, self.tmpdir)
        identity = Identity(principal="user:test")
        intent = Intent(domain="filesystem", operation="read", target=Resource(path="/tmp/test.txt"))

        result = guard.check(identity, intent)
        self.assertTrue(result["allowed"])
        self.assertEqual(result["rule"], "allow-tmp-read")
        self.assertLess(result["risk_score"], 0.3)

    def test_deny_action(self):
        guard = Guard(self.policy_path, self.tmpdir)
        identity = Identity(principal="user:test")
        intent = Intent(domain="filesystem", operation="delete", target=Resource(path="/etc/passwd"))

        result = guard.check(identity, intent)
        self.assertFalse(result["allowed"])
        self.assertEqual(result["rule"], "deny-system")

    def test_log_entry_created(self):
        guard = Guard(self.policy_path, self.tmpdir)
        identity = Identity(principal="user:test")
        intent = Intent(domain="filesystem", operation="read", target=Resource(path="/tmp/test.txt"))

        guard.check(identity, intent)

        # Check ledger has entry
        ledger_files = [f for f in os.listdir(self.tmpdir) if f.startswith("ledger-")]
        self.assertEqual(len(ledger_files), 1)

        with open(os.path.join(self.tmpdir, ledger_files[0])) as f:
            entry = json.loads(f.readline())

        self.assertEqual(entry["data"]["intent"]["domain"], "filesystem")
        self.assertEqual(entry["seq"], 1)

    def test_executes_command(self):
        guard = Guard(self.policy_path, self.tmpdir)
        identity = Identity(principal="user:test")
        intent = Intent(domain="filesystem", operation="read", target=Resource(path="/tmp/test.txt"))

        result = guard.check(identity, intent, cmd=["echo", "hello"])
        self.assertTrue(result["allowed"])
        self.assertIsNotNone(result["execution"])
        self.assertTrue(result["execution"]["success"])
        self.assertIn("hello", result["execution"]["stdout"])


if __name__ == "__main__":
    unittest.main()
