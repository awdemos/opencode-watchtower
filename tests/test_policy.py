"""Tests for the policy engine."""
import unittest
import json
import os
import tempfile

from watchtower.policy import PolicyEngine, PolicyRule, SafeEvaluator
from watchtower.schema import Resource


class TestSafeEvaluator(unittest.TestCase):
    def test_basic_arithmetic(self):
        ev = SafeEvaluator({})
        self.assertEqual(ev.evaluate("1 + 2"), 3)
        self.assertEqual(ev.evaluate("10 * 5"), 50)
        self.assertEqual(ev.evaluate("10 // 3"), 3)

    def test_boolean_logic(self):
        ev = SafeEvaluator({})
        self.assertTrue(ev.evaluate("True and True"))
        self.assertFalse(ev.evaluate("True and False"))
        self.assertTrue(ev.evaluate("True or False"))

    def test_comparison(self):
        ev = SafeEvaluator({"x": 5})
        self.assertTrue(ev.evaluate("x > 3"))
        self.assertFalse(ev.evaluate("x < 3"))
        self.assertTrue(ev.evaluate("x == 5"))

    def test_string_methods(self):
        ev = SafeEvaluator({"path": "/home/user/file.txt"})
        self.assertTrue(ev.evaluate("path.startswith('/home/')"))
        self.assertFalse(ev.evaluate("path.startswith('/etc/')"))
        self.assertTrue(ev.evaluate("'..' not in path"))

    def test_list_comprehension(self):
        ev = SafeEvaluator({"items": [1, 2, 3, 4]})
        self.assertEqual(ev.evaluate("[x * 2 for x in items]"), [2, 4, 6, 8])

    def test_disallowed_import(self):
        ev = SafeEvaluator({})
        with self.assertRaises(ValueError):
            ev.evaluate("__import__('os')")

    def test_disallowed_exec(self):
        ev = SafeEvaluator({})
        with self.assertRaises(ValueError):
            ev.evaluate("exec('print(1)')")

    def test_disallowed_open(self):
        ev = SafeEvaluator({})
        with self.assertRaises(ValueError):
            ev.evaluate("open('/etc/passwd')")


class TestPolicyEngine(unittest.TestCase):
    def setUp(self):
        self.rules = [
            PolicyRule(
                name="allow-home",
                priority=100,
                match_domain="filesystem",
                match_operations=["read"],
                condition="target.path.startswith('/home/')",
                action="allow",
            ),
            PolicyRule(
                name="deny-system",
                priority=50,
                match_domain="filesystem",
                match_operations=["write", "delete"],
                condition="target.path.startswith('/etc/')",
                action="deny",
            ),
            PolicyRule(
                name="default-deny",
                priority=0,
                condition="True",
                action="deny",
            ),
        ]
        self.engine = PolicyEngine(self.rules)

    def test_allow_match(self):
        rule = self.engine.evaluate(
            domain="filesystem",
            operation="read",
            target=Resource(path="/home/user/file.txt"),
            identity={"principal": "user:test"},
            params={},
        )
        self.assertIsNotNone(rule)
        self.assertEqual(rule.name, "allow-home")

    def test_deny_match(self):
        rule = self.engine.evaluate(
            domain="filesystem",
            operation="delete",
            target=Resource(path="/etc/passwd"),
            identity={"principal": "user:test"},
            params={},
        )
        self.assertIsNotNone(rule)
        self.assertEqual(rule.name, "deny-system")

    def test_default_deny(self):
        rule = self.engine.evaluate(
            domain="network",
            operation="connect",
            target=Resource(path="/anywhere"),
            identity={"principal": "user:test"},
            params={},
        )
        self.assertIsNotNone(rule)
        self.assertEqual(rule.name, "default-deny")

    def test_priority_ordering(self):
        # Higher priority rule should win even if lower also matches
        rule = self.engine.evaluate(
            domain="filesystem",
            operation="read",
            target=Resource(path="/home/user/etc/file"),
            identity={"principal": "user:test"},
            params={},
        )
        self.assertIsNotNone(rule)
        self.assertEqual(rule.name, "allow-home")

    def test_from_file(self):
        policy = {
            "policies": [
                {
                    "name": "test-allow",
                    "priority": 100,
                    "match": {"domain": "test"},
                    "condition": "True",
                    "action": "allow",
                }
            ]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(policy, f)
            path = f.name
        try:
            engine = PolicyEngine.from_file(path)
            rule = engine.evaluate("test", "op", Resource(), {}, {})
            self.assertIsNotNone(rule)
            self.assertEqual(rule.name, "test-allow")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
