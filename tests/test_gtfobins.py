"""Tests for the GTFOBins detection engine."""
import unittest
import json
import os
import tempfile

from watchtower.gtfobins import GTFOEngine, GTFOResult


class TestGTFOEngine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "gtfo.json")
        db = {
            "binaries": {
                "bash": {
                    "risk": "critical",
                    "vectors": ["shell", "sudo", "suid", "file-read", "file-write"],
                    "functions": ["shell", "command", "file-read", "file-write", "suid", "sudo"],
                    "description": "Shell access",
                },
                "python3": {
                    "risk": "critical",
                    "vectors": ["shell", "sudo", "suid"],
                    "functions": ["shell", "command", "file-read", "file-write"],
                    "description": "Can spawn shell via os.system/exec",
                },
                "cat": {
                    "risk": "low",
                    "vectors": ["sudo", "file-read"],
                    "functions": ["file-read"],
                    "description": "Can read arbitrary files with sudo",
                },
                "sed": {
                    "risk": "high",
                    "vectors": ["file-write", "sudo"],
                    "functions": ["file-write", "file-read"],
                    "description": "Can write to arbitrary files",
                },
            }
        }
        with open(self.db_path, "w") as f:
            json.dump(db, f)
        self.engine = GTFOEngine(self.db_path)

    def tearDown(self):
        for f in os.listdir(self.tmpdir):
            os.unlink(os.path.join(self.tmpdir, f))
        os.rmdir(self.tmpdir)

    def test_is_gtfo(self):
        self.assertTrue(self.engine.is_gtfo("bash"))
        self.assertTrue(self.engine.is_gtfo("python3"))
        self.assertFalse(self.engine.is_gtfo("ls"))

    def test_lookup(self):
        info = self.engine.lookup("bash")
        self.assertIsNotNone(info)
        self.assertEqual(info["risk"], "critical")

    def test_analyze_command_critical(self):
        result = self.engine.analyze_command(["bash", "-c", "whoami"])
        self.assertIsNotNone(result)
        self.assertEqual(result.binary, "bash")
        self.assertEqual(result.risk, "critical")
        self.assertTrue(result.score > 0.5)

    def test_analyze_command_high(self):
        result = self.engine.analyze_command(["sed", "-i", "s/old/new/", "file.txt"])
        self.assertIsNotNone(result)
        self.assertEqual(result.binary, "sed")
        self.assertEqual(result.risk, "high")

    def test_analyze_command_low(self):
        result = self.engine.analyze_command(["cat", "/etc/passwd"])
        self.assertIsNotNone(result)
        self.assertEqual(result.binary, "cat")
        self.assertEqual(result.risk, "low")

    def test_analyze_command_not_gtfo(self):
        result = self.engine.analyze_command(["ls", "-la"])
        self.assertIsNone(result)

    def test_analyze_shell_command(self):
        results = self.engine.analyze_shell_command("bash -p -c 'whoami'")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].binary, "bash")

    def test_get_all_critical(self):
        critical = self.engine.get_all_critical()
        self.assertIn("bash", critical)
        self.assertIn("python3", critical)
        self.assertNotIn("cat", critical)

    def test_generate_policy_rules(self):
        rules = self.engine.generate_policy_rules()
        self.assertTrue(len(rules) > 0)
        # bash and python3 are critical -> escalate
        bash_rules = [r for r in rules if r["name"] == "gtfo-critical-bash"]
        self.assertEqual(len(bash_rules), 1)
        self.assertEqual(bash_rules[0]["action"], "escalate")
        # sed is high -> shadow
        sed_rules = [r for r in rules if r["name"] == "gtfo-high-sed"]
        self.assertEqual(len(sed_rules), 1)
        self.assertEqual(sed_rules[0]["action"], "shadow")


if __name__ == "__main__":
    unittest.main()
