"""Tests for the tamper-evident ledger."""
import unittest
import os
import tempfile
import json

from watchtower.ledger import Ledger


class TestLedger(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        for f in os.listdir(self.tmpdir):
            os.unlink(os.path.join(self.tmpdir, f))
        os.rmdir(self.tmpdir)

    def test_append_and_verify(self):
        ledger = Ledger(self.tmpdir)
        entry1 = ledger.append({"test": "data1"})
        entry2 = ledger.append({"test": "data2"})

        self.assertEqual(entry1["seq"], 1)
        self.assertEqual(entry2["seq"], 2)
        self.assertNotEqual(entry1["hash"], entry2["hash"])
        self.assertEqual(entry2["prev_hash"], entry1["hash"])

        violations = ledger.verify()
        self.assertEqual(len(violations), 0)

    def test_tamper_detection(self):
        ledger = Ledger(self.tmpdir)
        ledger.append({"test": "data1"})
        ledger.append({"test": "data2"})

        # Tamper with the file
        files = [f for f in os.listdir(self.tmpdir) if f.startswith("ledger-")]
        with open(os.path.join(self.tmpdir, files[0]), "r") as f:
            lines = f.readlines()

        # Modify a line
        data = json.loads(lines[0])
        data["data"]["test"] = "TAMPERED"
        lines[0] = json.dumps(data) + "\n"

        with open(os.path.join(self.tmpdir, files[0]), "w") as f:
            f.writelines(lines)

        violations = ledger.verify()
        self.assertGreater(len(violations), 0)
        self.assertEqual(violations[0]["type"], "hash_mismatch")

    def test_query(self):
        ledger = Ledger(self.tmpdir)
        ledger.append({"domain": "fs", "op": "read"})
        ledger.append({"domain": "fs", "op": "write"})
        ledger.append({"domain": "net", "op": "connect"})

        results = ledger.query(domain="fs")
        self.assertEqual(len(results), 2)

    def test_tail(self):
        ledger = Ledger(self.tmpdir)
        for i in range(10):
            ledger.append({"idx": i})

        tail = ledger.tail(3)
        self.assertEqual(len(tail), 3)
        self.assertEqual(tail[-1]["data"]["idx"], 9)

    def test_recovery(self):
        ledger = Ledger(self.tmpdir)
        ledger.append({"test": "data1"})
        del ledger

        # Reopen - should recover state
        ledger2 = Ledger(self.tmpdir)
        entry = ledger2.append({"test": "data2"})
        self.assertEqual(entry["seq"], 2)


if __name__ == "__main__":
    unittest.main()
