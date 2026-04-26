"""Tamper-evident append-only ledger."""
from __future__ import annotations

import glob
import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional


class Ledger:
    def __init__(self, base_dir: str, max_file_size: int = 10 * 1024 * 1024):
        self.base_dir = os.path.expanduser(base_dir)
        self.max_file_size = max_file_size
        self._seq = 0
        self._prev_hash = "0" * 64
        self._current_file: Optional[str] = None
        self._ensure_dir()
        self._recover_state()

    def _ensure_dir(self) -> None:
        os.makedirs(self.base_dir, mode=0o700, exist_ok=True)

    def _recover_state(self) -> None:
        files = sorted(glob.glob(os.path.join(self.base_dir, "ledger-*.jsonl")))
        if not files:
            self._seq = 0
            self._prev_hash = "0" * 64
            self._rotate_file()
            return

        self._current_file = files[-1]
        with open(self._current_file, "r") as f:
            lines = f.readlines()

        if lines:
            last = json.loads(lines[-1])
            self._seq = last["seq"]
            self._prev_hash = last["hash"]
        else:
            self._seq = 0
            self._prev_hash = "0" * 64

        if os.path.getsize(self._current_file) >= self.max_file_size:
            self._rotate_file()

    def _rotate_file(self) -> None:
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        self._current_file = os.path.join(self.base_dir, f"ledger-{timestamp}.jsonl")

    @staticmethod
    def _compute_hash(data: str, prev_hash: str) -> str:
        h = hashlib.sha256()
        h.update(prev_hash.encode())
        h.update(data.encode())
        return h.hexdigest()

    @staticmethod
    def _to_dict(obj: Any) -> Any:
        """Recursively convert dataclasses and other objects to JSON-serializable dicts."""
        import enum
        if isinstance(obj, enum.Enum):
            return obj.value
        if hasattr(obj, "__dataclass_fields__"):
            return {k: Ledger._to_dict(v) for k, v in obj.__dict__.items()}
        if isinstance(obj, dict):
            return {k: Ledger._to_dict(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [Ledger._to_dict(v) for v in obj]
        if isinstance(obj, tuple):
            return [Ledger._to_dict(v) for v in obj]
        return obj

    def append(self, record: Any) -> Dict[str, Any]:
        if self._current_file is None:
            self._rotate_file()

        self._seq += 1
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Convert to dict recursively (handles nested dataclasses)
        data = self._to_dict(record)

        # Remove hash fields if present
        if isinstance(data, dict):
            data.pop("hash", None)
            data.pop("prev_hash", None)

        entry: Dict[str, Any] = {
            "seq": self._seq,
            "timestamp": timestamp,
            "data": data,
            "prev_hash": self._prev_hash,
        }

        canonical = json.dumps(entry["data"], sort_keys=True, separators=(",", ":"))
        entry["hash"] = self._compute_hash(canonical, self._prev_hash)
        self._prev_hash = entry["hash"]

        line = json.dumps(entry, separators=(",", ":")) + "\n"
        with open(self._current_file, "a") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

        if os.path.getsize(self._current_file) >= self.max_file_size:
            self._rotate_file()

        return entry

    def verify(self) -> List[Dict[str, Any]]:
        """Verify integrity of all ledger files."""
        violations: List[Dict[str, Any]] = []
        files = sorted(glob.glob(os.path.join(self.base_dir, "ledger-*.jsonl")))
        expected_prev = "0" * 64

        for filepath in files:
            with open(filepath, "r") as f:
                for line_no, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError as e:
                        violations.append({
                            "file": filepath, "line": line_no,
                            "type": "json_error", "message": str(e),
                        })
                        continue

                    if entry.get("prev_hash") != expected_prev:
                        violations.append({
                            "file": filepath, "line": line_no,
                            "type": "chain_break",
                            "expected_prev": expected_prev,
                            "got_prev": entry.get("prev_hash"),
                        })

                    data = entry.get("data", {})
                    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
                    computed = self._compute_hash(canonical, expected_prev)
                    if entry.get("hash") != computed:
                        violations.append({
                            "file": filepath, "line": line_no,
                            "type": "hash_mismatch",
                            "expected_hash": computed,
                            "got_hash": entry.get("hash"),
                        })

                    expected_prev = entry.get("hash", expected_prev)

        return violations

    def query(self, **filters: Any) -> List[Dict[str, Any]]:
        """Query ledger entries with simple equality filters on data fields."""
        results: List[Dict[str, Any]] = []
        files = sorted(glob.glob(os.path.join(self.base_dir, "ledger-*.jsonl")))

        for filepath in files:
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    data = entry.get("data", {})
                    match = True
                    for key, value in filters.items():
                        if key not in data or data[key] != value:
                            match = False
                            break
                    if match:
                        results.append(entry)

        return results

    def tail(self, n: int = 20) -> List[Dict[str, Any]]:
        """Return last n entries across all files."""
        all_entries: List[Dict[str, Any]] = []
        files = sorted(glob.glob(os.path.join(self.base_dir, "ledger-*.jsonl")))
        for filepath in files:
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        all_entries.append(json.loads(line))
        return all_entries[-n:] if n < len(all_entries) else all_entries
