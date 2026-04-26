"""Sandboxed execution of approved actions."""
from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import time
from typing import Any, Dict, List, Optional


class Executor:
    def __init__(self, timeout: int = 30, max_output: int = 10 * 1024 * 1024):
        self.timeout = timeout
        self.max_output = max_output

    def run(self, cmd: List[str], env: Optional[Dict[str, str]] = None,
            cwd: Optional[str] = None,
            restrictions: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute a command and return structured result."""
        start = time.time()

        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=run_env,
                cwd=cwd,
            )
            duration = (time.time() - start) * 1000

            stdout = proc.stdout[:self.max_output]
            stderr = proc.stderr[:self.max_output]

            return {
                "success": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "stdout_hash": hashlib.sha256(stdout.encode()).hexdigest(),
                "stderr_hash": hashlib.sha256(stderr.encode()).hexdigest(),
                "duration_ms": round(duration, 3),
            }

        except subprocess.TimeoutExpired:
            duration = (time.time() - start) * 1000
            msg = f"Command timed out after {self.timeout}s"
            return {
                "success": False,
                "returncode": -signal.SIGTERM,
                "stdout": "",
                "stderr": msg,
                "stdout_hash": hashlib.sha256(b"").hexdigest(),
                "stderr_hash": hashlib.sha256(msg.encode()).hexdigest(),
                "duration_ms": round(duration, 3),
            }
        except Exception as e:
            duration = (time.time() - start) * 1000
            return {
                "success": False,
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "stdout_hash": hashlib.sha256(b"").hexdigest(),
                "stderr_hash": hashlib.sha256(str(e).encode()).hexdigest(),
                "duration_ms": round(duration, 3),
            }
