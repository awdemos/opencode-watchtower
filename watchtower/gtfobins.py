"""GTFOBins detection and monitoring engine.

Parses the complete GTFOBins database and provides runtime detection
of high-risk binary invocations, flag combinations, and exploit contexts.
"""
from __future__ import annotations

import json
import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class GTFOResult:
    binary: str
    risk: str  # critical, high, medium, low
    vectors: List[str]
    functions: List[str]
    description: str
    matched_flags: List[str] = field(default_factory=list)
    score: float = 0.0
    context: str = ""


class GTFOEngine:
    """Engine for detecting GTFOBins usage in command lines and audit streams."""

    # Command-line flags/signatures commonly associated with GTFOBins exploits
    FLAG_SIGNATURES: Dict[str, List[Tuple[str, str]]] = {
        "shell": [
            ("bash", ["-c", "-p", "--posix"]),
            ("sh", ["-c", "-p"]),
            ("zsh", ["-c"]),
            ("python", ["-c", "-m", "pty"]),
            ("python3", ["-c", "-m", "pty"]),
            ("perl", ["-e", "-T"]),
            ("ruby", ["-e", "-r", "pty"]),
            ("php", ["-r", "-f"]),
            ("node", ["-e", "-p"]),
            ("awk", ["BEGIN", "system"]),
            ("gawk", ["BEGIN", "system"]),
            ("find", ["-exec", "-ok"]),
            ("xargs", ["-I", "-i"]),
            ("env", ["-c"]),
            ("vim", ["-c", "+", "-S"]),
            ("vi", ["-c", "+"]),
            ("nvim", ["-c", "+", "-S"]),
            ("emacs", ["-eval", "-Q"]),
            ("less", ["!", "+"]),
            ("more", ["!"]),
            ("man", ["!"]),
            ("git", ["-p", "--exec"]),
            ("docker", ["run", "exec"]),
            ("kubectl", ["exec", "run"]),
        ],
        "file-read": [
            ("cat", []),
            ("less", []),
            ("more", []),
            ("head", []),
            ("tail", []),
            ("nl", []),
            ("od", []),
            ("xxd", []),
            ("hexdump", []),
            ("strings", []),
            ("base64", ["-d"]),
            ("cp", ["/etc/shadow", "/etc/passwd"]),
            ("mv", []),
            ("tar", ["-x", "-f"]),
            ("gzip", ["-d", "-c"]),
            ("gunzip", ["-c"]),
            ("zip", ["-d"]),
            ("unzip", ["-p"]),
            ("ar", ["-p"]),
            ("cpio", ["-i", "-F"]),
        ],
        "file-write": [
            ("sed", ["-i", "w"]),
            ("awk", [">>"]),
            ("tee", ["-a"]),
            ("dd", ["of="]),
            ("cp", []),
            ("mv", []),
            ("chmod", []),
            ("chown", []),
            ("tar", ["-c", "-f"]),
            ("zip", []),
            ("ar", ["-r"]),
        ],
        "sudo": [
            ("sudo", ["-u#-1", "-u#4294967295", "ALL", "!root", "-e", "-l", "-k"]),
        ],
        "suid": [
            ("bash", ["-p"]),
            ("sh", ["-p"]),
            ("dash", ["-p"]),
            ("zsh", ["-p"]),
        ],
    }

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            # Look in project root, then current dir
            candidates = [
                os.path.join(os.path.dirname(__file__), "..", "gtfo.json"),
                "gtfo.json",
                "/usr/local/share/watchtower/gtfo.json",
            ]
            for c in candidates:
                c = os.path.abspath(c)
                if os.path.exists(c):
                    db_path = c
                    break
        self.db_path = db_path
        self.binaries: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self.db_path or not os.path.exists(self.db_path):
            return
        with open(self.db_path) as f:
            data = json.load(f)
        self.binaries = data.get("binaries", {})

    def is_gtfo(self, binary: str) -> bool:
        """Check if a binary name is in the GTFOBins database."""
        return binary in self.binaries

    def lookup(self, binary: str) -> Optional[Dict[str, Any]]:
        """Get GTFOBins data for a binary."""
        return self.binaries.get(binary)

    def analyze_command(self, cmd: List[str]) -> Optional[GTFOResult]:
        """Analyze a command line for GTFOBins usage.
        
        Returns a GTFOResult if a GTFOBin is detected, None otherwise.
        """
        if not cmd:
            return None
        
        binary = os.path.basename(cmd[0])
        info = self.lookup(binary)
        if not info:
            return None
        
        # Determine context from command arguments
        args_str = " ".join(cmd[1:])
        matched_flags: List[str] = []
        context = "unprivileged"
        
        if "sudo" in args_str.lower() or (len(cmd) > 1 and cmd[0] == "sudo"):
            context = "sudo"
        
        # Check for flag signatures
        for vector, sigs in self.FLAG_SIGNATURES.items():
            for sig_binary, flags in sigs:
                if sig_binary == binary:
                    for flag in flags:
                        if flag in args_str:
                            matched_flags.append(f"{vector}:{flag}")
        
        # Score based on risk + flags + context
        base_score = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.1}.get(info["risk"], 0.5)
        if matched_flags:
            base_score = min(base_score + 0.2, 1.0)
        if context in ("sudo", "suid", "capabilities"):
            base_score = min(base_score + 0.3, 1.0)
        
        return GTFOResult(
            binary=binary,
            risk=info["risk"],
            vectors=info.get("vectors", []),
            functions=info.get("functions", []),
            description=info.get("description", ""),
            matched_flags=matched_flags,
            score=base_score,
            context=context,
        )

    def analyze_shell_command(self, command: str) -> List[GTFOResult]:
        """Analyze a shell command string for multiple GTFOBins.
        
        Parses the command line and checks each invoked binary.
        """
        results: List[GTFOResult] = []
        try:
            tokens = shlex.split(command)
        except ValueError:
            # Fallback: simple split
            tokens = command.split()
        
        if not tokens:
            return results
        
        # Check main command
        result = self.analyze_command(tokens)
        if result:
            results.append(result)
        
        # Check for subcommands (e.g., sudo bash, docker run ...)
        for i, token in enumerate(tokens):
            if i == 0:
                continue
            binary = os.path.basename(token)
            info = self.lookup(binary)
            if info:
                subcmd = tokens[i:]
                subresult = self.analyze_command(subcmd)
                if subresult and subresult.binary != results[0].binary if results else True:
                    results.append(subresult)
        
        return results

    def get_all_critical(self) -> List[str]:
        """Return all critical-risk binaries."""
        return [name for name, info in self.binaries.items() if info.get("risk") == "critical"]

    def get_all_high(self) -> List[str]:
        """Return all high-risk binaries."""
        return [name for name, info in self.binaries.items() if info.get("risk") == "high"]

    def scan_ledger_entry(self, entry: Dict[str, Any]) -> List[GTFOResult]:
        """Scan a ledger entry for GTFOBins usage.
        
        Checks annotations first, then falls back to intent analysis.
        """
        results: List[GTFOResult] = []
        data = entry.get("data", {})
        
        # First check annotations (stored by guard during execution)
        annotations = data.get("annotations", {})
        gtfo_alerts = annotations.get("gtfo_alerts", [])
        for alert in gtfo_alerts:
            binary = alert.get("binary", "")
            info = self.lookup(binary)
            if info:
                results.append(GTFOResult(
                    binary=binary,
                    risk=alert.get("risk", info.get("risk", "medium")),
                    vectors=info.get("vectors", []),
                    functions=info.get("functions", []),
                    description=info.get("description", ""),
                    matched_flags=alert.get("flags", []),
                    score=alert.get("score", 0.5),
                ))
        
        if results:
            return results
        
        # Fallback: check intent operation and domain
        intent = data.get("intent", {})
        operation = intent.get("operation", "")
        domain = intent.get("domain", "")
        target = intent.get("target", {})
        params = intent.get("params", {})
        
        if domain == "filesystem":
            synthetic_cmd = [operation]
            if target.get("path"):
                synthetic_cmd.append(target["path"])
            for k, v in params.items():
                synthetic_cmd.append(f"--{k}={v}")
            result = self.analyze_command(synthetic_cmd)
            if result:
                results.append(result)
        
        return results

    def generate_policy_rules(self) -> List[Dict[str, Any]]:
        """Generate Watchtower policy rules from GTFOBins database.
        
        Creates default-deny rules for critical and high-risk binaries.
        """
        rules: List[Dict[str, Any]] = []
        
        # Critical binaries: escalate or deny by default
        for name, info in self.binaries.items():
            risk = info.get("risk", "medium")
            if risk == "critical":
                rules.append({
                    "name": f"gtfo-critical-{name}",
                    "description": f"GTFOBins critical: {info.get('description', name)}",
                    "priority": 150,
                    "match": {"domain": "gtfo", "operation": name},
                    "condition": "True",
                    "action": "escalate",
                    "audit": "alert",
                    "risk_level": "critical",
                })
            elif risk == "high":
                rules.append({
                    "name": f"gtfo-high-{name}",
                    "description": f"GTFOBins high: {info.get('description', name)}",
                    "priority": 120,
                    "match": {"domain": "gtfo", "operation": name},
                    "condition": "True",
                    "action": "shadow",
                    "audit": "alert",
                    "risk_level": "high",
                })
        
        return rules
