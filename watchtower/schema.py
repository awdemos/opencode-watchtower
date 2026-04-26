"""Core data models for Watchtower."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class Verdict(Enum):
    UNKNOWN = "unknown"
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"
    SHADOW = "shadow"

    def is_allowed(self) -> bool:
        return self in (Verdict.ALLOW, Verdict.SHADOW)


@dataclass
class Identity:
    principal: str
    capabilities: List[str] = field(default_factory=list)
    attestation: Dict[str, str] = field(default_factory=dict)


@dataclass
class Resource:
    path: str = ""
    host: str = ""
    namespace: str = ""
    name: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Intent:
    domain: str
    operation: str
    target: Resource = field(default_factory=Resource)
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyDecision:
    verdict: Verdict
    matched_rules: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    escalation_reasons: List[str] = field(default_factory=list)


@dataclass
class ExecutionResult:
    success: bool
    returncode: int
    stdout_hash: str
    stderr_hash: str
    duration_ms: float


@dataclass
class ActionRecord:
    seq: int
    timestamp: str
    identity: Identity
    intent: Intent
    decision: PolicyDecision
    execution: Optional[ExecutionResult] = None
    annotations: Dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    hash: str = ""

    def canonical_data(self) -> str:
        """Return canonical JSON of all fields except hash chain."""
        d: Dict[str, Any] = {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "identity": asdict(self.identity),
            "intent": {
                "domain": self.intent.domain,
                "operation": self.intent.operation,
                "target": asdict(self.intent.target),
                "params": self.intent.params,
            },
            "decision": {
                "verdict": self.decision.verdict.value,
                "matched_rules": self.decision.matched_rules,
                "risk_score": self.decision.risk_score,
                "escalation_reasons": self.decision.escalation_reasons,
            },
        }
        if self.execution:
            d["execution"] = {
                "success": self.execution.success,
                "returncode": self.execution.returncode,
                "stdout_hash": self.execution.stdout_hash,
                "stderr_hash": self.execution.stderr_hash,
                "duration_ms": self.execution.duration_ms,
            }
        return json.dumps(d, sort_keys=True, separators=(",", ":"))
