"""Main guard orchestrator."""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

from watchtower.schema import (
    Identity,
    Intent,
    PolicyDecision,
    Verdict,
    ExecutionResult,
    ActionRecord,
)
from watchtower.policy import PolicyEngine
from watchtower.ledger import Ledger
from watchtower.executor import Executor
from watchtower.gtfobins import GTFOEngine


class Guard:
    def __init__(self, policy_path: str, ledger_dir: str, gtfo_path: Optional[str] = None):
        self.engine = PolicyEngine.from_file(policy_path)
        self.ledger = Ledger(ledger_dir)
        self.executor = Executor()
        self.gtfo = GTFOEngine(gtfo_path)

    def check(self, identity: Identity, intent: Intent,
              cmd: Optional[List[str]] = None) -> Dict[str, Any]:
        """Check an action against policy, execute if allowed, and log."""
        # GTFOBins pre-check
        gtfo_results: List[Any] = []
        if cmd:
            result = self.gtfo.analyze_command(cmd)
            if result:
                gtfo_results = [result]
        
        rule = self.engine.evaluate(
            domain=intent.domain,
            operation=intent.operation,
            target=intent.target,
            identity=identity,
            params=intent.params,
        )

        if rule is None:
            verdict = Verdict.DENY
            matched = ["default-deny"]
            risk_score = 1.0
            escalation_reasons = ["no_matching_policy"]
        else:
            action_map = {
                "allow": Verdict.ALLOW,
                "deny": Verdict.DENY,
                "escalate": Verdict.ESCALATE,
                "shadow": Verdict.SHADOW,
            }
            verdict = action_map.get(rule.action, Verdict.UNKNOWN)
            matched = [rule.name]
            risk_score = self._compute_risk(intent, rule, gtfo_results)
            escalation_reasons = []
            if verdict == Verdict.ESCALATE:
                escalation_reasons.append("policy_matched")
            if gtfo_results:
                for g in gtfo_results:
                    if g.risk == "critical":
                        escalation_reasons.append(f"gtfo_critical:{g.binary}")
                        if verdict == Verdict.ALLOW:
                            verdict = Verdict.ESCALATE
                    elif g.risk == "high":
                        escalation_reasons.append(f"gtfo_high:{g.binary}")

        decision = PolicyDecision(
            verdict=verdict,
            matched_rules=matched,
            risk_score=risk_score,
            escalation_reasons=escalation_reasons,
        )

        execution: Optional[ExecutionResult] = None
        exec_result: Optional[Dict[str, Any]] = None
        if verdict in (Verdict.ALLOW, Verdict.SHADOW) and cmd:
            exec_result = self.executor.run(cmd)
            execution = ExecutionResult(
                success=exec_result["success"],
                returncode=exec_result["returncode"],
                stdout_hash=exec_result["stdout_hash"],
                stderr_hash=exec_result["stderr_hash"],
                duration_ms=exec_result["duration_ms"],
            )

        record = ActionRecord(
            seq=0,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            identity=identity,
            intent=intent,
            decision=decision,
            execution=execution,
            annotations={"gtfo_alerts": [
                {"binary": g.binary, "risk": g.risk, "score": g.score, "flags": g.matched_flags}
                for g in gtfo_results
            ]} if gtfo_results else {},
        )

        entry = self.ledger.append(record)

        result = {
            "verdict": verdict.value,
            "allowed": verdict.is_allowed(),
            "rule": matched[0],
            "risk_score": decision.risk_score,
            "execution": exec_result,
            "ledger_entry": entry,
            "gtfo_alerts": [
                {
                    "binary": g.binary,
                    "risk": g.risk,
                    "score": g.score,
                    "flags": g.matched_flags,
                }
                for g in gtfo_results
            ],
        }
        return result

    @staticmethod
    def _compute_risk(intent: Intent, rule: Any, gtfo_results: Optional[List[Any]] = None) -> float:
        base_risk = {
            "critical": 1.0,
            "high": 0.7,
            "medium": 0.4,
            "low": 0.1,
        }.get(getattr(rule, "risk_level", "medium"), 0.5)

        if intent.operation in ("delete", "chmod", "chown", "exec", "move"):
            base_risk += 0.15
        if intent.operation in ("copy", "write", "create_dir"):
            base_risk += 0.1

        # Factor in GTFOBins risk
        if gtfo_results:
            for g in gtfo_results:
                if g.risk == "critical":
                    base_risk = 1.0
                    break
                elif g.risk == "high":
                    base_risk = max(base_risk, 0.85)

        return min(base_risk, 1.0)
