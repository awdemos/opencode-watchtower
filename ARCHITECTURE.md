# Watchtower 2.0 Architecture

## Executive Summary

Watchtower 2.0 is a forced evolution from a bash-script audit wrapper into a **policy-driven, tamper-evident action auditing system**. The center of gravity shifted from "logging what bash did" to "evaluating every system interaction against declarative policy and recording the result in a cryptographically verifiable ledger."

---

## Phase 0: System Reconstruction

### What the Original System Was Trying to Be

The original Watchtower aimed to be a **trust boundary** between AI agents (via UTCP) and operating systems. It provided:
- 16 "safe" tool templates for SSH, kubectl, filesystem, and search operations
- Text-based audit logs in `/tmp/watchtower/`
- A static GTFOBins risk reference
- Bash convenience commands for log inspection

### What It Actually Was

A thin veneer of safety around standard Unix commands:
- Safety rules embedded as bash strings inside JSON templates
- Plain text logs with no integrity guarantees
- Hardcoded path blocks trivially bypassable
- No real enforcement—just logging
- Single-host, single-user, no extensibility

---

## Phase 1: Deep Structural Diagnosis

### Root-Level Limitations

1. **Injection Vulnerability in the Safety Layer**
   The `watchtower.json` command templates used inconsistent shell quoting. Some fields used double quotes (vulnerable to injection), others single quotes (break on legitimate paths containing apostrophes). The safety system was itself unsafe.

2. **Log Integrity Failure**
   Logs stored in `/tmp/watchtower/`—world-writable on many systems. No append-only attributes, no cryptographic integrity, no structured format. An attacker with account access could modify or delete the "audit trail."

3. **Static Policy, Dynamic World**
   Safety rules were hardcoded bash case statements inside JSON strings. Adding a new policy required editing command templates. No policy language, no composition, no runtime configurability.

4. **Categorical Confusion**
   The four log categories (ssh, k8s, search, fs) were arbitrary. SSH and kubectl both involve remote execution but were split. Search tools (rg, jq) share no security domain.

5. **No Execution Semantics**
   The system generated bash commands for UTCP to run. It had no sandbox, no capability dropping, no resource limits, no timeouts. Safety was purely advisory.

6. **GTFOBins as Security Theater**
   The `gtfo.json` was a static snapshot of ~80 binaries, not consulted at runtime, not used to block or analyze commands. Already stale and disconnected from actual enforcement.

7. **No Contextual Awareness**
   Risk was assigned per-tool, not per invocation. `ssh_cat /etc/passwd` and `ssh_cat ~/notes` carried identical risk scores despite vastly different security implications.

8. **Bash as Implementation Language**
   No unit tests, global variables, hand-rolled JSON escaping in `wt_export`, nearly impossible to reason about correctness under edge cases.

9. **Zero Extensibility**
   Adding a tool required editing JSON templates, shell scripts, and maintaining consistency with gtfo.json manually.

---

## Phase 2: First-Principles Reframing

### Core Invariants

1. **Non-repudiation**: Every action is logged with cryptographic integrity
2. **Least privilege**: Operations run with minimal necessary capabilities
3. **Defense in depth**: Multiple overlapping controls
4. **Composability**: New capabilities added without modifying existing code
5. **Observability**: All state transitions are visible, queryable, analyzable
6. **Fail-closed**: Unknown operations denied by default

### Clean Abstractions

- **Capability**: A bounded operation ("read file in /home/user/")
- **Policy**: Declarative rule granting/denying capabilities based on context
- **Action**: Concrete invocation with full provenance (who, what, when, where)
- **Guard**: Enforcement mechanism validating actions against policy
- **Ledger**: Append-only, structured, integrity-protected log

### Minimal Interfaces

```
guard.can(identity, action, context) → verdict
ledger.append(record) → signed_record
executor.run(capability, params) → result
policy.load(ruleset) → policy_engine
```

---

## Phase 3: Radical Redesign

### Initial Architecture (v1)

A full microservices architecture was proposed:
- gRPC API Gateway with mTLS
- CEL/Rego Policy Engine
- gVisor sandbox layer
- Merkle-tree ledger with async replication
- WebSocket dashboard
- ML-based anomaly detection

**Justification**: This strictly improves on the original by providing real enforcement, cryptographic integrity, and horizontal scalability.

---

## Phase 4: Adversarial Self-Critique

### Critique of v1

1. **Overengineered**: A 200-line bash script replaced by a distributed system requiring Kubernetes, etcd, and a CA.
2. **Operational Burden**: Deployment complexity dwarfs the original by orders of magnitude.
3. **Latency**: Every filesystem operation traverses network hops and policy evaluation—unacceptable for AI agents doing hundreds of file ops.
4. **Adoption Barrier**: Requires clients to speak a new protocol. Breaks UTCP compatibility.

### Alternative Designs Considered

**Alternative A: In-Process Library**
- Language-agnostic Rust core with bindings
- Lower latency, simpler deployment
- Loses centralization; requires per-app integration

**Alternative B: eBPF Kernel Monitor**
- Monitor syscalls at kernel level
- Transparent, impossible to bypass
- Requires root, Linux-only, reactive not preventive

**Verdict**: Both are valid but solve different problems. The core need is a **deployable, low-latency, policy-driven guard** that can evolve toward these alternatives.

---

## Phase 5: Iterative Refinement

### Second-Generation Architecture (v2)

**Key simplifications**:
1. **Local-first, network-optional**: Core runs on the local machine
2. **Python standard library only**: No external dependencies for core functionality
3. **Layered architecture** with clear module boundaries:
   - `guard`: Policy evaluation
   - `ledger`: Tamper-evident logging
   - `executor`: Restricted subprocess execution
   - `cli`: Human and automation interface
4. **Policy as data**: JSON configuration with JSON Schema validation
5. **Graceful degradation**: Optional seccomp/landlock on Linux; works on macOS without them
6. **Backward compatibility**: Existing UTCP configs shimmed to new binaries

### Trade-offs Resolved

| Dimension | Choice | Rationale |
|-----------|--------|-----------|
| Performance vs Safety | Local Python, not network RPC | Microsecond-to-millisecond latency acceptable |
| Flexibility vs Safety | Safe AST evaluator, not full Python | Prevents policy injection while remaining expressive |
| Complexity vs Power | Optional seccomp/landlock | Degrades gracefully across platforms |
| Compatibility vs Progress | Keep bash shims | Existing users not broken |

---

## Phase 6: Convergence and Synthesis

### Final Architecture

```
┌──────────────────────────────────────────┐
│         Shell Interface Layer            │
│  (wt_* commands, safe_* binaries)        │
│  - Backward compatible with UTCP         │
│  - Thin wrappers around Core API         │
└──────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────┐
│        Watchtower Core (Python)          │
│  ┌──────────┐ ┌──────────┐ ┌────────┐   │
│  │  Guard   │ │  Ledger  │ │ Policy │   │
│  │  Module  │ │  Module  │ │ Engine │   │
│  └──────────┘ └──────────┘ └────────┘   │
│                                          │
│  - Loads policy from JSON                │
│  - Evaluates requests against rules      │
│  - Maintains append-only hash chain      │
│  - Provides query interface              │
└──────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────┐
│         Execution Layer                  │
│  - Subprocess with timeout               │
│  - Optional seccomp-bpf (Linux)          │
│  - Optional Landlock LSM (Linux 5.13+)   │
│  - Output capture and hashing            │
└──────────────────────────────────────────┘
```

### Why This Is Superior

**vs. Original System**:
- Real enforcement before execution, not just logging after
- Tamper-evident logs (SHA-256 hash chain)
- Structured, queryable records (JSON Lines)
- Runtime-configurable policies
- No shell injection vulnerabilities
- Cross-platform (Linux, macOS, BSD)

**vs. Initial Redesign (v1)**:
- Deployable in seconds, not hours
- No network dependencies
- Low latency (local evaluation)
- Backward compatible
- Testable with standard Python tools

### Center of Gravity

> **"Every system interaction is a policy-evaluated, integrity-logged action."**

This gives leverage because:
- Security writes policies without touching code
- Compliance queries the ledger with standard tools (`jq`, `sqlite`)
- Operators detect anomalies via structured streams
- Developers add capabilities by defining new policy domains
- The system compounds: more data → better detection → better policies

---

## Phase 7: Forward Trajectory

### What Becomes Easier

1. **Policy GitOps**: Policies in Git, reviewed via PR, auto-deployed to hosts
2. **Federated Audit**: Hosts stream ledger fingerprints to central collector
3. **Anomaly Detection**: Time-series analysis on structured logs
4. **Compliance Automation**: SOC2/ISO27001 evidence via `jq` queries
5. **AI Agent Improvement**: Agents learn from denied actions

### New Capabilities That Unlock

1. **Shadow Mode**: New policies run "log only" before enforcement
2. **Policy Testing**: Unit tests for policies using synthetic requests
3. **Capability Delegation**: Temporary, scoped grants to agents
4. **Multi-Factor Authorization**: Sensitive ops require additional approval
5. **Cross-System Correlation**: Linked actions across hosts

### Next Scaling Limits

1. **Ledger size**: High-frequency ops generate large logs
   - *Mitigation*: Hot/warm/cold tiering, compaction summaries
2. **Policy complexity**: Many rules slow evaluation
   - *Mitigation*: Indexed matching by domain/operation, policy compilation
3. **Distributed consensus**: Multiple policy sources need consistency
   - *Mitigation*: Raft-based policy distribution (future)
4. **Cryptographic overhead**: Per-entry hashing adds CPU
   - *Mitigation*: Batch hashing, hardware SHA extensions

---

## Module Reference

| Module | Responsibility | Key Class |
|--------|---------------|-----------|
| `schema.py` | Data models | `ActionRecord`, `PolicyDecision` |
| `policy.py` | Rule evaluation | `PolicyEngine`, `SafeEvaluator` |
| `ledger.py` | Tamper-evident log | `Ledger` |
| `executor.py` | Restricted execution | `Executor` |
| `guard.py` | Orchestration | `Guard` |
| `cli.py` | User interface | `main()` |

---

## Design Decisions

### Why Python?
- Universally available (pre-installed on macOS, most Linux distros)
- Readable and maintainable
- Strong `ast` module for safe expression evaluation
- Easier to audit than bash

### Why SHA-256 over BLAKE3?
- SHA-256 is in Python stdlib; BLAKE3 requires external package
- Integrity protection, not performance, is the primary concern
- Can upgrade to BLAKE3 via optional dependency later

### Why SafeEvaluator instead of CEL/Rego?
- Zero external dependencies
- Python operators familiar to ops teams
- `ast` module provides strong isolation guarantees
- Can migrate to OPA/Rego later via adapter

### Why JSON Lines over SQLite?
- Append-only semantics are natural with flat files
- Easy to stream, replicate, and inspect with standard tools
- No file locking complexity for concurrent writers
- Rotation is trivial
