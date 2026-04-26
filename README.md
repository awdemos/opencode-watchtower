# Watchtower 2.0

**Policy-driven audit and guard system for safe operations.**

Watchtower intercepts system operations (SSH, kubectl, filesystem, search), evaluates them against declarative policies, executes approved actions in restricted subprocesses, and records everything in a tamper-evident ledger.

## What's New in 2.0

- **Policy Engine**: Declarative JSON policies with a safe expression language—no more hardcoded bash rules
- **Tamper-Evident Ledger**: SHA-256 hash chain across append-only JSON Lines files
- **Structured Logging**: Every action is a queryable record, not a text line
- **Safe Command Wrappers**: Real binaries that parse arguments, evaluate policy, and execute with restrictions
- **No External Dependencies**: Core runs on Python 3.8+ standard library only
- **Cross-Platform**: Linux, macOS, and BSD support with graceful degradation

## Requirements

- Python 3.8+
- Bash or Zsh (for shell integration)

Optional (for enhanced sandboxing on Linux):
- `python-seccomp` for syscall filtering
- Linux 5.13+ for Landlock LSM support

## Install

```bash
# Clone
git clone https://github.com/awdemos/opencode-watchtower.git
cd opencode-watchtower

# Setup
./install.sh
source ~/.bashrc   # or ~/.zshrc
```

## Quick Start

```bash
# Initialize
wt_init

# Check status
wt_status

# View recent activity
wt_tail

# Verify ledger integrity
wt_verify

# Export for analysis
wt_export ./audit-report.json
```

## Shell Commands

| Command | Purpose |
|---------|---------|
| `wt_init` | Create ledger directory and default policy |
| `wt_clean` | Clear all ledger files |
| `wt_stats` | Show usage statistics by domain and verdict |
| `wt_watch` | Live dashboard (updates every 2s) |
| `wt_tail` | Show recent ledger entries |
| `wt_alert` | Alert on filesystem mutations |
| `wt_gtfo` | GTFOBins monitoring and alerting |
| `wt_export` | Export ledger as JSON |
| `wt_report` | Usage frequency report |
| `wt_recent` | Show last N entries |
| `wt_status` | Check initialization status |
| `wt_verify` | Verify ledger cryptographic integrity |

## Safe Commands

All safe commands route through the Watchtower Guard:

### Filesystem
- `safe-rm`, `safe-cp`, `safe-mv`
- `safe-mkdir`, `safe-touch`
- `safe-chown`, `safe-chmod`, `safe-ln`

### SSH
- `ssh-ls`, `ssh-cat`, `ssh-ps`

### Kubernetes
- `kubectl-exec-read`, `kubectl-get-yaml`, `kubectl-logs`

### Search
- `rg-search`, `jq-query`

## UTCP Integration

Add to your `~/.utcp_config.json`:

```json
{
  "imports": ["/path/to/opencode-watchtower/watchtower.json"]
}
```

## Policies

Policies are stored in `~/.watchtower/policy.json`. Example:

```json
{
  "version": "2.0.0",
  "policies": [
    {
      "name": "allow-tmp-read",
      "priority": 100,
      "match": {
        "domain": "filesystem",
        "operation": "read"
      },
      "condition": "target.path.startswith('/tmp/')",
      "action": "allow",
      "audit": "standard",
      "risk_level": "low"
    }
  ]
}
```

### Policy Actions

| Action | Behavior |
|--------|----------|
| `allow` | Execute and log |
| `deny` | Block and log |
| `escalate` | Queue for approval |
| `shadow` | Execute with heavy logging |

### Condition Language

A safe subset of Python expressions:

```python
target.path.startswith('/home/') and '..' not in target.path
identity.capabilities.count('fs:read') > 0
any(target.path.startswith(p) for p in ('/etc', '/usr'))
```

## Audit Ledger

Stored in `~/.watchtower/ledger-*.jsonl`:

```json
{
  "seq": 1,
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "identity": {"principal": "user:alice", "capabilities": ["fs:read"]},
    "intent": {"domain": "filesystem", "operation": "read", "target": {"path": "/tmp/test.txt"}},
    "decision": {"verdict": "allow", "matched_rules": ["allow-tmp-read"], "risk_score": 0.15}
  },
  "prev_hash": "0000...0000",
  "hash": "a3f2...b8c1"
}
```

Each entry chains to the previous via SHA-256. Tampering breaks the chain and is detected by `wt_verify`.

## GTFOBins Monitoring

Watchtower 2.0 includes the **complete GTFOBins database** (458 binaries) and actively monitors for GTFOBins invocations at runtime.

### GTFOBins Detection

Every executed command is analyzed against the full GTFOBins database:
- **Binary matching** — detects if a GTFOBin is invoked
- **Flag analysis** — identifies dangerous flag combinations (`-c`, `-exec`, `-p`, etc.)
- **Context awareness** — detects sudo/suid/capabilities contexts
- **Dynamic scoring** — critical binaries score 1.0, high-risk score 0.85+

### GTFOBins Policy Integration

GTFOBins detections automatically influence policy decisions:
- **Critical GTFOBins** → auto-escalate to require approval
- **High-risk GTFOBins** → shadow mode (execute with heavy logging)
- **All GTFOBins** → annotated in the tamper-evident ledger

### GTFOBins Commands

```bash
# List all GTFOBins in the database
wt_gtfo --list

# Scan ledger for GTFOBins usage
wt_gtfo

# Real-time GTFOBins monitoring
wt_gtfo --monitor
```

### GTFOBins Ledger Output

When a GTFOBin is detected, the ledger entry includes:

```json
{
  "annotations": {
    "gtfo_alerts": [
      {
        "binary": "bash",
        "risk": "critical",
        "score": 1.0,
        "flags": ["shell:-c"]
      }
    ]
  }
}
```

The complete database is sourced from [GTFOBins.github.io](https://gtfobins.github.io/) and parsed directly from the official repository.

## GTFOBins Risk Classification (Legacy)

The original static `gtfo.json` has been replaced with the full 458-binary database. Risk levels in policies (`critical`, `high`, `medium`, `low`) are dynamically computed from the GTFOBins functions (shell, command, file-read, file-write, suid, sudo, capabilities, etc.).

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `WATCHTOWER_DIR` | `~/.watchtower` | Ledger and policy directory |
| `WT_PYTHON` | `python3` | Python interpreter path |

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design evolution, trade-off analysis, and forward trajectory.

## License

MIT
