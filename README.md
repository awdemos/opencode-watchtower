# Watchtower

Production-grade remote operations with audit logging. Safe commands for SSH, kubectl, and filesystem operations with centralized logging and mutation alerts.

## Install

```bash
# Clone
git clone https://github.com/awdemos/opencode-watchtower.git
cd opencode-watchtower

# Setup
./install.sh
source ~/.bashrc
```

## UTCP Integration

Add to your `~/.utcp_config.json`:

```json
{
  "imports": ["/path/to/opencode-watchtower/watchtower.json"]
}
```

Or copy the `remote-safe` template into your config.

## Shell Commands

| Command | Purpose |
|---------|---------|
| `wt_init` | Create `/tmp/watchtower/` audit logs |
| `wt_clean` | Clear all logs |
| `wt_stats` | Show tool usage statistics |
| `wt_watch` | Live dashboard (updates every 2s) |
| `wt_tail` | `tail -f` all logs |
| `wt_alert` | Alert on mutations (rm/chmod/chown) |
| `wt_export` | Export logs as JSON |
| `wt_report` | Daily command frequency report |
| `wt_recent` | Show last N entries |
| `wt_status` | Check initialization status |

## UTCP Tools (16 total)

### SSH Operations
- `ssh_ls` — Read-only directory listing
- `ssh_cat` — Read file contents
- `ssh_ps` — List processes

### Kubernetes Operations
- `kubectl_exec_read` — Safe kubectl exec (cat, ls, ps, df, top)
- `kubectl_get_yaml` — Get resource as YAML
- `kubectl_logs` — Get pod logs

### Search Operations
- `rg_search` — Ripgrep search (no mutation flags)
- `jq_query` — JSON processing

### Filesystem Operations
- `safe_rm` — Remove with protected path blocking
- `safe_mkdir` — Create directories
- `safe_touch` — Create/update files
- `safe_mv` — Move (no-clobber by default)
- `safe_cp` — Copy (no-clobber by default)
- `safe_chown` — Change ownership (restricted combos)
- `safe_chmod` — Change permissions (safe modes only)
- `safe_ln` — Create symlinks

## Audit Logs

```
/tmp/watchtower/
├── ssh.log      # SSH operations
├── k8s.log      # Kubernetes operations
├── search.log   # rg/jq operations
└── fs.log       # Filesystem operations
```

Each logged entry includes `[WATCHTOWER]` prefix for easy parsing.

## Safety Guards

### Path Protection
`safe_rm` blocks: `/`, `/home`, `/etc`, `/var`, `/usr`, `/root`, `/bin`, `/sbin`, `/lib`, `/opt`

### Mode Restrictions
- `safe_chmod`: Only `644`, `755`, `600`, `700`, `640`, `750`
- `safe_chown`: Only `root:root`, `www-data:www-data`, `ubuntu:ubuntu`, `$USER:$USER`
- `kubectl_exec_read`: Only `cat`, `ls`, `ps`, `df`, `top`

### Default Behavior
- `safe_mv`, `safe_cp`: `no-clobber` by default (won't overwrite)
- `safe_rm`: Requires explicit `mode: dir-recursive` for recursive deletion

## Example Usage

```bash
# Initialize
wt_init

# Watch live in one terminal
wt_watch

# In another terminal, use UTCP tools
# (AI agent calls safe_rm, kubectl_exec_read, etc.)

# Check stats
wt_stats

# Export for analysis
wt_export ./audit-report.json
```

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `WATCHTOWER_DIR` | `/tmp/watchtower` | Audit log directory |

## License

MIT
