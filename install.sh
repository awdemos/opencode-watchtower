#!/usr/bin/env bash
set -e

WATCHTOWER_DIR="${WATCHTOWER_DIR:-$HOME/.watchtower}"
CONF_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Watchtower 2.0 Setup ==="
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "❌ python3 is required but not installed"
    exit 1
fi

# Detect pip install capability (PEP 668 externally-managed environments)
PIP_INSTALL="python3 -m pip install -e ."
if python3 -m pip install --dry-run -e . 2>&1 | grep -q "externally-managed-environment"; then
    PIP_INSTALL="python3 -m pip install -e . --break-system-packages"
    echo "Note: Using --break-system-packages for system Python"
fi

echo "Installing watchtower package..."
cd "$CONF_DIR"
$PIP_INSTALL --quiet

echo "✅ Package installed"
echo "   Commands available: safe-rm, safe-cp, ssh-ls, kubectl-logs, watchtower, etc."
echo ""

# Resolve absolute paths to all safe commands for opencode integration
SAFE_RM="$(command -v safe-rm || true)"
SAFE_CP="$(command -v safe-cp || true)"
SAFE_MV="$(command -v safe-mv || true)"
SAFE_MKDIR="$(command -v safe-mkdir || true)"
SAFE_TOUCH="$(command -v safe-touch || true)"
SAFE_CHOWN="$(command -v safe-chown || true)"
SAFE_CHMOD="$(command -v safe-chmod || true)"
SAFE_LN="$(command -v safe-ln || true)"
SSH_LS="$(command -v ssh-ls || true)"
SSH_CAT="$(command -v ssh-cat || true)"
SSH_PS="$(command -v ssh-ps || true)"
KUBECTL_EXEC="$(command -v kubectl-exec-read || true)"
KUBECTL_GET="$(command -v kubectl-get-yaml || true)"
KUBECTL_LOGS="$(command -v kubectl-logs || true)"
RG_SEARCH="$(command -v rg-search || true)"
JQ_QUERY="$(command -v jq-query || true)"

# Generate opencode-ready config with absolute paths
INSTALLED_CONFIG="$CONF_DIR/watchtower.installed.json"
python3 << EOF
import json

def quote(s):
    return s.replace("'", "'\\''")

with open("$CONF_DIR/watchtower.json") as f:
    config = json.load(f)

tools = config["manual_call_templates"][0]["tools"]
for tool in tools:
    name = tool["name"]
    cmd = None
    if name == "safe_rm": cmd = "$SAFE_RM"
    elif name == "safe_cp": cmd = "$SAFE_CP"
    elif name == "safe_mv": cmd = "$SAFE_MV"
    elif name == "safe_mkdir": cmd = "$SAFE_MKDIR"
    elif name == "safe_touch": cmd = "$SAFE_TOUCH"
    elif name == "safe_chown": cmd = "$SAFE_CHOWN"
    elif name == "safe_chmod": cmd = "$SAFE_CHMOD"
    elif name == "safe_ln": cmd = "$SAFE_LN"
    elif name == "ssh_ls": cmd = "$SSH_LS"
    elif name == "ssh_cat": cmd = "$SSH_CAT"
    elif name == "ssh_ps": cmd = "$SSH_PS"
    elif name == "kubectl_exec_read": cmd = "$KUBECTL_EXEC"
    elif name == "kubectl_get_yaml": cmd = "$KUBECTL_GET"
    elif name == "kubectl_logs": cmd = "$KUBECTL_LOGS"
    elif name == "rg_search": cmd = "$RG_SEARCH"
    elif name == "jq_query": cmd = "$JQ_QUERY"
    
    if cmd:
        # Keep bash as the command but replace tool names with absolute paths
        old_args = tool["call_template"]["args"]
        if len(old_args) == 2 and old_args[0] == "-c":
            inner = old_args[1]
            # Replace the command name at the start of the bash string with absolute path
            import re
            tool_name = name.replace("_", "-")
            # Match tool name at start or after a semicolon/&&/||
            pattern = r'(^|[;|&]\s*)' + re.escape(tool_name) + r'\b'
            replacement = r'\1' + cmd
            new_inner = re.sub(pattern, replacement, inner)
            tool["call_template"]["args"] = ["-c", new_inner]
            tool["call_template"]["command"] = "bash"

with open("$INSTALLED_CONFIG", "w") as f:
    json.dump(config, f, indent=2)
EOF

echo "✅ Generated opencode config: $INSTALLED_CONFIG"
echo ""

# Create ledger directory and default policy
mkdir -p "$WATCHTOWER_DIR"
chmod 700 "$WATCHTOWER_DIR"

if [ ! -f "$WATCHTOWER_DIR/policy.json" ]; then
    cp "$CONF_DIR/policies/default.json" "$WATCHTOWER_DIR/policy.json"
    echo "✅ Default policy installed"
fi

# Initialize ledger
watchtower init

# Shell integration
if [ -n "$BASH_VERSION" ]; then
    rc_file="$HOME/.bashrc"
elif [ -n "$ZSH_VERSION" ]; then
    rc_file="$HOME/.zshrc"
else
    rc_file="$HOME/.profile"
fi

source_line="source \"$CONF_DIR/watchtower.sh\""

if grep -qF "$source_line" "$rc_file" 2>/dev/null; then
    echo "✅ Already sourced in $rc_file"
else
    {
        echo ""
        echo "# Watchtower 2.0 - policy-driven audit system"
        echo "$source_line"
    } >> "$rc_file"
    echo "✅ Added to $rc_file"
fi

echo ""
echo "=== Opencode Integration ==="
echo "Add this to your ~/.utcp_config.json:"
echo ""
echo '  {'
echo '    "imports": ["'$INSTALLED_CONFIG'"],'
echo '    "mcpServers": {}'
echo '  }'
echo ""
echo "To use now: source $CONF_DIR/watchtower.sh"
echo "Or use commands directly: watchtower init, safe-rm, ssh-ls, etc."
echo "Then run: watchtower status"
