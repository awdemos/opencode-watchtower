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

mkdir -p "$WATCHTOWER_DIR"
chmod 700 "$WATCHTOWER_DIR"

# Create default policy if missing
if [ ! -f "$WATCHTOWER_DIR/policy.json" ]; then
    cp "$CONF_DIR/policies/default.json" "$WATCHTOWER_DIR/policy.json"
    echo "✅ Default policy installed"
fi

# Initialize ledger
PYTHONPATH="$CONF_DIR:$PYTHONPATH" python3 -m watchtower.cli init

# Create symlinks for safe binaries
if [ -d "$CONF_DIR/bin" ]; then
    for cmd in safe-rm safe-cp safe-mv safe-mkdir safe-touch safe-chown safe-chmod safe-ln \
               ssh-ls ssh-cat ssh-ps \
               kubectl-exec-read kubectl-get-yaml kubectl-logs \
               rg-search jq-query; do
        ln -sf "$CONF_DIR/bin/watchtower-safe" "$CONF_DIR/bin/$cmd" 2>/dev/null || true
    done
    echo "✅ Safe command wrappers installed"
fi

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
echo "To use now: source $CONF_DIR/watchtower.sh"
echo "Then run: wt_status"
