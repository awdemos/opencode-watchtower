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
echo "To use now: source $CONF_DIR/watchtower.sh"
echo "Or use commands directly: watchtower init, safe-rm, ssh-ls, etc."
echo "Then run: watchtower status"
