#!/usr/bin/env bash
set -e

WATCHTOWER_DIR="${WATCHTOWER_DIR:-/tmp/watchtower}"
CONF_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Watchtower Setup ==="
echo ""

mkdir -p "$WATCHTOWER_DIR"
chmod 700 "$WATCHTOWER_DIR"

for log in ssh.log k8s.log search.log fs.log; do
    touch "$WATCHTOWER_DIR/$log"
    chmod 600 "$WATCHTOWER_DIR/$log"
done

echo "✅ Audit logs created in $WATCHTOWER_DIR/"
echo ""

if [ -f "$CONF_DIR/gtfo.json" ]; then
    echo "✅ GTFOBins signatures available at $CONF_DIR/gtfo.json"
    echo "   Reference: https://gtfobins.github.io/"
    echo ""
fi

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
        echo "# Watchtower - audit logging for safe operations"
        echo "$source_line"
    } >> "$rc_file"
    echo "✅ Added to $rc_file"
fi

echo ""
echo "To use now: source $CONF_DIR/watchtower.sh"
echo "Then run: wt_status"
