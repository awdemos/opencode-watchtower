#!/usr/bin/env bash
# watchtower.sh - Shell interface for Watchtower 2.0
# Source this file: source /path/to/watchtower.sh

WATCHTOWER_DIR="${WATCHTOWER_DIR:-$HOME/.watchtower}"
WT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WT_RED='\033[0;31m'
WT_GREEN='\033[0;32m'
WT_YELLOW='\033[0;33m'
WT_BLUE='\033[0;34m'
WT_RESET='\033[0m'

# Python module path
WT_PYTHON="${WT_PYTHON:-python3}"
WT_MODULE="${WT_SCRIPT_DIR}"

wt_init() {
    if ! command -v "$WT_PYTHON" &>/dev/null; then
        echo -e "${WT_RED}Error: python3 not found${WT_RESET}"
        return 1
    fi
    PYTHONPATH="$WT_MODULE:$PYTHONPATH" "$WT_PYTHON" -m watchtower.cli init
}

wt_clean() {
    read -p "Delete all ledger files in $WATCHTOWER_DIR? [y/N] " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        rm -f "$WATCHTOWER_DIR"/ledger-*.jsonl
        echo -e "${WT_GREEN}✅ Ledger cleaned${WT_RESET}"
    else
        echo "Cancelled"
    fi
}

wt_stats() {
    PYTHONPATH="$WT_MODULE:$PYTHONPATH" "$WT_PYTHON" -m watchtower.cli stats
}

wt_watch() {
    if [ ! -d "$WATCHTOWER_DIR" ]; then
        echo -e "${WT_RED}Watchtower not initialized. Run: wt_init${WT_RESET}"
        return 1
    fi
    echo -e "${WT_BLUE}=== Watchtower Live Dashboard ===${WT_RESET}"
    echo "Press Ctrl+C to stop"
    while true; do
        clear
        PYTHONPATH="$WT_MODULE:$PYTHONPATH" "$WT_PYTHON" -m watchtower.cli stats
        sleep 2
    done
}

wt_tail() {
    PYTHONPATH="$WT_MODULE:$PYTHONPATH" "$WT_PYTHON" -m watchtower.cli tail -n "${1:-20}"
}

wt_alert() {
    PYTHONPATH="$WT_MODULE:$PYTHONPATH" "$WT_PYTHON" -m watchtower.cli alert
}

wt_export() {
    PYTHONPATH="$WT_MODULE:$PYTHONPATH" "$WT_PYTHON" -m watchtower.cli export -o "${1:-$WATCHTOWER_DIR/export.json}"
}

wt_report() {
    PYTHONPATH="$WT_MODULE:$PYTHONPATH" "$WT_PYTHON" -m watchtower.cli report
}

wt_recent() {
    PYTHONPATH="$WT_MODULE:$PYTHONPATH" "$WT_PYTHON" -m watchtower.cli tail -n "${1:-20}"
}

wt_status() {
    if [ -d "$WATCHTOWER_DIR" ]; then
        echo -e "${WT_GREEN}✅ Watchtower active: $WATCHTOWER_DIR${WT_RESET}"
        echo ""
        echo "Available commands:"
        echo "  wt_init      - Initialize audit directory"
        echo "  wt_clean     - Clear all logs"
        echo "  wt_stats     - Show tool usage statistics"
        echo "  wt_watch     - Live dashboard"
        echo "  wt_tail      - Tail ledger entries"
        echo "  wt_alert     - Alert on mutations"
        echo "  wt_gtfo      - GTFOBins monitoring"
        echo "  wt_export    - Export ledger as JSON"
        echo "  wt_report    - Usage report"
        echo "  wt_recent    - Show recent activity"
        echo "  wt_verify    - Verify ledger integrity"
    else
        echo -e "${WT_YELLOW}⚠️  Watchtower not initialized${WT_RESET}"
        echo "Run: wt_init"
    fi
}

wt_verify() {
    PYTHONPATH="$WT_MODULE:$PYTHONPATH" "$WT_PYTHON" -m watchtower.cli verify
}

wt_gtfo() {
    PYTHONPATH="$WT_MODULE:$PYTHONPATH" "$WT_PYTHON" -m watchtower.cli gtfo "$@"
}

# Aliases
alias watchtower-init='wt_init'
alias watchtower-clean='wt_clean'
alias watchtower-stats='wt_stats'
alias watchtower-watch='wt_watch'
alias watchtower-tail='wt_tail'
alias watchtower-alert='wt_alert'
alias watchtower-export='wt_export'
alias watchtower-report='wt_report'
alias watchtower-recent='wt_recent'
alias watchtower-status='wt_status'
alias watchtower-verify='wt_verify'
alias watchtower-gtfo='wt_gtfo'

# PATH setup for safe binaries
if [ -d "$WT_SCRIPT_DIR/bin" ]; then
    export PATH="$WT_SCRIPT_DIR/bin:$PATH"
fi
