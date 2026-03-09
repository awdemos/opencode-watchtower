#!/usr/bin/env bash
# watchtower.sh - Audit logging and monitoring for safe operations
# Source this file: source /path/to/watchtower.sh

WATCHTOWER_DIR="${WATCHTOWER_DIR:-/tmp/watchtower}"
WATCHTOWER_LOGS=("ssh.log" "k8s.log" "search.log" "fs.log")

WT_RED='\033[0;31m'
WT_GREEN='\033[0;32m'
WT_YELLOW='\033[0;33m'
WT_BLUE='\033[0;34m'
WT_RESET='\033[0m'

wt_init() {
    mkdir -p "$WATCHTOWER_DIR"
    for log in "${WATCHTOWER_LOGS[@]}"; do
        touch "$WATCHTOWER_DIR/$log"
        chmod 644 "$WATCHTOWER_DIR/$log"
    done
    echo -e "${WT_GREEN}✅ Watchtower initialized in $WATCHTOWER_DIR/${WT_RESET}"
    echo "   Logs: ${WATCHTOWER_LOGS[*]}"
}

wt_clean() {
    for log in "${WATCHTOWER_LOGS[@]}"; do
        > "$WATCHTOWER_DIR/$log"
    done
    echo -e "${WT_GREEN}✅ Watchtower logs cleaned${WT_RESET}"
}

wt_stats() {
    echo -e "${WT_BLUE}=== Watchtower Statistics ===${WT_RESET}"
    if [ ! -d "$WATCHTOWER_DIR" ]; then
        echo -e "${WT_RED}Watchtower not initialized. Run: wt_init${WT_RESET}"
        return 1
    fi
    echo ""
    echo -e "${WT_YELLOW}By tool:${WT_RESET}"
    grep -h '\[WATCHTOWER\]' "$WATCHTOWER_DIR"/*.log 2>/dev/null | \
        sed 's/.*\[WATCHTOWER\] //' | cut -d' ' -f1 | sort | uniq -c | sort -rn
    echo ""
    echo -e "${WT_YELLOW}By log file:${WT_RESET}"
    for log in "${WATCHTOWER_LOGS[@]}"; do
        count=$(wc -l < "$WATCHTOWER_DIR/$log" 2>/dev/null || echo 0)
        printf "  %-15s %s entries\n" "$log" "$count"
    done
}

wt_watch() {
    if [ ! -d "$WATCHTOWER_DIR" ]; then
        echo -e "${WT_RED}Watchtower not initialized. Run: wt_init${WT_RESET}"
        return 1
    fi
    watch -n 2 "tail -n 25 $WATCHTOWER_DIR/*.log 2>/dev/null | tail -n 25"
}

wt_tail() {
    if [ ! -d "$WATCHTOWER_DIR" ]; then
        echo -e "${WT_RED}Watchtower not initialized. Run: wt_init${WT_RESET}"
        return 1
    fi
    tail -f "$WATCHTOWER_DIR"/*.log
}

wt_alert() {
    if [ ! -d "$WATCHTOWER_DIR" ]; then
        echo -e "${WT_RED}Watchtower not initialized. Run: wt_init${WT_RESET}"
        return 1
    fi
    echo -e "${WT_YELLOW}🚨 Watching for mutations (rm, chmod, chown)...${WT_RESET}"
    tail -f "$WATCHTOWER_DIR"/*.log 2>/dev/null | \
        grep --line-buffered -E "(rm|chmod|chown)" | \
        while read -r line; do
            echo -e "${WT_RED}🚨 MUTATION: $line${WT_RESET}"
        done
}

wt_export() {
    local output="${1:-/var/log/watchtower-export.json}"
    if [ ! -d "$WATCHTOWER_DIR" ]; then
        echo -e "${WT_RED}Watchtower not initialized. Run: wt_init${WT_RESET}"
        return 1
    fi
    echo "Exporting logs to $output..."
    local first=true
    echo '{"events": [' > "$output"
    for log in "${WATCHTOWER_LOGS[@]}"; do
        while IFS= read -r line; do
            if [ -n "$line" ]; then
                [ "$first" = false ] && echo ',' >> "$output"
                first=false
                escaped=$(echo "$line" | sed 's/"/\\"/g')
                echo "{\"log\": \"$log\", \"entry\": \"$escaped\"}" >> "$output"
            fi
        done < "$WATCHTOWER_DIR/$log"
    done
    echo ']}' >> "$output"
    echo -e "${WT_GREEN}✅ Exported to $output${WT_RESET}"
}

wt_report() {
    echo -e "${WT_BLUE}=== Watchtower Daily Report ===${WT_RESET}"
    if [ ! -d "$WATCHTOWER_DIR" ]; then
        echo -e "${WT_RED}Watchtower not initialized. Run: wt_init${WT_RESET}"
        return 1
    fi
    echo ""
    echo -e "${WT_YELLOW}Command frequency (last 24h):${WT_RESET}"
    find "$WATCHTOWER_DIR" -name "*.log" -mtime -1 -exec cat {} \; 2>/dev/null | \
        sed -n 's/.*\[WATCHTOWER\] \([^ ]*\).*/\1/p' | sort | uniq -c | sort -rn | head -20
    echo ""
    echo -e "${WT_YELLOW}Total entries by log:${WT_RESET}"
    for log in "${WATCHTOWER_LOGS[@]}"; do
        count=$(wc -l < "$WATCHTOWER_DIR/$log" 2>/dev/null || echo 0)
        printf "  %-15s %s entries\n" "$log" "$count"
    done
}

wt_recent() {
    local n="${1:-20}"
    echo -e "${WT_BLUE}=== Last $n entries ===${WT_RESET}"
    if [ ! -d "$WATCHTOWER_DIR" ]; then
        echo -e "${WT_RED}Watchtower not initialized. Run: wt_init${WT_RESET}"
        return 1
    fi
    tail -n "$n" "$WATCHTOWER_DIR"/*.log 2>/dev/null
}

wt_status() {
    if [ -d "$WATCHTOWER_DIR" ]; then
        echo -e "${WT_GREEN}✅ Watchtower active: $WATCHTOWER_DIR${WT_RESET}"
        echo ""
        echo "Available commands:"
        echo "  wt_init      - Initialize audit directory"
        echo "  wt_clean     - Clear all logs"
        echo "  wt_stats     - Show tool usage statistics"
        echo "  wt_watch     - Live dashboard (updates every 2s)"
        echo "  wt_tail      - Tail all logs"
        echo "  wt_alert     - Alert on mutations"
        echo "  wt_export    - Export logs as JSON"
        echo "  wt_report    - Daily report"
        echo "  wt_recent    - Show recent activity"
    else
        echo -e "${WT_YELLOW}⚠️  Watchtower not initialized${WT_RESET}"
        echo "Run: wt_init"
    fi
}

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
