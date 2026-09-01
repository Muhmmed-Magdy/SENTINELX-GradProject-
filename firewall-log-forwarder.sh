#!/bin/bash
# =============================================================
# AI SOC Dashboard - Firewall Log Forwarder
#
# Usage:
#   chmod +x firewall-log-forwarder.sh
#   INGEST_KEY=soc-your-key-here sudo ./firewall-log-forwarder.sh
#
# Generate a key: Settings → Ingest Keys → Add Key in the dashboard.
# =============================================================

SOC_URL="${SOC_URL:-http://localhost:8001/api/logs/ingest}"
INGEST_KEY="${INGEST_KEY:-}"
HOSTNAME_VAL=$(hostname)
SYSLOG_MODE=false
SYSLOG_PORT=514

if [ -z "$INGEST_KEY" ]; then
    echo "ERROR: INGEST_KEY is not set."
    echo "  Export it: export INGEST_KEY=soc-your-key-here"
    exit 1
fi

# Parse args
for arg in "$@"; do
    case $arg in
        --syslog) SYSLOG_MODE=true ;;
        --url=*)  SOC_URL="${arg#*=}" ;;
    esac
done

# Firewall log files to monitor
FW_LOG_FILES=(
    "/var/log/ufw.log"            # Ubuntu UFW
    "/var/log/firewall.log"       # Generic
    "/var/log/iptables.log"       # iptables
    "/var/log/pf.log"             # BSD pf (pfSense base)
    "/var/log/filter.log"         # pfSense/OPNsense
    "/var/log/cisco-asa.log"      # Cisco ASA (if syslog-ng writes here)
)

# ── Parse a single firewall log line into structured fields ──

parse_firewall_line() {
    local line="$1"
    local lower
    lower=$(echo "$line" | tr '[:upper:]' '[:lower:]')

    # Action
    local action="allow"
    if echo "$lower" | grep -qE '\bblock\b|\bdeny\b|\bdrop\b|\brejected?\b|\brefused\b'; then
        action="deny"
    elif echo "$lower" | grep -qE '\ballow\b|\baccept\b|\bpass\b|\bpermit\b'; then
        action="allow"
    fi

    # Severity
    local severity="info"
    if [ "$action" = "deny" ]; then
        severity="medium"
        # Elevate for sensitive destination ports
        if echo "$line" | grep -qE ':22\b|:23\b|:3389\b|:445\b|:1433\b|:3306\b|dport=22 |dport=3389 '; then
            severity="high"
        fi
    fi

    # IPs
    local src_ip
    src_ip=$(echo "$line" | grep -oP '(?<=SRC=|src=|source=|from )\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | head -1)
    [ -z "$src_ip" ] && src_ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)

    local dst_ip
    dst_ip=$(echo "$line" | grep -oP '(?<=DST=|dst=|dest=|to )\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | head -1)
    [ -z "$dst_ip" ] && dst_ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tail -1)

    # Ports
    local dst_port
    dst_port=$(echo "$line" | grep -oP '(?<=DPT=|dport=|dst_port=|:)\d+' | head -1)

    local proto
    proto=$(echo "$line" | grep -oP '\b(TCP|UDP|ICMP|tcp|udp|icmp)\b' | head -1 | tr '[:upper:]' '[:lower:]')

    echo "$action|$severity|$src_ip|$dst_ip|$dst_port|$proto"
}

send_batch() {
    local json="$1"
    [ -z "$json" ] || [ "$json" = "[]" ] && return
    local rc
    rc=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$SOC_URL" \
        -H "Content-Type: application/json" \
        -H "X-Ingest-Key: ${INGEST_KEY}" \
        --data-binary "{\"logs\": $json}" \
        --connect-timeout 5 --max-time 10 2>/dev/null)
    if [ "$rc" = "401" ]; then
        echo "  [ERROR] INGEST_KEY rejected — exiting." >&2; exit 1
    fi
}

process_line() {
    local line="$1"
    [ -z "${line// }" ] && return

    local parsed
    parsed=$(parse_firewall_line "$line")
    IFS='|' read -r action severity src_ip dst_ip dst_port proto <<< "$parsed"

    local msg
    msg=$(echo "$line" | cut -c1-500 | sed 's/"/\\"/g')

    local obj
    obj=$(printf '{
        "timestamp": "%s",
        "source": "%s",
        "source_type": "firewall",
        "event_type": "network",
        "severity": "%s",
        "message": "%s",
        "raw_log": "%s",
        "source_ip": "%s",
        "destination_ip": "%s",
        "destination_port": %s,
        "hostname": "%s",
        "tags": ["firewall", "%s", "%s"]
    }' \
        "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        "$HOSTNAME_VAL" \
        "$severity" \
        "$msg" "$msg" \
        "${src_ip:-}" \
        "${dst_ip:-}" \
        "${dst_port:-0}" \
        "$HOSTNAME_VAL" \
        "$action" \
        "${proto:-unknown}")

    echo "$obj"
}

# ── Syslog listener mode (for network firewalls) ─────────────
run_syslog_mode() {
    echo "  Mode: UDP syslog listener on port $SYSLOG_PORT"
    echo "  Configure your firewall to send syslog to: $(hostname -I | awk '{print $1}'):$SYSLOG_PORT"
    echo ""

    # Requires netcat
    if ! command -v nc &>/dev/null; then
        echo "ERROR: netcat (nc) is required for syslog mode. Install with: apt install netcat"
        exit 1
    fi

    BATCH="[]"; BATCH_COUNT=0; TOTAL_SENT=0; LAST_FLUSH=$SECONDS

    nc -lu "$SYSLOG_PORT" 2>/dev/null | while IFS= read -r line; do
        OBJ=$(process_line "$line")
        [ -z "$OBJ" ] && continue

        if [ "$BATCH" = "[]" ]; then BATCH="[$OBJ]"
        else BATCH="${BATCH%]},${OBJ}]"; fi
        BATCH_COUNT=$((BATCH_COUNT + 1))

        NOW=$SECONDS
        if [ $BATCH_COUNT -ge 50 ] || [ $((NOW - LAST_FLUSH)) -ge 5 ]; then
            send_batch "$BATCH"
            TOTAL_SENT=$((TOTAL_SENT + BATCH_COUNT))
            printf "  [%s]  Sent: %-4d  Total: %d\n" "$(date '+%H:%M:%S')" "$BATCH_COUNT" "$TOTAL_SENT"
            BATCH="[]"; BATCH_COUNT=0; LAST_FLUSH=$NOW
        fi
    done
}

# ── File tail mode (for local firewall logs) ─────────────────
run_file_mode() {
    TAIL_ARGS=()
    echo "  Monitoring:"
    for f in "${FW_LOG_FILES[@]}"; do
        if [ -r "$f" ]; then
            TAIL_ARGS+=("$f")
            echo "    ✓ $f"
        else
            echo "    ✗ $f  (not found)"
        fi
    done
    echo ""

    if [ ${#TAIL_ARGS[@]} -eq 0 ]; then
        echo "No readable firewall log files found."
        echo "Try --syslog mode for network firewalls, or check log paths."
        exit 1
    fi

    BATCH="[]"; BATCH_COUNT=0; TOTAL_SENT=0; LAST_FLUSH=$SECONDS

    tail -F -n 0 "${TAIL_ARGS[@]}" 2>/dev/null | while IFS= read -r line; do
        [[ "$line" =~ ^==\>.*\<==$ ]] && continue

        OBJ=$(process_line "$line")
        [ -z "$OBJ" ] && continue

        if [ "$BATCH" = "[]" ]; then BATCH="[$OBJ]"
        else BATCH="${BATCH%]},${OBJ}]"; fi
        BATCH_COUNT=$((BATCH_COUNT + 1))

        NOW=$SECONDS
        if [ $BATCH_COUNT -ge 50 ] || [ $((NOW - LAST_FLUSH)) -ge 5 ]; then
            send_batch "$BATCH"
            TOTAL_SENT=$((TOTAL_SENT + BATCH_COUNT))
            printf "  [%s]  Sent: %-4d  Total: %d\n" "$(date '+%H:%M:%S')" "$BATCH_COUNT" "$TOTAL_SENT"
            BATCH="[]"; BATCH_COUNT=0; LAST_FLUSH=$NOW
        fi
    done
}

# ── Entry point ───────────────────────────────────────────────

echo "============================================"
echo "  AI SOC Dashboard - Firewall Log Forwarder"
echo "============================================"
echo "  Target : $SOC_URL"
echo "  Host   : $HOSTNAME_VAL"
echo ""

if $SYSLOG_MODE; then
    run_syslog_mode
else
    run_file_mode
fi
