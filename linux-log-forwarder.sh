#!/bin/bash
# =============================================================
# AI SOC Dashboard - Linux Log Forwarder
# Works on: Kali, Ubuntu, Debian, CentOS, RHEL, Fedora, Arch
#
# Usage (run as root):
#   sudo SOC_URL=http://WINDOWS_IP:8001/api/logs/ingest \
#        INGEST_KEY=soc-your-key-here \
#        ./linux-log-forwarder.sh
#
# Or set variables at the top of this file.
#
# Generate an ingest key in the dashboard:
#   Settings → Ingest Keys → Add Key
#   or: curl -X POST http://localhost:8001/api/auth/ingest-keys \
#            -H "Authorization: Bearer <admin-token>" \
#            -H "Content-Type: application/json" \
#            -d '{"name":"linux-forwarder-01"}'
# =============================================================

SOC_URL="${SOC_URL:-http://localhost:8001/api/logs/ingest}"
INGEST_KEY="${INGEST_KEY:-}"   # Set via env or replace here
HOSTNAME_VAL=$(hostname)
INTERVAL=5
BATCH_SIZE=50

if [ -z "$INGEST_KEY" ]; then
    echo "ERROR: INGEST_KEY is not set."
    echo "  Export it before running: export INGEST_KEY=soc-your-key-here"
    echo "  Or set it inline:          INGEST_KEY=soc-... sudo ./linux-log-forwarder.sh"
    exit 1
fi

# ── Detect distro and logging method ─────────────────────────

HAS_JOURNALD=false
HAS_LOGFILES=false

if command -v journalctl &>/dev/null; then
    HAS_JOURNALD=true
fi

# Check which log files actually exist
LOG_FILES=()
for f in \
    "/var/log/auth.log" \
    "/var/log/syslog" \
    "/var/log/kern.log" \
    "/var/log/ufw.log" \
    "/var/log/fail2ban.log" \
    "/var/log/audit/audit.log" \
    "/var/log/secure" \
    "/var/log/messages" \
    "/var/log/dpkg.log"
do
    if [ -r "$f" ]; then
        LOG_FILES+=("$f")
        HAS_LOGFILES=true
    fi
done

# ── Helpers ───────────────────────────────────────────────────

classify_severity() {
    local msg
    msg=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    if echo "$msg" | grep -qE 'critical|emergency|panic|kernel panic|out of memory'; then
        echo "critical"
    elif echo "$msg" | grep -qE 'error|fail|denied|attack|blocked|malicious|invalid|refused|reject|unauthorized|breach'; then
        echo "high"
    elif echo "$msg" | grep -qE 'warn|timeout|retry|suspicious|unusual|repeated'; then
        echo "medium"
    else
        echo "info"
    fi
}

extract_ip() {
    echo "$1" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v '^127\.' | head -1
}

extract_user() {
    local msg="$1"
    echo "$msg" | grep -oP '(?<=for user )\S+' 2>/dev/null | head -1 \
    || echo "$msg" | grep -oP '(?<=for invalid user )\S+' 2>/dev/null | head -1 \
    || echo "$msg" | grep -oP '(?<=user=)\S+' 2>/dev/null | head -1 \
    || echo ""
}

escape_json() {
    # Escape backslashes and double-quotes for JSON
    echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n\r'
}

make_log_obj() {
    local msg="$1"
    local source_type="${2:-linux}"
    local event_type="${3:-syslog}"

    local severity
    severity=$(classify_severity "$msg")
    local src_ip
    src_ip=$(extract_ip "$msg")
    local username
    username=$(extract_user "$msg")
    local safe_msg
    safe_msg=$(escape_json "${msg:0:500}")

    printf '{
        "timestamp":"%s",
        "source":"%s",
        "source_type":"%s",
        "event_type":"%s",
        "severity":"%s",
        "message":"%s",
        "raw_log":"%s",
        "source_ip":"%s",
        "username":"%s",
        "hostname":"%s",
        "tags":["linux","live","%s"]
    }' \
        "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        "$HOSTNAME_VAL" \
        "$source_type" \
        "$event_type" \
        "$severity" \
        "$safe_msg" \
        "$safe_msg" \
        "${src_ip:-}" \
        "${username:-}" \
        "$HOSTNAME_VAL" \
        "$HOSTNAME_VAL"
}

send_batch() {
    local json="$1"
    [ -z "$json" ] || [ "$json" = "[]" ] && return
    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$SOC_URL" \
        -H "Content-Type: application/json" \
        -H "X-Ingest-Key: ${INGEST_KEY}" \
        --data-binary "{\"logs\": $json}" \
        --connect-timeout 5 --max-time 10 2>/dev/null)
    if [ "$response" = "401" ]; then
        echo "  [ERROR] Invalid or missing INGEST_KEY — check your key." >&2
        exit 1
    elif [ "$response" != "200" ]; then
        echo "  [WARN] POST returned HTTP $response" >&2
    fi
}

flush_batch() {
    local -n _batch=$1
    local -n _count=$2
    local -n _total=$3

    if [ "$_batch" != "[]" ] && [ "$_count" -gt 0 ]; then
        send_batch "$_batch"
        _total=$((_total + _count))
        printf "  [%s]  Sent: %-4d  Total: %d  (source: %s)\n" \
            "$(date '+%H:%M:%S')" "$_count" "$_total" "$HOSTNAME_VAL"
    fi
    _batch="[]"
    _count=0
}

# ── journald mode — Kali / modern Debian / Ubuntu ────────────

run_journald() {
    echo "  Mode    : systemd journal (journalctl)"
    echo "  Coverage: auth, ssh, sudo, kernel, system services"
    echo ""
    echo "  Press Ctrl+C to stop"
    echo ""

    BATCH="[]"
    BATCH_COUNT=0
    TOTAL_SENT=0
    LAST_FLUSH=$SECONDS

    # Follow journal from NOW, no historical backfill
    # -o short-iso gives clean timestamped lines
    journalctl -f -n 0 -o short-iso \
        --no-pager 2>/dev/null | while IFS= read -r line; do

        [ -z "${line// }" ] && continue

        # Determine event type from the line content
        local lower
        lower=$(echo "$line" | tr '[:upper:]' '[:lower:]')
        local etype="system"
        if echo "$lower" | grep -qE 'sshd|ssh'; then           etype="sshd"
        elif echo "$lower" | grep -qE 'sudo|su\b'; then         etype="sudo"
        elif echo "$lower" | grep -qE 'kernel|kern'; then       etype="kernel"
        elif echo "$lower" | grep -qE 'systemd|service'; then   etype="systemd"
        elif echo "$lower" | grep -qE 'ufw|iptables|nftables'; then etype="firewall"
        elif echo "$lower" | grep -qE 'cron|at\b'; then         etype="cron"
        elif echo "$lower" | grep -qE 'pam|login|auth'; then    etype="auth"
        fi

        OBJ=$(make_log_obj "$line" "linux" "$etype")

        if [ "$BATCH" = "[]" ]; then
            BATCH="[$OBJ]"
        else
            BATCH="${BATCH%]},${OBJ}]"
        fi
        BATCH_COUNT=$((BATCH_COUNT + 1))

        NOW=$SECONDS
        if [ $BATCH_COUNT -ge $BATCH_SIZE ] || [ $((NOW - LAST_FLUSH)) -ge $INTERVAL ]; then
            flush_batch BATCH BATCH_COUNT TOTAL_SENT
            LAST_FLUSH=$NOW
        fi
    done
}

# ── file tail mode — older distros with /var/log files ───────

run_file_mode() {
    echo "  Mode    : file tail"
    echo "  Coverage:"
    for f in "${LOG_FILES[@]}"; do
        echo "    ✓ $f"
    done
    echo ""
    echo "  Press Ctrl+C to stop"
    echo ""

    BATCH="[]"
    BATCH_COUNT=0
    TOTAL_SENT=0
    LAST_FLUSH=$SECONDS

    tail -F -n 0 "${LOG_FILES[@]}" 2>/dev/null | while IFS= read -r line; do
        [[ "$line" =~ ^==\>.*\<==$ ]] && continue
        [ -z "${line// }" ] && continue

        OBJ=$(make_log_obj "$line" "linux" "syslog")

        if [ "$BATCH" = "[]" ]; then
            BATCH="[$OBJ]"
        else
            BATCH="${BATCH%]},${OBJ}]"
        fi
        BATCH_COUNT=$((BATCH_COUNT + 1))

        NOW=$SECONDS
        if [ $BATCH_COUNT -ge $BATCH_SIZE ] || [ $((NOW - LAST_FLUSH)) -ge $INTERVAL ]; then
            flush_batch BATCH BATCH_COUNT TOTAL_SENT
            LAST_FLUSH=$NOW
        fi
    done
}

# ── Entry point ───────────────────────────────────────────────

echo "============================================"
echo "  AI SOC Dashboard - Linux Log Forwarder"
echo "============================================"
echo "  Target  : $SOC_URL"
echo "  Host    : $HOSTNAME_VAL"
echo "  Interval: ${INTERVAL}s"
echo ""

# Connectivity check
echo -n "  Checking dashboard connection... "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$SOC_URL" \
    -H "Content-Type: application/json" \
    -H "X-Ingest-Key: ${INGEST_KEY}" \
    -d '{"logs":[]}' \
    --connect-timeout 5 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "200" ]; then
    echo "OK (HTTP 200)"
elif [ "$HTTP_CODE" = "401" ]; then
    echo "FAILED (HTTP 401 — Invalid INGEST_KEY)"
    echo ""
    echo "  Your INGEST_KEY was rejected. Check:"
    echo "    1. Key was generated in dashboard Settings → Ingest Keys"
    echo "    2. Key has not been revoked"
    exit 1
else
    echo "FAILED (HTTP $HTTP_CODE)"
    echo ""
    echo "  Cannot reach $SOC_URL"
    echo "  Check:"
    echo "    1. Backend is running: python run.py"
    echo "    2. Firewall allows port 8001"
    echo "    3. IP address is correct"
    exit 1
fi

echo ""

# Choose mode: journald > file logs
if $HAS_JOURNALD; then
    run_journald
elif $HAS_LOGFILES; then
    run_file_mode
else
    echo "ERROR: Neither journald nor log files found."
    echo "       Install systemd or rsyslog."
    exit 1
fi
