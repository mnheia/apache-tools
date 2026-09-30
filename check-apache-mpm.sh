#!/usr/bin/env bash
set -uo pipefail

WARN_PCT="${WARN_PCT:-80}"
CRIT_PCT="${CRIT_PCT:-90}"
LOG_SINCE="${LOG_SINCE:-2 hours ago}"
STATUS_URL="${STATUS_URL:-http://127.0.0.1/server-status?auto}"
TAIL_LINES="${TAIL_LINES:-3000}"

HOST="$(hostname -f 2>/dev/null || hostname)"

if command -v apache2ctl >/dev/null 2>&1; then
    APCTL="apache2ctl"
    SERVICE="apache2"
elif command -v apachectl >/dev/null 2>&1; then
    APCTL="apachectl"
    SERVICE="apache2"
elif command -v httpd >/dev/null 2>&1; then
    APCTL="httpd"
    SERVICE="httpd"
else
    echo "CRITICAL [$HOST] Apache command not found"
    exit 2
fi

issues=()
warnings=()
info=()

# Check service status
if ! systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
    issues+=("Apache service is not active")
fi

# Check Apache config syntax
if ! SYNTAX_OUT="$($APCTL -t 2>&1)"; then
    issues+=("Apache config syntax check failed: $SYNTAX_OUT")
fi

# Read runtime config
RUNCFG="$($APCTL -t -D DUMP_RUN_CFG 2>&1 || true)"

MPM="$(awk -F: '/Server MPM/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' <<< "$RUNCFG")"
MAX_WORKERS="$(awk -F: '/MaxRequestWorkers/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' <<< "$RUNCFG")"
SERVER_LIMIT="$(awk -F: '/ServerLimit/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' <<< "$RUNCFG")"
THREADS_PER_CHILD="$(awk -F: '/ThreadsPerChild/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' <<< "$RUNCFG")"
MAX_CONN_PER_CHILD="$(awk -F: '/MaxConnectionsPerChild/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' <<< "$RUNCFG")"

[ -n "$MPM" ] && info+=("MPM=$MPM")
[ -n "$MAX_WORKERS" ] && info+=("MaxRequestWorkers=$MAX_WORKERS")
[ -n "$SERVER_LIMIT" ] && info+=("ServerLimit=$SERVER_LIMIT")
[ -n "$THREADS_PER_CHILD" ] && info+=("ThreadsPerChild=$THREADS_PER_CHILD")
[ -n "$MAX_CONN_PER_CHILD" ] && info+=("MaxConnectionsPerChild=$MAX_CONN_PER_CHILD")

# Check if MaxRequestWorkers exceeds theoretical slot capacity
if [[ "$SERVER_LIMIT" =~ ^[0-9]+$ ]] && [[ "$THREADS_PER_CHILD" =~ ^[0-9]+$ ]] && [[ "$MAX_WORKERS" =~ ^[0-9]+$ ]]; then
    CAPACITY=$((SERVER_LIMIT * THREADS_PER_CHILD))
    if [ "$MAX_WORKERS" -gt "$CAPACITY" ]; then
        issues+=("Invalid/ineffective MPM capacity: MaxRequestWorkers=$MAX_WORKERS but ServerLimit*ThreadsPerChild=$CAPACITY")
    fi
fi

# Check recent logs for saturation
LOG_HITS=""

if command -v journalctl >/dev/null 2>&1; then
    LOG_HITS="$(journalctl -u "$SERVICE" --since "$LOG_SINCE" --no-pager 2>/dev/null \
        | grep -Eai 'MaxRequestWorkers|scoreboard is full|server reached|AH00161|AH03490|AH00484' \
        | tail -n 5 || true)"
fi

if [ -z "$LOG_HITS" ]; then
    for log in /var/log/apache2/error.log /var/log/httpd/error_log; do
        if [ -r "$log" ]; then
            LOG_HITS="$(tail -n "$TAIL_LINES" "$log" 2>/dev/null \
                | grep -Eai 'MaxRequestWorkers|scoreboard is full|server reached|AH00161|AH03490|AH00484' \
                | tail -n 5 || true)"
            [ -n "$LOG_HITS" ] && break
        fi
    done
fi

if [ -n "$LOG_HITS" ]; then
    issues+=("Recent Apache worker saturation found in logs")
fi

# Try mod_status
STATUS="$(curl -fsS --max-time 2 "$STATUS_URL" 2>/dev/null || true)"

if grep -q '^BusyWorkers:' <<< "$STATUS"; then
    BUSY="$(awk -F': ' '/^BusyWorkers:/ {print $2}' <<< "$STATUS")"
    IDLE="$(awk -F': ' '/^IdleWorkers:/ {print $2}' <<< "$STATUS")"

    info+=("BusyWorkers=$BUSY")
    info+=("IdleWorkers=$IDLE")

    if [[ "$BUSY" =~ ^[0-9]+$ ]] && [[ "$MAX_WORKERS" =~ ^[0-9]+$ ]] && [ "$MAX_WORKERS" -gt 0 ]; then
        USAGE=$((BUSY * 100 / MAX_WORKERS))
        info+=("WorkerUsage=${USAGE}%")

        if [ "$USAGE" -ge "$CRIT_PCT" ]; then
            issues+=("Apache workers are critically high: ${USAGE}% used")
        elif [ "$USAGE" -ge "$WARN_PCT" ]; then
            warnings+=("Apache workers are high: ${USAGE}% used")
        fi
    fi

    if [[ "$IDLE" =~ ^[0-9]+$ ]] && [ "$IDLE" -le 2 ]; then
        warnings+=("Very few idle Apache workers available: IdleWorkers=$IDLE")
    fi
else
    warnings+=("mod_status not available on $STATUS_URL - live worker usage could not be checked")
fi

# Memory overview
if command -v free >/dev/null 2>&1; then
    AVAIL_MB="$(free -m | awk '/^Mem:/ {print $7}')"
    info+=("AvailableRAM=${AVAIL_MB}MB")
fi

if pgrep -x apache2 >/dev/null 2>&1; then
    APACHE_RSS_MB="$(ps -C apache2 -o rss= 2>/dev/null | awk '{sum+=$1} END {printf "%.0f", sum/1024}')"
    info+=("ApacheRSS=${APACHE_RSS_MB}MB")
elif pgrep -x httpd >/dev/null 2>&1; then
    APACHE_RSS_MB="$(ps -C httpd -o rss= 2>/dev/null | awk '{sum+=$1} END {printf "%.0f", sum/1024}')"
    info+=("ApacheRSS=${APACHE_RSS_MB}MB")
fi

# Final output
if [ "${#issues[@]}" -gt 0 ]; then
    echo "CRITICAL [$HOST] Apache MPM needs attention"
    printf ' - %s\n' "${issues[@]}"
    [ "${#warnings[@]}" -gt 0 ] && printf ' - Warning: %s\n' "${warnings[@]}"
    echo " - Info: ${info[*]}"
    if [ -n "$LOG_HITS" ]; then
        echo
        echo "Recent matching log lines:"
        echo "$LOG_HITS"
    fi
    exit 2
fi

if [ "${#warnings[@]}" -gt 0 ]; then
    echo "WARNING [$HOST] Apache is running, but check capacity"
    printf ' - %s\n' "${warnings[@]}"
    echo " - Info: ${info[*]}"
    exit 1
fi

echo "OK [$HOST] Apache MPM looks healthy - ${info[*]}"
exit 0