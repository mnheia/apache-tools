#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./apache-visitors-range.sh
#   ./apache-visitors-range.sh 2026-01-01 2026-07-06
#   ./apache-visitors-range.sh 2026-01-01 2026-07-06 /var/log/apache2
#
# Options:
#   FILTER_BOTS=0 ./apache-visitors-range.sh
#   EXCLUDE_PRIVATE_IPS=0 ./apache-visitors-range.sh
#   EXCLUDE_STATIC=0 ./apache-visitors-range.sh
#   ONLY_STATUS_2XX_3XX=0 ./apache-visitors-range.sh
#   TOP_IPS=20 ./apache-visitors-range.sh
#
# Optional domain exclusion:
#   EXCLUDE_DOMAINS="admin.example.com,status.example.com" ./apache-visitors-range.sh

START_DATE="${1:-$(date -d '6 months ago' '+%Y-%m-%d')}"
END_DATE="${2:-$(date '+%Y-%m-%d')}"
LOG_ROOT="${3:-/var/log/apache2}"

FILTER_BOTS="${FILTER_BOTS:-1}"
EXCLUDE_PRIVATE_IPS="${EXCLUDE_PRIVATE_IPS:-1}"
EXCLUDE_STATIC="${EXCLUDE_STATIC:-1}"
ONLY_STATUS_2XX_3XX="${ONLY_STATUS_2XX_3XX:-1}"
EXCLUDE_DOMAINS="${EXCLUDE_DOMAINS:-}"
TOP_IPS="${TOP_IPS:-25}"

START_KEY="$(date -d "$START_DATE" '+%Y%m%d')"
END_KEY="$(date -d "$END_DATE" '+%Y%m%d')"

TMP_HITS="$(mktemp)"
TMP_COUNTS="$(mktemp)"
trap 'rm -f "$TMP_HITS" "$TMP_COUNTS"' EXIT

find_log_files() {
    find "$LOG_ROOT" -type f \( \
        -name 'access_log' -o \
        -name 'access_log.*' -o \
        -name 'access.log' -o \
        -name 'access.log.*' -o \
        -name '*access*.log' -o \
        -name '*access*.log.*' \
    \) -print
}

read_log_file() {
    local file="$1"

    if [[ "$file" == *.gz ]]; then
        gzip -cd -- "$file"
    else
        cat -- "$file"
    fi
}

process_file() {
    local file="$1"

    read_log_file "$file" | awk \
        -v src="$file" \
        -v start_key="$START_KEY" \
        -v end_key="$END_KEY" \
        -v filter_bots="$FILTER_BOTS" \
        -v exclude_private_ips="$EXCLUDE_PRIVATE_IPS" \
        -v exclude_static="$EXCLUDE_STATIC" \
        -v only_status_2xx_3xx="$ONLY_STATUS_2XX_3XX" \
        -v exclude_domains="$EXCLUDE_DOMAINS" '
        BEGIN {
            month["Jan"] = 1
            month["Feb"] = 2
            month["Mar"] = 3
            month["Apr"] = 4
            month["May"] = 5
            month["Jun"] = 6
            month["Jul"] = 7
            month["Aug"] = 8
            month["Sep"] = 9
            month["Oct"] = 10
            month["Nov"] = 11
            month["Dec"] = 12

            n = split(exclude_domains, excluded, /[ ,]+/)
            for (i = 1; i <= n; i++) {
                if (excluded[i] != "") {
                    skip_domain[excluded[i]] = 1
                }
            }
        }

        function looks_like_ip(s) {
            if (s ~ /^([0-9][0-9]?[0-9]?\.)[0-9][0-9]?[0-9]?\.[0-9][0-9]?[0-9]?\.[0-9][0-9]?[0-9]?$/) {
                return 1
            }

            if (s ~ /^[0-9A-Fa-f:][0-9A-Fa-f:]*$/ && index(s, ":") > 0) {
                return 1
            }

            return 0
        }

        function is_private_ip(ip, parts, first, second, low) {
            low = tolower(ip)

            if (low == "::1") {
                return 1
            }

            if (low ~ /^fc/ || low ~ /^fd/ || low ~ /^fe80/) {
                return 1
            }

            if (ip !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                return 0
            }

            split(ip, parts, ".")
            first = parts[1] + 0
            second = parts[2] + 0

            if (first == 10) {
                return 1
            }

            if (first == 127) {
                return 1
            }

            if (first == 192 && second == 168) {
                return 1
            }

            if (first == 172 && second >= 16 && second <= 31) {
                return 1
            }

            if (first == 169 && second == 254) {
                return 1
            }

            return 0
        }

        function clean_domain(d) {
            sub(/:[0-9]+$/, "", d)
            return d
        }

        function basename(path, b) {
            b = path
            sub(/^.*\//, "", b)
            return b
        }

        function parent_dir(path, p) {
            p = path
            sub(/\/[^\/]+$/, "", p)
            sub(/^.*\//, "", p)
            return p
        }

        function domain_from_path(path, filebase, parent) {
            filebase = basename(path)
            parent = parent_dir(path)

            sub(/\.gz$/, "", filebase)
            sub(/\.[0-9]+$/, "", filebase)

            if (filebase == "access_log" || filebase == "access.log") {
                return parent
            }

            sub(/\.log$/, "", filebase)
            sub(/_log$/, "", filebase)
            gsub(/[-_.]?access[-_.]?log$/, "", filebase)
            gsub(/[-_.]?access$/, "", filebase)

            if (filebase == "" || filebase == "access") {
                return parent
            }

            return filebase
        }

        function is_bot_ua(ua, l) {
            l = tolower(ua)

            if (l ~ /bot|crawler|spider|slurp|bingpreview|facebookexternalhit|ahrefs|semrush|mj12bot|dotbot|petalbot|bytespider|yandex|baidu|duckduckbot|applebot|ccbot|gptbot|chatgpt-user|claudebot|perplexitybot/) {
                return 1
            }

            if (l ~ /curl|wget|python-requests|go-http-client|java\/|libwww|scrapy|httpclient|masscan|zgrab|nmap/) {
                return 1
            }

            return 0
        }

        function is_static_uri(uri, u) {
            u = tolower(uri)
            sub(/\?.*$/, "", u)

            if (u ~ /\.(css|js|png|jpg|jpeg|gif|svg|ico|webp|avif|bmp|tif|tiff|woff|woff2|ttf|eot|map|mp4|mp3|webm|pdf|zip|gz|rar|7z)$/) {
                return 1
            }

            return 0
        }

        {
            if (!match($0, /\[[0-9][0-9]\/[A-Za-z][A-Za-z][A-Za-z]\/[0-9][0-9][0-9][0-9]:/)) {
                next
            }

            datestr = substr($0, RSTART + 1, 11)

            dd = substr(datestr, 1, 2) + 0
            mon = substr(datestr, 4, 3)
            yyyy = substr(datestr, 8, 4)

            if (!(mon in month)) {
                next
            }

            date_key = sprintf("%04d%02d%02d", yyyy, month[mon], dd)

            if (date_key < start_key || date_key > end_key) {
                next
            }

            month_key = sprintf("%04d-%02d", yyyy, month[mon])

            domain = ""
            ip = ""

            if (looks_like_ip($1)) {
                domain = domain_from_path(src)
                ip = $1
            } else {
                domain = clean_domain($1)
                ip = $2
            }

            if (domain == "" || ip == "" || ip == "-") {
                next
            }

            if (domain in skip_domain) {
                next
            }

            request = ""
            status = ""
            uri = ""
            ua = ""

            q_count = split($0, q, "\"")

            if (q_count >= 2) {
                request = q[2]
                split(request, req_parts, " ")
                method = req_parts[1]
                uri = req_parts[2]
            }

            if (q_count >= 3) {
                rest = q[3]
                sub(/^ +/, "", rest)
                split(rest, status_parts, / +/)
                status = status_parts[1]
            }

            if (q_count >= 6) {
                ua = q[6]
            }

            clean = 1

            if (exclude_private_ips == "1" && is_private_ip(ip)) {
                clean = 0
            }

            if (filter_bots == "1" && is_bot_ua(ua)) {
                clean = 0
            }

            if (exclude_static == "1" && is_static_uri(uri)) {
                clean = 0
            }

            if (only_status_2xx_3xx == "1" && status !~ /^[23][0-9][0-9]$/) {
                clean = 0
            }

            print date_key "\t" month_key "\t" domain "\t" ip "\t" clean "\t" status "\t" uri "\t" ua
        }
    '
}

while IFS= read -r file; do
    process_file "$file"
done < <(find_log_files) > "$TMP_HITS"

if [[ ! -s "$TMP_HITS" ]]; then
    echo "No Apache access log entries found from $START_DATE to $END_DATE in $LOG_ROOT."
    exit 0
fi

echo
echo "Apache visitor report"
echo "Range:    $START_DATE to $END_DATE"
echo "Log root: $LOG_ROOT"
echo
echo "Filters for human-ish traffic:"
echo "  Exclude private/local IPs: $EXCLUDE_PRIVATE_IPS"
echo "  Filter bots/user-agents:   $FILTER_BOTS"
echo "  Exclude static files:      $EXCLUDE_STATIC"
echo "  Only HTTP 2xx/3xx:         $ONLY_STATUS_2XX_3XX"

if [[ -n "$EXCLUDE_DOMAINS" ]]; then
    echo "  Excluded domains:          $EXCLUDE_DOMAINS"
fi

echo

echo "Summary by domain - raw vs human-ish"
echo "------------------------------------"

awk -F '\t' '
    {
        domain = $3
        ip = $4
        clean = $5

        raw_hits[domain]++

        raw_key = domain FS ip
        if (!(raw_key in raw_seen)) {
            raw_seen[raw_key] = 1
            raw_unique[domain]++
        }

        if (clean == 1) {
            clean_hits[domain]++

            clean_key = domain FS ip
            if (!(clean_key in clean_seen)) {
                clean_seen[clean_key] = 1
                clean_unique[domain]++
            }
        }
    }
    END {
        for (domain in raw_hits) {
            print clean_hits[domain] + 0 FS clean_unique[domain] + 0 FS raw_hits[domain] FS raw_unique[domain] FS domain
        }
    }
' "$TMP_HITS" \
    | sort -t $'\t' -k1,1nr -k3,3nr \
    | awk -F '\t' 'BEGIN {
        printf "%-45s %14s %14s %12s %12s\n", "Domain", "Human-ish PV", "Human-ish IPs", "Raw hits", "Raw IPs"
        printf "%-45s %14s %14s %12s %12s\n", "------", "------------", "-------------", "--------", "-------"
    } {
        printf "%-45s %14d %14d %12d %12d\n", $5, $1, $2, $3, $4
    }'

echo
echo "Monthly summary by domain - human-ish"
echo "-------------------------------------"

awk -F '\t' '
    {
        month = $2
        domain = $3
        ip = $4
        clean = $5

        if (clean != 1) {
            next
        }

        clean_hits[month FS domain]++

        key = month FS domain FS ip
        if (!(key in seen_ip)) {
            seen_ip[key] = 1
            clean_unique[month FS domain]++
        }
    }
    END {
        for (key in clean_hits) {
            split(key, parts, FS)
            month = parts[1]
            domain = parts[2]

            print month FS domain FS clean_hits[key] FS clean_unique[key]
        }
    }
' "$TMP_HITS" \
    | sort -t $'\t' -k1,1 -k3,3nr \
    | awk -F '\t' 'BEGIN {
        printf "%-10s %-45s %14s %14s\n", "Month", "Domain", "Human-ish PV", "Human-ish IPs"
        printf "%-10s %-45s %14s %14s\n", "-----", "------", "------------", "-------------"
    } {
        printf "%-10s %-45s %14d %14d\n", $1, $2, $3, $4
    }'

echo
echo "Top IPs by domain - human-ish only"
echo "----------------------------------"

awk -F '\t' '
    {
        domain = $3
        ip = $4
        clean = $5

        if (clean != 1) {
            next
        }

        count[domain FS ip]++
    }
    END {
        for (key in count) {
            split(key, parts, FS)
            domain = parts[1]
            ip = parts[2]

            print domain FS ip FS count[key]
        }
    }
' "$TMP_HITS" \
    | sort -t $'\t' -k1,1 -k3,3nr > "$TMP_COUNTS"

awk -F '\t' -v top="$TOP_IPS" '
    {
        domain = $1
        ip = $2
        hits = $3

        rank[domain]++

        if (rank[domain] <= top) {
            if (domain != current_domain) {
                current_domain = domain
                print ""
                print domain
                printf "%-40s %12s\n", "IP", "Human-ish PV"
                printf "%-40s %12s\n", "--", "------------"
            }

            printf "%-40s %12d\n", ip, hits
        }
    }
' "$TMP_COUNTS"