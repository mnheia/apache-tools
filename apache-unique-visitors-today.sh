#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./apache-unique-visitors-today.sh
#   ./apache-unique-visitors-today.sh 17/Jun/2026
#   ./apache-unique-visitors-today.sh 17/Jun/2026 /var/log/apache2
#
# Options:
#   RESOLVE_DNS=0 ./apache-unique-visitors-today.sh
#   DNS_TIMEOUT=1 ./apache-unique-visitors-today.sh

TODAY="${1:-$(LC_ALL=C date '+%d/%b/%Y')}"
LOG_ROOT="${2:-/var/log/apache2}"

RESOLVE_DNS="${RESOLVE_DNS:-1}"
DNS_TIMEOUT="${DNS_TIMEOUT:-2}"

TMP_HITS="$(mktemp)"
TMP_COUNTS="$(mktemp)"
trap 'rm -f "$TMP_HITS" "$TMP_COUNTS"' EXIT

declare -A DNS_CACHE

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

reverse_dns() {
    local ip="$1"
    local out=""

    if [[ "$RESOLVE_DNS" != "1" ]]; then
        echo ""
        return 0
    fi

    if [[ -n "${DNS_CACHE[$ip]:-}" ]]; then
        echo "${DNS_CACHE[$ip]}"
        return 0
    fi

    if command -v dig >/dev/null 2>&1; then
        out="$(timeout "$DNS_TIMEOUT" dig +short -x "$ip" 2>/dev/null | sed 's/\.$//' | head -n 1 || true)"
    elif command -v host >/dev/null 2>&1; then
        out="$(timeout "$DNS_TIMEOUT" host "$ip" 2>/dev/null | awk '/domain name pointer/ {print $5; exit}' | sed 's/\.$//' || true)"
    elif command -v getent >/dev/null 2>&1; then
        out="$(timeout "$DNS_TIMEOUT" getent hosts "$ip" 2>/dev/null | awk '{print $2; exit}' || true)"
    fi

    DNS_CACHE["$ip"]="$out"
    echo "$out"
}

country_hint_from_hostname() {
    local hostname="$1"
    local tld=""

    tld="${hostname##*.}"

    case "$tld" in
        si) echo "Slovenia" ;;
        de) echo "Germany" ;;
        at) echo "Austria" ;;
        hr) echo "Croatia" ;;
        it) echo "Italy" ;;
        hu) echo "Hungary" ;;
        rs) echo "Serbia" ;;
        ba) echo "Bosnia and Herzegovina" ;;
        eu) echo "European Union / EU domain" ;;
        uk) echo "United Kingdom" ;;
        fr) echo "France" ;;
        nl) echo "Netherlands" ;;
        be) echo "Belgium" ;;
        ch) echo "Switzerland" ;;
        pl) echo "Poland" ;;
        cz) echo "Czechia" ;;
        sk) echo "Slovakia" ;;
        ua) echo "Ukraine" ;;
        ru) echo "Russia" ;;
        us) echo "United States" ;;
        ca) echo "Canada" ;;
        com|net|org|info|biz|cloud|host|online|site|io) echo "generic / unknown" ;;
        *) echo "unknown" ;;
    esac
}

process_file() {
    local file="$1"

    if [[ "$file" == *.gz ]]; then
        gzip -cd -- "$file"
    else
        cat -- "$file"
    fi | awk -v today="$TODAY" -v src="$file" '
        function looks_like_ip(s) {
            if (s ~ /^([0-9][0-9]?[0-9]?\.)[0-9][0-9]?[0-9]?\.[0-9][0-9]?[0-9]?\.[0-9][0-9]?[0-9]?$/) {
                return 1
            }

            if (s ~ /^[0-9A-Fa-f:][0-9A-Fa-f:]*$/ && index(s, ":") > 0) {
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

            # Layout:
            # /var/log/apache2/psihopat.si/access_log
            if (filebase == "access_log" || filebase == "access.log") {
                return parent
            }

            # Layout:
            # /var/log/apache2/psihopat.si-access.log
            sub(/\.log$/, "", filebase)
            sub(/_log$/, "", filebase)
            gsub(/[-_.]?access[-_.]?log$/, "", filebase)
            gsub(/[-_.]?access$/, "", filebase)

            if (filebase == "" || filebase == "access") {
                return parent
            }

            return filebase
        }

        index($0, "[" today ":") {
            domain = ""
            ip = ""

            # Normal Apache combined log:
            # IP - - [date] "GET ..."
            if (looks_like_ip($1)) {
                domain = domain_from_path(src)
                ip = $1
            }

            # Debian vhost_combined:
            # domain:443 IP - - [date] "GET ..."
            else {
                domain = clean_domain($1)
                ip = $2
            }

            if (domain != "" && ip != "" && ip != "-") {
                print domain "\t" ip
            }
        }
    '
}

while IFS= read -r file; do
    process_file "$file"
done < <(find_log_files) > "$TMP_HITS"

if [[ ! -s "$TMP_HITS" ]]; then
    echo "No Apache access log entries found for $TODAY in $LOG_ROOT."
    exit 0
fi

# Per-domain/IP hit counts.
awk -F '\t' '
    {
        key = $1 FS $2
        count[key]++
    }
    END {
        for (key in count) {
            print key FS count[key]
        }
    }
' "$TMP_HITS" | sort -t $'\t' -k1,1 -k3,3nr > "$TMP_COUNTS"

echo
echo "Apache visitor report for $TODAY"
echo "Log root: $LOG_ROOT"
echo

echo "Summary by domain"
echo "-----------------"

awk -F '\t' '
    {
        domain = $1
        ip = $2

        total_hits[domain]++

        key = domain FS ip
        if (!(key in seen_ip)) {
            seen_ip[key] = 1
            unique_ips[domain]++
        }
    }
    END {
        for (domain in total_hits) {
            print total_hits[domain] FS unique_ips[domain] FS domain
        }
    }
' "$TMP_HITS" \
    | sort -t $'\t' -k1,1nr \
    | awk -F '\t' 'BEGIN {
        printf "%-45s %12s %12s\n", "Domain", "Total hits", "Unique IPs"
        printf "%-45s %12s %12s\n", "------", "----------", "----------"
    } {
        printf "%-45s %12d %12d\n", $3, $1, $2
    }'

echo
echo "Details by domain - resolved hostnames only"
echo "-------------------------------------------"

current_domain=""

while IFS=$'\t' read -r domain ip hits; do
    hostname="$(reverse_dns "$ip")"

    # Skip unresolved IPs in details.
    if [[ -z "$hostname" ]]; then
        continue
    fi

    country="$(country_hint_from_hostname "$hostname")"

    if [[ "$domain" != "$current_domain" ]]; then
        current_domain="$domain"
        echo
        echo "$domain"
        printf "%-40s %8s  %-55s  %-30s\n" "IP" "Hits" "Hostname" "Country hint"
        printf "%-40s %8s  %-55s  %-30s\n" "--" "----" "--------" "------------"
    fi

    printf "%-40s %8s  %-55s  %-30s\n" "$ip" "$hits" "$hostname" "$country"
done < "$TMP_COUNTS"