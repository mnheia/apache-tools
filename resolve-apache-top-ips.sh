#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./resolve-apache-top-ips.sh apache-report.txt
#   TOP=20 ./resolve-apache-top-ips.sh apache-report.txt
#   ./apache-visitors-range.sh > apache-report.txt
#   ./resolve-apache-top-ips.sh apache-report.txt
#
# Output:
#   resolved-top-ips.tsv

REPORT="${1:-/dev/stdin}"
TOP="${TOP:-20}"
OUT="${OUT:-resolved-top-ips.tsv}"
DNS_TIMEOUT="${DNS_TIMEOUT:-2}"

TMP_IPS="$(mktemp)"
trap 'rm -f "$TMP_IPS"' EXIT

country_name() {
    case "$1" in
        SI) echo "Slovenia" ;;
        DE) echo "Germany" ;;
        AT) echo "Austria" ;;
        HR) echo "Croatia" ;;
        IT) echo "Italy" ;;
        HU) echo "Hungary" ;;
        RS) echo "Serbia" ;;
        BA) echo "Bosnia and Herzegovina" ;;
        NL) echo "Netherlands" ;;
        BE) echo "Belgium" ;;
        FR) echo "France" ;;
        CH) echo "Switzerland" ;;
        CZ) echo "Czechia" ;;
        SK) echo "Slovakia" ;;
        PL) echo "Poland" ;;
        UA) echo "Ukraine" ;;
        RU) echo "Russia" ;;
        GB|UK) echo "United Kingdom" ;;
        IE) echo "Ireland" ;;
        US) echo "United States" ;;
        CA) echo "Canada" ;;
        BR) echo "Brazil" ;;
        CN) echo "China" ;;
        HK) echo "Hong Kong" ;;
        SG) echo "Singapore" ;;
        IN) echo "India" ;;
        JP) echo "Japan" ;;
        KR) echo "South Korea" ;;
        AU) echo "Australia" ;;
        *) echo "" ;;
    esac
}

reverse_ipv4() {
    local ip="$1"
    IFS=. read -r a b c d <<< "$ip"
    echo "$d.$c.$b.$a"
}

reverse_dns() {
    local ip="$1"
    timeout "$DNS_TIMEOUT" dig +short -x "$ip" 2>/dev/null \
        | sed 's/\.$//' \
        | head -n 1 \
        || true
}

cymru_asn_lookup() {
    local ip="$1"
    local rev=""
    local raw=""
    local asn=""
    local prefix=""
    local cc=""
    local registry=""
    local allocated=""
    local asname_raw=""
    local asname=""

    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        rev="$(reverse_ipv4 "$ip")"
        raw="$(timeout "$DNS_TIMEOUT" dig +short TXT "${rev}.origin.asn.cymru.com" 2>/dev/null | tr -d '"' | head -n 1 || true)"
    else
        raw=""
    fi

    if [[ -z "$raw" ]]; then
        printf "\t\t\t\t\t"
        return 0
    fi

    # Format:
    # ASN | BGP Prefix | CC | Registry | Allocated
    asn="$(echo "$raw" | awk -F'|' '{gsub(/^ +| +$/, "", $1); print $1}')"
    prefix="$(echo "$raw" | awk -F'|' '{gsub(/^ +| +$/, "", $2); print $2}')"
    cc="$(echo "$raw" | awk -F'|' '{gsub(/^ +| +$/, "", $3); print $3}')"
    registry="$(echo "$raw" | awk -F'|' '{gsub(/^ +| +$/, "", $4); print $4}')"
    allocated="$(echo "$raw" | awk -F'|' '{gsub(/^ +| +$/, "", $5); print $5}')"

    if [[ -n "$asn" ]]; then
        asname_raw="$(timeout "$DNS_TIMEOUT" dig +short TXT "AS${asn}.asn.cymru.com" 2>/dev/null | tr -d '"' | head -n 1 || true)"
        asname="$(echo "$asname_raw" | awk -F'|' '{gsub(/^ +| +$/, "", $5); print $5}')"
    fi

    printf "%s\t%s\t%s\t%s\t%s\t%s" "$asn" "$asname" "$prefix" "$cc" "$registry" "$allocated"
}

geoip_mmdb_hint() {
    local ip="$1"
    local db=""
    local country=""
    local city=""

    for candidate in \
        /usr/share/GeoIP/GeoLite2-City.mmdb \
        /var/lib/GeoIP/GeoLite2-City.mmdb \
        /usr/local/share/GeoIP/GeoLite2-City.mmdb
    do
        if [[ -f "$candidate" ]]; then
            db="$candidate"
            break
        fi
    done

    if [[ -z "$db" ]] || ! command -v mmdblookup >/dev/null 2>&1; then
        printf "\t"
        return 0
    fi

    country="$(mmdblookup --file "$db" --ip "$ip" country names en 2>/dev/null \
        | awk -F'"' '/utf8_string/ {print $2; exit}' || true)"

    city="$(mmdblookup --file "$db" --ip "$ip" city names en 2>/dev/null \
        | awk -F'"' '/utf8_string/ {print $2; exit}' || true)"

    if [[ -n "$city" && -n "$country" ]]; then
        printf "%s, %s" "$city" "$country"
    elif [[ -n "$country" ]]; then
        printf "%s" "$country"
    else
        printf ""
    fi
}

traffic_hint() {
    local ip="$1"
    local hostname="$2"
    local asname="$3"
    local text=""

    text="$(printf "%s %s %s" "$ip" "$hostname" "$asname" | tr '[:upper:]' '[:lower:]')"

    if [[ "$ip" =~ ^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
        echo "internal/private"
    elif [[ "$text" =~ shodan|censys|binaryedge|shadowserver|internet-census|scanner|scan ]]; then
        echo "scanner/research"
    elif [[ "$text" =~ amazon|aws|google|microsoft|azure|digitalocean|linode|akamai|ovh|hetzner|vultr|oracle|cloudflare ]]; then
        echo "cloud/datacenter"
    elif [[ "$text" =~ vpn|proxy|hosting|pfcloud|techoff|colo|server|dedicated ]]; then
        echo "hosting/vpn/suspicious"
    elif [[ "$text" =~ telecom|telekom|a1|t-2|telemach|siol|amis|mobitel|broadband|dsl|cable ]]; then
        echo "possible residential/ISP"
    else
        echo "unknown"
    fi
}

# Parse the "Top IPs by domain - human-ish only" section from your report.
awk -v top="$TOP" '
    BEGIN {
        in_top = 0
        current_domain = ""
    }

    /^Top IPs by domain - human-ish only/ {
        in_top = 1
        next
    }

    in_top == 0 {
        next
    }

    /^[[:space:]]*$/ {
        next
    }

    /^IP[[:space:]]+/ {
        next
    }

    /^--[[:space:]]+/ {
        next
    }

    /^[A-Za-z0-9._-]+\.[A-Za-z]{2,}$/ {
        current_domain = $1
        rank[current_domain] = 0
        next
    }

    current_domain != "" && $1 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ {
        rank[current_domain]++

        if (rank[current_domain] <= top) {
            print current_domain "\t" $1 "\t" $2
        }

        next
    }
' "$REPORT" > "$TMP_IPS"

{
    printf "Domain\tIP\tHuman-ish PV\tReverse DNS\tASN\tASN name\tBGP prefix\tASN country\tCountry name\tRegistry\tAllocated\tGeoIP hint\tTraffic hint\n"

    while IFS=$'\t' read -r domain ip hits; do
        hostname="$(reverse_dns "$ip")"

        asn_data="$(cymru_asn_lookup "$ip")"
        IFS=$'\t' read -r asn asname prefix cc registry allocated <<< "$asn_data"

        cname="$(country_name "$cc")"
        geo_hint="$(geoip_mmdb_hint "$ip")"
        hint="$(traffic_hint "$ip" "$hostname" "$asname")"

        printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
            "$domain" \
            "$ip" \
            "$hits" \
            "$hostname" \
            "$asn" \
            "$asname" \
            "$prefix" \
            "$cc" \
            "$cname" \
            "$registry" \
            "$allocated" \
            "$geo_hint" \
            "$hint"
    done < "$TMP_IPS"
} > "$OUT"

echo "Wrote: $OUT"
echo
column -t -s $'\t' "$OUT" | less -S