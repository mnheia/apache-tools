#!/usr/bin/env bash
# Author: mnheia
# Copyright (c) 2026 mnheia
# Repository: https://github.com/mnheia/apache-tools
# License: GPL-3.0 (see LICENSE)
set -euo pipefail

# Investigate top IP addresses from an Apache visitor report.
# Usage: ./resolve-apache-top-ips.sh apache-report.txt
#        SOURCE=suspicious TOP=25 ./resolve-apache-top-ips.sh apache-report.txt
# Options:
#   SOURCE=human|suspicious|both (default: human, as in original script)
#   OUT=resolved-top-ips.tsv TOP=20 RESOLVE_DNS=1 LOOKUP_ASN=1 DNS_TIMEOUT=2
# No country/GeoIP lookups; ASN is informational, not an automatic exclusion.

command -v python3 >/dev/null 2>&1 || { echo 'ERROR: python3 is required' >&2; exit 1; }
exec python3 - "${1:--}" <<'PY'
import csv
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

source = os.getenv('SOURCE', 'human').lower()
if source not in ('human', 'suspicious', 'both'):
    raise SystemExit('ERROR: SOURCE must be human, suspicious or both')
try:
    top = max(0, min(int(os.getenv('TOP', '20')), 500))
    timeout = max(.2, min(float(os.getenv('DNS_TIMEOUT', '2')), 15.0))
except ValueError:
    raise SystemExit('ERROR: TOP and DNS_TIMEOUT must be numeric')
use_dns = os.getenv('RESOLVE_DNS', '1') == '1'
use_asn = os.getenv('LOOKUP_ASN', '1') == '1'
out = Path(os.getenv('OUT', 'resolved-top-ips.tsv'))


def safe_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


if sys.argv[1] == '-':
    lines = sys.stdin.read().splitlines()
else:
    try:
        lines = Path(sys.argv[1]).read_text(encoding='utf-8').splitlines()
    except OSError as exc:
        raise SystemExit(f'ERROR: {exc}')

found = []
mode = ''
domain = ''
by_domain = {}
suspicious_count = 0
for line in lines:
    if line.startswith('Top IPs by domain - human-ish only') or line.startswith('Top IPs by domain - likely-human'):
        mode = 'human'
        domain = ''
        continue
    if line.startswith('Top suspicious IPs - raw requests'):
        mode = 'suspicious'
        domain = ''
        continue
    # Stop at the first later section.
    if re.match(r'^\S.*\n?$', line) and line.startswith(('Note:', 'HTTP errors', 'Traffic classification', 'Top pages', 'Known automated', 'Top probe paths')):
        mode = ''
    if not line.strip() or line.lstrip().startswith(('IP ', '--', 'Hits ')):
        continue
    if mode == 'human' and re.fullmatch(r'[A-Za-z0-9._-]+\.[A-Za-z]{2,}', line.strip()):
        domain = line.strip()
        by_domain[domain] = 0
        continue
    parts = line.split()
    if mode == 'human' and source in ('human', 'both') and domain and len(parts) >= 2:
        ip = safe_ip(parts[0])
        if ip and parts[1].isdigit() and by_domain[domain] < top:
            found.append((mode, domain, ip, int(parts[1]), 'likely-human page views'))
            by_domain[domain] += 1
    elif mode == 'suspicious' and source in ('suspicious', 'both') and len(parts) >= 3:
        ip = safe_ip(parts[0])
        if ip and parts[1].isdigit() and parts[2].isdigit() and suspicious_count < top:
            reason = ' '.join(parts[3:])
            found.append((mode, str(parts[2]) + ' domains', ip, int(parts[1]), reason))
            suspicious_count += 1


def lookup(args):
    if not shutil.which('dig'):
        return ''
    try:
        r = subprocess.run(['dig', '+time=1', '+tries=1', '+short', *args],
                           capture_output=True, text=True, timeout=timeout, check=False)
        return next((x.strip().strip('"') for x in r.stdout.splitlines() if x.strip()), '')
    except (subprocess.TimeoutExpired, OSError):
        return ''


def enrich_ip(ip):
    rdns = lookup(['-x', ip]).rstrip('.') if use_dns else ''
    asn = as_name = prefix = ''
    if use_asn and ':' not in ip:
        q = '.'.join(reversed(ip.split('.'))) + '.origin.asn.cymru.com'
        fields = [part.strip() for part in lookup(['TXT', q]).split('|')]
        if len(fields) >= 2:
            asn, prefix = fields[:2]
            if asn.isdigit():
                details = [part.strip() for part in lookup(['TXT', f'AS{asn}.asn.cymru.com']).split('|')]
                if len(details) >= 5:
                    as_name = details[4]
    return (rdns, asn, as_name, prefix)


# Deduplicate repeated IPs across vhosts, and parallelize slow DNS lookups.
unique_ips = list(dict.fromkeys(ip for _, _, ip, _, _ in found))
with ThreadPoolExecutor(max_workers=8) as pool:
    cache = dict(zip(unique_ips, pool.map(enrich_ip, unique_ips)))
rows = []
for kind, domain, ip, hits, reason in found:
    rdns, asn, as_name, prefix = cache[ip]
    rows.append([kind, domain, ip, hits, rdns, asn, as_name, prefix, reason])

with out.open('w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f, delimiter='\t')
    writer.writerow(['Source', 'Domain/Scope', 'IP', 'Hits', 'Reverse DNS', 'ASN', 'ASN name', 'BGP prefix', 'Reason'])
    writer.writerows(rows)

print(f'Wrote: {out} ({len(rows)} rows)')
for kind, scope, ip, hits, dns, asn, name, prefix, reason in rows[:60]:
    print(f'{kind:<10} {ip:<39} {hits:>7} {scope:<25} {asn:<9} {dns or name or "-"}')
if not rows:
    print('No IP rows found in the selected section. Set SOURCE=human or SOURCE=suspicious.')
PY
