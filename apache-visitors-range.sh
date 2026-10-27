#!/usr/bin/env bash
# Author: mnheia
# Copyright (c) 2026 mnheia
# Repository: https://github.com/mnheia/apache-tools
# License: GPL-3.0 (see LICENSE)
set -euo pipefail

# Apache statistics, standard-library Python parser (no external analytics service).
# Usage: apache-visitors-range.sh [START_YYYY-MM-DD] [END_YYYY-MM-DD] [LOG_ROOT]
# Defaults: previous six months through today, /var/log/apache2.
# Backwards-compatible switches: FILTER_BOTS, EXCLUDE_PRIVATE_IPS, EXCLUDE_STATIC,
# ONLY_STATUS_2XX_3XX, EXCLUDE_DOMAINS, TOP_IPS.
# Additional: FILTER_SUSPICIOUS=1, FILTER_RESEARCH_SCANNERS=1, SCANNER_IPS_FILE, TOP_PAGES=10,
# DAILY_BY_DOMAIN=0, TOP_SUSPICIOUS=20, TOP_ERRORS=10.
# PV definition: GET, HTTP 200, non-static, non-API path, after traffic filtering.
# 'Visitors' are approximate unique client IP + User-Agent combinations, NOT people.

command -v python3 >/dev/null 2>&1 || { echo 'ERROR: python3 is required' >&2; exit 1; }
exec python3 - "${1:-}" "${2:-}" "${3:-}" <<'PY'
import collections
import datetime as dt
import fnmatch
import gzip
import ipaddress
import lzma
import os
import subprocess
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit


def setting(name, default):
    return os.environ.get(name, str(default))


def enabled(name, default=1):
    return setting(name, default) == '1'


def number(name, default, limit=100):
    try:
        value = int(setting(name, default))
        return max(0, min(value, limit))
    except ValueError:
        raise SystemExit(f'ERROR: {name} must be an integer')


try:
    today = dt.date.today()
    # GNU date '6 months ago' is used only to preserve the previous default range.
    if not sys.argv[1]:
        start = subprocess.check_output(['date', '-d', '6 months ago', '+%Y-%m-%d'], text=True).strip()
    else:
        start = sys.argv[1]
    end = sys.argv[2] or today.isoformat()
    start_date, end_date = dt.date.fromisoformat(start), dt.date.fromisoformat(end)
except (ValueError, subprocess.CalledProcessError, FileNotFoundError):
    raise SystemExit('ERROR: Dates must be YYYY-MM-DD')
if start_date > end_date:
    raise SystemExit('ERROR: START_DATE must not be after END_DATE')
root = Path(sys.argv[3] or '/var/log/apache2')
if not root.is_dir():
    raise SystemExit(f'ERROR: Log directory does not exist: {root}')

FILTER_BOTS = enabled('FILTER_BOTS')
FILTER_SUSPICIOUS = enabled('FILTER_SUSPICIOUS')
FILTER_RESEARCH_SCANNERS = enabled('FILTER_RESEARCH_SCANNERS')
EXCLUDE_PRIVATE = enabled('EXCLUDE_PRIVATE_IPS')
EXCLUDE_STATIC = enabled('EXCLUDE_STATIC')
ONLY_2XX_3XX = enabled('ONLY_STATUS_2XX_3XX')
EXCLUDE_DOMAINS = {d.lower() for d in re.split(r'[\s,]+', setting('EXCLUDE_DOMAINS', '').strip()) if d}
TOP_IPS = number('TOP_IPS', 25, 500)
TOP_PAGES = number('TOP_PAGES', 10, 500)
TOP_SUSPICIOUS = number('TOP_SUSPICIOUS', 20, 500)
TOP_ERRORS = number('TOP_ERRORS', 10, 500)
DAILY_BY_DOMAIN = enabled('DAILY_BY_DOMAIN', 0)

MONTH = {s: i for i, s in enumerate(['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'], 1)}
# Supports Combined and Debian vhost_combined. Optional UA/referrer are allowed.
LOG_LINE = re.compile(
    r'^(?P<prefix>.*?)\s+\[(?P<date>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]'
    r'\s+"(?P<req>(?:\\.|[^"\\])*)"\s+(?P<status>\d{3}|-)\s+\S+'
    r'(?:\s+"(?:\\.|[^"\\])*"\s+"(?P<ua>(?:\\.|[^"\\])*)")?'
)
BOT_UA = re.compile(
    r'bot|crawler|spider|slurp|bingpreview|facebookexternalhit|facebookcatalog|'
    r'ahrefs|semrush|mj12|dotbot|petalbot|bytespider|yandex|baidu|duckduck|'
    r'applebot|ccbot|gptbot|chatgpt-user|claudebot|perplexity|googleother|'
    r'google-inspectiontool|software security research|softsec\.ruhr-uni-bochum\.de|'
    r'curl|wget|python-requests|python-urllib|go-http-client|'
    r'libwww|scrapy|httpclient|masscan|zgrab|nmap|headlesschrome|phantomjs|'
    r'playwright|selenium|uptimerobot|statuscake|site24x7|pingdom|'
    r'bytespider|whatsapp|slackbot|discordbot|telegrambot|linkpreview|'
    r'check_http|okhttp|java/|httpx|aiohttp|node-fetch|axios|postmanruntime',
    re.I,
)
SCANNER_UA = re.compile(r'masscan|zgrab|nmap|nikto|sqlmap|nuclei|acunetix|nessus|wpscan|gobuster|dirbuster|whatweb', re.I)
STATIC_EXT = re.compile(
    r'\.(css|js|mjs|png|jpg|jpeg|gif|svg|ico|webp|avif|bmp|tif|tiff|woff|woff2|'
    r'ttf|eot|map|mp4|mp3|webm|pdf|zip|gz|rar|7z|txt|xml|json|webmanifest|'
    r'wasm|csv|otf|mov|avi|docx?|xlsx?|pptx?)$', re.I,
)
NON_PAGE = re.compile(
    r'^/(?:api(?:/|$)|rest(?:/|$)|graphql(?:/|$)|wp-json(?:/|$)|'
    r'cgi-bin(?:/|$)|\.well-known(?:/|$)|metrics(?:/|$)|health(?:/|$)|'
    r'server-status(?:/|$)|server-info(?:/|$)|wp-admin(?:/|$)|wp-login\.php$|'
    r'mcp(?:/|$)|sse(?:/|$)|'
    r'xmlrpc\.php$)', re.I,
)
# A hit on these paths is a probe indicator; a *single* hit is not enough
# to exclude every subsequent page request from the same IP.
PROBE_PATH = re.compile(
    r'(?:^|/)(?:\.env(?:\.|/|$)|\.git(?:/|$)|\.svn(?:/|$)|'
    r'\.aws(?:/|$)|\.DS_Store$|phpmyadmin(?:/|$)|pma(?:/|$)|'
    r'cgi-bin(?:/|$)|vendor/phpunit(?:/|$)|actuator(?:/|$)|'
    r'wp-login\.php$|wp-admin/install\.php$|xmlrpc\.php$|'
    r'boaform(?:/|$)|HNAP1$|server-status$|etc/passwd$|'
    r'config\.json$|id_rsa$|autodiscover/autodiscover\.xml$|'
    r'owa/auth(?:/|$)|\.htaccess$)', re.I,
)


def is_private(address):
    return not address.is_global


def is_log(name):
    # Same families as the old find() expression, plus compressed .xz logs.
    return any(fnmatch.fnmatch(name, pattern) for pattern in (
        'access_log', 'access_log.*', 'access.log', 'access.log.*',
        '*access*.log', '*access*.log.*',
    ))


files = sorted(p for p in root.rglob('*') if p.is_file() and is_log(p.name))
if not files:
    raise SystemExit(f'ERROR: No access logs found under {root}')


def path_domain(filename):
    name = filename.name
    name = re.sub(r'\.(gz|xz)$', '', name)
    name = re.sub(r'\.\d+$', '', name)
    if name in ('access_log', 'access.log'):
        return filename.parent.name.lower()
    name = re.sub(r'\.log$|_log$', '', name)
    name = re.sub(r'[-_.]?access[-_.]?log$|[-_.]?access$', '', name)
    return (name or filename.parent.name).lower()


def parse_address(value):
    try:
        return ipaddress.ip_address(value.strip('[]'))
    except ValueError:
        return None


def path_only(uri):
    if '://' in uri:
        try:
            path = urlsplit(uri).path
        except ValueError:
            path = uri.split('?', 1)[0]
    else:
        path = uri.split('?', 1)[0].split('#', 1)[0]
    path = unquote(path, errors='replace') or '/'
    path = re.sub(r'/+', '/', path)
    if len(path) > 1:
        path = path.rstrip('/')
    # Defensive terminal hygiene: never output attacker-supplied control chars.
    return ''.join(c if c.isprintable() and c not in '\t\r\n' else '?' for c in path)[:500]


def iter_records():
    for filename in files:
        opener = gzip.open if filename.suffix == '.gz' else lzma.open if filename.suffix == '.xz' else open
        try:
            with opener(filename, 'rt', errors='replace') as log:
                for line in log:
                    m = LOG_LINE.match(line)
                    if not m:
                        continue
                    stamp = m['date']
                    mon = MONTH.get(stamp[3:6])
                    if not mon:
                        continue
                    day = f'{stamp[7:11]}-{mon:02d}-{stamp[:2]}'
                    if not start <= day <= end:
                        continue
                    prefix = m['prefix'].split()
                    if not prefix:
                        continue
                    addr = parse_address(prefix[0])
                    if addr is not None:
                        ip = str(addr)
                        domain = path_domain(filename)
                    elif len(prefix) >= 2 and (addr := parse_address(prefix[1])) is not None:
                        ip = str(addr)
                        domain = re.sub(r':\d+$', '', prefix[0]).lower().rstrip('.')
                    else:
                        continue
                    if domain in EXCLUDE_DOMAINS:
                        continue
                    bits = m['req'].split(' ', 2)
                    method = bits[0] if bits else ''
                    uri = bits[1] if len(bits) >= 2 else ''
                    p = path_only(uri)
                    status = int(m['status']) if m['status'].isdigit() else 0
                    ua = m['ua'] or ''
                    minute = day + ' ' + stamp[12:17]
                    static = bool(STATIC_EXT.search(p))
                    page = method == 'GET' and status == 200 and not static and not NON_PAGE.search(p)
                    yield (day, day[:7], domain, ip, ua, method, p, status, minute, static, page,
                           bool(PROBE_PATH.search(p)))
        except (OSError, EOFError, lzma.LZMAError) as exc:
            print(f'WARNING: Cannot read {filename}: {exc}', file=sys.stderr)


networks = []
blocked_file = setting('SCANNER_IPS_FILE', '')
if blocked_file:
    try:
        with open(blocked_file, encoding='utf-8') as f:
            for lineno, line in enumerate(f, 1):
                value = line.split('#', 1)[0].strip()
                if value:
                    try:
                        networks.append(ipaddress.ip_network(value, strict=False))
                    except ValueError as exc:
                        raise SystemExit(f'ERROR: {blocked_file}:{lineno}: {exc}')
    except OSError as exc:
        raise SystemExit(f'ERROR: Cannot open SCANNER_IPS_FILE: {exc}')

# First pass: classify behavior across ALL hosted domains, not only per vhost.
profiles = collections.defaultdict(lambda: {
    'n': 0, 'domains': set(), 'paths': set(), 'errors': 0,
    'probes': 0, 'probe_example': '', 'mins': collections.Counter(),
    'day_domains': collections.defaultdict(set), 'day_hits': collections.Counter(),
    'known_bot': 0, 'known_scanner_ua': 0, 'day_errors': collections.Counter(),
    'day_probes': collections.Counter(), 'day_probe_example': {},
    'day_scanner_ua': collections.Counter(), 'day_bots': collections.Counter(),
    'day_paths': collections.defaultdict(set), 'day_peak': collections.Counter(),
})
records_total = 0
for day, month, domain, ip, ua, method, path, status, minute, static, page, probe in iter_records():
    records_total += 1
    profile = profiles[ip]
    profile['n'] += 1
    profile['domains'].add(domain)
    profile['day_domains'][day].add(domain)
    profile['day_hits'][day] += 1
    if not static:
        profile['paths'].add(path)
        profile['day_paths'][day].add(path)
        if method == 'GET':
            profile['mins'][minute] += 1
            profile['day_peak'][day] = max(profile['day_peak'][day], profile['mins'][minute])
    if 400 <= status <= 499:
        profile['errors'] += 1
        profile['day_errors'][day] += 1
    if probe:
        profile['probes'] += 1
        profile['day_probes'][day] += 1
        profile['day_probe_example'].setdefault(day, path)
        if not profile['probe_example']:
            profile['probe_example'] = path
    if BOT_UA.search(ua) or not ua or ua == '-':
        profile['known_bot'] += 1
        profile['day_bots'][day] += 1
    if SCANNER_UA.search(ua):
        profile['known_scanner_ua'] += 1
        profile['day_scanner_ua'][day] += 1

if not records_total:
    print(f'No Apache access log entries found from {start} to {end} in {root}.')
    sys.exit(0)

# Ruhr University Bochum publicly identifies these network ranges as the origin
# of automated Internet measurements: https://finn.softsec.ruhr-uni-bochum.de/
# Other research/scanner networks may be added to SCANNER_IPS_FILE after verification.
RESEARCH_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    '185.73.23.0/24', '2a05:3e07:801::/48',
))

# Persistent exclusions apply across the reporting range. Behavioral exclusions
# apply only on days when the IP matches an actual scanning pattern.
scanner_reason = {}
daily_scanner_reason = {}
private_ip = {}
for ip, p in profiles.items():
    address = ipaddress.ip_address(ip)
    private_ip[ip] = is_private(address)
    if any(address in network for network in networks):
        scanner_reason[ip] = 'manual IP/CIDR exclusion'
    elif FILTER_RESEARCH_SCANNERS and any(address in network for network in RESEARCH_NETWORKS):
        scanner_reason[ip] = 'known research measurement network (Ruhr University Bochum)'

    # Internal IPs do not need behavioral scanning for visitor analytics.
    if private_ip[ip] and EXCLUDE_PRIVATE:
        continue
    for day, hits in p['day_hits'].items():
        probes = p['day_probes'][day]
        errors = p['day_errors'][day]
        paths = len(p['day_paths'][day])
        reason = ''
        if p['day_scanner_ua'][day]:
            reason = 'scanner User-Agent'
        elif probes >= 3:
            reason = f'{probes} probe paths ({p["day_probe_example"][day]})'
        elif probes >= 1 and errors >= 4:
            reason = f'probe + {errors} HTTP 4xx'
        elif (p['day_bots'][day] < hits and len(p['day_domains'][day]) >= 5
              and hits >= 8 and errors / hits >= .60):
            reason = '5+ domains/day with >=60% HTTP 4xx'
        elif (p['day_bots'][day] < hits and errors >= 12
              and paths >= 10 and errors / hits >= .70):
            reason = f'{errors} HTTP 4xx ({errors / hits:.0%})'
        elif p['day_bots'][day] < hits and p['day_peak'][day] >= 35:
            reason = 'high non-static request rate (>=35/min)'
        if reason:
            daily_scanner_reason[day, ip] = reason

# Second pass: produce stats without storing all requests in memory.
raw = collections.Counter()
raw_ips = collections.defaultdict(set)
classification = collections.Counter()
filtered_requests = collections.Counter()
filtered_ips = collections.defaultdict(set)
pv = collections.Counter()
visitors = collections.defaultdict(set)
monthly = collections.Counter()
monthly_visitors = collections.defaultdict(set)
daily = collections.Counter()
daily_visitors = collections.defaultdict(set)
per_page = collections.Counter()
page_visitors = collections.defaultdict(set)
ip_pageviews = collections.Counter()
errors_raw = collections.Counter()
errors_filtered = collections.Counter()
top_404 = collections.Counter()
scanner_hits = collections.Counter()
scanner_visible_reason = {}
raw_probe_paths = collections.Counter()
bot_ua_names = collections.Counter()


def family(ua):
    if not ua or ua == '-':
        return 'missing User-Agent'
    low = ua.lower()
    if 'software security research' in low or 'softsec.ruhr-uni-bochum.de' in low:
        return 'university research scanners'
    for name in ('googlebot', 'bingbot', 'gptbot', 'chatgpt-user', 'claudebot', 'perplexity', 'ahrefs', 'semrush', 'yandex', 'bytespider', 'facebook', 'curl', 'python', 'wget'):
        if name in low:
            return name
    return 'other automated User-Agents'


for day, month, domain, ip, ua, method, path, status, minute, static, page, probe in iter_records():
    raw[domain] += 1
    raw_ips[domain].add(ip)
    if status >= 400:
        errors_raw[domain, '4xx' if status < 500 else '5xx' if status < 600 else 'other'] += 1
    if probe:
        raw_probe_paths[path] += 1
    scanner = ip in scanner_reason or (day, ip) in daily_scanner_reason
    bot = bool(BOT_UA.search(ua)) or not ua or ua == '-'
    if private_ip[ip] and EXCLUDE_PRIVATE:
        category = 'internal'
    elif scanner and FILTER_SUSPICIOUS:
        category = 'suspicious'
    elif bot and FILTER_BOTS:
        category = 'known bot'
    elif probe and FILTER_SUSPICIOUS:
        # Exclude even a single probe request without blacklisting the entire IP.
        category = 'suspicious'
    else:
        category = 'eligible'

    classification[domain, category] += 1
    if category == 'suspicious':
        scanner_hits[ip] += 1
        reason = scanner_reason.get(ip) or daily_scanner_reason.get((day, ip)) or f'probe path ({path})'
        if ip not in scanner_visible_reason or not scanner_visible_reason[ip].startswith(('manual', 'known research')):
            scanner_visible_reason[ip] = reason
    if bot:
        bot_ua_names[family(ua)] += 1
    if category != 'eligible':
        continue
    if status >= 400:
        errors_filtered[domain, '4xx' if status < 500 else '5xx' if status < 600 else 'other'] += 1
        if status == 404 and not static and not probe:
            top_404[domain, path] += 1
    if EXCLUDE_STATIC and static:
        continue
    if ONLY_2XX_3XX and not 200 <= status < 400:
        continue
    filtered_requests[domain] += 1
    filtered_ips[domain].add(ip)
    if not page or probe:
        continue
    vk = (ip, ua)
    pv[domain] += 1
    visitors[domain].add(vk)
    monthly[month, domain] += 1
    monthly_visitors[month, domain].add(vk)
    daily[day, domain] += 1
    daily_visitors[day, domain].add(vk)
    daily[day, '__ALL__'] += 1
    daily_visitors[day, '__ALL__'].add(vk)
    per_page[domain, path] += 1
    page_visitors[domain, path].add(vk)
    ip_pageviews[domain, ip] += 1


def header(title):
    print('\n' + title + '\n' + '-' * len(title))


print('\nApache visitor report')
print(f'Range:    {start} to {end}')
print(f'Log root: {root}')
print(f'Files:    {len(files)}')
print('Page view: GET with HTTP 200 on a non-static, non-API, non-probe URL.')
print('Estimated visitor: unique IP + User-Agent per domain / period (not a person).')
print(f'Filters: bots={int(FILTER_BOTS)} suspicious={int(FILTER_SUSPICIOUS)} '
      f'private={int(EXCLUDE_PRIVATE)} research={int(FILTER_RESEARCH_SCANNERS)} '
      f'static={int(EXCLUDE_STATIC)} 2xx/3xx-request-filter={int(ONLY_2XX_3XX)}')
if EXCLUDE_DOMAINS:
    print('Excluded domains: ' + ', '.join(sorted(EXCLUDE_DOMAINS)))
if blocked_file:
    print(f'Scanner list: {blocked_file} ({len(networks)} networks)')

header('Summary by domain - likely-human page views')
print(f'{"Domain":<42} {"Page views":>12} {"Est. visitors":>14} {"Filtered req.":>14} {"Raw hits":>11} {"Raw IPs":>9}')
print('-' * 111)
for domain in sorted(raw, key=lambda d: (-pv[d], d)):
    print(f'{domain:<42} {pv[domain]:>12} {len(visitors[domain]):>14} {filtered_requests[domain]:>14} {raw[domain]:>11} {len(raw_ips[domain]):>9}')
all_visitors = set().union(*visitors.values())
all_raw_ips = set().union(*raw_ips.values())
print('-' * 111)
print(f'{"TOTAL (deduplicated visitors)":<42} {sum(pv.values()):>12} {len(all_visitors):>14} '
      f'{sum(filtered_requests.values()):>14} {sum(raw.values()):>11} {len(all_raw_ips):>9}')

header('Monthly summary by domain - likely-human')
print(f'{"Month":<10} {"Domain":<42} {"Page views":>12} {"Est. visitors":>14}')
for month, domain in sorted(monthly, key=lambda pair: (pair[0], -monthly[pair], pair[1])):
    print(f'{month:<10} {domain:<42} {monthly[month,domain]:>12} {len(monthly_visitors[month,domain]):>14}')

header('Daily trend - all included domains')
print(f'{"Date":<12} {"Page views":>12} {"Est. visitors":>14}')
cursor = start_date
while cursor <= end_date:
    day = cursor.isoformat()
    print(f'{day:<12} {daily[day,"__ALL__"]:>12} {len(daily_visitors[day,"__ALL__"]):>14}')
    cursor += dt.timedelta(days=1)
if DAILY_BY_DOMAIN:
    header('Daily summary by domain - likely-human')
    print(f'{"Date":<12} {"Domain":<42} {"Page views":>12} {"Est. visitors":>14}')
    for day, domain in sorted((d, dom) for d, dom in daily if dom != '__ALL__'):
        print(f'{day:<12} {domain:<42} {daily[day,domain]:>12} {len(daily_visitors[day,domain]):>14}')

header('Top pages by domain - likely-human page views')
for domain in sorted(raw):
    entries = sorted(((p, v) for (d,p),v in per_page.items() if d == domain), key=lambda x: (-x[1],x[0]))[:TOP_PAGES]
    if not entries:
        continue
    print(f'\n{domain}')
    print(f'  {"Views":>8} {"Visitors":>9}  Path')
    for path, n in entries:
        print(f'  {n:>8} {len(page_visitors[domain,path]):>9}  {path}')

header('Traffic classification - raw requests by domain')
print(f'{"Domain":<42} {"Internal":>10} {"Known bots":>12} {"Suspicious":>12} {"Eligible":>12}')
for domain in sorted(raw):
    print(f'{domain:<42} {classification[domain,"internal"]:>10} '
          f'{classification[domain,"known bot"]:>12} {classification[domain,"suspicious"]:>12} '
          f'{classification[domain,"eligible"]:>12}')

header('Known automated User-Agents - raw requests')
for name, count in bot_ua_names.most_common(20):
    print(f'{name:<32} {count:>10}')

header('Top suspicious IPs - raw requests')
print('Counts are suspicious-classified requests; internal traffic omitted; behavior evaluated per IP/day.')
print(f'{"IP":<40} {"Hits":>9} {"Domains":>8}  Reason')
for ip, count in scanner_hits.most_common(TOP_SUSPICIOUS):
    print(f'{ip:<40} {count:>9} {len(profiles[ip]["domains"]):>8}  {scanner_visible_reason[ip]}')

header('Top probe paths - all raw requests')
print(f'{"Hits":>10}  Path')
for path, hits in raw_probe_paths.most_common(TOP_ERRORS):
    print(f'{hits:>10}  {path}')

header('HTTP errors - raw and eligible requests')
print(f'{"Domain":<42} {"Raw 4xx":>11} {"Raw 5xx":>11} {"Eligible 4xx":>14} {"Eligible 5xx":>14}')
for domain in sorted(raw):
    print(f'{domain:<42} {errors_raw[domain,"4xx"]:>11} {errors_raw[domain,"5xx"]:>11} '
          f'{errors_filtered[domain,"4xx"]:>14} {errors_filtered[domain,"5xx"]:>14}')

header('Top HTTP 404 paths - eligible non-static, non-probe requests')
for domain in sorted(raw):
    entries = sorted(((p, v) for (d,p),v in top_404.items() if d == domain), key=lambda x: (-x[1], x[0]))[:TOP_ERRORS]
    if entries:
        print(f'\n{domain}')
        for path, count in entries:
            print(f'  {count:>8}  {path}')

# Keep the historical heading for the resolver compatibility.
header('Top IPs by domain - human-ish only')
for domain in sorted(raw):
    entries = sorted(((ip, v) for (d,ip), v in ip_pageviews.items() if d == domain), key=lambda x: (-x[1], x[0]))[:TOP_IPS]
    if entries:
        print(f'\n{domain}')
        print(f'{"IP":<40} {"Human-ish PV":>12}')
        print(f'{"--":<40} {"------------":>12}')
        for ip, n in entries:
            print(f'{ip:<40} {n:>12}')

print('\nNote: browser-mimicking bots cannot always be identified from Apache logs;')
print('missing JS telemetry means visitor counts are estimates, not verified people.')
print('Known scanner networks are excluded from analytics only; no firewall rules are modified.')
PY
