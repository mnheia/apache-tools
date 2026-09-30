Copyright (c) 2026, Mnheia <mnheia@gmail.com>

# apache-tools
Bash utilities for Apache log analysis, visitor statistics, IP resolution and MPM health monitoring.

## Scripts

### apache-unique-visitors-today.sh
Analyzes Apache access logs for one day, summarizes hits and unique client IPs per domain, and can optionally resolve client addresses with reverse DNS.

It supports common Apache access-log layouts, including per-vhost log directories and Debian-style `vhost_combined` logs, and reads rotated gzip logs.

```bash
./apache-unique-visitors-today.sh
./apache-unique-visitors-today.sh 30/Sep/2026
./apache-unique-visitors-today.sh 30/Sep/2026 /var/log/apache2
```

Set `RESOLVE_DNS=0` to disable reverse DNS lookups.

### apache-visitors-range.sh
Analyzes Apache access logs over a date range with optional filtering for bots, private addresses, static files, HTTP status classes and excluded domains.

```bash
./apache-visitors-range.sh 2026-09-01 2026-09-30 /var/log/apache2
```

Useful environment variables include:

- `FILTER_BOTS`
- `EXCLUDE_PRIVATE_IPS`
- `EXCLUDE_STATIC`
- `ONLY_STATUS_2XX_3XX`
- `EXCLUDE_DOMAINS`
- `TOP_IPS`

### resolve-apache-top-ips.sh
Takes the report produced by `apache-visitors-range.sh` and enriches the top IPv4 clients with reverse DNS, Team Cymru ASN information and optional GeoLite2 data when `mmdblookup` and a GeoLite2 City database are available.

```bash
./apache-visitors-range.sh > apache-report.txt
./resolve-apache-top-ips.sh apache-report.txt
```

The default output is `resolved-top-ips.tsv`.

### check-apache-mpm.sh
Checks Apache service state, configuration syntax, active MPM settings, theoretical worker capacity, recent worker-saturation messages, live `mod_status` worker usage and basic memory consumption.

The output uses Nagios-style exit codes:

- `0` OK
- `1` WARNING
- `2` CRITICAL

By default the script queries:

```text
http://127.0.0.1/server-status?auto
```

Override it with `STATUS_URL` when required.

Example:

```bash
WARN_PCT=80 CRIT_PCT=90 ./check-apache-mpm.sh
```

## mod_status configuration
`mod_status.conf.example` contains a minimal configuration for `check-apache-mpm.sh`.

On Debian/Ubuntu, for example:

```bash
cp mod_status.conf.example /etc/apache2/conf-available/mod_status.conf
a2enmod status
a2enconf mod_status
systemctl reload apache2
```

The example permits localhost access only. Add trusted monitoring networks explicitly if remote access is required. Avoid exposing `/server-status` publicly.

## Requirements
Depending on the script:

- Bash
- Apache/httpd
- GNU core utilities
- `awk`, `grep`, `sed`, `find`, `sort`
- `gzip` for rotated compressed logs
- `curl` for `check-apache-mpm.sh`
- `dig` or another resolver for reverse-DNS enrichment
- optional `mmdblookup` with a GeoLite2 City database

## Privacy
Apache reports may contain visitor IP addresses, hostnames and requested domains or paths. Review generated reports before sharing them externally.

## Bugs
Please report bugs or feature requests through the web interface at https://github.com/mnheia/apache-tools/issues