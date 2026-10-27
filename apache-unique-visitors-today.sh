#!/usr/bin/env bash
# Author: mnheia
# Copyright (c) 2026 mnheia
# Repository: https://github.com/mnheia/apache-tools
# License: GPL-3.0 (see LICENSE)
set -euo pipefail

# Daily report; shares parsing, classification and page-view logic with range script.
# Usage:
#   ./apache-unique-visitors-today.sh
#   ./apache-unique-visitors-today.sh 17/Jun/2026
#   ./apache-unique-visitors-today.sh 2026-06-17 /var/log/apache2
# The old RESOLVE_DNS option is replaced by the separate IP resolver.

DAY="${1:-$(LC_ALL=C date '+%d/%b/%Y')}"
LOG_ROOT="${2:-/var/log/apache2}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

command -v python3 >/dev/null 2>&1 || { echo 'ERROR: python3 is required' >&2; exit 1; }
DAY_ISO="$(LC_ALL=C python3 - "$DAY" <<'PY'
import datetime as dt
import sys
for fmt in ('%d/%b/%Y', '%Y-%m-%d'):
    try:
        print(dt.datetime.strptime(sys.argv[1], fmt).date().isoformat())
        break
    except ValueError:
        pass
else:
    raise SystemExit('ERROR: Date must be DD/Mon/YYYY or YYYY-MM-DD')
PY
)"

# A single day already fits on one trend line; print top pages, bots, errors and IPs too.
exec "$SCRIPT_DIR/apache-visitors-range.sh" "$DAY_ISO" "$DAY_ISO" "$LOG_ROOT"
