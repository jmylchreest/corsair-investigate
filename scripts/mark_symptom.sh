#!/usr/bin/env bash
# Stamp "I just noticed the symptom" into the marker log.
# Usage: ./mark_symptom.sh ["optional description"]
# Suitable for a hotkey binding — fast, no subshell-heavy work.
set -euo pipefail

MARKERS="${SCIMITAR_DIAG_MARKERS:-/var/log/scimitar-diag/markers.log}"

ts_ns=$(date +%s%N)
iso=$(date +%Y-%m-%dT%H:%M:%S.%N%z)
desc="${1:-}"

printf '%s\t%s\t%s\n' "$ts_ns" "$iso" "$desc" >> "$MARKERS"
printf 'Marker written at %s\n' "${iso#*T}"
