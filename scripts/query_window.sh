#!/usr/bin/env bash
# For each symptom marker, print all events within ±N seconds with
# ghost-press annotation.
# Usage: ./query_window.sh [-w <seconds>] [-l <events_log>] [-m <markers_log>]
set -euo pipefail

WINDOW=30
EVENTS="/var/log/scimitar-diag/events.log"
MARKERS="/var/log/scimitar-diag/markers.log"
GHOST_MS=500

while getopts "w:l:m:g:h" opt; do
    case $opt in
        w) WINDOW=$OPTARG ;;
        l) EVENTS=$OPTARG ;;
        m) MARKERS=$OPTARG ;;
        g) GHOST_MS=$OPTARG ;;
        h|*) echo "Usage: $0 [-w seconds] [-l events_log] [-m markers_log] [-g ghost_ms]" >&2
             exit 0 ;;
    esac
done

[[ -r $EVENTS ]]  || { echo "ERROR: events log not readable: $EVENTS" >&2; exit 1; }
[[ -r $MARKERS ]] || { echo "ERROR: markers log not readable: $MARKERS (run mark_symptom.sh first)" >&2; exit 1; }
[[ -s $MARKERS ]] || { echo "No markers recorded yet." >&2; exit 0; }

# Include rotated log so a marker near rotation still finds its events.
LOGS=()
[[ -r $EVENTS.1 ]] && LOGS+=("$EVENTS.1")
LOGS+=("$EVENTS")

awk -F'\t' -v window="$WINDOW" -v ghost_ms="$GHOST_MS" '
function codename(c) {
    if (c in CN) return CN[c]
    return (c >= 256 && c < 352 ? "BTN_" c : "KEY_" c)
}
function valname(v) { return v == 0 ? "RELEASE" : v == 1 ? "PRESS" : "REPEAT" }

BEGIN {
    CN[272]="BTN_LEFT"; CN[273]="BTN_RIGHT"; CN[274]="BTN_MIDDLE"
    CN[275]="BTN_SIDE"; CN[276]="BTN_EXTRA"; CN[277]="BTN_FORWARD"
    CN[278]="BTN_BACK"; CN[279]="BTN_TASK"
    CN[29]="KEY_LEFTCTRL"; CN[42]="KEY_LEFTSHIFT"; CN[56]="KEY_LEFTALT"
    CN[125]="KEY_LEFTMETA"
    for (i = 2; i <= 11; i++) CN[i] = "KEY_" (i - 1) % 10
    nev = 0
}

# markers file: pass 1 (FNR==NR over first file)
FNR == NR {
    if ($0 ~ /^#/ || NF < 2) next
    nm++; m_ts[nm] = $1; m_iso[nm] = $2; m_desc[nm] = (NF >= 3 ? $3 : "")
    next
}

# events files
/^#/ {
    if (match($0, /boot_ns_offset=-?[0-9]+/))
        offset = substr($0, RSTART + 15, RLENGTH - 15) + 0
    next
}
NF >= 8 {
    nev++
    e_wall[nev] = $2 + offset   # ts_boot + offset = realtime ns
    e_code[nev] = $4; e_val[nev] = $5
    e_vidpid[nev] = $6; e_dev[nev] = $7; e_phys[nev] = $8
}

END {
    if (nm == 0) { print "No markers found." > "/dev/stderr"; exit 0 }

    # ghost detection over the full event stream, keyed by phys+code
    for (i = 1; i <= nev; i++) {
        k = e_phys[i] SUBSEP e_code[i]
        if (e_val[i] == 1) {
            open_press[k] = i
        } else if (e_val[i] == 0 && (k in open_press)) {
            p = open_press[k]
            dt_ms = (e_wall[i] - e_wall[p]) / 1e6
            released_after[p] = dt_ms
            if (dt_ms > ghost_ms) ghost[p] = 1
            delete open_press[k]
        }
    }
    for (k in open_press) { ghost[open_press[k]] = 1; never_released[open_press[k]] = 1 }

    for (m = 1; m <= nm; m++) {
        printf "\n=== SYMPTOM at %s ===\n", m_iso[m]
        if (m_desc[m] != "") printf "Description: \"%s\"\n", m_desc[m]
        printf "Window: ±%d seconds\n\n", window
        printf "%-12s %5s  %-16s %-8s %-9s %-28s %s\n", \
               "OFFSET_MS", "CODE", "CODENAME", "VALUE", "VID:PID", "DEVICE", "ANNOTATION"

        lo = m_ts[m] - window * 1e9
        hi = m_ts[m] + window * 1e9
        shown = 0
        for (i = 1; i <= nev; i++) {
            if (e_wall[i] < lo || e_wall[i] > hi) continue
            shown++
            note = ""
            if (ghost[i]) {
                if (never_released[i])
                    note = "[GHOST PRESS — never released]"
                else
                    note = sprintf("[GHOST PRESS — released after %.1fms]", released_after[i])
            }
            printf "%+12.3f %5d  %-16s %-8s %-9s %-28.28s %s\n", \
                   (e_wall[i] - m_ts[m]) / 1e6, e_code[i], codename(e_code[i]), \
                   valname(e_val[i]), e_vidpid[i], e_dev[i], note
        }
        if (shown == 0)
            print "(no events in window — was the daemon running?)"
    }
}
' "$MARKERS" "${LOGS[@]}"
