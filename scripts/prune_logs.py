#!/usr/bin/env python3
"""Prune scimitar-diag logs down to the data that matters.

Keeps a log line if it falls within ±--window-min of any marker, or is
newer than --grace-hours (a symptom may not have been marked yet).
Header lines (# scimitar-diag ... boot_ns_offset=...) are always kept —
they carry the clock offset every other tool needs. Markers are never
pruned.

The capture daemons hold open file descriptors, so rewriting their logs
behind their backs would lose in-flight writes; --restart-services
stops them, prunes, and starts them again (a ~2s capture gap).
"""

import argparse
import glob
import os
import re
import subprocess
import sys
import tempfile
import time

LOG_DIR = "/var/log/scimitar-diag"
SERVICES_GLOB = ["scimitar-diag.service", "scimitar-diag-hid@*.service"]


def read_markers(path):
    """Marker timestamps in realtime ns."""
    ts = []
    try:
        with open(path) as f:
            for line in f:
                parts = line.split("\t")
                if parts and parts[0].strip().isdigit():
                    ts.append(int(parts[0]))
    except OSError:
        pass
    return sorted(ts)


def near_marker(wall_ns, markers, window_ns):
    # markers per box are few (handful per investigation): linear scan fine
    return any(abs(wall_ns - m) <= window_ns for m in markers)


def prune_file(path, markers, window_ns, grace_cutoff_ns, dry_run):
    """Returns (kept, dropped, bytes_saved)."""
    kept = dropped = 0
    offset_ns = None
    size_before = os.path.getsize(path)
    out_lines = []

    with open(path) as f:
        for line in f:
            if line.startswith("#"):
                m = re.search(r"boot_ns_offset=(-?\d+)", line)
                if m:
                    offset_ns = int(m.group(1))
                out_lines.append(line)
                continue
            cols = line.split("\t", 3)
            # events.log: col1=ts_boot; hid_reports: col0=ts_boot
            ts_col = cols[1] if len(cols) >= 7 else cols[0]
            try:
                ts_boot = int(ts_col)
            except ValueError:
                out_lines.append(line)  # malformed: keep, never destroy
                kept += 1
                continue
            if offset_ns is None:
                out_lines.append(line)  # can't convert: keep
                kept += 1
                continue
            wall = ts_boot + offset_ns
            if wall >= grace_cutoff_ns or near_marker(wall, markers, window_ns):
                out_lines.append(line)
                kept += 1
            else:
                dropped += 1

    if dry_run or dropped == 0:
        return kept, dropped, sum(len(l) for l in out_lines) - size_before

    st = os.stat(path)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w") as f:
            f.writelines(out_lines)
        os.chmod(tmp, st.st_mode & 0o7777)
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except PermissionError:
            pass  # unprivileged run on a file we own: keep our ownership
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise
    return kept, dropped, os.path.getsize(path) - size_before


def systemctl(verb):
    units = []
    for pat in SERVICES_GLOB:
        r = subprocess.run(
            ["systemctl", "list-units", "--plain", "--no-legend", pat],
            capture_output=True, text=True)
        units += [l.split()[0] for l in r.stdout.splitlines() if l.split()]
    if units:
        subprocess.run(["systemctl", verb] + units, check=False)
    return units


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", default=LOG_DIR)
    ap.add_argument("--markers", default=None,
                    help=f"markers file (default <dir>/markers.log)")
    ap.add_argument("--window-min", type=float, default=10,
                    help="keep events within ±N minutes of a marker")
    ap.add_argument("--grace-hours", type=float, default=24,
                    help="always keep events newer than this")
    ap.add_argument("--restart-services", action="store_true",
                    help="stop capture services during prune, restart after")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    markers_path = args.markers or os.path.join(args.dir, "markers.log")
    markers = read_markers(markers_path)
    window_ns = int(args.window_min * 60 * 1e9)
    grace_cutoff_ns = int((time.time() - args.grace_hours * 3600) * 1e9)

    targets = sorted(
        p for pat in ("events.log*", "hid_reports.*.log*")
        for p in glob.glob(os.path.join(args.dir, pat)))
    if not targets:
        print(f"nothing to prune in {args.dir}")
        return

    stopped = []
    if args.restart_services and not args.dry_run:
        stopped = systemctl("stop")
    try:
        total_saved = 0
        for path in targets:
            kept, dropped, delta = prune_file(
                path, markers, window_ns, grace_cutoff_ns, args.dry_run)
            total_saved -= delta
            tag = " (dry-run)" if args.dry_run else ""
            print(f"{path}: kept {kept}, dropped {dropped}, "
                  f"saved {-delta / 1024:.1f} KiB{tag}")
        print(f"total saved: {total_saved / 1024:.1f} KiB "
              f"({len(markers)} markers, ±{args.window_min}min window, "
              f"{args.grace_hours}h grace)")
    finally:
        if stopped:
            systemctl("start")


if __name__ == "__main__":
    main()
