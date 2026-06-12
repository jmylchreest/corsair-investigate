#!/usr/bin/env python3
"""Decode scimitar-diag event logs into human-readable output.

Usage:
  decode_events.py [--input events.log] [--format table|json|csv]
                   [--since <iso_datetime>] [--until <iso_datetime>]
                   [--device <substring>] [--code <keycode_int_or_name>]
                   [--ghost-ms 500]

Reads the log header for boot_ns_offset, converts ts_boot to wall-clock
ISO 8601, resolves key codes to names, and annotates ghost presses
(a PRESS with no RELEASE on the same device+code within --ghost-ms).
"""

import argparse
import csv
import json
import re
import sys
from datetime import datetime, timezone

DEFAULT_LOG = "/var/log/scimitar-diag/events.log"
INPUT_CODES_HEADER = "/usr/include/linux/input-event-codes.h"

# Fallback table, used when the kernel uapi header is unavailable.
BUILTIN_CODES = {
    1: "KEY_ESC", 14: "KEY_BACKSPACE", 15: "KEY_TAB", 28: "KEY_ENTER",
    29: "KEY_LEFTCTRL", 42: "KEY_LEFTSHIFT", 54: "KEY_RIGHTSHIFT",
    56: "KEY_LEFTALT", 57: "KEY_SPACE", 97: "KEY_RIGHTCTRL",
    100: "KEY_RIGHTALT", 125: "KEY_LEFTMETA", 126: "KEY_RIGHTMETA",
    272: "BTN_LEFT", 273: "BTN_RIGHT", 274: "BTN_MIDDLE",
    275: "BTN_SIDE", 276: "BTN_EXTRA", 277: "BTN_FORWARD",
    278: "BTN_BACK", 279: "BTN_TASK",
}
# digits row KEY_1..KEY_0 = 2..11 (common Scimitar hardware-remap targets)
for i, k in enumerate(range(2, 12)):
    BUILTIN_CODES[k] = f"KEY_{(i + 1) % 10}"
# extended mouse buttons (Scimitar 12-button grid)
for k in range(280, 288):
    BUILTIN_CODES[k] = f"BTN_{k:#x}"

VALUE_NAMES = {0: "RELEASE", 1: "PRESS", 2: "REPEAT"}


def load_code_names():
    """Prefer the kernel uapi header so every code resolves."""
    names = dict(BUILTIN_CODES)
    try:
        with open(INPUT_CODES_HEADER) as f:
            text = f.read()
        defs = {}
        for m in re.finditer(
            r"#define\s+((?:KEY|BTN)_\w+)\s+(0x[0-9a-fA-F]+|\d+)(?:\s|$)", text
        ):
            name, val = m.group(1), int(m.group(2), 0)
            # keep the first (canonical) name for each code
            if val not in defs and not name.endswith(("_MAX", "_CNT")):
                defs[val] = name
        names.update({k: v for k, v in defs.items() if k not in names or True})
        # canonical names from header win over builtin fallbacks
        names.update(defs)
    except OSError:
        pass
    return names


CODE_NAMES = load_code_names()


def code_name(code: int) -> str:
    if code in CODE_NAMES:
        return CODE_NAMES[code]
    return f"{'BTN' if 0x100 <= code < 0x160 else 'KEY'}_{code}"


def parse_code_arg(arg: str) -> int:
    try:
        return int(arg, 0)
    except ValueError:
        for k, v in CODE_NAMES.items():
            if v == arg.upper():
                return k
        sys.exit(f"ERROR: unknown key code/name: {arg}")


def parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt


def read_events(path):
    """Yield event dicts; tracks boot_ns_offset across header lines."""
    offset_ns = None
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#"):
                m = re.search(r"boot_ns_offset=(-?\d+)", line)
                if m:
                    offset_ns = int(m.group(1))
                continue
            parts = line.split("\t")
            if len(parts) < 8:
                print(f"WARNING: malformed line {lineno}", file=sys.stderr)
                continue
            ts_ns, ts_boot, etype, code, value = map(int, parts[:5])
            vidpid, devname, phys = parts[5], parts[6], parts[7]
            wall_ns = ts_boot + offset_ns if offset_ns is not None else None
            yield {
                "ts_ns": ts_ns,
                "ts_boot": ts_boot,
                "wall_ns": wall_ns,
                "type": etype,
                "code": code,
                "value": value,
                "vidpid": vidpid,
                "device": devname,
                "phys": phys,
            }


def annotate_ghosts(events, ghost_ms: int):
    """Mark PRESS events that get no RELEASE within ghost_ms.

    Keyed on (phys, code) so the same keycode on different devices is
    tracked independently (keyboard KEY_1 vs side-button-as-KEY_1).
    """
    events = list(events)
    ghost_ns = ghost_ms * 1_000_000
    open_press = {}  # (phys, code) -> index of last unmatched press
    for i, e in enumerate(events):
        key = (e["phys"], e["code"])
        e["ghost"] = False
        e["release_after_ms"] = None
        if e["value"] == 1:
            open_press[key] = i
        elif e["value"] == 0 and key in open_press:
            pi = open_press.pop(key)
            dt = e["ts_boot"] - events[pi]["ts_boot"]
            events[pi]["release_after_ms"] = dt / 1e6
            if dt > ghost_ns:
                events[pi]["ghost"] = True
    # presses never released at all by end of log
    for pi in open_press.values():
        events[pi]["ghost"] = True
        events[pi]["release_after_ms"] = None
    return events


def wall_iso(e):
    if e["wall_ns"] is None:
        return f"boot+{e['ts_boot'] / 1e9:.6f}s"
    dt = datetime.fromtimestamp(e["wall_ns"] / 1e9, tz=timezone.utc).astimezone()
    return dt.isoformat(timespec="microseconds")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", default=DEFAULT_LOG)
    ap.add_argument("--format", choices=["table", "json", "csv"], default="table")
    ap.add_argument("--since", type=parse_iso)
    ap.add_argument("--until", type=parse_iso)
    ap.add_argument("--device", help="device name substring filter")
    ap.add_argument("--code", help="keycode (int) or name (e.g. BTN_SIDE)")
    ap.add_argument("--ghost-ms", type=int, default=500,
                    help="press with no release within this window = ghost")
    args = ap.parse_args()

    code_filter = parse_code_arg(args.code) if args.code else None

    try:
        events = list(read_events(args.input))
    except OSError as e:
        sys.exit(f"ERROR: cannot read {args.input}: {e}")

    # ghost detection runs on the full stream so filters don't hide releases
    events = annotate_ghosts(events, args.ghost_ms)

    def keep(e):
        if args.device and args.device.lower() not in e["device"].lower():
            return False
        if code_filter is not None and e["code"] != code_filter:
            return False
        if (args.since or args.until) and e["wall_ns"] is None:
            return False
        if args.since and e["wall_ns"] < args.since.timestamp() * 1e9:
            return False
        if args.until and e["wall_ns"] > args.until.timestamp() * 1e9:
            return False
        return True

    events = [e for e in events if keep(e)]

    if args.format == "json":
        for e in events:
            out = dict(e, wall_clock=wall_iso(e), codename=code_name(e["code"]),
                       value_name=VALUE_NAMES.get(e["value"], str(e["value"])))
            print(json.dumps(out))
    elif args.format == "csv":
        w = csv.writer(sys.stdout)
        w.writerow(["wall_clock", "ts_boot", "code", "codename", "value",
                    "vidpid", "device", "phys", "ghost"])
        for e in events:
            w.writerow([wall_iso(e), e["ts_boot"], e["code"],
                        code_name(e["code"]),
                        VALUE_NAMES.get(e["value"], e["value"]),
                        e["vidpid"], e["device"], e["phys"], e["ghost"]])
    else:
        fmt = "{:<32} {:>5} {:<16} {:<8} {:<9} {:<28} {}"
        print(fmt.format("WALL_CLOCK", "CODE", "CODENAME", "VALUE",
                         "VID:PID", "DEVICE", "ANNOTATION"))
        ghosts = 0
        for e in events:
            note = ""
            if e["ghost"]:
                ghosts += 1
                if e["release_after_ms"] is None:
                    note = "[GHOST PRESS — never released]"
                else:
                    note = (f"[GHOST PRESS — released after "
                            f"{e['release_after_ms']:.1f}ms]")
            print(fmt.format(wall_iso(e), e["code"], code_name(e["code"]),
                             VALUE_NAMES.get(e["value"], str(e["value"])),
                             e["vidpid"], e["device"][:28], note))
        print(f"\n{len(events)} events, {ghosts} ghost presses "
              f"(threshold {args.ghost_ms}ms)", file=sys.stderr)


if __name__ == "__main__":
    main()
