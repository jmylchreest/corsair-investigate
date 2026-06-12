#!/usr/bin/env python3
"""scimitar-sidecar — detect Scimitar ghost-presses live and (optionally)
recover the device with a USB reset, auto-stamping a marker every time so
the always-running capture has a labelled window with the reason.

Detection: read the Scimitar's evdev nodes directly. A key whose PRESS has
been outstanding longer than --threshold-ms with no RELEASE is the ghost
signature (the firmware's keyboard endpoint has frozen mid-keypress — see
docs/FINDINGS.md). On detection we always write a marker describing which
button and how long; if --reset is enabled we then USBDEVFS_RESET the
device (a software replug) and record the result in the same marker.

Default is OBSERVE mode (marker only, no reset) so you can confirm the
pattern — e.g. "is it always KEY_MINUS?" via --stats — and tune the
threshold before arming the reset.

Recovery note: a USB reset re-enumerates the device, which both unsticks
the key and revives the dead buttons. Injecting a synthetic release from a
virtual device is deliberately NOT done here — evdev key state is
per-device, so only the real device (via the planned HID-BPF quirk) or a
reset can clear it reliably.
"""

import argparse
import ctypes
import errno
import fcntl
import glob
import os
import select
import sys
import time
from datetime import datetime, timezone

try:
    import evdev
    from evdev import ecodes
except ImportError:
    sys.exit("ERROR: python-evdev required (pacman -S python-evdev)")

DEFAULT_MARKERS = "/var/log/scimitar-diag/markers.log"
USBDEVFS_RESET = ord("U") << 8 | 20  # _IO('U', 20)

# minimal code->name (side buttons usually map to the number row)
CODE_NAMES = {
    ecodes.BTN_SIDE: "BTN_SIDE", ecodes.BTN_EXTRA: "BTN_EXTRA",
    ecodes.BTN_FORWARD: "BTN_FORWARD", ecodes.BTN_BACK: "BTN_BACK",
    ecodes.BTN_TASK: "BTN_TASK", ecodes.BTN_LEFT: "BTN_LEFT",
    ecodes.BTN_RIGHT: "BTN_RIGHT", ecodes.BTN_MIDDLE: "BTN_MIDDLE",
}
for _n in range(1, 11):
    CODE_NAMES[getattr(ecodes, f"KEY_{_n % 10}")] = f"KEY_{_n % 10}"
CODE_NAMES[ecodes.KEY_MINUS] = "KEY_MINUS"
CODE_NAMES[ecodes.KEY_EQUAL] = "KEY_EQUAL"


def code_name(code):
    return CODE_NAMES.get(code, ecodes.KEY.get(code, ecodes.BTN.get(code, f"code_{code}")))


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def find_evdev_nodes(vid, pid):
    """Scimitar event nodes by VID:PID (side buttons live on the kbd iface)."""
    nodes = []
    for path in glob.glob("/dev/input/event*"):
        try:
            d = evdev.InputDevice(path)
            if d.info.vendor == vid and d.info.product == pid:
                nodes.append(d)
            else:
                d.close()
        except (OSError, PermissionError):
            continue
    return nodes


def find_usb_sysfs(vid, pid):
    """Map VID:PID to its /sys/bus/usb/devices/<X> directory."""
    want_v, want_p = f"{vid:04x}", f"{pid:04x}"
    for d in glob.glob("/sys/bus/usb/devices/*"):
        try:
            if (open(os.path.join(d, "idVendor")).read().strip() == want_v and
                    open(os.path.join(d, "idProduct")).read().strip() == want_p):
                return d
        except OSError:
            continue
    return None


def find_usb_devnode(vid, pid):
    """Map VID:PID to /dev/bus/usb/BBB/DDD for USBDEVFS_RESET."""
    d = find_usb_sysfs(vid, pid)
    if not d:
        return None
    try:
        busnum = int(open(os.path.join(d, "busnum")).read())
        devnum = int(open(os.path.join(d, "devnum")).read())
        return f"/dev/bus/usb/{busnum:03d}/{devnum:03d}"
    except (OSError, ValueError):
        return None


def usb_reset(vid, pid, method):
    """Recover the device. Returns (ok, detail). Methods, weakest first:
      bus-reset   USBDEVFS_RESET — USB bus-level reset, ~0.5s, device stays
                  powered. Re-inits the USB stack but NOT the MCU.
      reauthorize echo 0/1 > authorized — de-configure + re-configure, a
                  closer approximation of a replug (still no power cut).
      rebind      unbind/rebind the usb device from the usb driver.
    A true power cycle (VBUS off) needs external port-power control
    (uhubctl) and only works on hubs with per-port power switching."""
    if method == "bus-reset":
        node = find_usb_devnode(vid, pid)
        if not node:
            return False, "usb node not found"
        try:
            fd = os.open(node, os.O_WRONLY)
        except OSError as e:
            return False, f"open {node}: {e.strerror}"
        try:
            fcntl.ioctl(fd, USBDEVFS_RESET, 0)
            return True, f"USBDEVFS_RESET on {node}"
        except OSError as e:
            return False, f"ioctl: {e.strerror}"
        finally:
            os.close(fd)

    sysfs = find_usb_sysfs(vid, pid)
    if not sysfs:
        return False, "usb sysfs not found"
    busid = os.path.basename(sysfs)

    if method == "reauthorize":
        try:
            with open(os.path.join(sysfs, "authorized"), "w") as f:
                f.write("0")
            time.sleep(0.3)
            with open(os.path.join(sysfs, "authorized"), "w") as f:
                f.write("1")
            return True, f"reauthorized {busid}"
        except OSError as e:
            return False, f"authorized: {e.strerror}"

    if method == "rebind":
        try:
            with open("/sys/bus/usb/drivers/usb/unbind", "w") as f:
                f.write(busid)
            time.sleep(0.3)
            with open("/sys/bus/usb/drivers/usb/bind", "w") as f:
                f.write(busid)
            return True, f"rebound {busid}"
        except OSError as e:
            return False, f"rebind: {e.strerror}"

    return False, f"unknown method {method}"


def write_marker(path, reason):
    ts_ns = time.time_ns()
    iso = datetime.now().astimezone().isoformat()
    try:
        with open(path, "a") as f:
            f.write(f"{ts_ns}\t{iso}\t{reason}\n")
    except OSError as e:
        log(f"WARNING: cannot write marker: {e}")


def stats(path):
    """Tabulate AUTO markers by button — answers 'is it always X?'."""
    from collections import Counter
    counts, total = Counter(), 0
    try:
        for line in open(path):
            parts = line.rstrip("\n").split("\t", 2)
            if len(parts) == 3 and parts[2].startswith("AUTO"):
                total += 1
                # reason like: "AUTO ghost KEY_MINUS (code 12) ..."
                toks = parts[2].split()
                name = toks[2] if len(toks) > 2 else "?"
                counts[name] += 1
    except OSError as e:
        sys.exit(f"ERROR: {e}")
    if not total:
        print("No AUTO detections recorded yet.")
        return
    print(f"{total} auto-detected ghost presses:")
    for name, n in counts.most_common():
        print(f"  {n:5d}  {name}  ({100*n/total:.0f}%)")


def run(args):
    vid, pid = args.vid, args.pid
    threshold = args.threshold_ms / 1000.0
    devices = find_evdev_nodes(vid, pid)
    if not devices:
        log(f"no evdev nodes for {vid:04x}:{pid:04x} yet; will keep scanning")
    log(f"watching {len(devices)} node(s); threshold={args.threshold_ms}ms "
        f"reset={'ON' if args.reset else 'OFF (observe)'} "
        f"cooldown={args.cooldown_s}s")
    if args.codes:
        log(f"restricted to codes: {sorted(args.codes)}")

    outstanding = {}   # (devpath, code) -> press_monotonic
    handled = set()    # (devpath, code) already markered for this hold
    last_reset = 0.0
    last_scan = 0.0

    while True:
        # periodic rescan picks up replug / post-reset re-enumeration
        now = time.monotonic()
        if now - last_scan > 2.0:
            live = {d.path for d in devices}
            current = {d.path for d in find_evdev_nodes(vid, pid)}
            if current != live:
                for d in devices:
                    try:
                        d.close()
                    except OSError:
                        pass
                devices = find_evdev_nodes(vid, pid)
                outstanding.clear()
                handled.clear()
                log(f"device set changed -> watching {len(devices)} node(s)")
            last_scan = now

        fds = {d.fd: d for d in devices}
        try:
            r, _, _ = select.select(fds.keys(), [], [], 0.2) if fds else ([], [], [])
        except OSError:
            r = []
        if not fds:
            time.sleep(0.5)

        for fd in r:
            dev = fds[fd]
            try:
                for ev in dev.read():
                    if ev.type != ecodes.EV_KEY:
                        continue
                    if args.codes and ev.code not in args.codes:
                        continue
                    key = (dev.path, ev.code)
                    if ev.value == 1:            # press
                        outstanding[key] = time.monotonic()
                    elif ev.value == 0:          # release
                        outstanding.pop(key, None)
                        handled.discard(key)
                    # value==2 (autorepeat) ignored: don't refresh the clock
            except OSError as e:
                if e.errno in (errno.ENODEV, errno.EBADF):
                    log(f"node {dev.path} vanished")
                    last_scan = 0  # force rescan

        # check for overdue presses
        now = time.monotonic()
        for key, t0 in list(outstanding.items()):
            held = now - t0
            if held < threshold or key in handled:
                continue
            devpath, code = key
            handled.add(key)
            name = code_name(code)
            held_ms = int(held * 1000)
            reason = (f"AUTO ghost {name} (code {code}) on {os.path.basename(devpath)} "
                      f"held {held_ms}ms no release")
            action = ""
            if args.reset:
                if now - last_reset < args.cooldown_s:
                    action = "; reset SKIPPED (cooldown)"
                else:
                    ok, detail = usb_reset(vid, pid, args.reset_method)
                    action = f"; reset {'OK' if ok else 'FAILED'} ({detail})"
                    if ok:
                        last_reset = now
                        last_scan = 0  # device will re-enumerate
            write_marker(args.markers, reason + action)
            log(reason + action)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vid", type=lambda s: int(s, 16),
                    default=int(os.environ.get("SIDECAR_VID", "1b1c"), 16))
    ap.add_argument("--pid", type=lambda s: int(s, 16),
                    default=int(os.environ.get("SIDECAR_PID", "2b22"), 16))
    ap.add_argument("--threshold-ms", type=int,
                    default=int(os.environ.get("SIDECAR_THRESHOLD_MS", "1500")),
                    help="press held longer than this with no release = ghost")
    ap.add_argument("--reset", action="store_true",
                    default=os.environ.get("SIDECAR_RESET", "0") == "1",
                    help="USBDEVFS_RESET the device on detection (default: observe only)")
    ap.add_argument("--reset-method",
                    default=os.environ.get("SIDECAR_RESET_METHOD", "bus-reset"),
                    choices=["bus-reset", "reauthorize", "rebind"],
                    help="recovery method, weakest first (default bus-reset, ~0.5s)")
    ap.add_argument("--cooldown-s", type=float,
                    default=float(os.environ.get("SIDECAR_COOLDOWN_S", "10")),
                    help="minimum seconds between resets")
    ap.add_argument("--codes", default=os.environ.get("SIDECAR_CODES", ""),
                    help="comma-separated keycodes to watch (default: all)")
    ap.add_argument("--markers", default=os.environ.get("SIDECAR_MARKERS", DEFAULT_MARKERS))
    ap.add_argument("--stats", action="store_true",
                    help="print a tally of auto-detections by button and exit")
    args = ap.parse_args()
    args.codes = {int(c) for c in args.codes.split(",") if c.strip()} if args.codes else set()

    if args.stats:
        stats(args.markers)
        return
    try:
        run(args)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
