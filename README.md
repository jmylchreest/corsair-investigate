# scimitar-diag

eBPF diagnostic logger for the Corsair Scimitar **ghost-press / vanishing
side-button** firmware defect.

## The problem

Corsair Scimitar mice (Scimitar, Pro, RGB Elite, Elite Wireless / SE) have a
long-standing defect where the 12-button side grid intermittently either
**ghost-presses** (a press event is sent but the matching release never
arrives — the OS sees the button held forever, which locks the whole keyboard
if the button maps to a modifier) or **vanishes** (no input at all until the
mouse is unplugged and replugged). Reports go back to 2015 across every
hardware generation and both Windows and Linux; Corsair has never shipped a
root-cause fix. See [docs/RESEARCH.md](docs/RESEARCH.md) for the full
evidence trail.

This tool captures the data needed to prove *where* the release event is
lost, so a proper fix (a HID-BPF program that synthesises the missing
release) can be written and upstreamed.

## Architecture

Two independent capture layers bracket the kernel's HID parsing, giving a
differential diagnosis:

```
Corsair Scimitar firmware
        │
        │  USB HID interrupt report
        ▼
[Layer B] scimitar_hid.bpf.c   ←── HID-BPF struct_ops (raw bytes, pre-parse)
        │
        ▼
HID core / hid-generic report parsing
        │
        ▼
input subsystem — input_handle_event()
        │
[Layer A] scimitar_log.bpf.c   ←── kprobe (EV_KEY events, post-parse)
        │
        ▼
evdev → libinput → Wayland/X11 → applications
```

| Layer B shows release bytes | Layer A shows KEY_UP | Conclusion |
|---|---|---|
| no  | no  | firmware never sent it → **firmware bug confirmed** |
| yes | no  | kernel HID parsing bug → report upstream |
| yes | yes | problem is above evdev (compositor/app) |

Layer A logs **every `EV_KEY` event from every input device** (keyboard
included) with nanosecond timestamps, the originating device's name,
VID:PID and USB phys path. Capturing everything matters because:
side buttons remapped in hardware profiles arrive as *keyboard* keys, and
cross-device interactions (keyboard key + side button held simultaneously,
possibly with the same keycode) are a suspected trigger — the per-event
device identity lets analysis separate those streams.

## Quick start (Arch / CachyOS)

```sh
git clone https://github.com/jmylchreest/corsair-investigate
cd corsair-investigate
sudo ./install.sh
```

Requires kernel ≥ 5.8 with BTF (`/sys/kernel/btf/vmlinux`); Layer B
additionally needs `CONFIG_HID_BPF=y` (≥ 6.11 for the struct_ops API).
Both are standard on CachyOS kernels.

Verify it's running:

```sh
systemctl status scimitar-diag
tail -f /var/log/scimitar-diag/events.log    # press any key/button
```

## Marking a symptom

The moment you notice a stuck or dead button, stamp the time:

```sh
scimitar-mark "side button 4 stuck, ctrl locked"
```

Bind it to a hotkey so it's one keystroke away:

- **i3/sway**: `bindsym $mod+F12 exec scimitar-mark`
- **Hyprland**: `bind = $mainMod, F12, exec, scimitar-mark`
- **GNOME**: Settings → Keyboard → Custom Shortcuts → command `scimitar-mark`
- **KDE**: System Settings → Shortcuts → Custom Shortcuts → `scimitar-mark`

## Analysing

```sh
scimitar-query -w 30          # events ±30s around every marker
scimitar-decode --format table --device CORSAIR
scimitar-decode --format json --code BTN_SIDE
```

What a ghost press looks like in `scimitar-query` output:

```
=== SYMPTOM at 2026-06-12T14:23:01.123456789+01:00 ===
Description: "side buttons died"
Window: ±30 seconds

OFFSET_MS    CODE  CODENAME    VALUE    VID:PID   DEVICE                  ANNOTATION
-29843.210    275  BTN_SIDE    PRESS    1b1c:2b22 Corsair CORSAIR SCIMI…
-29701.876    275  BTN_SIDE    RELEASE  1b1c:2b22 Corsair CORSAIR SCIMI…
   -12.034    275  BTN_SIDE    PRESS    1b1c:2b22 Corsair CORSAIR SCIMI… [GHOST PRESS — never released]
+45200.118    275  BTN_SIDE    PRESS    1b1c:2b22 Corsair CORSAIR SCIMI…
```

A `PRESS` with no matching `RELEASE` on the same device within 500ms is
annotated as a ghost press (`-g <ms>` / `--ghost-ms` to tune; long
intentional holds of keyboard keys will trip the default threshold, so judge
mouse-button ghosts and keyboard ghosts separately).

## Layer B: raw HID capture

A `scimitar-diag-hid@hidrawN` instance is **auto-started by udev for every
Corsair hidraw node** the moment it appears, and stops when it vanishes.
hidraw numbers change on every replug — and replugging is exactly what you
do when the bug strikes — so udev ownership is what keeps wire-level
coverage across the failure/recovery cycle.

```sh
scimitar-find                                  # map nodes to interfaces
systemctl list-units 'scimitar-diag-hid@*'     # running captures
```

Output (`/var/log/scimitar-diag/hid_reports.hidrawN.log`) is hex-encoded,
one report per line. On the Elite Wireless SE, pointer traffic uses 15-byte
reports on the `input0` interface, while **side buttons arrive as keyboard
bitmap reports on the `input3` interface** (hardware-remap mode) — both are
captured.

## Next steps

Once logs confirm the firmware ghost-press pattern, the fix phase is a
HID-BPF quirk in the style of the kernel's
`drivers/hid/bpf/progs/IOGEAR__Kaliber-MMOmentum.bpf.c`: track button-bit
state per report, and when a press is observed with no release within a
threshold (or logically-impossible sequences appear), synthesise the release
report via `hid_bpf_input_report()` (kernel ≥ 6.9) driven by a `bpf_wq`
timer. That quirk is upstreamable via
[udev-hid-bpf](https://libevdev.pages.freedesktop.org/udev-hid-bpf/) →
kernel `drivers/hid/bpf/progs/`.

## Disk usage and pruning

Measured rates during active use: Layer A ~0.2MB/h; Layer B ~3MB/h on the
pointer interface (mouse-motion reports dominate), ~nothing on the others.
Rotation hard-caps every log at 100MB + one `.1` generation.

A daily timer (`scimitar-diag-prune.timer`, 04:00) shrinks this to almost
nothing: it keeps only events within **±10 minutes of a marker** plus a
**24-hour grace period** (data leading up to a symptom you haven't marked
yet), and drops the rest. Headers and markers are never pruned. Tune via
`PRUNE_WINDOW_MIN` / `PRUNE_GRACE_HOURS` in
`/etc/scimitar-diag/scimitar-diag.env`, or run manually:

```sh
sudo scimitar-prune --restart-services --window-min 10 --grace-hours 24
sudo scimitar-prune --dry-run ...        # preview only
```

(`--restart-services` briefly stops the capture daemons so the rewrite
can't race their open file descriptors.) Net effect: steady-state disk
usage is a few MB — one day of full-rate logs plus small slices around
each marker.

## Uninstall

```sh
sudo ./uninstall.sh    # keeps /var/log/scimitar-diag
```

## Licence

GPL-2.0-only (BPF programs and vendored kernel headers require it).
