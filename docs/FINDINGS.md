# Findings: ghost-press root cause confirmed (2026-06-12)

Two live captures on a Scimitar Elite Wireless SE (`1b1c:2b22`, wired
connection), both with full Layer A (evdev) + Layer B (raw HID) coverage.

> **Full evidence corpus** (writeup + filtered Layer A/B data for both
> captures):
> https://gist.github.com/jmylchreest/8ab9e19099328cc76157599b34b36e06

## Capture 1 — marker 18:33:08, side button 3 (KEY_3)

- Layer A: minutes of clean press/release pairs, then at marker−6.501s a
  PRESS with **no release**. Userspace key state stuck down ~14.9s.
- Layer B (side-button interface, report id `01` + usage bitmap): wire
  alternates press/release cleanly (−338ms, −248ms, −173ms, −63ms), then
  the press report `01 00 00 00 00 00 01 00…` (KEY_3 bit 32 set) at T+0 is
  **the last report the interface ever transmitted**. No release bytes.
- Pointer interface on the same cable kept streaming motion reports for
  **9.3 more seconds**, until re-enumeration (manual replug) at ~T+12s.

## Capture 2 — marker 18:47:10, side button 11 (KEY_MINUS)

Identical signature on the post-replug device instance:

- Layer A: PRESS at marker−5.732s, no release, stuck ~12.7s.
- Layer B: final report from the side-button interface is
  `…00 20…` (KEY_MINUS bit 45 set) — frozen mid-keypress, then silence.
- Pointer interface alive for **8.5 more seconds** until replug.

## Conclusion

| Evidence | Implication |
|---|---|
| Release absent at Layer B and Layer A | Not a kernel/parsing/host bug |
| Pointer endpoint healthy while side-button endpoint frozen | Not USB, not cable, not the link |
| Reproduces wired and via dongle (owner report) | Not RF |
| Replug (firmware reset) restores function | Firmware state corruption |

**The firmware's side-button (keyboard) endpoint handler dies mid-keypress:
it sends a press report and then stops transmitting on that endpoint
entirely, while the rest of the device continues to function.** The
"ghost press" and the "vanished buttons" are the same failure: the stuck
key is the last report before the freeze; the dead buttons are the
silence after it.

Matrix-scan timing notes: both failures occurred during rapid button
mashing (~5–10 presses/sec), suggesting a race in the firmware's
matrix-scan/report queue under load.

## Capture 3 — side button KEY_4 (auto-detected, 2026-06-12 21:33)

First freeze caught by the sidecar rather than a manual marker. KEY_4 (code
5) pressed, no release; sidecar flagged it at the 3s threshold; the watcher
confirmed the device was replugged while the key was still held (~15s
stuck, consistent with captures 1–2). Sidecar was in observe mode so no
reset was attempted.

Across the three captures the stuck button was **KEY_3, KEY_MINUS, KEY_4** —
a different side button each time, confirming the freeze is a property of
the whole side-button grid/path, not one defective switch.

**Detector-tuning lesson:** an early threshold-only sidecar (any key held
>1.5s) produced 194 false positives in ~2h, 98% of them `BTN_RIGHT` — i.e.
ordinary right-click-and-hold. Restricting to the side-button keycodes
(2–13, the keyboard interface) and raising the threshold to 3s eliminated
them. A stuck-key detector must scope to the affected interface; raw "key
held too long" is dominated by legitimate mouse-button holds.

## Recovery-method evaluation (2026-06-12) — the USB-reset approach is compromised

Live testing on the device produced three hard results that redirect the fix:

1. **No passive hold-vs-freeze discriminator exists.** During a genuine
   6.7s hold, the keyboard interface emitted exactly two raw HID reports —
   the press and, 6.7s later, the release — with total silence between.
   The Scimitar sends no HID idle resends, so a genuine hold and a freeze
   are byte-identical at *both* the evdev and raw-HID layers. The only
   difference is that a hold eventually releases and a freeze never does.
   ⇒ detection can only be a timeout.

2. **`USBDEVFS_RESET` (bus-reset) does not clear a stuck key.** It is fast
   (~0.5s) and safe, but the kernel keeps the input device bound across it
   (no `input_unregister`), so a logically-held key stays held — the
   keyboard-lock symptom would persist even after the reset.

3. **`reauthorize` / `rebind` clear the key but can wedge the device.**
   They *do* tear the input devices down (udev shows the full remove set —
   `input_unregister` releases held keys), but in testing this left the
   device in a state that only a **physical replug** recovered. As
   automatic recovery they are unsafe: they can turn a recoverable freeze
   into a hard lockup. (Consistent with buggy firmware that mishandles USB
   re-configuration.)

**Conclusion:** no USB-reset method is both safe *and* effective — the safe
one doesn't fix the stuck key, the effective ones can brick until replug.
The stuck-key symptom (the disruptive one — a locked modifier) should
instead be fixed by the **HID-BPF quirk injecting the missing release
report directly on the device** (`hid_bpf_input_report`): it clears the key
at the HID layer instantly, never touches USB configuration, and cannot
wedge the device. The residual "buttons dead until replug" is not solvable
in software, but it is the benign half of the failure. Auto-reset is left
disabled (observe mode) pending the BPF quirk.

## Firmware-side root cause

Static RE of the firmware image (`docs/FIRMWARE_RE.md`) narrowed the freeze
to a single producer/consumer hand-off on the keyboard-report path getting
permanently stuck "busy/full" while the independent mouse path runs on.
Two ranked hypotheses, both consistent with every observed symptom:
**H1** — an `assert(button < BUTTON_COUNT)` in `keyMapStateIndexToStdReport`
trips under a rapid press/release race and suspends only the keyboard task;
**H2** — `taskNotifyOnNotifySend`'s "report-in-flight" flag is left set on
an error path, blocking all future keyboard sends. Definitive confirmation
needs the ROM/bootloader (the FreeRTOS kernel + USB driver live below
0x40000, outside the downloadable app image) or live SWD tracing.

**New actionable lead:** the trigger is rapid input (~5–10/s). Rate-limiting
or coalescing side-button keyboard reports to stay below the race threshold
may *prevent* the freeze, not just recover from it — a strong candidate for
the HID-BPF quirk to do in addition to release synthesis.

## Implications for the fix phase

1. **Synthesising the missing release works and is worth doing.** A
   HID-BPF quirk on the side-button interface: on any report with key bits
   set, arm a `bpf_wq` timeout; if no all-zeros (or changed) report arrives
   within a threshold, inject a zeroed report via `hid_bpf_input_report()`.
   This unsticks the key (the worst symptom — locked modifiers) instantly.
2. **The buttons stay dead until reset regardless** — no BPF program can
   make a silent endpoint speak. But the freeze is *detectable* (bits set
   + endpoint silence + pointer interface still active), which enables a
   userspace companion to trigger an automatic USB port reset
   (`USBDEVFS_RESET`) — a software replug, no cable touching. Detect →
   synthesise release → auto-reset → buttons back in ~2s.
