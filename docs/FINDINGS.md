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
