# Research: Corsair Scimitar side-button failures (June 2026)

Summary of online research into prevalence, prior analysis, and existing fix
work for the Scimitar ghost-press / vanishing side-button defect.

## How widespread is it?

Reports span **2015 → present**, every Scimitar generation, and both
Windows and Linux:

- [Corsair forum: "Scimitar side buttons not working"](https://forum.corsair.com/forums/topic/118271-scimitar-side-buttons-not-working/)
  — the canonical thread, 8+ pages over ~8 years. Side buttons
  intermittently stop registering while their LEDs stay lit (MCU alive,
  input path dead). Corsair support collected logs for a "validation team";
  no fix ever shipped. Several users returned the product.
- [Corsair forum: "Side buttons Scimitar Pro sometimes stuck"](https://forum.corsair.com/forums/topic/143858-side-buttons-corsair-scimitar-pro-sometimes-stuck/)
  — the ghost-press variant on the Pro.
- [Corsair forum: "Scimitar RGB Elite MMO buttons randomly stop working"](https://forum.corsair.com/forums/topic/165148-scimitar-rbg-elite-mmo-buttons-randomly-stop-working/)
  (2020) — same on RGB Elite; firmware updates and iCUE reinstalls did not
  help.
- [Steam discussion (2016)](https://steamcommunity.com/discussions/forum/1/412448792363335113/)
  and Reddit r/Corsair threads from 2015 — reboot/replug as the only
  recovery, matching the firmware-state-reset hypothesis.

### Windows-specific confound

On Windows much of the "vanish" mode is caused by iCUE's *Corsair Composite
Virtual Input Device* driver breaking (device hidden / error 45; buttons
return the instant iCUE is killed; reinstalling `CorsairVBusDriver` +
`CorsairVHidDriver` restores them until reboot). That is an iCUE software
bug layered on top. The defect reproducing on **Linux without iCUE** is what
isolates the device firmware as the remaining suspect.

### Linux history

- ckb-next issues:
  [stuck modifiers #32](https://github.com/ckb-next/ckb-next/issues/32),
  [left click stuck on hold randomly (Scimitar) #258](https://github.com/mattanger/ckb-next/issues/258),
  [RGB Elite buttons 1/4/7/10 unmappable #801](https://github.com/ckb-next/ckb-next/issues/801).
- Corsair has prior form shipping out-of-spec HID: the Scimitar Pro RGB's
  report descriptor was malformed (Logical Maximum encoded as a second
  Logical Minimum) and needed a
  [2017 kernel patch](https://lkml.rescloud.iu.edu/1702.1/02516.html)
  before the mouse worked on Linux at all.
- Corsair K90 keyboards had a comparable stuck-key firmware bug
  ([AnandTech thread](https://forums.anandtech.com/threads/corsair-k90-stuck-keys-firmware-bug-not-physically-stuck.2297409/)),
  showing this failure class recurs across Corsair firmware.

## Has anyone published root-cause captures?

**No.** No published usbmon/hidraw/evdev capture proving where the
Scimitar's release event is lost was found. The closest precedents are
methodological:

- [unix.SE: debugging missing ButtonRelease present in usbmon](https://unix.stackexchange.com/questions/403616/how-can-i-debug-x11-missing-mouse-buttonrelease-events-that-are-present-in-usbmo)
  — the same layered-capture differential approach this project automates.
- [cazander.ca: "Fixing a broken mouse the hard way"](https://cazander.ca/2022/fixing-borked-mouse/)
  — a misbehaving Razer fixed in userspace with interception-tools
  (fallback option if HID-BPF were unavailable).

This project's logs would therefore be the first published evidence for
this defect.

## Existing fix work

No Corsair quirk exists in either upstream HID-BPF tree (checked 2026-06-12):

- kernel `drivers/hid/bpf/progs/` — no `Corsair__*.bpf.c`
- [udev-hid-bpf](https://gitlab.freedesktop.org/libevdev/udev-hid-bpf)
  `src/bpf/testing/` — none

But the machinery for the fix is mature:

- [udev-hid-bpf](https://libevdev.pages.freedesktop.org/udev-hid-bpf/)
  exists precisely for "event sequences that are logically impossible"
  (their quirk definition), with a tutorial and a kernel upstreaming path.
- `IOGEAR__Kaliber-MMOmentum.bpf.c` in the kernel tree fixes another
  12-button MMO mouse (report-descriptor fixup) — structural template.
- [`hid_bpf_input_report()`](https://github.com/torvalds/linux/commit/9be50ac30a83896a753ab9f64e941763bb7900be)
  (kernel ≥ 6.9) injects a report *as if from the device* — the exact
  primitive needed to synthesise a missing release. `bpf_wq` provides the
  deferred-work timer. Both are declared in the kernel's
  `hid_bpf_helpers.h` (vendored in `bpf/`).

## Open questions this tool should answer

1. Does the release report ever reach the host (Layer B) when a ghost
   press occurs (Layer A)?
2. Is the trigger correlated with simultaneous keyboard + side-button
   activity (cross-device, possibly same keycode)? Per-event VID:PID +
   phys in the log makes this testable.
3. Wireless-specific: is the loss correlated with the RF link (dongle)
   rather than the button matrix? Does it reproduce wired?
4. Which of the four HID interfaces (`input0/3/4/5` on the Elite Wireless
   SE, `1b1c:2b22`) carries side-button traffic in each profile mode, and
   does the failure follow the interface or the physical button?
