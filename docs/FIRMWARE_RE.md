# Firmware RE: Corsair Scimitar Elite Wireless SE (1b1c:2b22)

Reverse-engineering notes for the side-button KEYBOARD-endpoint freeze bug.

Target image: `firmware-local/Blade_Mouse_App_v7.8.11.bin` (245920 bytes / 0x3C0A0,
UNENCRYPTED). Corsair copyrighted — never leaves `firmware-local/` (gitignored).

This is legitimate interoperability/repair research on the user's own device.

---

## 1. Setup / reproducible recipe

- Architecture: ARM Cortex-M (Thumb-2), little-endian.
- **Flash load base = 0x00040000.** `mem_addr = 0x40000 + file_offset`.
  (Bootloader presumed to live in 0x0..0x40000; not in this image.)
- Disassembler: **capstone 5.0.9** (`pip install --user --break-system-packages capstone`).
  Config: `Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)`, `md.detail = True`.

Analysis scripts live in `firmware-local/re-scripts/` (gitignored):
- `re.py`     — core helpers: load image, vector table, string extraction, word-ref search,
                prologue-based function discovery. (Import via `load.py` to dodge stdlib `re` clash.)
- `litscan.py`— resolve PC-relative literal (`LDR Rd,[pc]`/`ADR`) targets across a linear sweep.
- `movscan.py`— find `MOVW`/`MOVT` immediate pairs that build 32-bit pointers.

Run example:
```
cd firmware-local/re-scripts
python3 -c "import load; fw=load.fw; print(hex(fw.u32(0x40004)))"   # reset vector
```

---

## 2. Vector table (file offset 0 = mem 0x40000, 64 words)

| # | Off | Value | Meaning |
|---|-----|-------|---------|
| 0 | 0x000 | 0x20040000 | Initial SP |
| 1 | 0x004 | 0x0004082d | Reset (Thumb) |
| 2 | 0x008 | 0x00040855 | NMI |
| 3 | 0x00c | 0x00035cb9 | **HardFault** (note: 0x35cb9 is BELOW load base 0x40000 — lives in bootloader/ROM region, NOT in this image) |
| 4 | 0x010 | 0x00040859 | MemManage |
| 5 | 0x014 | 0x0004085b | BusFault |
| 6 | 0x018 | 0x0004085d | UsageFault |
| 11 | 0x02c | 0x0004bbe1 | SVCall (FreeRTOS `vPortSVCHandler`) |
| 12 | 0x030 | 0x00040861 | DebugMon |
| 14 | 0x038 | 0x0004bc01 | PendSV (FreeRTOS `xPortPendSVHandler`) |
| 15 | 0x03c | 0x00040865 | SysTick |

Default/unused IRQ handler (most common word): **0x00040867** (a tight infinite-loop trap).

Populated (non-default) external IRQ handlers (slot = IRQ number):
```
IRQ0  0x0003d8c5   IRQ1  0x0002d96d*  IRQ2  0x0003e675   IRQ3  0x0003fa45
IRQ4  0x0003f40d   IRQ6  0x0003d42d   IRQ7  0x0003ffdd   IRQ8  0x0002d959*
IRQ9  0x0003e089   IRQ10 0x0003e09d   IRQ11 0x0003cc09   IRQ16 0x0003e7d5
IRQ17 0x0004bd0d   IRQ18 0x0003e915   IRQ22 0x0004bded   IRQ26 0x0003e0b5
IRQ27 0x0003e0cd   IRQ35 0x0003fa55   IRQ39 0x00042299   IRQ47 0x0003ff65
```
(*) IRQ1 (0x2d96d) and IRQ8 (0x2d959) point BELOW the load base — they live in the
bootloader/ROM region (like HardFault). All others are in-image.

The HardFault and two IRQs vectoring into 0x2xxxx/0x35xxx (below 0x40000) is a strong
signal there is a ROM/bootloader the app shares handlers with. Relevant later: the app's
own fault path for the keyboard task is in-image.

---

## 3. Strings & the rodata-reference puzzle (IMPORTANT caveat)

Source paths survive in the image (build host `/home/jenkins/workspace/TW/Blade/
Blade_Mouse_Application/...`). Key anchor strings and their **in-file** addresses:

| mem addr | string |
|----------|--------|
| 0x000780a8 | `.../app/Tasks/TaskMain/TaskMain.c` |
| 0x0007817c | `.../app/Tasks/TaskAction/TaskAction.c` |
| 0x000781e0 | `taskActionOnPlaybackOutput` |
| 0x000781fc | `button` |
| 0x00078238 | `keyboard` |
| 0x00078250 | `.../app/Tasks/TaskMouse/TaskMouse.c` |
| 0x000782cc | `len <= NOTIFICATION_MAX_LEN` |
| 0x000782e8 | `.../app/Tasks/TaskNotify/TaskNotify.c` |
| 0x0007834c | `taskNotifyOnNotifySend` |
| 0x00078fa8 | `button < BUTTON_COUNT` |
| 0x00078fc0 | `.../app/KeyMap/KeyMap.c` |
| 0x00079010 | `keyMapStateIndexToStdReport` |
| 0x0007bb0d | `assertion "%s" failed: file "%s", line %d%s%s` |

### Caveat that shaped the rest of the analysis
The planned technique — "find the 32-bit literal equal to each assert string's address to
name the enclosing function" — **does not work on this image.** Findings:

- There are 962 word-aligned intra-image pointers, but their targets stop at ~0x70014 and
  then there is a SECOND cluster of ~82 pointer-words in **0x7e000–0x7f200**, which is
  **past the file end (mem 0x7c0a0)** — i.e. they reference a rodata blob NOT contained in
  this .bin.
- NOT A SINGLE 32-bit word in the image equals any of the in-file string addresses above
  (checked all alignments). No `MOVW/MOVT` pair builds them either (only 12 such pairs
  exist, none to strings). No uniform relocation delta maps in-file strings onto the
  referenced word-set (brute-forced; only noise-level hits).

Interpretation: the **referenced** string/rodata table lives at runtime ~0x7e000+ and is
**outside this image** (only the app's `.text` + a partial rodata copy ending at 0x7c0a0 is
present; the linker placed the live string table higher / in a region this .bin truncates).
Consequently the assert strings I can read are effectively un-resolvable to call sites by
pointer-matching.

**Pivot:** name and map the keyboard/HID pipeline **structurally** (prologue scan + call
graph + immediate-constant heuristics) rather than via assert strings.
This is less tidy but more reliable for this particular dump. (Documented so the recipe is
honest about what didn't work.)

### 3a. MAJOR structural finding: most IRQs (incl. USB) live in ROM, not this image
Re-classifying the vector table by whether each handler address is in-image (>=0x40000)
vs below the load base:

```
IN-IMAGE handlers:   IRQ17 0x0004bd0d   IRQ22 0x0004bded   IRQ39 0x00042299
ROM/bootloader (<0x40000): IRQ0,1,2,3,4,6,7,8,9,10,11,16,18,26,27,35,47  +HardFault +2 others
```

So **the low-level USB device IRQ (TX-complete / endpoint servicing) is in the ROM /
bootloader region that is NOT contained in this .bin.** The application talks to USB
through a HAL/callback layer. Recursive disassembly was therefore seeded only from the 13
in-image vector entries + prologue scan (582 functions, 26205 insn addresses covered;
`/tmp/cg.json`).

**Implication for the bug:** a lost hardware TX-completion interrupt would live in ROM and
would not, by itself, explain "ONE endpoint (keyboard) wedged while the pointer endpoint
keeps working" — a ROM driver fault would tend to be device-wide. The asymmetric, single-
endpoint, persists-until-replug symptom points instead at an **application-level
per-endpoint state machine**: a "report in flight"/busy flag, a FreeRTOS queue/semaphore,
or a task-suspending assert specific to the keyboard report path. That is where the
investigation now concentrates.

### 3b. Why the assert strings can't be resolved (final word)
The rodata that code actually references lives at runtime **0x7e000–0x7f200+, past the
file end (0x7c0a0)** — not in this .bin. Spot-checking referenced targets against the
in-file string blob shows the SAME string *content* but at **non-uniform offsets**: e.g.
ref `0x7e8ac` matches `"Gaming Mouse"` at file 0x7882c with delta 0x6080, while ref `0x7e8ac`
ALSO matches `"...Default Profile"` at file 0x788ac with delta 0x6000 — two different
deltas, so no single relocation applies. The rodata was re-laid-out (pooled/reordered)
between the in-file copy and the referenced copy, or the referenced copy simply isn't in
this image. Net: **assert-string → function naming is not feasible for this dump.** All
naming below is structural / behavioural, and labelled with confidence.

---

## 4. Function map & call graph (what was recoverable)

Recursive-descent disassembly (`recdis.py`, output `/tmp/cg.json`) seeded from the 13
in-image vector entries + prologue scan recovered **582 functions** (range 0x403d0–0x77xxx;
26205 instruction addresses decoded).

### Identified primitive functions (by behaviour, high confidence)
| addr | role | evidence |
|------|------|----------|
| 0x00076a8c | `memcpy` | classic byte copy: `ldrb r4,[r1],#1; strb r4,[r3,#1]!; cmp; bne` |
| 0x00076adc | mem op (memset/cmp) | leaf, 18 callers |
| 0x0006cb2c | **8-slot / 8-byte-record bounded buffer ENQUEUE** | `ldr r3,[r0,#0x40]; cmp #7; bhi …drop; store r0+r3*8; count++` — returns 0 when full (silent drop) |
| 0x0006cb54 | buffer reset/init | zeroes count@0x40 and @0x44 |
| 0x0006cb60 | table interpolator (mul + divide-by-const) | likely DPI/battery/gamma curve, NOT report path |
| 0x00064cf8 | refcount/critical helper | dec + conditional |
| 0x0004b828 | RTOS event-dispatch tail | called by PendSV + IRQ22 glue |
| 0x0004bc00 | PendSV / task switch (custom port) | references `pxCurrentTCB` @0x200055bc |
| 0x0004b870 | RTOS/radio state-machine step | uses state block @0x200055dc, fields 0x63/0x67 |

### Call-graph caveat (important)
The recovered graph is **heavily incomplete for cross-task / report flow** because:
- The FreeRTOS kernel (queues, semaphores, scheduler) and the USB device driver live in the
  **ROM/bootloader below 0x40000** (see §3a). Only `pxCurrentTCB` and 3 thin port shims are
  in-image; the app reaches the kernel through indirect pointers, not direct `BL`.
- The app itself is **callback/vtable-driven** (`ldr r3,[r0,#k]; blx r3` dispatch is pervasive),
  so most edges are indirect and invisible to a direct-BL graph (large functions show outdeg 0).

Consequence: a mechanical "button → … → usb_send" BL chain is **not reconstructable from this
image alone**. The mapping below is therefore behavioural + name-string informed, with stated
confidence rather than a proven edge list.

### Source-file modules present (from surviving paths) and inferred role
`app/Tasks/TaskMain` (init, owns `storageSystemMutex`,`i2cDriverMutex`),
`app/Tasks/TaskAction` (`taskActionOnPlaybackOutput`; dispatches `action`/`button`/`keyboard`/
`imusensor`/`lighting` event kinds — this is the **button→action layer**),
`app/Tasks/TaskMouse` (`taskMouseEventToData`, `len <= NOTIFICATION_MAX_LEN`),
`app/Tasks/TaskNotify` (`taskNotifyOnNotifySend` — the **HID/notification TX sink**),
`app/KeyMap` (`keyMapStateIndexToStdReport`, asserts `button < BUTTON_COUNT` — **builds the
standard keyboard HID report from button/key state**),
`app/Connection`, `app/Cco`, `app/Fs`, `app/Profile`, `app/Lighting`.

### HID report descriptors (found in rodata)
- 0x0007adcc: keyboard, **Report ID 1**, NKRO-style (8 modifier bits + ~86-bit key bitmap).
- 0x0007b76f: keyboard, **Report ID 2** (8 modifier bits + 104-entry usage array) + consumer
  control **Report ID 3**.
- 0x0007ae08 / 0x0007b010 / 0x0007b728: mouse (pointer) collections.

So the keyboard endpoint carries Report IDs 1/2 (+3 consumer). Side-button number-row keys go
out on this keyboard endpoint; the mouse pointer is a *separate* report/endpoint — matching the
symptom that the pointer keeps working while the keyboard endpoint wedges.

### The button → keyboard-HID pipeline (reconstructed by module role; confidence: MEDIUM)
```
side-button GPIO/scan  (ROM/HAL IRQ, not in image)
   → TaskAction  (app/Tasks/TaskAction.c: taskAction* — classifies event as "keyboard")
   → KeyMap      (app/KeyMap.c: keyMapStateIndexToStdReport — asserts button<BUTTON_COUNT,
                  builds the standard keyboard report bytes from current key/button state)
   → TaskNotify  (app/Tasks/TaskNotify.c: taskNotifyOnNotifySend — len<=NOTIFICATION_MAX_LEN;
                  enqueues the report as a "notification" toward the USB/transport layer)
   → USB device EP IN  (ROM driver: actual EP FIFO write + TX-complete IRQ — NOT in image)
```

---

## 5. Failure-mechanism hypotheses (ranked, honest confidence)

The symptom set is highly specific: **(a)** a PRESS report goes out, **(b)** the matching
RELEASE never does (key stuck), **(c)** all later side-button presses produce nothing,
**(d)** the POINTER endpoint stays healthy, **(e)** only a replug recovers, **(f)** triggered
by rapid (~5–10/s) mashing. That is the classic signature of a **single producer/consumer
hand-off for the keyboard report path getting permanently stuck "busy/full," while unrelated
paths (mouse) are unaffected.**

### H1 — `keyMapStateIndexToStdReport` assert fires under rapid input → keyboard/Action task suspended. CONFIDENCE: MEDIUM-HIGH
- Direct evidence the code has an `assert(button < BUTTON_COUNT)` *on the keyboard-report
  build path* (string at 0x78fa8, file `app/KeyMap/KeyMap.c`, function name
  `keyMapStateIndexToStdReport` at 0x79010 in rodata).
- newlib `__assert_func` is linked (format string 0x7bb0d). On Cortex-M FreeRTOS firmware the
  asserted task is very commonly `vTaskSuspend(NULL)`'d or spins — which would silence exactly
  one task while the rest (mouse pointer, lighting) keep running. Matches (b)(c)(d)(e) perfectly:
  once the keyboard/action task is suspended, no release and no further presses are emitted, and
  only a reset/replug restarts it.
- Mechanism that makes the assert fire under *rapid* input (f): a button index or key-slot index
  that transiently exceeds BUTTON_COUNT during a press/release race (e.g. a state-index computed
  from an event queue that briefly holds a sentinel/overflow value), or an off-by-one when a new
  press arrives before the previous release is consumed.
- **Why not higher:** I could not pin the exact compare-and-trap instruction because the ROM
  assert handler is out of image and the string is unresolvable (§3b). The "suspend on assert"
  behaviour is inferred from convention, not yet read from the ROM handler.

### H2 — TaskNotify report queue / "in-flight" hand-off wedges full under back-pressure. CONFIDENCE: MEDIUM
- `app/Tasks/TaskNotify.c: taskNotifyOnNotifySend` with assert `len <= NOTIFICATION_MAX_LEN`
  is the TX sink: it hands keyboard reports to the USB transport. If it uses a **single-depth
  "report in flight" flag** (set on submit, cleared on the ROM TX-complete callback) and an
  error/early-return path **fails to clear it**, every later keyboard send is blocked forever —
  precisely (b)(c)(d)(e). The pointer endpoint uses an independent flag, so it survives.
- I found a concrete *pattern* of "IRQ clears a busy byte then runs a dispatch tail"
  (IRQ22 @0x4bdec: `strb #0 → [0x200055dc+0x24]; b 0x4b828`). That is the radio/connection
  state block, not confirmed to be the USB-keyboard EP flag — but it proves the firmware *uses*
  the exact "completion-IRQ clears a busy flag" idiom that, on an error path, produces this bug.
- The 8-slot bounded buffer at 0x6cb2c **silently drops on full** (returns 0, no retry). If the
  keyboard report path feeds such a buffer and the consumer stalls (e.g. blocked on the stuck
  in-flight flag), the buffer stays full → all subsequent presses dropped (c). However this is a
  *generic* container (13 funcs use it), so its involvement in the keyboard path specifically is
  unproven.
- **Why not higher:** the actual queue object and the TX-complete clear path are in ROM /
  reached indirectly; not directly observable here.

### H3 — Lost USB TX-complete interrupt in the ROM driver (pure ROM-side race). CONFIDENCE: LOW-MEDIUM
- The USB device IRQ is in ROM (below 0x40000, not in image). A missed EP-IN TX-complete under
  rapid double-buffered transfers would leave the app's in-flight flag set (feeds H2) and the EP
  silent.
- Demoted because: a ROM USB-stack defect would more likely affect *all* IN endpoints, yet the
  pointer endpoint is unaffected — pointing back at a *per-endpoint, application-maintained*
  state object (H1/H2) rather than the shared ROM core. Also unfixable/unprovable without the
  ROM image.

### Most actionable conclusion
Ranked: **H1 ≳ H2 > H3.** The two functions to scrutinise (with a ROM dump or live debug) are:
1. **`keyMapStateIndexToStdReport`** (rodata name @0x79010; `app/KeyMap/KeyMap.c`,
   assert `button < BUTTON_COUNT` @0x78fa8) — verify whether a press/release race can drive the
   button/key index out of range and trip the assert that suspends the keyboard task.
2. **`taskNotifyOnNotifySend`** (rodata name @0x7834c; `app/Tasks/TaskNotify.c`,
   assert `len <= NOTIFICATION_MAX_LEN` @0x782cc) — verify the keyboard "report-in-flight" flag
   is cleared on *every* exit path of the TX-complete callback, including errors/aborts.

A clean software repair on the host side (the user's interop tool) would be to **rate-limit /
debounce side-button keyboard events to < ~5/s** to stay below the race threshold, and/or detect
the wedged state (press with no release within N ms + subsequent dead buttons) and trigger a USB
re-enumeration of the device.

---

## 6. Reproduce this analysis
```
cd firmware-local/re-scripts
python3 -m pip install --user --break-system-packages capstone   # v5.0.9
python3 recdis.py        # builds /tmp/cg.json (call graph, func starts, visited)
python3 litscan2.py      # PC-relative literal resolution over validated code
python3 movscan.py       # MOVW/MOVT pointer-pair scan
# helpers in re.py (import via load.py to avoid stdlib 're' name clash):
#   fw.vector_table(), fw.extract_strings(), fw.find_word_refs(), fw.find_func_starts()
```
All scripts are read-only against the .bin and emit only addresses/disassembly (no firmware
bytes) to /tmp and stdout. The .bin itself never leaves firmware-local/.
