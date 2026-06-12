// SPDX-License-Identifier: GPL-2.0-only
/*
 * Layer A: log every EV_KEY event passing through the input core.
 *
 * input_handle_event() would be the single choke point, but it is
 * static and gets inlined into its callers on optimised kernels
 * (verified on CachyOS 7.0: the kallsyms symbol exists yet a kprobe on
 * it never fires). Instead we attach the two exported functions that
 * feed it — they cannot be inlined across module boundaries and cover
 * disjoint paths with no double-counting:
 *
 *   input_event()        — all driver-originated events (HID, uinput…)
 *   input_inject_event() — events injected through evdev handles
 *
 * Captures press/release/repeat for every input device so a
 * ghost-press (press with no matching release) can be found in
 * post-analysis regardless of whether the Scimitar side buttons report
 * as mouse buttons or as remapped keyboard keys.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define EV_KEY_TYPE 0x01

struct event_rec {
	__u64 ts_ns;   /* CLOCK_MONOTONIC ns */
	__u64 ts_boot; /* CLOCK_BOOTTIME ns (survives suspend, maps to wall clock) */
	__u32 type;
	__u32 code;
	__s32 value; /* 0=release 1=press 2=repeat */
	__u16 bustype; /* input_dev->id: lets analysis distinguish devices */
	__u16 vendor;  /* sharing the same keycode (e.g. keyboard KEY_1 vs */
	__u16 product; /* Scimitar side-button remapped to KEY_1) */
	__u16 version;
	char devname[64];
	char phys[64];
};

/* Force BTF emission of the record type for the skeleton/consumers. */
const struct event_rec *unused_event_rec __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 23); /* 8 MiB */
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropped SEC(".maps");

static __always_inline int handle(struct input_dev *dev, unsigned int type,
				  unsigned int code, int value)
{
	struct event_rec *rec;
	const char *p;
	__u32 zero = 0;
	__u64 *cnt;

	if (type != EV_KEY_TYPE)
		return 0;

	rec = bpf_ringbuf_reserve(&events, sizeof(*rec), 0);
	if (!rec) {
		cnt = bpf_map_lookup_elem(&dropped, &zero);
		if (cnt)
			__sync_fetch_and_add(cnt, 1);
		return 0;
	}

	rec->ts_ns = bpf_ktime_get_ns();
	rec->ts_boot = bpf_ktime_get_boot_ns();
	rec->type = type;
	rec->code = code;
	rec->value = value;
	rec->bustype = BPF_CORE_READ(dev, id.bustype);
	rec->vendor = BPF_CORE_READ(dev, id.vendor);
	rec->product = BPF_CORE_READ(dev, id.product);
	rec->version = BPF_CORE_READ(dev, id.version);

	p = BPF_CORE_READ(dev, name);
	if (p)
		bpf_probe_read_kernel_str(rec->devname, sizeof(rec->devname), p);
	else
		rec->devname[0] = '\0';

	p = BPF_CORE_READ(dev, phys);
	if (p)
		bpf_probe_read_kernel_str(rec->phys, sizeof(rec->phys), p);
	else
		rec->phys[0] = '\0';

	bpf_ringbuf_submit(rec, 0);
	return 0;
}

SEC("kprobe/input_event")
int BPF_KPROBE(trace_input_event, struct input_dev *dev,
	       unsigned int type, unsigned int code, int value)
{
	return handle(dev, type, code, value);
}

SEC("kprobe/input_inject_event")
int BPF_KPROBE(trace_input_inject_event, struct input_handle *handle_arg,
	       unsigned int type, unsigned int code, int value)
{
	struct input_dev *dev = BPF_CORE_READ(handle_arg, dev);

	return handle(dev, type, code, value);
}

char LICENSE[] SEC("license") = "GPL";
