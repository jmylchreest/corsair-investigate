// SPDX-License-Identifier: GPL-2.0-only
/*
 * Layer B: raw HID input-report capture via HID-BPF (kernel 6.3+,
 * struct_ops API from 6.11+).
 *
 * Pure pass-through diagnostic: every input report the device sends is
 * copied into a ring buffer before the HID core parses it. Comparing
 * this stream against Layer A shows whether a ghost-press originates in
 * the device firmware (no release bytes ever arrive on the wire) or in
 * kernel-side report parsing (release arrives but no EV_KEY follows).
 *
 * The userspace loader writes the target device's hid_id into the
 * struct_ops map before load.
 */
#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>

#define MAX_REPORT 64

struct hid_rec {
	__u64 ts_ns;
	__u32 report_type;
	__u32 report_len; /* actual length, capped at MAX_REPORT */
	__u8 report[MAX_REPORT];
};

const struct hid_rec *unused_hid_rec __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22); /* 4 MiB */
} hid_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} hid_dropped SEC(".maps");

SEC(HID_BPF_DEVICE_EVENT)
int BPF_PROG(scimitar_hid_event, struct hid_bpf_ctx *hctx,
	     enum hid_report_type type, __u64 source)
{
	struct hid_rec *rec;
	__u8 *data;
	__u32 len, zero = 0;
	__u64 *cnt;

	data = hid_bpf_get_data(hctx, 0, MAX_REPORT);
	if (!data)
		return 0; /* EPERM check */

	rec = bpf_ringbuf_reserve(&hid_events, sizeof(*rec), 0);
	if (!rec) {
		cnt = bpf_map_lookup_elem(&hid_dropped, &zero);
		if (cnt)
			__sync_fetch_and_add(cnt, 1);
		return 0;
	}

	rec->ts_ns = bpf_ktime_get_ns();
	rec->report_type = type;

	len = hctx->size;
	if (len > MAX_REPORT)
		len = MAX_REPORT;
	rec->report_len = len;

	/* fixed-size copy keeps the verifier happy; report_len marks
	 * how much is valid */
	__builtin_memcpy(rec->report, data, MAX_REPORT);

	bpf_ringbuf_submit(rec, 0);
	return 0; /* pass-through, never modify or filter */
}

HID_BPF_OPS(scimitar_diag) = {
	.hid_device_event = (void *)scimitar_hid_event,
};

char LICENSE[] SEC("license") = "GPL";
