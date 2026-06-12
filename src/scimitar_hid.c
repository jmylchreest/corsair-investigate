// SPDX-License-Identifier: GPL-2.0-only
/*
 * Layer B userspace loader: resolves a hidraw node to its HID device
 * id, pins the struct_ops HID-BPF program to that device, and drains
 * raw input reports to a hex log.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "scimitar_hid.skel.h"

#define MAX_REPORT 64

struct hid_rec {
	__u64 ts_ns;
	__u32 report_type;
	__u32 report_len;
	__u8 report[MAX_REPORT];
};

static volatile sig_atomic_t exiting;

static struct {
	const char *hidraw_path;
	const char *out_path;
	long rotate_mb;
	bool verbose;
} cfg = {
	.hidraw_path = NULL,
	.out_path = "/var/log/scimitar-diag/hid_reports.log",
	.rotate_mb = 100,
	.verbose = false,
};

static FILE *out;
static long long bytes_written;
static unsigned long long total_reports;

static void sig_handler(int sig)
{
	(void)sig;
	exiting = 1;
}

/*
 * /sys/class/hidraw/hidrawN/device is a symlink to
 * .../0003:1B1C:2B22.0152 — the trailing hex component is the HID
 * device id that HID-BPF wants.
 */
static int hidraw_to_hid_id(const char *hidraw_path)
{
	char sys_path[PATH_MAX], link_target[PATH_MAX];
	const char *node;
	ssize_t n;
	char *dot;

	node = strrchr(hidraw_path, '/');
	node = node ? node + 1 : hidraw_path;

	snprintf(sys_path, sizeof(sys_path), "/sys/class/hidraw/%s/device",
		 node);
	n = readlink(sys_path, link_target, sizeof(link_target) - 1);
	if (n < 0) {
		fprintf(stderr, "ERROR: readlink %s: %s\n", sys_path,
			strerror(errno));
		return -1;
	}
	link_target[n] = '\0';

	dot = strrchr(link_target, '.');
	if (!dot) {
		fprintf(stderr, "ERROR: unexpected sysfs link: %s\n",
			link_target);
		return -1;
	}
	return (int)strtol(dot + 1, NULL, 16);
}

static long long realtime_minus_boottime_ns(void)
{
	struct timespec rt, bt;

	clock_gettime(CLOCK_REALTIME, &rt);
	clock_gettime(CLOCK_BOOTTIME, &bt);
	return (rt.tv_sec - bt.tv_sec) * 1000000000LL +
	       (rt.tv_nsec - bt.tv_nsec);
}

static int open_log(bool fresh)
{
	struct stat st;

	out = fopen(cfg.out_path, fresh ? "w" : "a");
	if (!out) {
		fprintf(stderr, "ERROR: cannot open %s: %s\n", cfg.out_path,
			strerror(errno));
		return -1;
	}
	setvbuf(out, NULL, _IOLBF, 0);
	bytes_written = 0;
	if (!fresh && fstat(fileno(out), &st) == 0)
		bytes_written = st.st_size;
	return 0;
}

static void write_header(void)
{
	char iso[64];
	struct timespec rt;
	struct tm tm;

	clock_gettime(CLOCK_REALTIME, &rt);
	localtime_r(&rt.tv_sec, &tm);
	strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%S%z", &tm);
	fprintf(out,
		"# scimitar-diag-hid started at %s boot_ns_offset=%lld device=%s\n",
		iso, realtime_minus_boottime_ns(), cfg.hidraw_path);
	fflush(out);
}

static void maybe_rotate(void)
{
	char old_path[4096];

	if (bytes_written < cfg.rotate_mb * 1024 * 1024)
		return;
	fclose(out);
	snprintf(old_path, sizeof(old_path), "%s.1", cfg.out_path);
	if (rename(cfg.out_path, old_path) != 0)
		fprintf(stderr, "WARNING: rotation rename failed: %s\n",
			strerror(errno));
	if (open_log(true) != 0)
		exit(1);
	write_header();
}

static int handle_event(void *ctx, void *data, size_t len)
{
	const struct hid_rec *r = data;
	char hex[MAX_REPORT * 3 + 1];
	unsigned int n, i;

	(void)ctx;
	if (len < sizeof(*r))
		return 0;

	n = r->report_len;
	if (n > MAX_REPORT)
		n = MAX_REPORT;
	for (i = 0; i < n; i++)
		snprintf(hex + i * 3, 4, "%02x ", r->report[i]);
	if (n)
		hex[n * 3 - 1] = '\0';
	else
		hex[0] = '\0';

	fprintf(out, "%llu\t%u\t%s\n", (unsigned long long)r->ts_ns,
		r->report_len, hex);
	bytes_written += 32 + n * 3;
	total_reports++;

	if (cfg.verbose)
		printf("%llu len=%u %s\n", (unsigned long long)r->ts_ns,
		       r->report_len, hex);
	return 0;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"Usage: %s -d <hidraw_path> [-o <path>] [-v] [--rotate-mb <N>]\n"
		"  -d <hidraw_path> hidraw node to attach to (e.g. /dev/hidraw2)\n"
		"  -o <path>        output log (default %s)\n"
		"  -v               verbose: echo reports to stdout\n"
		"  --rotate-mb <N>  rotate when log exceeds N MiB (default 100)\n",
		argv0, cfg.out_path);
}

int main(int argc, char **argv)
{
	struct scimitar_hid_bpf *skel;
	struct ring_buffer *rb = NULL;
	struct bpf_link *link = NULL;
	int hid_id, err = 0;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d") && i + 1 < argc) {
			cfg.hidraw_path = argv[++i];
		} else if (!strcmp(argv[i], "-o") && i + 1 < argc) {
			cfg.out_path = argv[++i];
		} else if (!strcmp(argv[i], "-v")) {
			cfg.verbose = true;
		} else if (!strcmp(argv[i], "--rotate-mb") && i + 1 < argc) {
			cfg.rotate_mb = atol(argv[++i]);
			if (cfg.rotate_mb < 1) {
				fprintf(stderr, "ERROR: bad --rotate-mb\n");
				return 1;
			}
		} else {
			usage(argv[0]);
			return !strcmp(argv[i], "-h") ||
					       !strcmp(argv[i], "--help") ?
				       0 :
				       1;
		}
	}

	if (!cfg.hidraw_path) {
		usage(argv[0]);
		return 1;
	}

	hid_id = hidraw_to_hid_id(cfg.hidraw_path);
	if (hid_id < 0)
		return 1;
	fprintf(stderr, "%s -> hid_id %d (0x%04x)\n", cfg.hidraw_path, hid_id,
		hid_id);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	skel = scimitar_hid_bpf__open();
	if (!skel) {
		fprintf(stderr, "ERROR: failed to open BPF skeleton\n");
		return 1;
	}

	skel->struct_ops.scimitar_diag->hid_id = hid_id;

	err = scimitar_hid_bpf__load(skel);
	if (err) {
		fprintf(stderr,
			"ERROR: failed to load BPF skeleton: %d\n"
			"       (requires CONFIG_HID_BPF=y, kernel 6.11+ for struct_ops)\n",
			err);
		goto cleanup;
	}

	link = bpf_map__attach_struct_ops(skel->maps.scimitar_diag);
	if (!link) {
		fprintf(stderr, "ERROR: struct_ops attach failed: %s\n",
			strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (open_log(false) != 0) {
		err = 1;
		goto cleanup;
	}
	write_header();

	rb = ring_buffer__new(bpf_map__fd(skel->maps.hid_events), handle_event,
			      NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ERROR: failed to create ring buffer\n");
		err = 1;
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	fprintf(stderr, "logging raw HID reports from %s to %s\n",
		cfg.hidraw_path, cfg.out_path);

	while (!exiting) {
		err = ring_buffer__poll(rb, 50 /* ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "ERROR: ring buffer poll: %d\n", err);
			break;
		}
		maybe_rotate();
	}

	fprintf(stderr, "shutting down: %llu reports logged\n", total_reports);
	err = 0;

cleanup:
	if (out)
		fclose(out);
	ring_buffer__free(rb);
	bpf_link__destroy(link);
	scimitar_hid_bpf__destroy(skel);
	return err != 0;
}
