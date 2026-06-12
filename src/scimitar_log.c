// SPDX-License-Identifier: GPL-2.0-only
/*
 * Layer A userspace loader: attaches the kprobe, drains the ring
 * buffer, writes tab-separated event lines, handles rotation and
 * dropped-event accounting.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "scimitar_log.skel.h"

struct event_rec {
	__u64 ts_ns;
	__u64 ts_boot;
	__u32 type;
	__u32 code;
	__s32 value;
	__u16 bustype;
	__u16 vendor;
	__u16 product;
	__u16 version;
	char devname[64];
	char phys[64];
};

static volatile sig_atomic_t exiting;

static struct {
	const char *out_path;
	const char *filter;
	bool verbose;
	long rotate_mb;
} cfg = {
	.out_path = "/var/log/scimitar-diag/events.log",
	.filter = NULL,
	.verbose = false,
	.rotate_mb = 100,
};

static FILE *out;
static long long bytes_written;
static unsigned long long total_events;
static unsigned long long last_dropped;

static void sig_handler(int sig)
{
	(void)sig;
	exiting = 1;
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

	fprintf(out, "# scimitar-diag started at %s boot_ns_offset=%lld\n", iso,
		realtime_minus_boottime_ns());
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

static unsigned long long sum_dropped(struct scimitar_log_bpf *skel)
{
	int ncpu = libbpf_num_possible_cpus();
	__u64 vals[ncpu];
	__u32 zero = 0;
	unsigned long long total = 0;

	if (ncpu < 1)
		return 0;
	if (bpf_map__lookup_elem(skel->maps.dropped, &zero, sizeof(zero), vals,
				 sizeof(vals), 0) != 0)
		return 0;
	for (int i = 0; i < ncpu; i++)
		total += vals[i];
	return total;
}

static int handle_event(void *ctx, void *data, size_t len)
{
	const struct event_rec *e = data;

	(void)ctx;
	if (len < sizeof(*e))
		return 0;

	if (cfg.filter && !strcasestr(e->devname, cfg.filter))
		return 0;

	fprintf(out, "%llu\t%llu\t%u\t%u\t%d\t%04x:%04x\t%s\t%s\n",
		(unsigned long long)e->ts_ns, (unsigned long long)e->ts_boot,
		e->type, e->code, e->value, e->vendor, e->product, e->devname,
		e->phys);
	bytes_written += 64; /* approximation, exact size checked on rotate */
	total_events++;

	if (cfg.verbose)
		printf("%llu code=%u value=%d dev=%s\n",
		       (unsigned long long)e->ts_boot, e->code, e->value,
		       e->devname);
	return 0;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"Usage: %s [-o <path>] [-f <filter>] [-v] [--rotate-mb <N>]\n"
		"  -o <path>        output log (default %s)\n"
		"  -f <filter>      only log devices whose name contains <filter>\n"
		"  -v               verbose: echo events to stdout\n"
		"  --rotate-mb <N>  rotate when log exceeds N MiB (default 100)\n",
		argv0, cfg.out_path);
}

int main(int argc, char **argv)
{
	struct scimitar_log_bpf *skel;
	struct ring_buffer *rb = NULL;
	struct bpf_link *link = NULL, *link_inject = NULL;
	int err = 0;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-o") && i + 1 < argc) {
			cfg.out_path = argv[++i];
		} else if (!strcmp(argv[i], "-f") && i + 1 < argc) {
			cfg.filter = argv[++i];
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

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	skel = scimitar_log_bpf__open();
	if (!skel) {
		fprintf(stderr, "ERROR: failed to open BPF skeleton\n");
		return 1;
	}

	err = scimitar_log_bpf__load(skel);
	if (err) {
		fprintf(stderr, "ERROR: failed to load BPF skeleton: %d\n",
			err);
		goto cleanup;
	}

	/* input_event is mandatory; input_inject_event is best-effort
	 * (covers evdev-handle injection, a rare path) */
	link = bpf_program__attach(skel->progs.trace_input_event);
	if (!link) {
		fprintf(stderr, "ERROR: kprobe attach (input_event): %s\n",
			strerror(errno));
		err = 1;
		goto cleanup;
	}
	link_inject =
		bpf_program__attach(skel->progs.trace_input_inject_event);
	if (!link_inject)
		fprintf(stderr,
			"NOTE: input_inject_event kprobe unavailable (%s) — injected events won't be logged\n",
			strerror(errno));
	fprintf(stderr, "attached kprobes: input_event%s\n",
		link_inject ? ", input_inject_event" : "");

	if (open_log(false) != 0) {
		err = 1;
		goto cleanup;
	}
	write_header();

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
			      NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ERROR: failed to create ring buffer\n");
		err = 1;
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	fprintf(stderr, "logging EV_KEY events to %s%s%s\n", cfg.out_path,
		cfg.filter ? " filter=" : "", cfg.filter ? cfg.filter : "");

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

		unsigned long long d = sum_dropped(skel);
		if (d > last_dropped) {
			fprintf(out,
				"# WARNING: ring buffer overflow — %llu events dropped since last check\n",
				d - last_dropped);
			last_dropped = d;
		}

		maybe_rotate();
	}

	fprintf(stderr,
		"shutting down: %llu events logged, %llu dropped total\n",
		total_events, sum_dropped(skel));
	err = 0;

cleanup:
	if (out)
		fclose(out);
	ring_buffer__free(rb);
	bpf_link__destroy(link);
	bpf_link__destroy(link_inject);
	scimitar_log_bpf__destroy(skel);
	return err != 0;
}
