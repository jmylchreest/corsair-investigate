# scimitar-diag — Corsair Scimitar ghost-press eBPF diagnostic
# Target: Arch / CachyOS (clang, bpftool, libbpf from pacman)

SHELL       := /bin/bash
CLANG       ?= clang
BPFTOOL     ?= bpftool
CC          ?= gcc
ARCH        := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

LIBBPF_CFLAGS := $(shell pkg-config libbpf --cflags 2>/dev/null)
LIBBPF_LIBS   := $(shell pkg-config libbpf --libs 2>/dev/null || echo -lbpf)

BPF_CFLAGS  := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
               -Wall -Wno-unused-value -Wno-pointer-sign \
               -Wno-compare-distinct-pointer-types \
               -Wno-missing-declarations \
               -Ibpf $(LIBBPF_CFLAGS)
USER_CFLAGS := -O2 -g -Wall -Wextra -Isrc $(LIBBPF_CFLAGS)
USER_LIBS   := $(LIBBPF_LIBS) -lelf -lz

VMLINUX_BTF := /sys/kernel/btf/vmlinux
HID_BPF_OK  := $(shell grep -qs 'CONFIG_HID_BPF=y' <(zcat /proc/config.gz 2>/dev/null) /boot/config-$(shell uname -r) 2>/dev/null && echo yes)

BINS_A := bin/scimitar_log
BINS_B := bin/scimitar_hid

.PHONY: all layer-a layer-b clean install uninstall check-deps

ifeq ($(HID_BPF_OK),yes)
all: check-deps layer-a layer-b
else
all: check-deps layer-a
	@echo "NOTE: CONFIG_HID_BPF not detected — skipping Layer B"
endif

layer-a: $(BINS_A)
layer-b: $(BINS_B)

check-deps:
	@command -v $(CLANG) >/dev/null   || { echo "ERROR: clang not found (pacman -S clang)"; exit 1; }
	@command -v $(BPFTOOL) >/dev/null || { echo "ERROR: bpftool not found (pacman -S bpf)"; exit 1; }
	@command -v $(CC) >/dev/null      || { echo "ERROR: $(CC) not found (pacman -S gcc)"; exit 1; }
	@pkg-config --exists libbpf 2>/dev/null || test -e /usr/include/bpf/libbpf.h \
		|| { echo "ERROR: libbpf headers not found (pacman -S libbpf)"; exit 1; }
	@test -e $(VMLINUX_BTF) || { echo "ERROR: $(VMLINUX_BTF) absent — kernel lacks BTF"; exit 1; }
	@echo "deps OK (clang=$$($(CLANG) --version | head -1), libbpf=$$(pkg-config --modversion libbpf 2>/dev/null || echo '?'))"

bpf/vmlinux.h: $(VMLINUX_BTF)
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

bpf/%.bpf.o: bpf/%.bpf.c bpf/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

src/%.skel.h: bpf/%.bpf.o
	$(BPFTOOL) gen skeleton $< name $*_bpf > $@

bin:
	mkdir -p bin

bin/scimitar_log: src/scimitar_log.c src/scimitar_log.skel.h | bin
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LIBS)

bin/scimitar_hid: src/scimitar_hid.c src/scimitar_hid.skel.h | bin
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LIBS)

clean:
	rm -f bpf/*.bpf.o bpf/vmlinux.h src/*.skel.h
	rm -rf bin

install: all
	sudo ./install.sh

uninstall:
	sudo ./uninstall.sh
