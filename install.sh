#!/usr/bin/env bash
# scimitar-diag installer — Arch / CachyOS
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "ERROR: run as root (sudo ./install.sh)" >&2; exit 1; }
cd "$(dirname "$0")"

echo "==> Checking build dependencies (pacman)"
if [[ -f /etc/arch-release ]] || grep -qiE 'arch|cachyos' /etc/os-release; then
    pacman -S --needed --noconfirm clang llvm libbpf gcc make pkgconf python || true
    # bpftool: 'bpf' on CachyOS/Arch kernels' tooling repo, 'bpftool' on vanilla Arch
    command -v bpftool >/dev/null || pacman -S --needed --noconfirm bpf 2>/dev/null \
        || pacman -S --needed --noconfirm bpftool
else
    echo "WARNING: not an Arch-like distro; install clang/llvm/libbpf/bpftool manually" >&2
fi

echo "==> Building"
sudo -u "${SUDO_USER:-root}" make all || make all

echo "==> Creating log directory and system user"
id -u scimitar-diag &>/dev/null || useradd --system --no-create-home --shell /usr/bin/nologin scimitar-diag
install -d -m 0770 -o root -g scimitar-diag /var/log/scimitar-diag
touch /var/log/scimitar-diag/markers.log
chmod 0666 /var/log/scimitar-diag/markers.log

echo "==> Installing binaries and scripts"
install -m 0755 bin/scimitar_log /usr/local/bin/scimitar_log
[[ -x bin/scimitar_hid ]] && install -m 0755 bin/scimitar_hid /usr/local/bin/scimitar_hid
install -m 0755 scripts/mark_symptom.sh  /usr/local/bin/scimitar-mark
install -m 0755 scripts/query_window.sh  /usr/local/bin/scimitar-query
install -m 0755 scripts/find_device.sh   /usr/local/bin/scimitar-find
install -m 0755 scripts/decode_events.py /usr/local/bin/scimitar-decode

echo "==> Installing udev rules"
install -m 0644 udev/99-scimitar-diag.rules /etc/udev/rules.d/
udevadm control --reload
udevadm trigger --subsystem-match=hidraw --subsystem-match=input

echo "==> Installing systemd service"
install -d /etc/scimitar-diag
install -m 0644 systemd/scimitar-diag.env /etc/scimitar-diag/
install -m 0644 systemd/scimitar-diag.service /etc/systemd/system/
install -m 0644 systemd/scimitar-diag-hid@.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now scimitar-diag.service

echo
echo "=========================================================="
echo " scimitar-diag installed."
echo
echo "   status:        systemctl status scimitar-diag"
echo "   live events:   tail -f /var/log/scimitar-diag/events.log"
echo "   find device:   scimitar-find"
echo "   mark symptom:  scimitar-mark \"side buttons died\""
echo "                  (bind this to a hotkey!)"
echo "   analyse:       scimitar-query -w 30"
echo "                  scimitar-decode --format table --device -i"
echo
echo " Optional raw HID capture (Layer B), per hidraw node:"
echo "   scimitar-find                      # find HIDRAW_NODE"
echo "   systemctl start scimitar-diag-hid@hidraw2"
echo "=========================================================="
