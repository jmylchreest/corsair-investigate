#!/usr/bin/env bash
# scimitar-diag uninstaller. Logs in /var/log/scimitar-diag are kept.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "ERROR: run as root (sudo ./uninstall.sh)" >&2; exit 1; }

systemctl disable --now scimitar-diag.service 2>/dev/null || true
systemctl disable --now scimitar-diag-prune.timer 2>/dev/null || true
systemctl stop 'scimitar-diag-hid@*.service' 2>/dev/null || true
rm -f /etc/systemd/system/scimitar-diag.service \
      /etc/systemd/system/scimitar-diag-hid@.service \
      /etc/systemd/system/scimitar-diag-prune.service \
      /etc/systemd/system/scimitar-diag-prune.timer
systemctl daemon-reload

rm -f /etc/udev/rules.d/99-scimitar-diag.rules
udevadm control --reload

rm -f /usr/local/bin/scimitar_log /usr/local/bin/scimitar_hid \
      /usr/local/bin/scimitar-mark /usr/local/bin/scimitar-query \
      /usr/local/bin/scimitar-find /usr/local/bin/scimitar-decode \
      /usr/local/bin/scimitar-prune
rm -rf /etc/scimitar-diag

userdel scimitar-diag 2>/dev/null || true

echo "Uninstalled. Logs kept in /var/log/scimitar-diag (remove manually if unwanted)."
