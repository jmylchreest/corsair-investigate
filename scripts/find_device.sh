#!/usr/bin/env bash
# Find all Corsair (VID 1b1c) input devices: event nodes, hidraw nodes, phys path.
# Usage: ./find_device.sh
set -euo pipefail

printf '%-14s %-11s %-20s %-14s %s\n' "DEVICE" "VID:PID" "EVENT_NODE" "HIDRAW_NODE" "PHYS"

found=0
shopt -s nullglob

for hidraw in /sys/class/hidraw/hidraw*; do
    dev_link=$(readlink -f "$hidraw/device")
    # HID id looks like 0003:1B1C:2B22.0152
    hid_id=$(basename "$dev_link")
    vid=${hid_id:5:4}
    pid=${hid_id:10:4}
    [[ ${vid,,} == "1b1c" ]] || continue
    found=1

    hidraw_node="/dev/$(basename "$hidraw")"
    name=$(cat "$dev_link/../uevent" 2>/dev/null | sed -n 's/^HID_NAME=//p' || true)
    [[ -n "${name:-}" ]] || name=$(sed -n 's/^HID_NAME=//p' "$dev_link/uevent" 2>/dev/null || true)

    event_node="-"
    phys="-"
    for input in "$dev_link"/input/input*; do
        [[ -d $input ]] || continue
        phys=$(cat "$input/phys" 2>/dev/null || echo "-")
        for ev in "$input"/event*; do
            [[ -d $ev ]] || continue
            event_node="/dev/input/$(basename "$ev")"
            printf '%-14.14s %-11s %-20s %-14s %s\n' \
                "${name:-?}" "${vid,,}:${pid,,}" "$event_node" "$hidraw_node" "$phys"
        done
    done
    # hidraw interfaces with no input node (vendor/control interfaces)
    if [[ $event_node == "-" ]]; then
        printf '%-14.14s %-11s %-20s %-14s %s\n' \
            "${name:-?}" "${vid,,}:${pid,,}" "-" "$hidraw_node" "${phys}"
    fi
done

if [[ $found -eq 0 ]]; then
    echo "No Corsair (1b1c) HID devices found." >&2
    exit 1
fi
