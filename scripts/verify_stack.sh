#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

systemctl status forensic-gadget.service --no-pager
systemctl status forensic-web.service --no-pager
cat /var/lib/forensic-imager/state.json 2>/dev/null || true
ls /sys/kernel/config/usb_gadget/forensic_imager || true
lsblk -o NAME,SIZE,FSTYPE,LABEL,TYPE,MOUNTPOINT /dev/sda || true
