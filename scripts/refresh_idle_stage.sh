#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

ATTACHED=0
if [[ -e /sys/kernel/config/usb_gadget/forensic_imager/functions/mass_storage.0/lun.1/file ]]; then
  /opt/forensic-imager/bin/gadget-manager detach-stage
  ATTACHED=1
fi
mkdir -p /mnt/forensics-stage
mount /dev/disk/by-label/F_DUMP /mnt/forensics-stage
python3 - <<'PY'
import sys
sys.path.insert(0, "/opt/forensic-imager/app")
import agent
agent.prepare_idle_stage(mounted=True)
PY
find /mnt/forensics-stage -maxdepth 2 -type f | sort
umount /mnt/forensics-stage
if [[ "${ATTACHED}" -eq 1 ]]; then
  /opt/forensic-imager/bin/gadget-manager attach-stage
fi
