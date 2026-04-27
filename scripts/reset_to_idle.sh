#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

install -m 0644 /tmp/state.idle.json /var/lib/forensic-imager/state.json
systemctl stop forensic-web.service forensic-gadget.service || true
/opt/forensic-imager/bin/gadget-manager stop || true
mkdir -p /mnt/forensics-stage
mount /dev/disk/by-label/F_DUMP /mnt/forensics-stage
python3 - <<'PY'
import sys
sys.path.insert(0, "/opt/forensic-imager/app")
import agent
agent.prepare_idle_stage(mounted=True)
PY
umount /mnt/forensics-stage
/opt/forensic-imager/bin/refresh-tools-volume
systemctl reset-failed forensic-gadget.service
systemctl start forensic-gadget.service
systemctl start forensic-web.service
