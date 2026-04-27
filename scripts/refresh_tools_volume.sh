#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

mkdir -p /mnt/forensics-tools
mount /dev/disk/by-label/F_TOOLS /mnt/forensics-tools
python3 - <<'PY'
import sys
sys.path.insert(0, "/opt/forensic-imager/app")
import agent
agent.prepare_tools_volume(mounted=True)
PY
find /mnt/forensics-tools -maxdepth 1 -type f | sort
umount /mnt/forensics-tools
