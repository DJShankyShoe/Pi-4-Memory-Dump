#!/usr/bin/env bash
set -euo pipefail

systemctl stop forensic-web.service forensic-gadget.service || true

umount /mnt/forensics-tools >/dev/null 2>&1 || true
umount /mnt/forensics-stage >/dev/null 2>&1 || true
umount /mnt/forensics-evidence >/dev/null 2>&1 || true
umount /opt/forensic-imager/evidence >/dev/null 2>&1 || true
cryptsetup close evidence_crypt >/dev/null 2>&1 || true
sleep 1

printf %s forensic | cryptsetup open /dev/disk/by-label/F_EVIDENCE_LUKS evidence_crypt --key-file=-

mkdir -p /mnt/forensics-evidence /mnt/forensics-stage /mnt/forensics-tools
mount /dev/mapper/evidence_crypt /mnt/forensics-evidence
mount /dev/disk/by-label/F_DUMP /mnt/forensics-stage
mount /dev/disk/by-label/F_TOOLS /mnt/forensics-tools

python3 - <<'PY'
from pathlib import Path
import shutil
import sys

sys.path.insert(0, "/opt/forensic-imager/app")
import agent

for root_path, keep_names in [
    (Path("/mnt/forensics-evidence"), set()),
    (Path("/mnt/forensics-stage"), {"System Volume Information"}),
]:
    for child in root_path.iterdir():
        if child.name in keep_names:
            continue
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)

agent.prepare_tools_volume(mounted=True)
PY

mkdir -p /var/lib/forensic-imager /var/log/forensic-imager
: > /var/log/forensic-imager/audit.log
: > /var/log/forensic-imager/security_events.jsonl
cat > /var/lib/forensic-imager/state.json <<'EOF'
{
  "status": "LOCKED_IDLE",
  "device_id": "pi-imager-001",
  "current_session": null,
  "last_error": null,
  "last_result": null,
  "pending_cleanup": null,
  "pending_session_events": [],
  "progress": {
    "phase": "IDLE",
    "percent": 0,
    "message": "Idle"
  }
}
EOF

sync
umount /mnt/forensics-tools || true
umount /mnt/forensics-stage || true
umount /mnt/forensics-evidence || true
cryptsetup close evidence_crypt || true

systemctl start forensic-gadget.service forensic-web.service
sleep 2
wget -qO- http://169.254.2.1:8080/status
