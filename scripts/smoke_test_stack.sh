#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

API_BASE="${API_BASE:-http://127.0.0.1}"
STATE_FILE="/var/lib/forensic-imager/state.json"
STAGE_MOUNT="/mnt/forensics-stage"
STAGE_DEVICE="/dev/disk/by-label/F_DUMP"

python3 - <<'PY'
import urllib.parse
import urllib.request

payload = urllib.parse.urlencode({
    "password": "forensic",
    "case_id": "CASE-SMOKE",
    "operator_id": "smoke-test",
    "target_host": "test-host",
    "notes": "automated smoke test"
}).encode()
print(urllib.request.urlopen("http://127.0.0.1/unlock", data=payload, timeout=30).status)
PY

session_id="$(jq -r '.current_session.session_id' "${STATE_FILE}")"
if [[ -z "${session_id}" || "${session_id}" == "null" ]]; then
  echo "No active session found after unlock." >&2
  exit 1
fi

/opt/forensic-imager/bin/gadget-manager detach-stage
mkdir -p "${STAGE_MOUNT}"
mount "${STAGE_DEVICE}" "${STAGE_MOUNT}"
mkdir -p "${STAGE_MOUNT}/${session_id}/output"
printf 'dummy memory dump\n' > "${STAGE_MOUNT}/${session_id}/output/memory.raw"
sync
find "${STAGE_MOUNT}/${session_id}" -maxdepth 3 -type f | sort
umount "${STAGE_MOUNT}"
/opt/forensic-imager/bin/gadget-manager attach-stage

python3 - <<'PY'
import urllib.request
print(urllib.request.urlopen("http://127.0.0.1/detect", data=b"", timeout=30).status)
print(urllib.request.urlopen("http://127.0.0.1/finalize", data=b"", timeout=30).status)
print(urllib.request.urlopen("http://127.0.0.1/api/status", timeout=30).read().decode())
PY

find /mnt/forensics-evidence/cases/CASE-SMOKE -maxdepth 4 -type f | sort
