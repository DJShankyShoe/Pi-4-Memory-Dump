#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

CASE_ID="${1:-}"
OPERATOR_ID="${2:-}"
TARGET_HOST="${3:-}"
NOTES="${4:-}"

python3 - "$CASE_ID" "$OPERATOR_ID" "$TARGET_HOST" "$NOTES" <<'PY'
import json
import sys
from pathlib import Path

case_id, operator_id, target_host, notes = sys.argv[1:5]
p = Path('/var/lib/forensic-imager/state.json')
state = json.loads(p.read_text())
session = state.get('current_session')
if not session:
    raise SystemExit('no active session')
session['case_id'] = case_id
session['operator_id'] = operator_id
session['target_host'] = target_host
session['notes'] = notes
p.write_text(json.dumps(state, indent=2) + '\n')
PY

python3 /opt/forensic-imager/app/agent.py finalize-current
