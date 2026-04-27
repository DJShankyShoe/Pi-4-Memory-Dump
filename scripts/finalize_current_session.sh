#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

/usr/bin/python3 /opt/forensic-imager/app/agent.py finalize-current

