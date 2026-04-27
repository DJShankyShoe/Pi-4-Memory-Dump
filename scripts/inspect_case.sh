#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

CASE_ID="${1:-CASE-SMOKE}"
DEVICE="${DEVICE:-/dev/disk/by-uuid/20b874e2-747a-4637-b2a3-112694650862}"
MAPPER="${MAPPER:-evidence_crypt}"
MOUNTPOINT="${MOUNTPOINT:-/mnt/forensics-evidence}"
LUKS_PASSWORD="${LUKS_PASSWORD:-}"

if [[ -z "${LUKS_PASSWORD}" ]]; then
  echo "Set LUKS_PASSWORD in the environment." >&2
  exit 1
fi

printf '%s' "${LUKS_PASSWORD}" | cryptsetup open "${DEVICE}" "${MAPPER}" --key-file=-
mkdir -p "${MOUNTPOINT}"
mount "/dev/mapper/${MAPPER}" "${MOUNTPOINT}"
find "${MOUNTPOINT}/cases/${CASE_ID}" -maxdepth 4 -type f | sort
cat "${MOUNTPOINT}/cases/${CASE_ID}"/*/manifest/manifest.json
umount "${MOUNTPOINT}"
cryptsetup close "${MAPPER}"
