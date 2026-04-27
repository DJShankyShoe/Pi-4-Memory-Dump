#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

DEVICE="${1:-/dev/sda}"
LUKS_NAME="${LUKS_NAME:-evidence_crypt}"
LUKS_PASSWORD="${LUKS_PASSWORD:-}"

if [[ -z "${LUKS_PASSWORD}" ]]; then
  echo "Set LUKS_PASSWORD in the environment before running this script." >&2
  exit 1
fi

lsblk -o NAME,SIZE,FSTYPE,LABEL,TYPE,MOUNTPOINT,UUID,PARTUUID "${DEVICE}"
cryptsetup luksDump "${DEVICE}3" | sed -n '1,30p'
printf '%s' "${LUKS_PASSWORD}" | cryptsetup open "${DEVICE}3" "${LUKS_NAME}" --key-file=-
blkid "/dev/mapper/${LUKS_NAME}"
cryptsetup close "${LUKS_NAME}"
