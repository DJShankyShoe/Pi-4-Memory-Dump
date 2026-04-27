#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

DEVICE="${1:-/dev/sda}"
TOOLS_SIZE_GB="${TOOLS_SIZE_GB:-1}"
STAGE_SIZE_GB="${STAGE_SIZE_GB:-80}"
TOOLS_LABEL="${TOOLS_LABEL:-F_TOOLS}"
STAGE_LABEL="${STAGE_LABEL:-F_DUMP}"
LUKS_NAME="${LUKS_NAME:-evidence_crypt}"
LUKS_PASSWORD="${LUKS_PASSWORD:-}"
LUKS_FS_LABEL="${LUKS_FS_LABEL:-F_EVIDENCE}"
LUKS_LABEL="${LUKS_LABEL:-F_EVIDENCE_LUKS}"

if [[ -z "${LUKS_PASSWORD}" ]]; then
  echo "Set LUKS_PASSWORD in the environment before running this script." >&2
  exit 1
fi

if [[ ! -b "${DEVICE}" ]]; then
  echo "Block device not found: ${DEVICE}" >&2
  exit 1
fi

if lsblk -nr -o MOUNTPOINT "${DEVICE}" | grep -q .; then
  echo "One or more partitions on ${DEVICE} are mounted. Unmount them first." >&2
  exit 1
fi

partprobe "${DEVICE}" || true

for partition in "${DEVICE}"?*; do
  if [[ -b "${partition}" ]]; then
    umount "${partition}" 2>/dev/null || true
  fi
done

wipefs -a "${DEVICE}"
sgdisk --zap-all "${DEVICE}"

START_MIB=1
TOOLS_END_MIB="$((TOOLS_SIZE_GB * 1024 + 1))"
STAGE_END_MIB="$((TOOLS_END_MIB + STAGE_SIZE_GB * 1024))"

parted -s "${DEVICE}" mklabel gpt
parted -s "${DEVICE}" unit MiB mkpart primary "${START_MIB}" "${TOOLS_END_MIB}"
parted -s "${DEVICE}" unit MiB mkpart primary "${TOOLS_END_MIB}" "${STAGE_END_MIB}"
parted -s "${DEVICE}" unit MiB mkpart primary "${STAGE_END_MIB}" 100%

partprobe "${DEVICE}"
sleep 2

P1="${DEVICE}1"
P2="${DEVICE}2"
P3="${DEVICE}3"

mkfs.exfat -n "${TOOLS_LABEL}" "${P1}"
mkfs.exfat -n "${STAGE_LABEL}" "${P2}"

printf '%s' "${LUKS_PASSWORD}" | cryptsetup luksFormat --type luks2 --label "${LUKS_LABEL}" "${P3}" -
printf '%s' "${LUKS_PASSWORD}" | cryptsetup open "${P3}" "${LUKS_NAME}" -

mkfs.ext4 -L "${LUKS_FS_LABEL}" "/dev/mapper/${LUKS_NAME}"
cryptsetup close "${LUKS_NAME}"

echo
echo "Provisioning complete."
echo "Device: ${DEVICE}"
echo "Partition 1: ${P1} (${TOOLS_LABEL}, ${TOOLS_SIZE_GB} GiB exFAT)"
echo "Partition 2: ${P2} (${STAGE_LABEL}, ${STAGE_SIZE_GB} GiB exFAT)"
echo "Partition 3: ${P3} (${LUKS_LABEL} -> ${LUKS_FS_LABEL})"
lsblk -o NAME,SIZE,FSTYPE,LABEL,TYPE,MOUNTPOINT "${DEVICE}"
