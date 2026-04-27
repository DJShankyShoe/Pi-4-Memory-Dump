#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

CONFIG_TXT="/boot/firmware/config.txt"
CMDLINE_TXT="/boot/firmware/cmdline.txt"

if ! grep -q '^dtoverlay=dwc2,dr_mode=peripheral$' "${CONFIG_TXT}"; then
  printf '\n[all]\ndtoverlay=dwc2,dr_mode=peripheral\n' >> "${CONFIG_TXT}"
fi

if ! grep -q 'modules-load=dwc2' "${CMDLINE_TXT}"; then
  sed -i '1 s#$# modules-load=dwc2#' "${CMDLINE_TXT}"
fi

echo "Updated ${CONFIG_TXT} and ${CMDLINE_TXT} for USB OTG gadget mode."

