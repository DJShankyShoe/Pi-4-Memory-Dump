#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${ROOT_DIR}/forensic_imager"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y openssl

mkdir -p /opt/forensic-imager/bin /etc/forensic-imager/keys /var/lib/forensic-imager /var/log/forensic-imager
rsync -a --delete "${SRC}/app/" /opt/forensic-imager/app/
rsync -a --delete "${SRC}/assets/" /opt/forensic-imager/assets/
rsync -a --delete "${SRC}/config/" /opt/forensic-imager/config/
rsync -a --delete "${SRC}/systemd/" /opt/forensic-imager/systemd/
install -m 0755 "${SRC}/bin/gadget-manager" /opt/forensic-imager/bin/gadget-manager
install -m 0755 "${ROOT_DIR}/scripts/verify_stack.sh" /opt/forensic-imager/bin/verify-stack
install -m 0755 "${ROOT_DIR}/scripts/finalize_current_session.sh" /opt/forensic-imager/bin/finalize-current-session
install -m 0755 "${ROOT_DIR}/scripts/recover_current_session.sh" /opt/forensic-imager/bin/recover-current-session
install -m 0755 "${ROOT_DIR}/scripts/refresh_idle_stage.sh" /opt/forensic-imager/bin/refresh-idle-stage
install -m 0755 "${ROOT_DIR}/scripts/refresh_tools_volume.sh" /opt/forensic-imager/bin/refresh-tools-volume
install -m 0755 "${ROOT_DIR}/scripts/reset_pi_clean.sh" /opt/forensic-imager/bin/reset-pi-clean
install -m 0755 "${ROOT_DIR}/scripts/reset_to_idle.sh" /opt/forensic-imager/bin/reset-to-idle
install -m 0644 "${ROOT_DIR}/ARCHITECTURE.md" /opt/forensic-imager/ARCHITECTURE.md
install -m 0644 "${ROOT_DIR}/SETUP_COMMANDS.md" /opt/forensic-imager/SETUP_COMMANDS.md
install -m 0644 "${ROOT_DIR}/README.md" /opt/forensic-imager/README.md
rm -rf /opt/forensic-imager/docs
rm -f /opt/forensic-imager/assets/DumpIt.exe

if [[ -f "${ROOT_DIR}/go-winpmem_amd64_1.0-rc2_signed.exe" ]]; then
  install -m 0644 "${ROOT_DIR}/go-winpmem_amd64_1.0-rc2_signed.exe" /opt/forensic-imager/assets/winpmem.exe
fi

install -m 0644 "${SRC}/systemd/forensic-gadget.service" /etc/systemd/system/forensic-gadget.service
install -m 0644 "${SRC}/systemd/forensic-web.service" /etc/systemd/system/forensic-web.service

systemctl daemon-reload
systemctl enable forensic-gadget.service forensic-web.service

echo "Pi stack installed. Reboot is required after OTG boot configuration."
