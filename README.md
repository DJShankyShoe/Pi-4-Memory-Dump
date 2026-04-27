# Forensics Imager

Raspberry Pi 4 forensic acquisition appliance for Windows memory capture.

This project uses USB gadget mode to present:
- a read-only `F_TOOLS` volume to the Windows host
- a transient writable `F_DUMP` volume for acquisition output
- a Pi-only `LUKS` evidence store for archival, hashing, signatures, and audit
- a `CDC-NCM` control link for password verification, case setup, finalization, and evidence browsing

## What This Export Contains

- `forensic_imager/`
  Main Pi-side application, gadget manager, config, staged assets, and systemd units.
- `scripts/`
  Provisioning, install, reset, verification, and maintenance scripts.
- `evidence_browser/`
  Desktop evidence-browser utility source.
- `ARCHITECTURE.md`
  Current architecture and workflow notes.
- `SETUP_COMMANDS.md`
  Provisioning and operational command history.

## Core Workflow

1. Windows sees `F_TOOLS` and the USB `CDC-NCM` link.
2. The investigator runs `Start_Case.bat`.
3. The launcher verifies the LUKS password over `CDC-NCM`.
4. After verification, case details are submitted to the Pi.
5. The Pi prepares and attaches `F_DUMP`.
6. `winpmem.exe` writes `F_DUMP\\output\\memory.raw`.
7. The launcher sends a finalize request over `CDC-NCM`.
8. The Pi detaches `F_DUMP`, archives the dump into the encrypted evidence store, computes `SHA-512`, signs the manifest, appends the session audit trail, and returns to idle.
9. The investigator runs `Browse_Evidence.bat` to review evidence through the Pi-served web UI.

## Trust Model

- The Windows host is untrusted.
- `F_DUMP` is disposable and untrusted scratch space.
- Integrity-sensitive actions happen on the Pi.
- The evidence store is Pi-only and authoritative.
- `F_TOOLS` is exported read-only and is rebuilt from the Pi-side canonical copy on gadget start/reset.

## Repository Notes

- This export is source-focused and omits local backups, temp files, caches, and packaged binaries.
- External binaries such as `winpmem.exe` should be supplied separately during deployment.
- Some project files still reflect active development rather than polished release packaging.

## Quick Start

1. Provision the Pi and SSD using the scripts in `scripts/`.
2. Install the stack onto the Pi.
3. Connect the Pi to a Windows 11 host over the OTG port.
4. Run `Start_Case.bat` from `F_TOOLS`.
5. Use `Browse_Evidence.bat` to inspect archived sessions.

## Current Status

The current build supports:
- password-first case start
- `CDC-NCM` control plane
- read-only `F_TOOLS`
- Pi-restaged tools volume on gadget start/reset
- `winpmem` acquisition
- signed manifest and signed per-session audit trail
- Pi-served evidence browser
