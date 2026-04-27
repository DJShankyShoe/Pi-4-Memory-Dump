# Forensics Imager Architecture

## Goal

Build a Raspberry Pi 4 forensic acquisition appliance that:

- connects to a Windows host in USB gadget mode
- exposes a persistent host-visible tools volume
- exposes a separate host-visible staging volume
- keeps the encrypted evidence volume hidden from the host
- uses one Windows-side launcher to drive case creation, acquisition, and finalization
- imports the final dump into a Pi-only LUKS evidence store
- computes hashes and signs a manifest on the Pi

## Final Storage Model

### Partition 1: Tools

- filesystem: `exFAT`
- label: `F_TOOLS`
- size: `1 GiB`
- visibility: always exposed to the Windows host as read-only
- purpose: static tools and launchers

Contents:

- `Start_Case.bat`
- `Browse_Evidence.bat`
- `cert\pub.cer`
- `tools\winpmem.exe`

This partition is intended to stay attached throughout the workflow.
It is exported read-only to improve integrity of the staged tool set.

### Partition 2: Stage

- filesystem: `exFAT`
- label: `F_DUMP`
- size: `80 GiB`
- visibility: exposed to the Windows host, but temporarily detached while the Pi processes requests or archives evidence
- purpose: transient requests, dump output, and result files

Idle contents:

- none required

Active-session contents:

- `output\memory.raw`

### Partition 3: Evidence

- encryption: `LUKS2`
- LUKS label: `F_EVIDENCE_LUKS`
- inner filesystem: `ext4`
- inner label: `F_EVIDENCE`
- visibility: Pi-only, never exposed to the Windows host
- purpose: authoritative evidence store

Contents:

- case folders
- session folders
- evidence files
- manifests
- signatures
- logs

## Trust Model

- The Windows host is untrusted.
- The tools volume is host-visible, but its contents are rebuilt from the Pi-side canonical copy on gadget start/reset.
- The staging volume is host-visible and untrusted.
- The evidence volume is Pi-only and authoritative.
- All integrity-sensitive actions happen on the Pi.
- `F_DUMP` is disposable scratch space, not trusted evidence storage.
- The LUKS password is encrypted to the Pi's request-encryption public key and sent over `CDC-NCM`.

## USB Gadget Composition

The current working gadget configuration exposes two mass-storage LUNs plus a separate `CDC-NCM` control link:

- LUN 0 -> `F_TOOLS`
- LUN 1 -> `F_DUMP`

The gadget also exposes `CDC-NCM` (`ncm.usb0`) as a separate control-plane network interface on Windows 11.
That same control channel also serves the evidence browser website from the Pi.

## Workflow

### Idle

The host sees:

- `F_TOOLS`
- the `CDC-NCM` control link

The host does not see `F_DUMP` in idle. The Pi keeps the dump LUN detached until
case authentication and setup complete.

The operator uses `F_TOOLS`.

### Case Start

1. Operator runs `Start_Case.bat` from `F_TOOLS`.
2. The script self-elevates to Administrator.
3. The script asks for the LUKS password first.
4. The script encrypts the password plus a per-request random salt to the Pi's public key and sends it over `CDC-NCM`.
5. The Pi controller verifies the password and unlocks LUKS.
6. Only after successful verification does the script ask for case metadata.
7. The case details are sent to the Pi over `CDC-NCM`.
8. The Pi creates a session, prepares the dump workspace, and attaches `F_DUMP`.
9. The script waits for `output\` to appear on `F_DUMP`.

Result:

- `F_TOOLS` remains visible
- `F_DUMP` appears only after authentication succeeds

### Acquisition

1. `Start_Case.bat` locates `F_DUMP` by label.
2. The same script runs `winpmem.exe` with Administrator rights.
3. The launcher suppresses raw tool output and shows percentage progress based on dump file growth.
3. `winpmem.exe` writes the dump to:
   - `F_DUMP\output\memory.raw`

### Finalization

1. After `winpmem.exe` finishes, `Start_Case.bat` sends a finalize request to the Pi over `CDC-NCM` using HTTP.
2. The Pi finalizes the session after acquisition has completed, without polling `F_DUMP` during the write.
3. The Pi detaches `F_DUMP`, copies `output\memory.raw` into the encrypted evidence store, hashes it, signs the manifest, cleans the dump volume, and returns to the hidden idle state.
4. The Pi returns a finalization response over the network control channel.

Result:

- `F_TOOLS` remains visible
- `F_DUMP` disappears again after finalization

### Verification

1. Operator runs `Browse_Evidence.bat` from `F_TOOLS` or opens `http://169.254.2.1:8080/evidence-browser`.
2. The evidence browser UI sends the LUKS password to the Pi over the private `CDC-NCM` link.
3. The Pi unlocks the evidence store locally.
4. The browser requests case/session data from the Pi.
5. The Pi verifies hashes and signatures locally and returns the results to the browser.
6. The browser can list case files, inspect the session audit trail, and download evidence artifacts through the Pi in read-only mode.

Result:

- the host never mounts the LUKS partition directly
- verification works through the Pi on any browser-capable host that can reach the control link

## Why the Stage Volume Briefly Disappears

Only `F_DUMP` is cycled because the Pi must safely take ownership of the transient writable volume before it:

- reads request files
- archives the dump
- deletes transient artifacts

The tools volume does not need to disappear because it is no longer used as the transient workspace.

## Pi-Side Components

### Gadget Manager

File:

- `forensic_imager/bin/gadget-manager`

Responsibilities:

- configures the two-LUN mass-storage gadget
- refreshes `F_TOOLS` from the Pi-side canonical copy before exposing it on gadget `start` and `reset`
- exports `F_TOOLS` permanently as read-only
- attaches/detaches `F_DUMP`

### Controller Agent

File:

- `forensic_imager/app/agent.py`

Responsibilities:

- decrypts encrypted request envelopes with the Pi-only request-decryption key
- unlocks and locks LUKS
- copies evidence into the encrypted store
- computes `SHA-512`
- generates and signs manifests
- maintains state and audit logs
- minimizes time between host request write and stage detach by polling once per second

### Control Server

File:

- `forensic_imager/app/controller.py`

Responsibilities:

- runs the case-start agent loop
- listens on `CDC-NCM` for finalize requests
- applies case metadata to the active session
- triggers final archival without using `F_DUMP` as a finalize control channel
- serves the evidence browser website and evidence browser API endpoints

### Windows Launchers

Files:

- `forensic_imager/assets/Start_Case.bat`

Responsibilities:

- `Start_Case.bat`
  - self-elevates
  - verifies the LUKS password first
  - collects case metadata only after successful verification
  - encrypts request payloads with `cert\pub.cer`
  - sends the encrypted password and case metadata over `CDC-NCM`
  - runs `winpmem.exe` with hidden raw output
  - shows percentage progress during acquisition
  - writes `output\memory.raw` to `F_DUMP`
  - sends the finalize request over `CDC-NCM`

## Evidence and Manifest

The Pi computes the final `SHA-512` over the archived copy inside the encrypted evidence volume.

Per-session outputs include:

- `evidence/memory.raw`
- `manifest/manifest.json`
- `manifest/manifest.sig`
- `logs/session_audit.jsonl`
- `logs/session_audit.jsonl.sig`

The manifest timestamps now include `acquisition_end_utc` when finalization is requested.
The per-session audit trail records stage mount/unmount, copy, hash, manifest write/sign, and audit-signing events with UTC timestamps.
`session_audit.jsonl` is now appended incrementally during the session and re-signed on each append.
Older archived sessions may still contain `session.log`, but new sessions use the per-session audit trail as the primary record.

## Trusted-PC Verification

The repo also still includes the desktop evidence browser app under `evidence_browser/`.

It remains useful for a trusted analysis machine that can:

- open a mounted evidence folder directly, or
- on Linux, open the LUKS evidence partition with `cryptsetup`

The Pi-served evidence browser website is now the preferred cross-platform path for Windows hosts.
It provides automatic verification plus a read-only case browser for archived files and logs.

## Current Constraints

- This build uses mass storage for tools/staging and `CDC-NCM` for finalization control.
- The LUKS password is not written to `F_DUMP`; it is sent over `CDC-NCM` inside an RSA-OAEP encrypted request envelope with a per-request random salt.
- `F_TOOLS` is host-visible but exported read-only.
- `F_DUMP` is host-visible, writable, and intentionally untrusted.
- On boot, the Pi treats any stale `AUTHENTICATED`, `READY_FOR_ACQUISITION`, or `FINALIZING` session as interrupted, clears `F_DUMP`, records an audit event, and returns to clean idle.
- If interruption happened after partial archival began, the Pi records a pending evidence cleanup marker and removes that partial case/session directory the next time the evidence volume is unlocked.
- The Pi hardware has shown undervoltage events during development; stable power still matters.
