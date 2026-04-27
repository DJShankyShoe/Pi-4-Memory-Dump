# Setup Commands

This file documents the final working 3-partition build.

## Final Layout

SSD device:

- `/dev/sda`

Partitions:

- `/dev/sda1`
  - filesystem: `exFAT`
  - label: `F_TOOLS`
  - size: `1 GiB`
  - uuid: `7DEF-B35F`
  - partuuid: `49fee72f-cec2-4faa-b30b-e8387ec4db29`
- `/dev/sda2`
  - filesystem: `exFAT`
  - label: `F_DUMP`
  - size: `80 GiB`
  - uuid: `E9EF-B35F`
  - partuuid: `9fcb14f4-8ca6-4cf2-a093-969f686f4242`
- `/dev/sda3`
  - type: `LUKS2`
  - label: `F_EVIDENCE_LUKS`
  - uuid: `c364b788-8351-40ee-8394-4f244eab9342`
  - partuuid: `645c245d-9277-43d2-8342-e3a2e3bc9cf5`
- `/dev/mapper/evidence_crypt`
  - filesystem: `ext4`
  - label: `F_EVIDENCE`
  - uuid: `738c7ee6-7f5f-4953-ad58-373c3e4f0c12`

LUKS password used in setup:

- `forensic`

## Final Gadget Behavior

At idle, the working USB gadget exports:

- `F_TOOLS` (read-only)

`F_EVIDENCE_LUKS` is never exposed to the host.
`F_DUMP` stays detached in idle and is attached only after successful password
verification and case setup.

CDC-NCM exploration:

- the gadget may also expose `ncm.usb0`
- Pi-side test address: `169.254.2.1/16`
- finalize control endpoint: `http://169.254.2.1:8080/finalize`
- evidence browser website: `http://169.254.2.1:8080/evidence-browser`

## Pi Provisioning Commands

Assumption:

- you are already logged into the Pi
- you are in the project root directory
- example:
  - `cd ~/Forensics-Imager`

Bootstrap packages:

```bash
chmod +x ./scripts/bootstrap_pi.sh
sudo ./scripts/bootstrap_pi.sh
```

Configure OTG boot:

```bash
chmod +x ./scripts/configure_otg_boot.sh
sudo ./scripts/configure_otg_boot.sh
```

Repartition and reprovision the SSD:

```bash
chmod +x ./scripts/provision_ssd.sh ./scripts/verify_ssd.sh
sudo env LUKS_PASSWORD=forensic TOOLS_SIZE_GB=1 STAGE_SIZE_GB=80 ./scripts/provision_ssd.sh /dev/sda
sudo env LUKS_PASSWORD=forensic ./scripts/verify_ssd.sh /dev/sda
```

## Stack Install Commands

Install the Pi stack from the current project checkout:

```bash
chmod +x ./scripts/install_pi_stack.sh ./scripts/verify_stack.sh ./scripts/refresh_idle_stage.sh ./scripts/refresh_tools_volume.sh ./scripts/finalize_current_session.sh
sudo ./scripts/install_pi_stack.sh
```

Install the acquisition tool into the staged assets:

```bash
sudo install -m 0644 ./go-winpmem_amd64_1.0-rc2_signed.exe /opt/forensic-imager/assets/winpmem.exe
```

Populate the tools volume, start the gadget, initialize the dump volume, and reboot cleanly:

```bash
sudo systemctl stop forensic-web.service forensic-gadget.service || true
sudo /opt/forensic-imager/bin/refresh-tools-volume
sudo /opt/forensic-imager/bin/gadget-manager start
sudo /opt/forensic-imager/bin/refresh-idle-stage
sudo systemctl start forensic-web.service
sudo reboot
```

Post-reboot verification:

```bash
sudo /opt/forensic-imager/bin/verify-stack
```

## Verified Final Runtime State

Observed after reboot:

- `forensic-gadget.service`: active
- `forensic-web.service`: active
- state file:
  - `status`: `LOCKED_IDLE`
  - `device_id`: `pi-imager-001`
- gadget UDC bound
- LUN 0 points to `/dev/sda1`
- LUN 1 is detached in idle

Verified tools volume contents:

- `Browse_Evidence.bat`
- `Start_Case.bat`
- `cert\pub.cer`
- `tools\winpmem.exe`

Verified stage volume idle contents:

- no required idle files
- optional `LAST_RESULT.txt`
- optional `ERROR.txt`

## Operator Workflow

### Idle

Windows should see:

- `F_TOOLS`

`F_DUMP` is detached in idle and appears only after successful case start.

### Start a Case

From `F_TOOLS`:

1. Run `Start_Case.bat`
2. Approve the Administrator prompt
3. Enter:
   - LUKS password
4. After password verification, enter:
   - case ID
   - operator ID
   - target host
   - notes
5. Wait while the Pi attaches `F_DUMP`
6. Leave the machine untouched while `winpmem.exe` runs
7. Watch the percentage progress shown by `Start_Case.bat`
8. Wait for the result summary returned over the USB network control channel

Expected behavior:

- `F_TOOLS` stays present
- `F_TOOLS` remains read-only
- `F_DUMP` appears only after authentication succeeds
- the password is not written to `F_DUMP`
- `winpmem.exe` runs from `F_TOOLS`
- raw `winpmem.exe` output is suppressed by the launcher

Expected output path:

- `F_DUMP\output\memory.raw`

Finalization is sent over `CDC-NCM`, not `FINALIZE_REQUEST.json` on `F_DUMP`.

### Verify Archived Evidence

From `F_TOOLS`:

1. Run `Browse_Evidence.bat`
2. Enter the LUKS password in the browser UI
3. Refresh or select a case
4. Review the Pi-computed hash and signature verification results
5. Browse case files, inspect the session audit trail, and download archived artifacts through the Pi

The evidence browser reads the evidence store through the Pi. Windows does not mount the LUKS partition directly.
Archived sessions now also include signed per-session audit artifacts:
- `logs/session_audit.jsonl`
- `logs/session_audit.jsonl.sig`

## End-to-End Verified Scripted Flow

The earlier 2-partition scripted flow was verified end to end and then redesigned into this 3-partition model.

The final 3-partition runtime was verified up to:

- clean boot
- two visible mass-storage LUNs
- correct tools volume contents
- correct idle stage contents
- active agent state

## Maintenance Commands

Trusted-PC evidence browser app:

```bash
python3 ./evidence_browser/app.py
```

Refresh the tools volume:

```bash
sudo install -m 0755 ./scripts/refresh_tools_volume.sh /opt/forensic-imager/bin/refresh-tools-volume
sudo systemctl stop forensic-gadget.service forensic-web.service || true
sudo /opt/forensic-imager/bin/refresh-tools-volume
sudo /opt/forensic-imager/bin/gadget-manager start
sudo systemctl start forensic-web.service
```

Refresh the dump volume:

```bash
sudo install -m 0755 ./scripts/refresh_idle_stage.sh /opt/forensic-imager/bin/refresh-idle-stage
sudo /opt/forensic-imager/bin/refresh-idle-stage
```

Inspect an archived case:

```bash
chmod +x ./scripts/inspect_case.sh
sudo env LUKS_PASSWORD=forensic ./scripts/inspect_case.sh CASE-001
```

## Known Constraints

- This build uses two mass-storage LUNs and `CDC-NCM` for control and finalization.
- The password and case details are sent over `CDC-NCM`; the Windows host could still capture user input before encryption if it is compromised.
- `F_TOOLS` is exported read-only.
- `F_TOOLS` is rebuilt from the Pi-side canonical copy when the gadget starts or resets.
- `F_DUMP` is disposable and untrusted scratch space.
- A reboot now discards any stale in-progress session, clears `F_DUMP`, writes an audit record, and returns the Pi to `LOCKED_IDLE`.
- If a partial evidence directory exists from an interrupted archival, it is deleted on the next successful evidence unlock.
- The Pi has shown undervoltage events during development; power stability still matters.
