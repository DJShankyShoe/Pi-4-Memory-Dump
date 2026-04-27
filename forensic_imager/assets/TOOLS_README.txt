Forensics Imager Tools Volume

This volume stays attached during the workflow.
This volume is exported read-only to the Windows host.

Steps:
1. Run `Start_Case.bat`
2. Approve the Administrator prompt
3. Enter the LUKS password
4. After verification, enter the case details
5. Wait while the Pi prepares the dump volume
6. Do not touch the machine while `winpmem.exe` runs
7. Watch the percentage progress shown by the launcher
8. Wait for the result summary from the Pi

`Start_Case.bat` handles case start, memory acquisition, and finalization.
The launcher sends the encrypted password and case details to the Pi over `CDC-NCM`.

The dump output is written to the separate dump volume (`F_DUMP`), not this tools volume.
