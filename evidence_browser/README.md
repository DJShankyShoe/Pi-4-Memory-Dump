# Evidence Browser

Desktop evidence browser for archived memory acquisition sessions.

## What It Does

- opens a mounted evidence root and lists cases
- optionally opens a LUKS evidence device directly on Linux with `cryptsetup`
- verifies each session hash against `manifest/manifest.json`
- optionally verifies `manifest/manifest.sig` if you provide the device public key PEM

## Run

```bash
python evidence_browser/app.py
```

## Direct LUKS Open

Direct LUKS open from this GUI is intended for a trusted Linux machine with:

- `python`
- `tkinter`
- `cryptsetup`
- `openssl`

On Windows, use the GUI against an already mounted evidence folder or through WSL/Linux.

## Signature Verification

To verify signatures, provide the Pi signing public key PEM.

If you do not provide it:

- hash verification still works
- signature status is shown as `Skipped`
