from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


def run(cmd: list[str], input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "command failed")
    return result


def sha512_file(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class SessionVerification:
    case_id: str
    session_id: str
    evidence_path: Path
    manifest_path: Path
    signature_path: Path | None
    size_bytes: int
    manifest_sha512: str
    actual_sha512: str
    hash_ok: bool
    signature_ok: bool | None
    notes: str


class EvidenceMount:
    def __init__(self, mountpoint: Path, mapper_name: str, opened_here: bool):
        self.mountpoint = mountpoint
        self.mapper_name = mapper_name
        self.opened_here = opened_here

    def close(self) -> None:
        if self.opened_here:
            subprocess.run(["umount", str(self.mountpoint)], check=False, capture_output=True, text=True)
            subprocess.run(["cryptsetup", "close", self.mapper_name], check=False, capture_output=True, text=True)


def open_luks(device: str, password: str, mapper_name: str = "evidence_verify", mountpoint: str | None = None) -> EvidenceMount:
    if os.name == "nt":
        raise RuntimeError("Direct LUKS opening is supported in this app only on Linux.")
    if shutil.which("cryptsetup") is None:
        raise RuntimeError("cryptsetup is required on this machine.")
    mount_dir = Path(mountpoint) if mountpoint else Path(tempfile.mkdtemp(prefix="forensics-evidence-"))
    run(["cryptsetup", "open", device, mapper_name, "--key-file=-"], input_text=password)
    try:
        mount_dir.mkdir(parents=True, exist_ok=True)
        run(["mount", f"/dev/mapper/{mapper_name}", str(mount_dir)])
    except Exception:
        subprocess.run(["cryptsetup", "close", mapper_name], check=False, capture_output=True, text=True)
        raise
    return EvidenceMount(mount_dir, mapper_name, True)


def load_cases(root: Path) -> list[tuple[str, Path]]:
    cases_dir = root / "cases"
    if not cases_dir.exists():
        raise RuntimeError(f"'cases' directory not found under {root}")
    return sorted([(p.name, p) for p in cases_dir.iterdir() if p.is_dir()], key=lambda item: item[0])


def verify_signature(manifest_path: Path, signature_path: Path, public_key_path: Path | None) -> bool | None:
    if not signature_path.exists():
        return None
    if public_key_path is None:
        return None
    run(
        [
            "openssl",
            "dgst",
            "-sha512",
            "-verify",
            str(public_key_path),
            "-signature",
            str(signature_path),
            str(manifest_path),
        ]
    )
    return True


def verify_case(case_dir: Path, public_key_path: Path | None = None) -> list[SessionVerification]:
    sessions: list[SessionVerification] = []
    for session_dir in sorted([p for p in case_dir.iterdir() if p.is_dir()], key=lambda p: p.name):
        manifest_path = session_dir / "manifest" / "manifest.json"
        signature_path = session_dir / "manifest" / "manifest.sig"
        if not manifest_path.exists():
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        evidence_file = session_dir / "evidence" / manifest["evidence"]["filename"]
        actual_sha = sha512_file(evidence_file)
        signature_ok = verify_signature(manifest_path, signature_path, public_key_path)
        sessions.append(
            SessionVerification(
                case_id=manifest["case_id"],
                session_id=manifest["session_id"],
                evidence_path=evidence_file,
                manifest_path=manifest_path,
                signature_path=signature_path if signature_path.exists() else None,
                size_bytes=evidence_file.stat().st_size,
                manifest_sha512=manifest["evidence"]["sha512"],
                actual_sha512=actual_sha,
                hash_ok=(actual_sha == manifest["evidence"]["sha512"]),
                signature_ok=signature_ok,
                notes=manifest.get("notes", ""),
            )
        )
    return sessions
