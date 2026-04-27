from __future__ import annotations

import hashlib
import json
import mimetypes
import subprocess
from dataclasses import dataclass
from pathlib import Path


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, text=True, capture_output=True, check=False)
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
    audit_path: Path | None
    audit_signature_path: Path | None
    size_bytes: int
    manifest_sha512: str
    actual_sha512: str
    hash_ok: bool
    signature_ok: bool | None
    audit_hash_ok: bool | None
    audit_signature_ok: bool | None
    notes: str


def load_cases(root: Path) -> list[tuple[str, Path]]:
    cases_dir = root / "cases"
    if not cases_dir.exists():
        return []
    return sorted([(p.name, p) for p in cases_dir.iterdir() if p.is_dir()], key=lambda item: item[0])


def verify_signature(manifest_path: Path, signature_path: Path, public_key_path: Path | None) -> bool | None:
    if not signature_path.exists() or public_key_path is None:
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
        audit_meta = manifest.get("artifacts", {}).get("session_audit", {})
        audit_rel_path = audit_meta.get("path", "")
        audit_sig_rel_path = audit_meta.get("signature_path", "")
        audit_path = (session_dir / audit_rel_path) if audit_rel_path else None
        audit_signature_path = (session_dir / audit_sig_rel_path) if audit_sig_rel_path else None
        audit_hash_ok = None
        audit_signature_ok = None
        if audit_path and audit_path.exists():
            expected_audit_sha = audit_meta.get("sha512")
            actual_audit_sha = sha512_file(audit_path)
            audit_hash_ok = (actual_audit_sha == expected_audit_sha) if expected_audit_sha else None
            if audit_signature_path and audit_signature_path.exists():
                audit_signature_ok = verify_signature(audit_path, audit_signature_path, public_key_path)
        sessions.append(
            SessionVerification(
                case_id=manifest["case_id"],
                session_id=manifest["session_id"],
                evidence_path=evidence_file,
                manifest_path=manifest_path,
                signature_path=signature_path if signature_path.exists() else None,
                audit_path=audit_path if audit_path and audit_path.exists() else None,
                audit_signature_path=audit_signature_path if audit_signature_path and audit_signature_path.exists() else None,
                size_bytes=evidence_file.stat().st_size,
                manifest_sha512=manifest["evidence"]["sha512"],
                actual_sha512=actual_sha,
                hash_ok=(actual_sha == manifest["evidence"]["sha512"]),
                signature_ok=signature_ok,
                audit_hash_ok=audit_hash_ok,
                audit_signature_ok=audit_signature_ok,
                notes=manifest.get("notes", ""),
            )
        )
    return sessions


def build_case_tree(case_dir: Path) -> list[dict]:
    entries: list[dict] = []
    for path in sorted(case_dir.rglob("*"), key=lambda p: (p.is_file(), str(p.relative_to(case_dir)).lower())):
        rel = path.relative_to(case_dir).as_posix()
        entries.append(
            {
                "relative_path": rel,
                "name": path.name,
                "is_dir": path.is_dir(),
                "size_bytes": path.stat().st_size if path.is_file() else None,
                "content_type": (mimetypes.guess_type(path.name)[0] or "application/octet-stream") if path.is_file() else None,
            }
        )
    return entries


def collect_case_logs(case_dir: Path) -> list[dict]:
    logs: list[dict] = []
    patterns = ("logs/session_audit.jsonl", "logs/*.log")
    seen: set[Path] = set()
    matched: list[Path] = []
    for pattern in patterns:
        for path in case_dir.rglob(pattern):
            if path in seen:
                continue
            seen.add(path)
            matched.append(path)
    for log_path in sorted(matched, key=lambda p: str(p.relative_to(case_dir)).lower()):
        try:
            text = log_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = log_path.read_bytes().decode("utf-8", errors="replace")
        logs.append(
            {
                "relative_path": log_path.relative_to(case_dir).as_posix(),
                "name": log_path.name,
                "content": text,
                "kind": "session_audit" if log_path.name == "session_audit.jsonl" else "session_log",
            }
        )
    return logs


def safe_case_path(case_dir: Path, relative_path: str) -> Path:
    rel = Path(relative_path)
    if rel.is_absolute():
        raise RuntimeError("invalid path")
    resolved = (case_dir / rel).resolve()
    case_root = case_dir.resolve()
    if case_root not in resolved.parents and resolved != case_root:
        raise RuntimeError("path escapes case root")
    if not resolved.exists() or not resolved.is_file():
        raise RuntimeError("file not found")
    return resolved
