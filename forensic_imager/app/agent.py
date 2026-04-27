#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


CONFIG_PATH = Path("/opt/forensic-imager/config/device.json")
CONFIG = json.loads(CONFIG_PATH.read_text())
STATE_PATH = Path(CONFIG["session_state_path"])
AUDIT_LOG = Path(CONFIG["audit_log_path"])
SECURITY_EVENTS_LOG = Path(CONFIG["security_events_path"])


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def run(cmd, input_text=None, check=True):
    result = subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}\n{result.stderr.strip()}")
    return result


def ensure_paths():
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    SECURITY_EVENTS_LOG.parent.mkdir(parents=True, exist_ok=True)


def load_state():
    ensure_paths()
    if not STATE_PATH.exists():
        return normalize_state({
            "status": "LOCKED_IDLE",
            "device_id": CONFIG["device_id"],
            "current_session": None,
            "last_error": None,
        })
    return normalize_state(json.loads(STATE_PATH.read_text()))


def normalize_state(state):
    state.setdefault("last_result", None)
    state.setdefault("progress", {"phase": "IDLE", "percent": 0, "message": "Idle"})
    state.setdefault("pending_cleanup", None)
    state.setdefault("pending_session_events", [])
    return state


def save_state(state):
    ensure_paths()
    STATE_PATH.write_text(json.dumps(normalize_state(state), indent=2) + "\n")


def audit(event, **fields):
    line = {"ts_utc": utc_now(), "event": event, **fields}
    return line


def security_event(event, **fields):
    ensure_paths()
    line = {"ts_utc": utc_now(), "event": event, **fields}
    with SECURITY_EVENTS_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(line) + "\n")
    return line


def set_progress(state, phase: str, percent: int, message: str):
    state["progress"] = {"phase": phase, "percent": int(percent), "message": message}
    save_state(state)


def idle_state():
    return {
        "status": "LOCKED_IDLE",
        "device_id": CONFIG["device_id"],
        "current_session": None,
        "last_error": None,
        "last_result": None,
        "pending_cleanup": None,
        "pending_session_events": [],
        "progress": {"phase": "IDLE", "percent": 0, "message": "Idle"},
    }


def stage_mount():
    return Path(CONFIG["stage_mount"])


def tools_mount():
    return Path(CONFIG["tools_mount"])


def evidence_mount():
    return Path(CONFIG["evidence_mount"])


def mount_tools_local():
    tools_mount().mkdir(parents=True, exist_ok=True)
    run(["mount", CONFIG["tools_device"], CONFIG["tools_mount"]])


def umount_tools_local():
    run(["umount", CONFIG["tools_mount"]], check=False)


def mount_stage_local():
    stage_mount().mkdir(parents=True, exist_ok=True)
    run(["mount", CONFIG["stage_device"], CONFIG["stage_mount"]])


def umount_stage_local():
    run(["umount", CONFIG["stage_mount"]], check=False)


def unlock_evidence(password: str):
    run(
        [
            "cryptsetup",
            "open",
            CONFIG["evidence_device"],
            CONFIG["evidence_mapper"],
            "--key-file=-",
        ],
        input_text=password,
    )
    evidence_mount().mkdir(parents=True, exist_ok=True)
    run(
        [
            "mount",
            "-t",
            CONFIG["evidence_fs_type"],
            f"/dev/mapper/{CONFIG['evidence_mapper']}",
            CONFIG["evidence_mount"],
        ],
        check=False,
    )


def lock_evidence():
    run(["umount", CONFIG["evidence_mount"]], check=False)
    run(["cryptsetup", "close", CONFIG["evidence_mapper"]], check=False)


def gadget(action: str):
    run(["/opt/forensic-imager/bin/gadget-manager", action])


def stage_is_mounted_local() -> bool:
    return stage_mount().is_mount()


def detach_stage_from_host(state=None, persist_state: bool = True, session_events: list[dict] | None = None):
    was_attached = stage_is_attached()
    gadget("detach-stage")
    is_attached = stage_is_attached()
    if state is not None and was_attached and not is_attached:
        if session_events is not None:
            record_session_event(session_events, "dump_volume_dismounted_from_host")
        append_session_audit_event(state, "dump_volume_dismounted_from_host", persist_state=persist_state)


def attach_stage_to_host(state=None, persist_state: bool = True, session_events: list[dict] | None = None):
    was_attached = stage_is_attached()
    gadget("attach-stage")
    is_attached = stage_is_attached()
    if state is not None and not was_attached and is_attached:
        if session_events is not None:
            record_session_event(session_events, "dump_volume_mounted_to_host")
        append_session_audit_event(state, "dump_volume_mounted_to_host", persist_state=persist_state)


def mount_stage_on_pi(state=None, persist_state: bool = True, session_events: list[dict] | None = None):
    was_mounted = stage_is_mounted_local()
    mount_stage_local()
    is_mounted = stage_is_mounted_local()
    if state is not None and not was_mounted and is_mounted:
        if session_events is not None:
            record_session_event(session_events, "dump_volume_mounted_on_pi", mount_point=CONFIG["stage_mount"])
        append_session_audit_event(state, "dump_volume_mounted_on_pi", persist_state=persist_state, mount_point=CONFIG["stage_mount"])


def unmount_stage_from_pi(state=None, persist_state: bool = True, session_events: list[dict] | None = None):
    was_mounted = stage_is_mounted_local()
    umount_stage_local()
    is_mounted = stage_is_mounted_local()
    if state is not None and was_mounted and not is_mounted:
        if session_events is not None:
            record_session_event(session_events, "dump_volume_unmounted_from_pi", mount_point=CONFIG["stage_mount"])
        append_session_audit_event(state, "dump_volume_unmounted_from_pi", persist_state=persist_state, mount_point=CONFIG["stage_mount"])


def prepare_dump_workspace(state):
    root = stage_mount()
    for child in root.iterdir():
        if child.name == "System Volume Information":
            continue
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        elif child.is_file():
            child.unlink(missing_ok=True)
    (root / "output").mkdir(parents=True, exist_ok=True)
    if not (root / "output").is_dir():
        raise RuntimeError("failed to prepare stage output directory")
    run(["sync"])
    append_session_audit_event(state, "dump_workspace_prepared", path=str(root / "output"))


def mark_session_prepared(state, case_id: str, session_id: str):
    audit("session_prepared", session_id=session_id, case_id=case_id)
    append_session_audit_event(
        state,
        "session_prepared",
        case_id=case_id,
        session_id=session_id,
        operator_id=state["current_session"]["operator_id"],
        target_host=state["current_session"]["target_host"],
        stage_rel_path=state["current_session"]["stage_rel_path"],
    )


def copy_evidence_artifact(state, session_events: list[dict], source_path: Path, target_path: Path):
    copy_with_progress(source_path, target_path, state)
    record_session_event(
        session_events,
        "evidence_copy_completed",
        target_path=str(target_path),
        size_bytes=target_path.stat().st_size,
    )
    append_session_audit_event(
        state,
        "evidence_copy_completed",
        persist_state=False,
        target_path=str(target_path),
        size_bytes=target_path.stat().st_size,
    )


def hash_evidence_artifact(state, session_events: list[dict], target_path: Path) -> str:
    set_progress(state, "FINALIZING", 85, "Hashing evidence")
    evidence_sha512 = hash_file(target_path)
    record_session_event(
        session_events,
        "evidence_hash_completed",
        target_path=str(target_path),
        algorithm="SHA-512",
        sha512=evidence_sha512,
    )
    append_session_audit_event(
        state,
        "evidence_hash_completed",
        persist_state=False,
        target_path=str(target_path),
        algorithm="SHA-512",
        sha512=evidence_sha512,
    )
    return evidence_sha512


def write_manifest_artifact(state, session_events: list[dict], manifest: dict, manifest_path: Path, record_event: bool = True):
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    if record_event:
        record_session_event(session_events, "manifest_written", path=str(manifest_path))
        append_session_audit_event(state, "manifest_written", persist_state=False, path=str(manifest_path))


def sign_manifest_artifact(state, session_events: list[dict], manifest_path: Path, signature_path: Path, record_event: bool = True):
    set_progress(state, "FINALIZING", 95, "Signing manifest")
    sign_manifest(manifest_path, signature_path)
    if record_event:
        record_session_event(session_events, "manifest_signed", signature_path=str(signature_path))
        append_session_audit_event(state, "manifest_signed", persist_state=False, signature_path=str(signature_path))


def cleanup_dump_volume(state, session_events: list[dict]):
    set_progress(state, "FINALIZING", 98, "Cleaning staging volume")
    prepare_idle_stage(mounted=True)
    record_session_event(session_events, "dump_volume_cleanup_completed")
    append_session_audit_event(state, "dump_volume_cleanup_completed", persist_state=False)


def next_session_id():
    return datetime.now(timezone.utc).strftime("SESSION-%Y%m%dT%H%M%SZ")


def next_case_id(form_case_id: str):
    return form_case_id.strip() or datetime.now(timezone.utc).strftime("CASE-%Y%m%d")


def clean_text(value):
    if value is None:
        return ""
    return str(value).strip()


def ensure_signing_key():
    key = Path(CONFIG["signing_key_path"])
    pub = Path(CONFIG["signing_pub_path"])
    key.parent.mkdir(parents=True, exist_ok=True)
    if not key.exists():
        run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(key)])
        os.chmod(key, 0o600)
        run(["openssl", "rsa", "-in", str(key), "-pubout", "-out", str(pub)])


def ensure_request_key():
    key = Path(CONFIG["request_key_path"])
    cert = Path(CONFIG["request_cert_path"])
    key.parent.mkdir(parents=True, exist_ok=True)
    if not key.exists():
        run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(key)])
        os.chmod(key, 0o600)
    if not cert.exists():
        run(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-key",
                str(key),
                "-out",
                str(cert),
                "-days",
                "3650",
                "-subj",
                "/CN=Forensics Imager Request Encryption/",
            ]
        )


def decrypt_request_envelope(path: Path) -> dict:
    ensure_request_key()
    envelope = json.loads(path.read_text(encoding="utf-8-sig"))
    return decrypt_request_envelope_obj(envelope)


def decrypt_request_envelope_obj(envelope: dict) -> dict:
    ensure_request_key()
    ciphertext_b64 = envelope["encrypted_request_b64"]
    ciphertext = base64.b64decode(ciphertext_b64)
    input_path = None
    output_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as infile:
            infile.write(ciphertext)
            input_path = infile.name
        with tempfile.NamedTemporaryFile(delete=False) as outfile:
            output_path = outfile.name
        run(
            [
                "openssl",
                "pkeyutl",
                "-decrypt",
                "-inkey",
                CONFIG["request_key_path"],
                "-pkeyopt",
                "rsa_padding_mode:oaep",
                "-pkeyopt",
                "rsa_oaep_md:sha256",
                "-in",
                input_path,
                "-out",
                output_path,
            ]
        )
        return json.loads(Path(output_path).read_text(encoding="utf-8"))
    finally:
        for candidate in (input_path, output_path):
            if candidate:
                Path(candidate).unlink(missing_ok=True)


def prepare_tools_volume(mounted: bool = False):
    if not mounted:
        mount_tools_local()
    root = tools_mount()
    ensure_request_key()
    for child in root.iterdir():
        if child.name == "System Volume Information":
            continue
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        elif child.is_file():
            child.unlink(missing_ok=True)
    (root / "tools").mkdir(parents=True, exist_ok=True)
    (root / "cert").mkdir(parents=True, exist_ok=True)
    helper_files = {
        "Start_Case.bat": "/opt/forensic-imager/assets/Start_Case.bat",
        "Browse_Evidence.bat": "/opt/forensic-imager/assets/Browse_Evidence.bat",
        "cert/pub.cer": CONFIG["request_cert_path"],
        "tools/winpmem.exe": "/opt/forensic-imager/assets/winpmem.exe",
        "evidence_browser.html": "/opt/forensic-imager/assets/evidence_browser.html",
    }
    for relative_name, source in helper_files.items():
        destination = root / relative_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    run(["sync"])
    if not mounted:
        umount_tools_local()


def prepare_idle_stage(mounted: bool = False, error_message: str = "", result_message: str = ""):
    if not mounted:
        gadget("detach-stage")
        mount_stage_local()
    root = stage_mount()
    for child in root.iterdir():
        if child.name == "System Volume Information":
            continue
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        elif child.is_file():
            child.unlink(missing_ok=True)
    if error_message:
        (root / "ERROR.txt").write_text(error_message + "\n", encoding="utf-8")
    if result_message:
        (root / "LAST_RESULT.txt").write_text(result_message + "\n", encoding="utf-8")
    run(["sync"])
    if not mounted:
        umount_stage_local()


def reset_to_idle(reason: str = "manual_reset"):
    lock_evidence()
    prepare_idle_stage()
    state = idle_state()
    save_state(state)
    audit("state_reset", reason=reason)
    return state


def recover_boot_state():
    state = load_state()
    stale_statuses = {"AUTHENTICATED", "READY_FOR_ACQUISITION", "FINALIZING"}
    if state.get("current_session") or state.get("status") in stale_statuses:
        cleanup = None
        session = state.get("current_session") or {}
        if session:
            cleanup = {
                "case_id": session.get("case_id", ""),
                "session_id": session.get("session_id", ""),
                "reason": "interrupted_poweroff",
            }
        idle = idle_state()
        idle["pending_cleanup"] = cleanup
        prepare_idle_stage()
        save_state(idle)
        audit(
            "interrupted_session_discarded",
            previous_status=state.get("status"),
            case_id=session.get("case_id", ""),
            session_id=session.get("session_id", ""),
            reason="boot_recovery",
        )
        return idle
    if state.get("status") != "LOCKED_IDLE" or state.get("last_error"):
        return reset_to_idle("boot_normalize")
    prepare_idle_stage()
    save_state(state)
    return state


def stage_is_attached() -> bool:
    lun_file = Path("/sys/kernel/config/usb_gadget/forensic_imager/functions/mass_storage.0/lun.1/file")
    return lun_file.exists() and bool(lun_file.read_text().strip())


def tools_are_exposed_to_host() -> bool:
    lun_file = Path("/sys/kernel/config/usb_gadget/forensic_imager/functions/mass_storage.0/lun.0/file")
    return lun_file.exists() and bool(lun_file.read_text().strip())


def control_network_is_exposed() -> bool:
    if not CONFIG.get("usb_ncm_enabled", False):
        return False
    function_dir = Path("/sys/kernel/config/usb_gadget/forensic_imager/functions/ncm.usb0")
    config_link = Path("/sys/kernel/config/usb_gadget/forensic_imager/configs/c.1/ncm.usb0")
    return function_dir.exists() and config_link.exists()


def control_network_is_ready() -> bool:
    if not control_network_is_exposed():
        return False
    iface = CONFIG.get("usb_ncm_iface", "usb0")
    iface_dir = Path("/sys/class/net") / iface
    operstate = iface_dir / "operstate"
    try:
        return iface_dir.exists() and operstate.exists() and operstate.read_text().strip() in {"up", "unknown"}
    except Exception:
        return False


def stage_output_ready() -> bool:
    mount_stage_local()
    try:
        return (stage_mount() / "output").is_dir()
    finally:
        umount_stage_local()


def session_is_viable(state) -> bool:
    session = state.get("current_session")
    if not session:
        return False
    if state.get("status") not in {"AUTHENTICATED", "READY_FOR_ACQUISITION", "FINALIZING"}:
        return False
    if state.get("status") == "AUTHENTICATED":
        return False
    if not stage_is_attached():
        return False
    return stage_output_ready()


def evidence_session_dir(case_id: str, session_id: str) -> Path:
    return evidence_mount() / "cases" / case_id / session_id


def evidence_cleanup_dir(cleanup: dict) -> Path | None:
    if not cleanup:
        return None
    case_id = cleanup.get("case_id", "")
    session_id = cleanup.get("session_id", "")
    if not case_id or not session_id:
        return None
    return evidence_session_dir(case_id, session_id)


def hash_file(path: Path) -> str:
    result = run(["sha512sum", str(path)])
    return result.stdout.split()[0]


def sign_manifest(manifest_path: Path, signature_path: Path):
    run(["openssl", "dgst", "-sha512", "-sign", CONFIG["signing_key_path"], "-out", str(signature_path), str(manifest_path)])


def sign_file(path: Path, signature_path: Path):
    run(["openssl", "dgst", "-sha512", "-sign", CONFIG["signing_key_path"], "-out", str(signature_path), str(path)])


def record_session_event(events: list[dict], event: str, **fields):
    entry = {"ts_utc": utc_now(), "event": event, **fields}
    events.append(entry)
    return entry


def session_audit_paths(case_id: str, session_id: str) -> tuple[Path, Path]:
    log_dir = evidence_session_dir(case_id, session_id) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / "session_audit.jsonl", log_dir / "session_audit.jsonl.sig"


def append_session_audit_event(state, event: str, persist_state: bool = True, **fields):
    session = state.get("current_session") or {}
    case_id = clean_text(session.get("case_id", ""))
    session_id = clean_text(session.get("session_id", ""))
    if not case_id or not session_id:
        return None
    audit_path, signature_path = session_audit_paths(case_id, session_id)
    prev_hash = clean_text(session.get("audit_chain_head", ""))
    entry = {"ts_utc": utc_now(), "event": event, **fields, "prev_event_hash": prev_hash}
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
    entry["event_hash"] = hashlib.sha512(canonical).hexdigest()
    with audit_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    sign_file(audit_path, signature_path)
    session["audit_chain_head"] = entry["event_hash"]
    state["current_session"] = session
    if persist_state:
        save_state(state)
    return entry


def append_session_audit_entry(state, entry: dict, persist_state: bool = True):
    event = clean_text(entry.get("event", ""))
    if not event:
        return None
    session = state.get("current_session") or {}
    case_id = clean_text(session.get("case_id", ""))
    session_id = clean_text(session.get("session_id", ""))
    if not case_id or not session_id:
        return None
    audit_path, signature_path = session_audit_paths(case_id, session_id)
    prev_hash = clean_text(session.get("audit_chain_head", ""))
    payload = {k: v for k, v in entry.items() if k not in {"prev_event_hash", "event_hash"}}
    payload.setdefault("ts_utc", utc_now())
    payload["event"] = event
    payload["prev_event_hash"] = prev_hash
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["event_hash"] = hashlib.sha512(canonical).hexdigest()
    with audit_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload) + "\n")
    sign_file(audit_path, signature_path)
    session["audit_chain_head"] = payload["event_hash"]
    state["current_session"] = session
    if persist_state:
        save_state(state)
    return payload


def buffer_pre_session_event(state, event: str, **fields):
    entry = {"ts_utc": utc_now(), "event": event, **fields}
    queue = list(state.get("pending_session_events", []))
    queue.append(entry)
    state["pending_session_events"] = queue
    save_state(state)
    return entry


def record_session_event_immediate(state, event: str, **fields):
    if state.get("current_session"):
        return append_session_audit_event(state, event, **fields)
    return buffer_pre_session_event(state, event, **fields)


def flush_pending_session_events(state):
    pending = list(state.get("pending_session_events", []))
    if not pending or not state.get("current_session"):
        state["pending_session_events"] = []
        save_state(state)
        return
    pending.sort(key=lambda item: item.get("ts_utc", ""))
    for item in pending:
        append_session_audit_entry(state, item, persist_state=False)
    state["pending_session_events"] = []
    save_state(state)


def copy_with_progress(source: Path, target: Path, state):
    total_bytes = max(1, source.stat().st_size)
    copied = 0
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as src, target.open("wb") as dst:
        while True:
            chunk = src.read(16 * 1024 * 1024)
            if not chunk:
                break
            dst.write(chunk)
            copied += len(chunk)
            percent = 10 + int((copied * 70) / total_bytes)
            set_progress(state, "FINALIZING", percent, f"Copying evidence ({percent}%)")
    shutil.copystat(source, target)


def cleanup_pending_evidence(state):
    cleanup = state.get("pending_cleanup")
    cleanup_dir = evidence_cleanup_dir(cleanup)
    if not cleanup_dir:
        state["pending_cleanup"] = None
        save_state(state)
        return

    if cleanup_dir.exists():
        shutil.rmtree(cleanup_dir, ignore_errors=True)
    audit(
        "pending_cleanup_completed",
        case_id=cleanup.get("case_id", ""),
        session_id=cleanup.get("session_id", ""),
        reason=cleanup.get("reason", "unknown"),
    )
    state["pending_cleanup"] = None
    save_state(state)


def start_session(state, request: dict):
    if state.get("current_session"):
        raise RuntimeError("session already active")
    if state.get("status") != "AUTHENTICATED":
        raise RuntimeError("password not verified")

    error_message = ""
    try:
        ensure_signing_key()
        session_id = next_session_id()
        case_id = next_case_id(request.get("case_id", ""))
        state["current_session"] = {
            "session_id": session_id,
            "case_id": case_id,
            "operator_id": clean_text(request.get("operator_id", "")),
            "target_host": clean_text(request.get("target_host", "")),
            "notes": clean_text(request.get("notes", "")),
            "session_start_utc": utc_now(),
            "stage_rel_path": "output/memory.raw",
            "audit_chain_head": "",
        }
        save_state(state)
        flush_pending_session_events(state)
        detach_stage_from_host(state)
        mount_stage_on_pi(state)
        prepare_dump_workspace(state)
        unmount_stage_from_pi(state)
        attach_stage_to_host(state)
        state["status"] = "READY_FOR_ACQUISITION"
        state["last_error"] = None
        save_state(state)
        mark_session_prepared(state, case_id, session_id)
        return state["current_session"]
    except Exception as exc:
        error_message = str(exc)
        state["status"] = "LOCKED_IDLE"
        state["current_session"] = None
        state["last_error"] = error_message
        save_state(state)
        audit("error", detail=error_message)
        prepare_idle_stage(error_message=error_message)
        lock_evidence()
        raise


def verify_password(state, request: dict):
    if state.get("current_session"):
        raise RuntimeError("session already active")

    password = request.get("password", "")
    if not password:
        raise RuntimeError("missing password")

    try:
        lock_evidence()
        unlock_evidence(password)
        cleanup_pending_evidence(state)
        ensure_signing_key()
        record_session_event_immediate(state, "password_verified")
        state["status"] = "AUTHENTICATED"
        state["current_session"] = None
        state["last_error"] = None
        state["last_result"] = None
        state["progress"] = {"phase": "AUTHENTICATED", "percent": 0, "message": "Password verified"}
        save_state(state)
        audit("auth_verified")
        return {"ok": True, "status": "AUTHENTICATED"}
    except Exception as exc:
        error_message = str(exc)
        state["status"] = "LOCKED_IDLE"
        state["current_session"] = None
        state["last_error"] = error_message
        save_state(state)
        audit("error", detail=error_message)
        lock_evidence()
        raise


def finalize_session(state):
    session = state["current_session"]
    if not session:
        raise RuntimeError("no active session")
    session_id = session["session_id"]
    case_id = session["case_id"]
    stage_rel = Path(session["stage_rel_path"])
    session_events: list[dict] = []
    state["status"] = "FINALIZING"
    state["last_error"] = None
    state["last_result"] = None
    set_progress(state, "FINALIZING", 5, "Detaching staging volume")
    record_session_event(session_events, "finalization_begun", case_id=case_id, session_id=session_id)
    append_session_audit_event(state, "finalization_begun", persist_state=False, case_id=case_id, session_id=session_id)
    detach_stage_from_host(state, persist_state=False, session_events=session_events)
    mount_stage_on_pi(state, persist_state=False, session_events=session_events)
    local_stage_file = stage_mount() / stage_rel
    if not local_stage_file.exists():
        raise RuntimeError(f"staged dump not found: {local_stage_file}")
    target_dir = evidence_session_dir(case_id, session_id)
    (target_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (target_dir / "manifest").mkdir(parents=True, exist_ok=True)
    (target_dir / "logs").mkdir(parents=True, exist_ok=True)
    target_file = target_dir / "evidence" / local_stage_file.name
    copy_evidence_artifact(state, session_events, local_stage_file, target_file)
    evidence_sha512 = hash_evidence_artifact(state, session_events, target_file)
    manifest = {
        "manifest_version": "1.0",
        "device_id": CONFIG["device_id"],
        "case_id": case_id,
        "session_id": session_id,
        "operator_id": session["operator_id"],
        "target_host": session["target_host"],
        "tool": {"name": "winpmem", "source": "staged session tool"},
        "timestamps": {
            "session_start_utc": session["session_start_utc"],
            "acquisition_end_utc": session.get("acquisition_end_utc", ""),
            "archive_complete_utc": utc_now(),
        },
        "evidence": {
            "filename": target_file.name,
            "size_bytes": target_file.stat().st_size,
            "sha512": evidence_sha512,
        },
        "notes": session["notes"],
        "events": [
            "auth_success",
            "stage_prepared",
            "host_storage_detached",
            "archive_complete",
            "manifest_signed",
        ],
    }
    manifest_path = target_dir / "manifest" / "manifest.json"
    signature_path = target_dir / "manifest" / "manifest.sig"
    write_manifest_artifact(state, session_events, manifest, manifest_path)
    cleanup_dump_volume(state, session_events)
    unmount_stage_from_pi(state, persist_state=False, session_events=session_events)
    session_audit_path, session_audit_sig = session_audit_paths(case_id, session_id)
    audit_signed_at = utc_now()
    manifest["artifacts"] = {
        "evidence": {"path": f"evidence/{target_file.name}", "sha512": evidence_sha512},
        "manifest": {
            "path": "manifest/manifest.json",
            "signature_path": "manifest/manifest.sig",
        },
        "session_audit": {
            "path": "logs/session_audit.jsonl",
            "sha512": hash_file(session_audit_path),
            "signature_path": "logs/session_audit.jsonl.sig",
            "signed_at_utc": audit_signed_at,
        },
    }
    write_manifest_artifact(state, session_events, manifest, manifest_path, record_event=False)
    sign_manifest_artifact(state, session_events, manifest_path, signature_path)
    manifest["artifacts"]["manifest"]["sha512"] = hash_file(manifest_path)
    manifest["artifacts"]["manifest"]["signed_at_utc"] = next(
        (e["ts_utc"] for e in session_events if e["event"] == "manifest_signed"), ""
    )
    manifest["artifacts"]["session_audit"]["sha512"] = hash_file(session_audit_path)
    manifest["artifacts"]["session_audit"]["signed_at_utc"] = next(
        (e["ts_utc"] for e in session_events if e["event"] == "manifest_signed"), audit_signed_at
    )
    manifest["audit_summary"] = [
        json.loads(line) for line in session_audit_path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    write_manifest_artifact(state, session_events, manifest, manifest_path, record_event=False)
    sign_manifest_artifact(state, session_events, manifest_path, signature_path, record_event=False)
    state["status"] = "LOCKED_IDLE"
    state["current_session"] = None
    state["last_error"] = None
    state["last_result"] = {
        "case_id": case_id,
        "session_id": session_id,
        "sha512": manifest["evidence"]["sha512"],
        "size_bytes": manifest["evidence"]["size_bytes"],
    }
    state["progress"] = {"phase": "IDLE", "percent": 100, "message": "Finalization complete"}
    save_state(state)
    audit("session_finalized", case_id=case_id, session_id=session_id, sha512=manifest["evidence"]["sha512"])
    lock_evidence()
    return manifest


def agent_loop():
    ensure_paths()
    recover_boot_state()
    audit("agent_start")
    while True:
        try:
            load_state()
        except Exception as exc:
            state = load_state()
            state["last_error"] = str(exc)
            save_state(state)
            audit("error", detail=str(exc))
        time.sleep(1)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "finalize-current":
        state = load_state()
        manifest = finalize_session(state)
        print(json.dumps(manifest, indent=2))
        return
    agent_loop()


if __name__ == "__main__":
    main()
