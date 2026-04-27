#!/usr/bin/env python3
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import agent
import evidence_service


LOCK = threading.Lock()
CONTROL_HOST = agent.CONFIG["control_bind_host"]
CONTROL_PORT = int(agent.CONFIG["control_port"])
FINALIZE_THREAD = None
EVIDENCE_BROWSER_HTML = Path("/opt/forensic-imager/assets/evidence_browser.html")


def with_lock(fn, *args, **kwargs):
    with LOCK:
        return fn(*args, **kwargs)


def load_state_for_request(validate_session: bool = True):
    state = with_lock(agent.load_state)
    if validate_session and state.get("current_session") and not with_lock(agent.session_is_viable, state):
        with_lock(
            agent.security_event,
            "stale_request_state_detected",
            previous_status=state.get("status"),
            session_id=(state.get("current_session") or {}).get("session_id", ""),
            case_id=(state.get("current_session") or {}).get("case_id", ""),
        )
        state = with_lock(agent.reset_to_idle, "stale_request_state")
    return state


def evidence_is_unlocked():
    mapper = Path(f"/dev/mapper/{agent.CONFIG['evidence_mapper']}")
    return mapper.exists() and agent.evidence_mount().is_dir()


def evidence_browser_root() -> Path:
    if not evidence_is_unlocked():
        raise RuntimeError("evidence store is locked")
    return agent.evidence_mount()


def evidence_browser_unlock(password: str):
    state = agent.load_state()
    if state.get("current_session"):
        raise RuntimeError("cannot unlock evidence browser while a session is active")
    agent.lock_evidence()
    agent.unlock_evidence(password)
    agent.cleanup_pending_evidence(state)
    agent.save_state(state)


class ControlHandler(BaseHTTPRequestHandler):
    server_version = "ForensicsControl/1.0"

    def _log_security(self, event: str, **fields):
        with_lock(agent.security_event, event, path=self.path, **fields)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _send_json(self, status: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, path: Path):
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path, content_type: str, download_name: str | None = None):
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if download_name:
            self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/evidence-browser":
            self._send_html(EVIDENCE_BROWSER_HTML)
            return
        if parsed.path == "/api/evidence-browser/status":
            self.handle_evidence_browser_status()
            return
        if parsed.path == "/api/evidence-browser/cases":
            self.handle_evidence_browser_cases()
            return
        if parsed.path.startswith("/api/evidence-browser/case/"):
            self.handle_evidence_browser_case(parsed.path)
            return
        if parsed.path == "/api/evidence-browser/download":
            self.handle_evidence_browser_download(parsed.query)
            return
        if parsed.path != "/status":
            self._log_security("unexpected_get_path")
            self._send_json(404, {"error": "not found"})
            return
        state = with_lock(agent.load_state)
        self._send_json(200, state)

    def do_POST(self):
        if self.path == "/verify-password":
            self.handle_verify_password()
            return
        if self.path == "/start-case":
            self.handle_start_case()
            return
        if self.path == "/acquisition-started":
            self.handle_acquisition_started()
            return
        if self.path == "/session-event":
            self.handle_session_event()
            return
        if self.path == "/api/evidence-browser/unlock":
            self.handle_evidence_browser_unlock()
            return
        if self.path == "/api/evidence-browser/lock":
            self.handle_evidence_browser_lock()
            return
        if self.path != "/finalize":
            self._log_security("unexpected_post_path")
            self._send_json(404, {"error": "not found"})
            return

        try:
            self._read_json()
        except Exception as exc:
            self._log_security("invalid_json", detail=str(exc))
            self._send_json(400, {"error": f"invalid json: {exc}"})
            return

        try:
            state = load_state_for_request(validate_session=False)
            session = state.get("current_session")
            if not session:
                self._log_security("finalize_without_active_session")
                self._send_json(409, {"error": "no active session"})
                return
            if not session.get("acquisition_end_utc"):
                session["acquisition_end_utc"] = agent.utc_now()
                state["current_session"] = session
                with_lock(agent.save_state, state)
                with_lock(agent.audit, "finalize_requested", session_id=session.get("session_id", ""), case_id=session.get("case_id", ""))
            global FINALIZE_THREAD
            if FINALIZE_THREAD and FINALIZE_THREAD.is_alive():
                self._send_json(202, {"ok": True, "status": "FINALIZING"})
                return
            FINALIZE_THREAD = threading.Thread(target=run_finalize, daemon=True)
            FINALIZE_THREAD.start()
            self._send_json(202, {"ok": True, "status": "FINALIZING"})
        except Exception as exc:
            self._log_security("finalize_rejected", detail=str(exc))
            self._send_json(500, {"error": str(exc)})

    def handle_start_case(self):
        try:
            payload = self._read_json()
        except Exception as exc:
            self._log_security("invalid_json", detail=str(exc))
            self._send_json(400, {"error": f"invalid json: {exc}"})
            return

        try:
            state = load_state_for_request()
            request = {
                "case_id": payload.get("case_id", ""),
                "operator_id": payload.get("operator_id", ""),
                "target_host": payload.get("target_host", ""),
                "notes": payload.get("notes", ""),
            }
            if with_lock(agent.tools_are_exposed_to_host):
                self._log_security("tools_volume_exposed_by_pi", tools_device=agent.CONFIG["tools_device"])
            if with_lock(agent.control_network_is_exposed):
                self._log_security("control_network_exposed_by_pi", interface=agent.CONFIG["usb_ncm_iface"])
            if with_lock(agent.control_network_is_ready):
                self._log_security(
                    "control_network_ready_on_pi",
                    interface=agent.CONFIG["usb_ncm_iface"],
                    address=agent.CONFIG.get("usb_ncm_device_cidr", ""),
                )
            with_lock(
                agent.record_session_event_immediate,
                state,
                "case_details_received_by_pi",
                requested_case_id=request.get("case_id", ""),
                operator_id=request.get("operator_id", ""),
                target_host=request.get("target_host", ""),
            )
            session = with_lock(agent.start_session, state, request)
            self._send_json(
                200,
                {
                    "ok": True,
                    "case_id": session["case_id"],
                    "session_id": session["session_id"],
                    "status": "READY_FOR_ACQUISITION",
                },
            )
        except Exception as exc:
            self._log_security("start_case_rejected", detail=str(exc))
            self._send_json(500, {"error": str(exc)})

    def handle_acquisition_started(self):
        try:
            payload = self._read_json()
        except Exception as exc:
            self._log_security("invalid_json", detail=str(exc))
            self._send_json(400, {"error": f"invalid json: {exc}"})
            return

        try:
            state = load_state_for_request(validate_session=False)
            session = state.get("current_session")
            if not session:
                self._log_security("acquisition_started_without_active_session")
                raise RuntimeError("no active session")
            with_lock(
                agent.audit,
                "acquisition_started",
                session_id=session.get("session_id", ""),
                case_id=session.get("case_id", ""),
                tool=payload.get("tool", "winpmem"),
            )
            self._send_json(200, {"ok": True})
        except Exception as exc:
            self._log_security("acquisition_started_rejected", detail=str(exc))
            self._send_json(500, {"error": str(exc)})

    def handle_session_event(self):
        try:
            payload = self._read_json()
        except Exception as exc:
            self._log_security("invalid_json", detail=str(exc))
            self._send_json(400, {"error": f"invalid json: {exc}"})
            return

        try:
            state = load_state_for_request(validate_session=False)
            session = state.get("current_session")
            event_name = str(payload.get("event", "")).strip()
            if not event_name:
                self._log_security("session_event_missing_name")
                raise RuntimeError("missing event")
            fields = {k: v for k, v in payload.items() if k != "event"}
            if session:
                fields.setdefault("session_id", session.get("session_id", ""))
                fields.setdefault("case_id", session.get("case_id", ""))
            with_lock(agent.record_session_event_immediate, state, event_name, **fields)
            with_lock(agent.audit, event_name, **fields)
            self._send_json(200, {"ok": True})
        except Exception as exc:
            self._log_security("session_event_rejected", detail=str(exc))
            self._send_json(500, {"error": str(exc)})

    def handle_verify_password(self):
        try:
            payload = self._read_json()
        except Exception as exc:
            self._log_security("invalid_json", detail=str(exc))
            self._send_json(400, {"error": f"invalid json: {exc}"})
            return

        try:
            request = with_lock(agent.decrypt_request_envelope_obj, payload)
            state = load_state_for_request()
            result = with_lock(agent.verify_password, state, request)
            self._send_json(200, result)
        except Exception as exc:
            self._log_security("password_verification_failed", detail=str(exc))
            self._send_json(500, {"error": str(exc)})

    def handle_evidence_browser_status(self):
        try:
            state = with_lock(agent.load_state)
            self._send_json(
                200,
                {
                    "evidence_unlocked": with_lock(evidence_is_unlocked),
                    "controller_status": state.get("status"),
                    "current_session": state.get("current_session"),
                },
            )
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})

    def handle_evidence_browser_unlock(self):
        try:
            payload = self._read_json()
        except Exception as exc:
            self._log_security("invalid_json", detail=str(exc))
            self._send_json(400, {"error": f"invalid json: {exc}"})
            return

        try:
            password = str(payload.get("password", ""))
            if not password:
                raise RuntimeError("missing password")
            with_lock(evidence_browser_unlock, password)
            self._send_json(200, {"ok": True, "evidence_unlocked": True})
        except Exception as exc:
            self._log_security("evidence_browser_unlock_rejected", detail=str(exc))
            self._send_json(500, {"error": str(exc)})

    def handle_evidence_browser_lock(self):
        try:
            with_lock(agent.lock_evidence)
            self._send_json(200, {"ok": True, "evidence_unlocked": False})
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})

    def handle_evidence_browser_cases(self):
        try:
            root = evidence_browser_root()
            cases = [
                {"case_id": case_id, "session_count": len([p for p in path.iterdir() if p.is_dir()])}
                for case_id, path in evidence_service.load_cases(root)
            ]
            self._send_json(200, {"cases": cases})
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})

    def handle_evidence_browser_case(self, request_path: str):
        try:
            case_id = unquote(request_path.rsplit("/", 1)[-1])
            if not case_id:
                raise RuntimeError("missing case id")
            root = evidence_browser_root()
            case_dir = root / "cases" / case_id
            if not case_dir.exists():
                raise RuntimeError("case not found")
            sessions = evidence_service.verify_case(case_dir, Path(agent.CONFIG["signing_pub_path"]))
            self._send_json(
                200,
                {
                    "case_id": case_id,
                    "files": evidence_service.build_case_tree(case_dir),
                    "logs": evidence_service.collect_case_logs(case_dir),
                    "sessions": [
                        {
                            "case_id": item.case_id,
                            "session_id": item.session_id,
                            "size_bytes": item.size_bytes,
                            "manifest_sha512": item.manifest_sha512,
                            "actual_sha512": item.actual_sha512,
                            "hash_ok": item.hash_ok,
                            "signature_ok": item.signature_ok,
                            "audit_hash_ok": item.audit_hash_ok,
                            "audit_signature_ok": item.audit_signature_ok,
                            "notes": item.notes,
                            "manifest": json.loads(item.manifest_path.read_text(encoding="utf-8")),
                        }
                        for item in sessions
                    ],
                },
            )
        except Exception as exc:
            self._log_security("evidence_browser_case_rejected", detail=str(exc))
            self._send_json(500, {"error": str(exc)})

    def handle_evidence_browser_download(self, query: str):
        try:
            params = parse_qs(query)
            case_id = unquote(params.get("case", [""])[0])
            relative_path = unquote(params.get("path", [""])[0])
            if not case_id or not relative_path:
                raise RuntimeError("missing case or path")
            root = evidence_browser_root()
            case_dir = root / "cases" / case_id
            if not case_dir.exists():
                raise RuntimeError("case not found")
            target = evidence_service.safe_case_path(case_dir, relative_path)
            content_type = evidence_service.mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            self._send_file(target, content_type, target.name)
        except Exception as exc:
            self._log_security("evidence_browser_download_rejected", detail=str(exc))
            self._send_json(500, {"error": str(exc)})

    def log_message(self, format, *args):
        return


def run_agent_loop():
    agent.agent_loop()


def run_finalize():
    try:
        state = agent.load_state()
        agent.finalize_session(state)
    except Exception as exc:
        state = agent.load_state()
        state["status"] = "LOCKED_IDLE"
        state["last_error"] = str(exc)
        state["progress"] = {"phase": "ERROR", "percent": 0, "message": "Finalization failed"}
        agent.save_state(state)
        agent.audit("error", detail=str(exc))
        agent.security_event("finalize_thread_failed", detail=str(exc))


def main():
    thread = threading.Thread(target=run_agent_loop, daemon=True)
    thread.start()
    httpd = ThreadingHTTPServer((CONTROL_HOST, CONTROL_PORT), ControlHandler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
