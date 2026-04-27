from __future__ import annotations

import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from core import EvidenceMount, load_cases, open_luks, verify_case


class VerifierApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Forensics Evidence Browser")
        self.root.geometry("1100x720")
        self.mount: EvidenceMount | None = None
        self.root_path: Path | None = None
        self.public_key_path: Path | None = None

        self.mode = tk.StringVar(value="mounted")
        self.mounted_path = tk.StringVar()
        self.device_path = tk.StringVar()
        self.password = tk.StringVar()
        self.public_key = tk.StringVar()
        self.status = tk.StringVar(value="Idle")

        self._build()

    def _build(self):
        top = ttk.Frame(self.root, padding=12)
        top.pack(fill="x")

        mode_frame = ttk.LabelFrame(top, text="Evidence Source", padding=10)
        mode_frame.pack(fill="x")
        ttk.Radiobutton(mode_frame, text="Mounted Evidence Folder", variable=self.mode, value="mounted").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(mode_frame, text="Open LUKS Device (Linux)", variable=self.mode, value="luks").grid(row=0, column=1, sticky="w", padx=(20, 0))

        ttk.Label(mode_frame, text="Evidence Root").grid(row=1, column=0, sticky="w", pady=(10, 0))
        ttk.Entry(mode_frame, textvariable=self.mounted_path, width=80).grid(row=2, column=0, columnspan=2, sticky="ew")
        ttk.Button(mode_frame, text="Browse", command=self.browse_root).grid(row=2, column=2, padx=(8, 0))

        ttk.Label(mode_frame, text="LUKS Device").grid(row=3, column=0, sticky="w", pady=(10, 0))
        ttk.Entry(mode_frame, textvariable=self.device_path, width=50).grid(row=4, column=0, sticky="ew")
        ttk.Label(mode_frame, text="Password").grid(row=3, column=1, sticky="w", pady=(10, 0))
        ttk.Entry(mode_frame, textvariable=self.password, show="", width=25).grid(row=4, column=1, sticky="ew", padx=(8, 0))
        ttk.Button(mode_frame, text="Open", command=self.open_source).grid(row=4, column=2, padx=(8, 0))

        ttk.Label(mode_frame, text="Signing Public Key (optional)").grid(row=5, column=0, sticky="w", pady=(10, 0))
        ttk.Entry(mode_frame, textvariable=self.public_key, width=80).grid(row=6, column=0, columnspan=2, sticky="ew")
        ttk.Button(mode_frame, text="Browse", command=self.browse_pubkey).grid(row=6, column=2, padx=(8, 0))

        ttk.Button(mode_frame, text="Load Cases", command=self.open_source).grid(row=7, column=0, pady=(12, 0), sticky="w")
        ttk.Label(mode_frame, textvariable=self.status).grid(row=7, column=1, columnspan=2, sticky="w", padx=(8, 0), pady=(12, 0))

        split = ttk.Panedwindow(self.root, orient="horizontal")
        split.pack(fill="both", expand=True, padx=12, pady=12)

        left = ttk.Frame(split, padding=8)
        right = ttk.Frame(split, padding=8)
        split.add(left, weight=1)
        split.add(right, weight=3)

        ttk.Label(left, text="Cases").pack(anchor="w")
        self.case_list = tk.Listbox(left, height=25)
        self.case_list.pack(fill="both", expand=True)
        self.case_list.bind("<<ListboxSelect>>", self.on_case_selected)

        ttk.Label(right, text="Verification Results").pack(anchor="w")
        cols = ("session", "hash", "signature", "size")
        self.tree = ttk.Treeview(right, columns=cols, show="headings", height=16)
        for col, title, width in (
            ("session", "Session", 220),
            ("hash", "Hash", 120),
            ("signature", "Signature", 120),
            ("size", "Size (bytes)", 140),
        ):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_session_selected)

        self.details = tk.Text(right, height=16, wrap="word")
        self.details.pack(fill="both", expand=True, pady=(10, 0))

        self.case_paths: dict[str, Path] = {}
        self.session_rows: dict[str, dict] = {}

    def browse_root(self):
        path = filedialog.askdirectory()
        if path:
            self.mounted_path.set(path)

    def browse_pubkey(self):
        path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if path:
            self.public_key.set(path)

    def set_status(self, text: str):
        self.status.set(text)
        self.root.update_idletasks()

    def open_source(self):
        thread = threading.Thread(target=self._open_source_worker, daemon=True)
        thread.start()

    def _open_source_worker(self):
        try:
            self.set_status("Opening evidence source...")
            self.close_mount()
            self.public_key_path = Path(self.public_key.get()) if self.public_key.get() else None
            if self.mode.get() == "mounted":
                root_path = Path(self.mounted_path.get())
                if not root_path.exists():
                    raise RuntimeError("Select a valid mounted evidence folder.")
                self.root_path = root_path
            else:
                if os.name == "nt":
                    raise RuntimeError("Direct LUKS open from this GUI is intended for Linux hosts with cryptsetup.")
                if not self.device_path.get():
                    raise RuntimeError("Enter a LUKS device path.")
                if not self.password.get():
                    raise RuntimeError("Enter the LUKS password.")
                self.mount = open_luks(self.device_path.get(), self.password.get())
                self.root_path = self.mount.mountpoint
            self.load_case_list()
            self.set_status("Evidence source loaded.")
        except Exception as exc:
            self.set_status("Open failed.")
            messagebox.showerror("Open Failed", str(exc))

    def load_case_list(self):
        self.case_list.delete(0, tk.END)
        self.case_paths.clear()
        for case_id, path in load_cases(self.root_path):
            self.case_paths[case_id] = path
            self.case_list.insert(tk.END, case_id)
        self.tree.delete(*self.tree.get_children())
        self.details.delete("1.0", tk.END)

    def on_case_selected(self, _event=None):
        selection = self.case_list.curselection()
        if not selection:
            return
        case_id = self.case_list.get(selection[0])
        thread = threading.Thread(target=self._verify_case_worker, args=(case_id,), daemon=True)
        thread.start()

    def _verify_case_worker(self, case_id: str):
        try:
            self.set_status(f"Verifying case {case_id}...")
            sessions = verify_case(self.case_paths[case_id], self.public_key_path)
            self.root.after(0, self.populate_sessions, sessions)
            self.set_status(f"Case {case_id} verified.")
        except Exception as exc:
            self.set_status("Verification failed.")
            messagebox.showerror("Verification Failed", str(exc))

    def populate_sessions(self, sessions):
        self.tree.delete(*self.tree.get_children())
        self.session_rows.clear()
        self.details.delete("1.0", tk.END)
        for session in sessions:
            signature = "OK" if session.signature_ok is True else ("Skipped" if session.signature_ok is None else "FAIL")
            hash_status = "OK" if session.hash_ok else "FAIL"
            row_id = self.tree.insert("", "end", values=(session.session_id, hash_status, signature, str(session.size_bytes)))
            self.session_rows[row_id] = {
                "session_id": session.session_id,
                "case_id": session.case_id,
                "evidence": str(session.evidence_path),
                "manifest": str(session.manifest_path),
                "signature": str(session.signature_path) if session.signature_path else "(none)",
                "manifest_sha512": session.manifest_sha512,
                "actual_sha512": session.actual_sha512,
                "hash_ok": session.hash_ok,
                "signature_ok": session.signature_ok,
                "notes": session.notes,
            }

    def on_session_selected(self, _event=None):
        selection = self.tree.selection()
        if not selection:
            return
        info = self.session_rows[selection[0]]
        lines = [
            f"Case ID: {info['case_id']}",
            f"Session ID: {info['session_id']}",
            f"Evidence: {info['evidence']}",
            f"Manifest: {info['manifest']}",
            f"Signature: {info['signature']}",
            f"Hash OK: {info['hash_ok']}",
            f"Signature OK: {info['signature_ok']}",
            f"Manifest SHA-512: {info['manifest_sha512']}",
            f"Actual SHA-512:   {info['actual_sha512']}",
            f"Notes: {info['notes']}",
        ]
        self.details.delete("1.0", tk.END)
        self.details.insert("1.0", "\n".join(lines))

    def close_mount(self):
        if self.mount:
            self.mount.close()
            self.mount = None


def main():
    root = tk.Tk()
    app = VerifierApp(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app.close_mount(), root.destroy()))
    root.mainloop()


if __name__ == "__main__":
    main()
