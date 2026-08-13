"""AntiFine Native Desktop Application.

A modern dark-themed Windows desktop GUI built with CustomTkinter.
Provides visual dashboard, audit controls, and report generation.
"""

from __future__ import annotations

import io
import sqlite3
import sys
import threading
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

import customtkinter as ctk

PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.setup import DB_PATH, initialize_database  # noqa: E402

# ── Appearance ──────────────────────────────────────────────────────────────
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

SEVERITY_COLORS = {
    "CRITICAL": "#e74c3c",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#3498db",
    "INFO":     "#95a5a6",
}


# ── Helpers ─────────────────────────────────────────────────────────────────

def _fetch_severity_counts(db_path: Path = DB_PATH) -> dict[str, int]:
    """Return {severity: count} from the audit database."""
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    if not db_path.is_file():
        return counts
    try:
        with sqlite3.connect(db_path) as conn:
            rows = conn.execute(
                "SELECT UPPER(severity) AS sev, COUNT(*) "
                "FROM scan_results GROUP BY sev"
            ).fetchall()
        for sev, cnt in rows:
            if sev in counts:
                counts[sev] = cnt
    except sqlite3.Error:
        pass
    return counts


def _fetch_all_findings(db_path: Path = DB_PATH) -> list[tuple]:
    """Return all findings as a list of tuples."""
    if not db_path.is_file():
        return []
    try:
        with sqlite3.connect(db_path) as conn:
            return conn.execute(
                "SELECT id, target_id, vulnerability_type, severity, status, "
                "timestamp FROM scan_results ORDER BY id DESC"
            ).fetchall()
    except sqlite3.Error:
        return []


# ── Severity Card Widget ───────────────────────────────────────────────────

class SeverityCard(ctk.CTkFrame):
    """A single dashboard card showing a severity count."""

    def __init__(self, master, label: str, count: int, color: str, **kw):
        super().__init__(master, corner_radius=12, fg_color="#1e1e2e", **kw)

        self.grid_columnconfigure(0, weight=1)

        count_label = ctk.CTkLabel(
            self, text=str(count), font=ctk.CTkFont(size=42, weight="bold"),
            text_color=color,
        )
        count_label.grid(row=0, column=0, padx=20, pady=(15, 0))

        name_label = ctk.CTkLabel(
            self, text=label, font=ctk.CTkFont(size=14),
            text_color="#a0a0b0",
        )
        name_label.grid(row=1, column=0, padx=20, pady=(0, 15))


# ── Main Application ──────────────────────────────────────────────────────

class AntiFineApp(ctk.CTk):
    """Root window and layout manager."""

    def __init__(self):
        super().__init__()

        # ── Window ──────────────────────────────────────────────────────
        self.title("AntiFine - Security Auditor")
        self.geometry("950x650")
        self.minsize(800, 500)

        # ── Grid layout: sidebar + content area ─────────────────────────
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # ── Sidebar ─────────────────────────────────────────────────────
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0, fg_color="#12121a")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(6, weight=1)

        logo = ctk.CTkLabel(
            self.sidebar, text="🛡️ AntiFine",
            font=ctk.CTkFont(size=22, weight="bold"),
        )
        logo.grid(row=0, column=0, padx=20, pady=(25, 5))

        subtitle = ctk.CTkLabel(
            self.sidebar, text="Security Auditor",
            font=ctk.CTkFont(size=12), text_color="#7a7a8a",
        )
        subtitle.grid(row=1, column=0, padx=20, pady=(0, 25))

        self.btn_dashboard = ctk.CTkButton(
            self.sidebar, text="📊  Dashboard", command=self.show_dashboard,
            fg_color="transparent", hover_color="#2a2a3a",
            anchor="w", font=ctk.CTkFont(size=14),
        )
        self.btn_dashboard.grid(row=2, column=0, padx=10, pady=5, sticky="ew")

        self.btn_audits = ctk.CTkButton(
            self.sidebar, text="🔍  Run Audits", command=self.show_audits,
            fg_color="transparent", hover_color="#2a2a3a",
            anchor="w", font=ctk.CTkFont(size=14),
        )
        self.btn_audits.grid(row=3, column=0, padx=10, pady=5, sticky="ew")

        self.btn_reports = ctk.CTkButton(
            self.sidebar, text="📄  Reports", command=self.show_reports,
            fg_color="transparent", hover_color="#2a2a3a",
            anchor="w", font=ctk.CTkFont(size=14),
        )
        self.btn_reports.grid(row=4, column=0, padx=10, pady=5, sticky="ew")

        version_label = ctk.CTkLabel(
            self.sidebar, text="v1.0.0", text_color="#555566",
            font=ctk.CTkFont(size=11),
        )
        version_label.grid(row=7, column=0, padx=20, pady=(0, 15))

        # ── Content area ────────────────────────────────────────────────
        self.content = ctk.CTkFrame(self, corner_radius=0, fg_color="#16161e")
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        # Initialize the database silently
        try:
            initialize_database()
        except Exception:
            pass

        self.show_dashboard()

    # ── View helpers ────────────────────────────────────────────────────

    def _clear_content(self):
        for widget in self.content.winfo_children():
            widget.destroy()

    def _highlight_button(self, active: ctk.CTkButton):
        for btn in (self.btn_dashboard, self.btn_audits, self.btn_reports):
            btn.configure(fg_color="transparent")
        active.configure(fg_color="#2a2a3a")

    # ── Dashboard View ──────────────────────────────────────────────────

    def show_dashboard(self):
        self._clear_content()
        self._highlight_button(self.btn_dashboard)

        header = ctk.CTkLabel(
            self.content, text="Security Dashboard",
            font=ctk.CTkFont(size=24, weight="bold"),
        )
        header.grid(row=0, column=0, columnspan=4, padx=30, pady=(25, 20), sticky="w")

        counts = _fetch_severity_counts()

        cards_frame = ctk.CTkFrame(self.content, fg_color="transparent")
        cards_frame.grid(row=1, column=0, columnspan=4, padx=25, pady=5, sticky="ew")
        for i in range(5):
            cards_frame.grid_columnconfigure(i, weight=1)

        for col, (sev, cnt) in enumerate(counts.items()):
            card = SeverityCard(
                cards_frame, label=sev, count=cnt,
                color=SEVERITY_COLORS.get(sev, "#ffffff"),
            )
            card.grid(row=0, column=col, padx=8, pady=5, sticky="nsew")

        # Findings table
        table_label = ctk.CTkLabel(
            self.content, text="Recent Findings",
            font=ctk.CTkFont(size=16, weight="bold"),
        )
        table_label.grid(row=2, column=0, padx=30, pady=(25, 5), sticky="w")

        table_frame = ctk.CTkScrollableFrame(
            self.content, fg_color="#1e1e2e", corner_radius=10,
        )
        table_frame.grid(row=3, column=0, columnspan=4, padx=25, pady=5, sticky="nsew")
        self.content.grid_rowconfigure(3, weight=1)

        # Column headers
        headers = ["ID", "Target", "Vulnerability", "Severity", "Status"]
        for col, hdr in enumerate(headers):
            lbl = ctk.CTkLabel(
                table_frame, text=hdr,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color="#8888aa",
            )
            lbl.grid(row=0, column=col, padx=10, pady=(8, 4), sticky="w")
            table_frame.grid_columnconfigure(col, weight=1 if col == 2 else 0)

        findings = _fetch_all_findings()
        for row_idx, f in enumerate(findings, start=1):
            fid, tid, vuln, sev, status, ts = f
            color = SEVERITY_COLORS.get((sev or "").upper(), "#ffffff")
            vals = [str(fid), str(tid), vuln or "", (sev or "").upper(), status or ""]
            for col, val in enumerate(vals):
                tc = color if col == 3 else "#c0c0d0"
                lbl = ctk.CTkLabel(
                    table_frame, text=val,
                    font=ctk.CTkFont(size=12),
                    text_color=tc,
                )
                lbl.grid(row=row_idx, column=col, padx=10, pady=2, sticky="w")

    # ── Audits View ─────────────────────────────────────────────────────

    def show_audits(self):
        self._clear_content()
        self._highlight_button(self.btn_audits)

        header = ctk.CTkLabel(
            self.content, text="Run Security Audits",
            font=ctk.CTkFont(size=24, weight="bold"),
        )
        header.grid(row=0, column=0, columnspan=2, padx=30, pady=(25, 20), sticky="w")

        # Input field
        input_label = ctk.CTkLabel(
            self.content, text="Target URL / File Path:",
            font=ctk.CTkFont(size=14),
        )
        input_label.grid(row=1, column=0, padx=30, pady=(10, 0), sticky="w")

        self.target_entry = ctk.CTkEntry(
            self.content, placeholder_text="e.g. http://host/api?url=test  or  ./infra/",
            width=500, height=38,
        )
        self.target_entry.grid(row=2, column=0, columnspan=2, padx=30, pady=5, sticky="ew")
        self.content.grid_columnconfigure(0, weight=1)

        # Buttons row
        btn_frame = ctk.CTkFrame(self.content, fg_color="transparent")
        btn_frame.grid(row=3, column=0, columnspan=2, padx=25, pady=10, sticky="w")

        ctk.CTkButton(
            btn_frame, text="🔍  Run SSRF Audit",
            command=self._run_ssrf, width=180,
            fg_color="#e67e22", hover_color="#d35400",
        ).grid(row=0, column=0, padx=5)

        ctk.CTkButton(
            btn_frame, text="🏗️  Run IaC Audit",
            command=self._run_iac, width=180,
            fg_color="#2ecc71", hover_color="#27ae60",
        ).grid(row=0, column=1, padx=5)

        ctk.CTkButton(
            btn_frame, text="🖥️  Run Local Audit",
            command=self._run_local, width=180,
            fg_color="#3498db", hover_color="#2980b9",
        ).grid(row=0, column=2, padx=5)

        # Console log
        log_label = ctk.CTkLabel(
            self.content, text="Console Output:",
            font=ctk.CTkFont(size=14),
        )
        log_label.grid(row=4, column=0, padx=30, pady=(15, 0), sticky="w")

        self.console_log = ctk.CTkTextbox(
            self.content, height=250, fg_color="#0d0d14",
            text_color="#00ff88", font=ctk.CTkFont(family="Consolas", size=12),
            corner_radius=10,
        )
        self.console_log.grid(row=5, column=0, columnspan=2, padx=25, pady=5, sticky="nsew")
        self.content.grid_rowconfigure(5, weight=1)
        self.console_log.insert("end", "Ready. Select an audit to begin.\n")
        self.console_log.configure(state="disabled")

    def _log(self, text: str):
        """Append text to the console log from any thread."""
        def _do():
            self.console_log.configure(state="normal")
            self.console_log.insert("end", text + "\n")
            self.console_log.see("end")
            self.console_log.configure(state="disabled")
        self.after(0, _do)

    def _run_in_thread(self, func, *args):
        """Run a function in a background thread, capturing stdout."""
        def _worker():
            self._log(f"▶ Starting scan...")
            buf = io.StringIO()
            try:
                with redirect_stdout(buf), redirect_stderr(buf):
                    func(*args)
            except Exception as exc:
                self._log(f"✘ Error: {exc}")
            output = buf.getvalue()
            if output.strip():
                self._log(output.strip())
            self._log("✔ Scan complete.\n")
        threading.Thread(target=_worker, daemon=True).start()

    def _run_ssrf(self):
        target = self.target_entry.get().strip()
        if not target:
            self._log("⚠ Please enter a target URL first.")
            return
        from src.main import run_audit_web
        self._run_in_thread(run_audit_web, target)

    def _run_iac(self):
        target = self.target_entry.get().strip()
        if not target:
            self._log("⚠ Please enter a file or directory path first.")
            return
        from src.main import run_audit_iac
        self._run_in_thread(run_audit_iac, target)

    def _run_local(self):
        from src.main import run_audit_local
        self._run_in_thread(run_audit_local)

    # ── Reports View ────────────────────────────────────────────────────

    def show_reports(self):
        self._clear_content()
        self._highlight_button(self.btn_reports)

        header = ctk.CTkLabel(
            self.content, text="Generate Reports",
            font=ctk.CTkFont(size=24, weight="bold"),
        )
        header.grid(row=0, column=0, columnspan=2, padx=30, pady=(25, 20), sticky="w")

        # Status label
        self.report_status = ctk.CTkLabel(
            self.content, text="", font=ctk.CTkFont(size=13),
            text_color="#2ecc71",
        )
        self.report_status.grid(row=1, column=0, columnspan=2, padx=30, pady=5, sticky="w")

        btn_frame = ctk.CTkFrame(self.content, fg_color="transparent")
        btn_frame.grid(row=2, column=0, padx=25, pady=20, sticky="w")

        ctk.CTkButton(
            btn_frame, text="📝  Generate Markdown Report",
            command=self._gen_markdown, width=260, height=45,
            font=ctk.CTkFont(size=14),
        ).grid(row=0, column=0, padx=8, pady=8)

        ctk.CTkButton(
            btn_frame, text="📦  Export SARIF JSON",
            command=self._gen_sarif, width=260, height=45,
            font=ctk.CTkFont(size=14),
            fg_color="#e67e22", hover_color="#d35400",
        ).grid(row=0, column=1, padx=8, pady=8)

    def _gen_markdown(self):
        try:
            from src.reporting.generate import generate_report
            path, count = generate_report()
            self.report_status.configure(
                text=f"✔ Markdown report generated: {path.name} ({count} findings)",
                text_color="#2ecc71",
            )
        except Exception as exc:
            self.report_status.configure(
                text=f"✘ Error: {exc}", text_color="#e74c3c",
            )

    def _gen_sarif(self):
        try:
            from src.reporting.sarif_exporter import export_to_sarif
            code = export_to_sarif("results.sarif")
            if code == 0:
                self.report_status.configure(
                    text="✔ SARIF report exported: results.sarif",
                    text_color="#2ecc71",
                )
            else:
                self.report_status.configure(
                    text="✘ SARIF export returned a non-zero exit code.",
                    text_color="#e74c3c",
                )
        except Exception as exc:
            self.report_status.configure(
                text=f"✘ Error: {exc}", text_color="#e74c3c",
            )


def launch_gui():
    """Entry point to start the desktop application."""
    app = AntiFineApp()
    app.mainloop()


if __name__ == "__main__":
    launch_gui()
