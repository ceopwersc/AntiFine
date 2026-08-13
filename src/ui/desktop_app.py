"""AntiFine Native Desktop Application — Enterprise OOP Architecture.

A robust, thread-safe CustomTkinter GUI featuring a centralized view router
and queue-based logging for safe background processing.
"""

from __future__ import annotations

import io
import queue
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


# ── Design Tokens ───────────────────────────────────────────────────────────

COLOR_BG_APP     = "#0B0F19"
COLOR_BG_SIDEBAR = "#111827"
COLOR_BG_CARD    = "#1F2937"
COLOR_ACCENT     = "#3B82F6"
COLOR_HOVER      = "#2563EB"
COLOR_TEXT_PRI   = "#F3F4F6"
COLOR_TEXT_SEC   = "#9CA3AF"

SEVERITY_COLORS = {
    "CRITICAL": "#EF4444",
    "HIGH":     "#F97316",
    "MEDIUM":   "#F59E0B",
    "LOW":      "#3B82F6",
}

FONT_HEADER = ("Segoe UI", 24, "bold")
FONT_BODY   = ("Segoe UI", 14)
FONT_TERM   = ("Consolas", 12)

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


# ── Helpers ─────────────────────────────────────────────────────────────────

def _fetch_severity_counts(db_path: Path = DB_PATH) -> dict[str, int]:
    """Return {severity: count} from the audit database."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
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


# ── Main Application ────────────────────────────────────────────────────────

class AntiFineApp(ctk.CTk):
    """Enterprise-grade thread-safe desktop UI."""

    def __init__(self):
        super().__init__()

        self.title("AntiFine - Security Auditor")
        self.geometry("1100x700")
        self.minsize(900, 600)
        self.configure(fg_color=COLOR_BG_APP)

        # Thread-Safe Event Loop
        self.log_queue = queue.Queue()
        self.after(100, self.check_queue)

        try:
            initialize_database()
        except Exception:
            pass

        # High-End Grid Layout
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=0)  # Sidebar
        self.grid_columnconfigure(1, weight=1)  # Main Content

        # The View Router
        self.frames = {}

        self._build_sidebar()
        self._build_dashboard_frame()
        self._build_scanner_frame()
        self._build_reports_frame()

        self.select_frame_by_name("dashboard")

    # ── Thread-Safe Logging ─────────────────────────────────────────────────

    def check_queue(self):
        """Poll the queue and safely update the UI from the main thread."""
        while not self.log_queue.empty():
            msg = self.log_queue.get()
            self.terminal.configure(state="normal")
            self.terminal.insert("end", msg + "\n")
            self.terminal.see("end")
            self.terminal.configure(state="disabled")
        self.after(100, self.check_queue)

    def select_frame_by_name(self, name: str):
        """View Router: grid_forget() all, grid() only the selected."""
        # Highlight active sidebar button
        for btn_name, btn in self.sidebar_buttons.items():
            if btn_name == name:
                btn.configure(fg_color=COLOR_BG_CARD)
            else:
                btn.configure(fg_color="transparent")
        
        # Route frames
        for frame_name, frame in self.frames.items():
            frame.grid_forget()
        
        selected = self.frames.get(name)
        if selected:
            selected.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
            
            # Refresh dynamic data if navigating to dashboard
            if name == "dashboard":
                self._populate_dashboard_metrics()
            # Refresh reports if navigating to reports
            elif name == "reports":
                self._load_report_preview()

    # ── Sidebar ─────────────────────────────────────────────────────────────

    def _build_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(
            self, fg_color=COLOR_BG_SIDEBAR, corner_radius=0, width=220
        )
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1)

        logo = ctk.CTkLabel(
            self.sidebar_frame, text="ANTIFINE", 
            font=FONT_HEADER, text_color=COLOR_ACCENT
        )
        logo.grid(row=0, column=0, padx=20, pady=(30, 40), sticky="w")

        self.sidebar_buttons = {}

        def add_nav_btn(idx, name, text):
            btn = ctk.CTkButton(
                self.sidebar_frame, text=text,
                fg_color="transparent", text_color=COLOR_TEXT_PRI,
                hover_color=COLOR_BG_CARD, anchor="w",
                font=FONT_BODY, height=45, corner_radius=8,
                command=lambda: self.select_frame_by_name(name)
            )
            btn.grid(row=idx, column=0, padx=15, pady=5, sticky="ew")
            self.sidebar_buttons[name] = btn

        add_nav_btn(1, "dashboard", "📊 Dashboard")
        add_nav_btn(2, "scanner", "🛡️ Scanner")
        add_nav_btn(3, "reports", "📄 Reports")

    # ── Dashboard View ──────────────────────────────────────────────────────

    def _build_dashboard_frame(self):
        self.dashboard_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.frames["dashboard"] = self.dashboard_frame
        
        self.dashboard_frame.grid_columnconfigure(0, weight=1)
        self.dashboard_frame.grid_rowconfigure(2, weight=1)

        hdr = ctk.CTkLabel(
            self.dashboard_frame, text="System Overview",
            font=FONT_HEADER, text_color=COLOR_TEXT_PRI
        )
        hdr.grid(row=0, column=0, sticky="w", pady=(0, 20))

        # 2x2 Metric Grid
        self.metrics_grid = ctk.CTkFrame(self.dashboard_frame, fg_color="transparent")
        self.metrics_grid.grid(row=1, column=0, sticky="nsew")
        self.metrics_grid.grid_columnconfigure((0, 1), weight=1)
        
        self.metric_labels = {}
        
        sevs = [
            ("CRITICAL", 0, 0), ("HIGH", 0, 1),
            ("MEDIUM", 1, 0), ("LOW", 1, 1)
        ]
        
        for sev, r, c in sevs:
            card = ctk.CTkFrame(
                self.metrics_grid, fg_color=COLOR_BG_CARD, corner_radius=12
            )
            card.grid(row=r, column=c, padx=10, pady=10, sticky="nsew")
            card.grid_columnconfigure(0, weight=1)
            
            lbl_val = ctk.CTkLabel(
                card, text="0", 
                font=("Segoe UI", 48, "bold"), 
                text_color=SEVERITY_COLORS.get(sev, COLOR_TEXT_PRI)
            )
            lbl_val.grid(row=0, column=0, pady=(30, 0))
            self.metric_labels[sev] = lbl_val
            
            lbl_title = ctk.CTkLabel(
                card, text=sev,
                font=FONT_BODY, text_color=COLOR_TEXT_SEC
            )
            lbl_title.grid(row=1, column=0, pady=(0, 30))

    def _populate_dashboard_metrics(self):
        counts = _fetch_severity_counts()
        for sev, lbl in self.metric_labels.items():
            lbl.configure(text=str(counts.get(sev, 0)))

    # ── Scanner View ────────────────────────────────────────────────────────

    def _build_scanner_frame(self):
        self.scanner_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.frames["scanner"] = self.scanner_frame
        
        self.scanner_frame.grid_columnconfigure(0, weight=1)
        self.scanner_frame.grid_rowconfigure(3, weight=1)

        hdr = ctk.CTkLabel(
            self.scanner_frame, text="Active Reconnaissance",
            font=FONT_HEADER, text_color=COLOR_TEXT_PRI
        )
        hdr.grid(row=0, column=0, sticky="w", pady=(0, 20))

        # Target Input Area
        input_area = ctk.CTkFrame(self.scanner_frame, fg_color="transparent")
        input_area.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        input_area.grid_columnconfigure(0, weight=1)

        self.target_entry = ctk.CTkEntry(
            input_area, height=40,
            placeholder_text="Enter Target URL or File Path",
            font=FONT_BODY
        )
        self.target_entry.grid(row=0, column=0, sticky="ew", padx=(0, 15))

        self.scan_type_menu = ctk.CTkOptionMenu(
            input_area, height=40,
            values=["SSRF Web Audit", "IaC Config Audit"],
            font=FONT_BODY
        )
        self.scan_type_menu.grid(row=0, column=1, padx=(0, 15))

        self.scan_btn = ctk.CTkButton(
            input_area, text="INITIALIZE SCAN",
            fg_color=COLOR_ACCENT, hover_color=COLOR_HOVER,
            height=45, font=("Segoe UI", 14, "bold"),
            command=self._start_scan
        )
        self.scan_btn.grid(row=0, column=2)

        # Live Terminal
        self.terminal = ctk.CTkTextbox(
            self.scanner_frame, fg_color="#000000", text_color="#00FF00",
            font=FONT_TERM, wrap="word"
        )
        self.terminal.grid(row=3, column=0, sticky="nsew")
        self.terminal.insert("end", "Terminal Ready.\n")
        self.terminal.configure(state="disabled")

    def _start_scan(self):
        target = self.target_entry.get().strip()
        scan_type = self.scan_type_menu.get()

        if not target:
            self.log_queue.put("[ERROR] Missing Target string.")
            return

        self.scan_btn.configure(state="disabled")
        threading.Thread(
            target=self.run_scan_thread, args=(scan_type, target), daemon=True
        ).start()

    def run_scan_thread(self, scan_type: str, target: str):
        self.log_queue.put(f"[*] Initializing {scan_type} against: {target}")
        buf = io.StringIO()
        try:
            with redirect_stdout(buf), redirect_stderr(buf):
                if scan_type == "SSRF Web Audit":
                    from src.main import run_audit_web
                    run_audit_web(target)
                elif scan_type == "IaC Config Audit":
                    from src.main import run_audit_iac
                    run_audit_iac(target)
        except Exception as exc:
            self.log_queue.put(f"[!] Error: {exc}")
        
        output = buf.getvalue().strip()
        if output:
            for line in output.splitlines():
                self.log_queue.put(line)
                
        self.log_queue.put("[*] Scan execution completed.")
        
        def _reset():
            self.scan_btn.configure(state="normal")
        self.after(0, _reset)

    # ── Reports View ────────────────────────────────────────────────────────

    def _build_reports_frame(self):
        self.reports_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.frames["reports"] = self.reports_frame
        
        self.reports_frame.grid_columnconfigure(0, weight=1)
        self.reports_frame.grid_rowconfigure(2, weight=1)

        hdr = ctk.CTkLabel(
            self.reports_frame, text="Compliance & Export",
            font=FONT_HEADER, text_color=COLOR_TEXT_PRI
        )
        hdr.grid(row=0, column=0, sticky="w", pady=(0, 20))

        btns_frame = ctk.CTkFrame(self.reports_frame, fg_color="transparent")
        btns_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))

        ctk.CTkButton(
            btns_frame, text="Generate Markdown Report",
            fg_color=COLOR_BG_CARD, hover_color=COLOR_HOVER,
            height=45, font=FONT_BODY,
            command=self._do_gen_markdown
        ).grid(row=0, column=0, padx=(0, 15))

        ctk.CTkButton(
            btns_frame, text="Export SARIF Standard",
            fg_color=COLOR_ACCENT, hover_color=COLOR_HOVER,
            height=45, font=FONT_BODY,
            command=self._do_gen_sarif
        ).grid(row=0, column=1)

        self.rpt_status = ctk.CTkLabel(
            btns_frame, text="", font=FONT_BODY, text_color=COLOR_TEXT_SEC
        )
        self.rpt_status.grid(row=0, column=2, padx=15)

        self.report_preview = ctk.CTkTextbox(
            self.reports_frame, fg_color=COLOR_BG_CARD, text_color=COLOR_TEXT_SEC,
            font=FONT_TERM, wrap="word"
        )
        self.report_preview.grid(row=2, column=0, sticky="nsew")
        self.report_preview.configure(state="disabled")

    def _load_report_preview(self):
        report_path = PROJECT_ROOT / "compliance_report.md"
        self.report_preview.configure(state="normal")
        self.report_preview.delete("1.0", "end")
        if report_path.is_file():
            try:
                self.report_preview.insert("end", report_path.read_text(encoding="utf-8")[:4000])
            except Exception:
                pass
        else:
            self.report_preview.insert("end", "No report file found.")
        self.report_preview.configure(state="disabled")

    def _do_gen_markdown(self):
        try:
            from src.reporting.generate import generate_report
            path, count = generate_report()
            self.rpt_status.configure(text=f"✔ Markdown generated ({count} items)")
            self._load_report_preview()
        except Exception as exc:
            self.rpt_status.configure(text=f"✘ Error: {exc}")

    def _do_gen_sarif(self):
        try:
            from src.reporting.sarif_exporter import export_to_sarif
            code = export_to_sarif("results.sarif")
            if code == 0:
                self.rpt_status.configure(text="✔ SARIF exported successfully")
            else:
                self.rpt_status.configure(text="✘ SARIF export failed")
        except Exception as exc:
            self.rpt_status.configure(text=f"✘ Error: {exc}")


def launch_gui():
    app = AntiFineApp()
    app.mainloop()


if __name__ == "__main__":
    launch_gui()
