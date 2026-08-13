"""AntiFine Native Desktop Application — Premium UI.

A high-end, commercial-grade cybersecurity dashboard built with CustomTkinter.
Dark-themed with precise color tokens, typography hierarchy, and polished layout.
"""

from __future__ import annotations

import io
import sqlite3
import sys
import threading
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
from pathlib import Path

import customtkinter as ctk

PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.setup import DB_PATH, initialize_database  # noqa: E402

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  DESIGN TOKENS                                                         ║
# ╚══════════════════════════════════════════════════════════════════════════╝

# Backgrounds
BG_ROOT       = "#090D16"
BG_SIDEBAR    = "#0B1120"
BG_CARD       = "#111827"
BG_INPUT      = "#030712"
BG_HOVER      = "#1E293B"
BG_ACTIVE     = "#1E293B"
BG_CONSOLE    = "#030712"

# Borders
BORDER_SUBTLE = "#1F2937"
BORDER_ACCENT = "#6366F1"

# Accents
ACCENT_INDIGO = "#6366F1"
ACCENT_CYAN   = "#06B6D4"

# Severity palette
CLR_CRITICAL  = "#F43F5E"
CLR_HIGH      = "#F43F5E"
CLR_MEDIUM    = "#FBBF24"
CLR_LOW       = "#38BDF8"
CLR_SAFE      = "#34D399"

SEVERITY_COLORS = {
    "CRITICAL": CLR_CRITICAL,
    "HIGH":     CLR_HIGH,
    "MEDIUM":   CLR_MEDIUM,
    "LOW":      CLR_LOW,
    "INFO":     "#94A3B8",
}

# Text colors
TXT_PRIMARY   = "#F1F5F9"
TXT_SECONDARY = "#94A3B8"
TXT_MUTED     = "#9CA3AF"
TXT_DIM       = "#64748B"

# Typography
FONT_FAMILY   = "Segoe UI"
FONT_H1       = (FONT_FAMILY, 22, "bold")
FONT_H2       = (FONT_FAMILY, 16, "bold")
FONT_H3       = (FONT_FAMILY, 14, "bold")
FONT_BODY     = (FONT_FAMILY, 12)
FONT_SMALL    = (FONT_FAMILY, 11)
FONT_MONO     = ("Consolas", 12)
FONT_MONO_SM  = ("Consolas", 11)

# Dimensions
SIDEBAR_W     = 200
CARD_RADIUS   = 12
BTN_RADIUS    = 8

# CTk global
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  DATA LAYER                                                            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def _fetch_severity_counts(db_path: Path = DB_PATH) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    if not db_path.is_file():
        return counts
    try:
        with sqlite3.connect(db_path) as conn:
            rows = conn.execute(
                "SELECT UPPER(severity) AS sev, COUNT(*) FROM scan_results GROUP BY sev"
            ).fetchall()
        for sev, cnt in rows:
            if sev in counts:
                counts[sev] = cnt
    except sqlite3.Error:
        pass
    return counts


def _fetch_all_findings(db_path: Path = DB_PATH) -> list[tuple]:
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


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WIDGETS                                                               ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class MetricCard(ctk.CTkFrame):
    """Hero metric card with a colored top indicator line."""

    def __init__(self, master, label: str, value: int, accent: str, **kw):
        super().__init__(
            master, corner_radius=CARD_RADIUS,
            fg_color=BG_CARD, border_color=BORDER_SUBTLE, border_width=1,
            **kw,
        )
        self.grid_columnconfigure(0, weight=1)

        # Top accent line
        bar = ctk.CTkFrame(self, height=3, corner_radius=0, fg_color=accent)
        bar.grid(row=0, column=0, sticky="new", padx=1, pady=(1, 0))

        val_lbl = ctk.CTkLabel(
            self, text=str(value),
            font=ctk.CTkFont(family=FONT_FAMILY, size=36, weight="bold"),
            text_color=accent,
        )
        val_lbl.grid(row=1, column=0, padx=20, pady=(18, 0))

        name_lbl = ctk.CTkLabel(
            self, text=label,
            font=ctk.CTkFont(family=FONT_FAMILY, size=12),
            text_color=TXT_MUTED,
        )
        name_lbl.grid(row=2, column=0, padx=20, pady=(2, 18))


class SeverityPill(ctk.CTkFrame):
    """A small rounded pill badge with severity color."""

    def __init__(self, master, text: str, color: str, **kw):
        super().__init__(
            master, corner_radius=6, fg_color=color + "22",
            border_color=color, border_width=1, **kw,
        )
        lbl = ctk.CTkLabel(
            self, text=text,
            font=ctk.CTkFont(family=FONT_FAMILY, size=11, weight="bold"),
            text_color=color,
        )
        lbl.grid(padx=10, pady=2)


class NavButton(ctk.CTkButton):
    """Sidebar navigation button with accent-left-pill highlight."""

    def __init__(self, master, text: str, command=None, **kw):
        super().__init__(
            master, text=text, command=command,
            fg_color="transparent", hover_color=BG_HOVER,
            anchor="w", corner_radius=BTN_RADIUS,
            font=ctk.CTkFont(family=FONT_FAMILY, size=14),
            text_color=TXT_SECONDARY, height=42,
            **kw,
        )

    def set_active(self, active: bool):
        if active:
            self.configure(fg_color=BG_ACTIVE, text_color=TXT_PRIMARY)
        else:
            self.configure(fg_color="transparent", text_color=TXT_SECONDARY)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  MAIN APPLICATION                                                      ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class AntiFineApp(ctk.CTk):
    """Root window and layout orchestrator."""

    def __init__(self):
        super().__init__()

        self.title("AntiFine — Security Auditor")
        self.geometry("950x650")
        self.minsize(850, 550)
        self.configure(fg_color=BG_ROOT)

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(1, weight=1)

        try:
            initialize_database()
        except Exception:
            pass

        self._build_header()
        self._build_sidebar()

        # Content container
        self.content = ctk.CTkFrame(self, corner_radius=0, fg_color=BG_ROOT)
        self.content.grid(row=1, column=1, sticky="nsew")
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        self.show_dashboard()

    # ── Header ──────────────────────────────────────────────────────────

    def _build_header(self):
        hdr = ctk.CTkFrame(
            self, height=50, corner_radius=0,
            fg_color=BG_SIDEBAR, border_color=BORDER_SUBTLE, border_width=1,
        )
        hdr.grid(row=0, column=0, columnspan=2, sticky="new")
        hdr.grid_columnconfigure(1, weight=1)

        logo = ctk.CTkLabel(
            hdr, text="🛡️  ANTIFINE",
            font=ctk.CTkFont(family=FONT_FAMILY, size=18, weight="bold"),
            text_color=ACCENT_INDIGO,
        )
        logo.grid(row=0, column=0, padx=20, pady=12, sticky="w")

        # Status pill
        status_frame = ctk.CTkFrame(
            hdr, corner_radius=10,
            fg_color=CLR_SAFE + "18", border_color=CLR_SAFE, border_width=1,
        )
        status_frame.grid(row=0, column=1, padx=0, pady=12, sticky="e")

        status_lbl = ctk.CTkLabel(
            status_frame, text="●  ENGINE ONLINE",
            font=ctk.CTkFont(family=FONT_FAMILY, size=11, weight="bold"),
            text_color=CLR_SAFE,
        )
        status_lbl.grid(padx=14, pady=4)

        # Refresh button
        self.refresh_btn = ctk.CTkButton(
            hdr, text="⟳  Refresh", width=90, height=30,
            corner_radius=BTN_RADIUS,
            fg_color=ACCENT_INDIGO, hover_color="#4F46E5",
            font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"),
            command=self._refresh_current_view,
        )
        self.refresh_btn.grid(row=0, column=2, padx=(10, 20), pady=12, sticky="e")

    # ── Sidebar ─────────────────────────────────────────────────────────

    def _build_sidebar(self):
        sb = ctk.CTkFrame(
            self, width=SIDEBAR_W, corner_radius=0,
            fg_color=BG_SIDEBAR, border_color=BORDER_SUBTLE, border_width=1,
        )
        sb.grid(row=1, column=0, sticky="nsew")
        sb.grid_rowconfigure(5, weight=1)
        sb.grid_propagate(False)

        pad_y = 4
        self.nav_btns: list[NavButton] = []

        self.btn_dash = NavButton(sb, text="📊  Overview Dashboard", command=self.show_dashboard)
        self.btn_dash.grid(row=0, column=0, padx=10, pady=(20, pad_y), sticky="ew")
        self.nav_btns.append(self.btn_dash)

        self.btn_scan = NavButton(sb, text="🛡️  Vulnerability Scanner", command=self.show_scanner)
        self.btn_scan.grid(row=1, column=0, padx=10, pady=pad_y, sticky="ew")
        self.nav_btns.append(self.btn_scan)

        self.btn_rpt = NavButton(sb, text="📄  Reports & SARIF", command=self.show_reports)
        self.btn_rpt.grid(row=2, column=0, padx=10, pady=pad_y, sticky="ew")
        self.nav_btns.append(self.btn_rpt)

        # Bottom branding
        ver = ctk.CTkLabel(
            sb, text="v1.0.0  ·  AntiFine Engine",
            font=ctk.CTkFont(family=FONT_FAMILY, size=10),
            text_color=TXT_DIM,
        )
        ver.grid(row=6, column=0, padx=10, pady=(0, 14))

    # ── Helpers ─────────────────────────────────────────────────────────

    def _clear_content(self):
        for w in self.content.winfo_children():
            w.destroy()

    def _activate_nav(self, active: NavButton):
        for btn in self.nav_btns:
            btn.set_active(btn is active)

    def _refresh_current_view(self):
        # Re-render whichever view is active
        for btn in self.nav_btns:
            if btn.cget("fg_color") == BG_ACTIVE:
                btn.invoke()
                return
        self.show_dashboard()

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  DASHBOARD VIEW                                                 ║
    # ╚══════════════════════════════════════════════════════════════════╝

    def show_dashboard(self):
        self._clear_content()
        self._activate_nav(self.btn_dash)

        wrapper = ctk.CTkScrollableFrame(self.content, fg_color=BG_ROOT, corner_radius=0)
        wrapper.grid(row=0, column=0, sticky="nsew")
        wrapper.grid_columnconfigure(0, weight=1)

        # Section title
        ctk.CTkLabel(
            wrapper, text="Overview Dashboard",
            font=ctk.CTkFont(*FONT_H1), text_color=TXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, columnspan=4, padx=30, pady=(28, 4), sticky="w")

        ctk.CTkLabel(
            wrapper, text="Real-time visibility into your security posture",
            font=ctk.CTkFont(*FONT_BODY), text_color=TXT_MUTED, anchor="w",
        ).grid(row=1, column=0, columnspan=4, padx=30, pady=(0, 18), sticky="w")

        # ── Metric cards ────────────────────────────────────────────────
        cards_row = ctk.CTkFrame(wrapper, fg_color="transparent")
        cards_row.grid(row=2, column=0, columnspan=4, padx=25, sticky="ew")
        for i in range(4):
            cards_row.grid_columnconfigure(i, weight=1)

        counts = _fetch_severity_counts()
        card_defs = [
            ("CRITICAL", counts["CRITICAL"], CLR_CRITICAL),
            ("HIGH",     counts["HIGH"],     CLR_HIGH),
            ("MEDIUM",   counts["MEDIUM"],   CLR_MEDIUM),
            ("LOW",      counts["LOW"],      CLR_LOW),
        ]
        for col, (label, val, clr) in enumerate(card_defs):
            MetricCard(cards_row, label=label, value=val, accent=clr).grid(
                row=0, column=col, padx=6, pady=4, sticky="nsew",
            )

        # ── Recent findings table ──────────────────────────────────────
        ctk.CTkLabel(
            wrapper, text="Recent Findings",
            font=ctk.CTkFont(*FONT_H2), text_color=TXT_PRIMARY, anchor="w",
        ).grid(row=3, column=0, padx=30, pady=(24, 8), sticky="w")

        table_outer = ctk.CTkFrame(
            wrapper, fg_color=BG_CARD,
            corner_radius=CARD_RADIUS, border_color=BORDER_SUBTLE, border_width=1,
        )
        table_outer.grid(row=4, column=0, columnspan=4, padx=25, pady=(0, 20), sticky="ew")
        table_outer.grid_columnconfigure(0, weight=1)

        # Headers
        hdr_frame = ctk.CTkFrame(table_outer, fg_color=BG_INPUT, corner_radius=0)
        hdr_frame.grid(row=0, column=0, sticky="ew", padx=1, pady=(1, 0))
        headers = ["ID", "Target", "Vulnerability", "Severity", "Status", "Detected"]
        col_weights = [0, 0, 1, 0, 0, 0]
        for c, (h, w) in enumerate(zip(headers, col_weights)):
            hdr_frame.grid_columnconfigure(c, weight=w)
            ctk.CTkLabel(
                hdr_frame, text=h,
                font=ctk.CTkFont(family=FONT_FAMILY, size=11, weight="bold"),
                text_color=TXT_DIM, anchor="w",
            ).grid(row=0, column=c, padx=14, pady=8, sticky="w")

        findings = _fetch_all_findings()
        for r, f in enumerate(findings, start=1):
            fid, tid, vuln, sev, status, ts = f
            sev_upper = (sev or "").upper()
            clr = SEVERITY_COLORS.get(sev_upper, TXT_SECONDARY)
            row_bg = BG_CARD if r % 2 == 0 else "#0F1729"

            row_frame = ctk.CTkFrame(table_outer, fg_color=row_bg, corner_radius=0)
            row_frame.grid(row=r, column=0, sticky="ew", padx=1)
            for c, w in enumerate(col_weights):
                row_frame.grid_columnconfigure(c, weight=w)

            vals = [str(fid), str(tid), vuln or "", sev_upper, status or "", ts or ""]
            for c, v in enumerate(vals):
                if c == 3:  # severity pill
                    pill = SeverityPill(row_frame, text=v, color=clr)
                    pill.grid(row=0, column=c, padx=14, pady=5, sticky="w")
                else:
                    tc = TXT_PRIMARY if c == 2 else TXT_SECONDARY
                    ctk.CTkLabel(
                        row_frame, text=v,
                        font=ctk.CTkFont(*FONT_SMALL), text_color=tc, anchor="w",
                    ).grid(row=0, column=c, padx=14, pady=6, sticky="w")

        if not findings:
            ctk.CTkLabel(
                table_outer, text="No findings recorded yet. Run an audit to populate.",
                font=ctk.CTkFont(*FONT_BODY), text_color=TXT_DIM,
            ).grid(row=1, column=0, padx=20, pady=30)

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  SCANNER VIEW                                                   ║
    # ╚══════════════════════════════════════════════════════════════════╝

    def show_scanner(self):
        self._clear_content()
        self._activate_nav(self.btn_scan)

        wrapper = ctk.CTkFrame(self.content, fg_color=BG_ROOT, corner_radius=0)
        wrapper.grid(row=0, column=0, sticky="nsew")
        wrapper.grid_rowconfigure(4, weight=1)
        wrapper.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            wrapper, text="Vulnerability Scanner",
            font=ctk.CTkFont(*FONT_H1), text_color=TXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, padx=30, pady=(28, 4), sticky="w")

        ctk.CTkLabel(
            wrapper, text="Select a scan type and configure target parameters",
            font=ctk.CTkFont(*FONT_BODY), text_color=TXT_MUTED, anchor="w",
        ).grid(row=0, column=0, padx=30, pady=(56, 0), sticky="w")

        # ── Scan type segment ──────────────────────────────────────────
        self._scan_mode = ctk.StringVar(value="ssrf")

        seg_frame = ctk.CTkFrame(wrapper, fg_color="transparent")
        seg_frame.grid(row=1, column=0, padx=25, pady=(18, 0), sticky="w")

        modes = [
            ("ssrf", "🌐  SSRF Web Audit"),
            ("iac",  "🏗️  IaC Config Audit"),
            ("net",  "🖥️  Network Audit"),
        ]
        for i, (val, label) in enumerate(modes):
            ctk.CTkRadioButton(
                seg_frame, text=label, variable=self._scan_mode, value=val,
                font=ctk.CTkFont(*FONT_BODY), text_color=TXT_SECONDARY,
                fg_color=ACCENT_INDIGO, hover_color=ACCENT_INDIGO,
                border_color=BORDER_SUBTLE,
            ).grid(row=0, column=i, padx=(0, 24), pady=8)

        # ── Input area ─────────────────────────────────────────────────
        input_card = ctk.CTkFrame(
            wrapper, fg_color=BG_CARD, corner_radius=CARD_RADIUS,
            border_color=BORDER_SUBTLE, border_width=1,
        )
        input_card.grid(row=2, column=0, padx=25, pady=12, sticky="ew")
        input_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            input_card, text="Target",
            font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"),
            text_color=TXT_MUTED, anchor="w",
        ).grid(row=0, column=0, padx=18, pady=(14, 2), sticky="w")

        self.scan_entry = ctk.CTkEntry(
            input_card, height=40,
            placeholder_text="e.g.  http://host/api?url=test   or   ./infrastructure/",
            fg_color=BG_INPUT, border_color=BORDER_SUBTLE, border_width=1,
            corner_radius=BTN_RADIUS,
            font=ctk.CTkFont(*FONT_BODY), text_color=TXT_PRIMARY,
        )
        self.scan_entry.grid(row=1, column=0, padx=18, pady=(0, 4), sticky="ew")

        self.start_btn = ctk.CTkButton(
            input_card, text="▶  START SCAN", height=40, width=170,
            corner_radius=BTN_RADIUS,
            fg_color=ACCENT_INDIGO, hover_color="#4F46E5",
            font=ctk.CTkFont(family=FONT_FAMILY, size=13, weight="bold"),
            command=self._dispatch_scan,
        )
        self.start_btn.grid(row=1, column=1, padx=(4, 18), pady=(0, 4))

        # ── Live console ───────────────────────────────────────────────
        ctk.CTkLabel(
            wrapper, text="Live Console",
            font=ctk.CTkFont(*FONT_H3), text_color=TXT_MUTED, anchor="w",
        ).grid(row=3, column=0, padx=30, pady=(8, 2), sticky="w")

        console_card = ctk.CTkFrame(
            wrapper, fg_color=BG_CONSOLE, corner_radius=CARD_RADIUS,
            border_color=BORDER_SUBTLE, border_width=1,
        )
        console_card.grid(row=4, column=0, padx=25, pady=(0, 20), sticky="nsew")
        console_card.grid_rowconfigure(0, weight=1)
        console_card.grid_columnconfigure(0, weight=1)

        self.console_box = ctk.CTkTextbox(
            console_card, fg_color=BG_CONSOLE,
            text_color=CLR_SAFE, corner_radius=0,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="word",
        )
        self.console_box.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
        self._console_write("[INFO]  Scanner ready. Configure target and press START SCAN.\n")
        self.console_box.configure(state="disabled")

    def _console_write(self, text: str):
        """Append styled text to the console box (thread-safe)."""
        def _do():
            self.console_box.configure(state="normal")
            self.console_box.insert("end", text)
            self.console_box.see("end")
            self.console_box.configure(state="disabled")
        if threading.current_thread() is threading.main_thread():
            _do()
        else:
            self.after(0, _do)

    def _dispatch_scan(self):
        mode = self._scan_mode.get()
        target = self.scan_entry.get().strip()

        if mode in ("ssrf", "iac") and not target:
            self._console_write("[WARN]  Please enter a target before starting.\n")
            return

        self.start_btn.configure(state="disabled", text="⏳  SCANNING…")

        def _worker():
            self._console_write(f"\n[INFO]  Starting {mode.upper()} scan…\n")
            buf = io.StringIO()
            try:
                with redirect_stdout(buf), redirect_stderr(buf):
                    if mode == "ssrf":
                        from src.main import run_audit_web
                        run_audit_web(target)
                    elif mode == "iac":
                        from src.main import run_audit_iac
                        run_audit_iac(target)
                    elif mode == "net":
                        from src.main import run_audit_local
                        run_audit_local()
            except Exception as exc:
                self._console_write(f"[VULN]  Error: {exc}\n")

            output = buf.getvalue()
            if output.strip():
                for line in output.strip().splitlines():
                    tag = "[INFO]"
                    if "error" in line.lower() or "insecure" in line.lower():
                        tag = "[VULN]"
                    elif "ok" in line.lower():
                        tag = "[SUCCESS]"
                    self._console_write(f"{tag}  {line}\n")

            self._console_write("[SUCCESS]  Scan complete.\n")
            self.after(0, lambda: self.start_btn.configure(state="normal", text="▶  START SCAN"))

        threading.Thread(target=_worker, daemon=True).start()

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  REPORTS VIEW                                                   ║
    # ╚══════════════════════════════════════════════════════════════════╝

    def show_reports(self):
        self._clear_content()
        self._activate_nav(self.btn_rpt)

        wrapper = ctk.CTkFrame(self.content, fg_color=BG_ROOT, corner_radius=0)
        wrapper.grid(row=0, column=0, sticky="nsew")
        wrapper.grid_rowconfigure(3, weight=1)
        wrapper.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            wrapper, text="Reports & SARIF Export",
            font=ctk.CTkFont(*FONT_H1), text_color=TXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, columnspan=2, padx=30, pady=(28, 4), sticky="w")

        ctk.CTkLabel(
            wrapper, text="Generate compliance reports and CI/CD-ready SARIF files",
            font=ctk.CTkFont(*FONT_BODY), text_color=TXT_MUTED, anchor="w",
        ).grid(row=0, column=0, padx=30, pady=(56, 0), sticky="w")

        # Status indicator
        self.rpt_status = ctk.CTkLabel(
            wrapper, text="",
            font=ctk.CTkFont(*FONT_BODY), text_color=CLR_SAFE,
        )
        self.rpt_status.grid(row=1, column=0, columnspan=2, padx=30, pady=(10, 0), sticky="w")

        # ── Report cards ───────────────────────────────────────────────
        cards_row = ctk.CTkFrame(wrapper, fg_color="transparent")
        cards_row.grid(row=2, column=0, columnspan=2, padx=25, pady=14, sticky="ew")
        cards_row.grid_columnconfigure(0, weight=1)
        cards_row.grid_columnconfigure(1, weight=1)

        # Markdown card
        md_card = ctk.CTkFrame(
            cards_row, fg_color=BG_CARD, corner_radius=CARD_RADIUS,
            border_color=BORDER_SUBTLE, border_width=1,
        )
        md_card.grid(row=0, column=0, padx=6, pady=4, sticky="nsew")
        md_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            md_card, text="📝  Markdown Compliance Report",
            font=ctk.CTkFont(*FONT_H3), text_color=TXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, padx=20, pady=(20, 4), sticky="w")

        ctk.CTkLabel(
            md_card, text="Generates a structured compliance_report.md\nwith severity breakdown and remediation guidance.",
            font=ctk.CTkFont(*FONT_SMALL), text_color=TXT_MUTED, anchor="w", justify="left",
        ).grid(row=1, column=0, padx=20, pady=(0, 12), sticky="w")

        ctk.CTkButton(
            md_card, text="Generate Markdown", height=38,
            corner_radius=BTN_RADIUS,
            fg_color=ACCENT_INDIGO, hover_color="#4F46E5",
            font=ctk.CTkFont(family=FONT_FAMILY, size=13, weight="bold"),
            command=self._gen_markdown,
        ).grid(row=2, column=0, padx=20, pady=(0, 20), sticky="w")

        # SARIF card
        sarif_card = ctk.CTkFrame(
            cards_row, fg_color=BG_CARD, corner_radius=CARD_RADIUS,
            border_color=BORDER_SUBTLE, border_width=1,
        )
        sarif_card.grid(row=0, column=1, padx=6, pady=4, sticky="nsew")
        sarif_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            sarif_card, text="📦  SARIF 2.1.0 Export",
            font=ctk.CTkFont(*FONT_H3), text_color=TXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, padx=20, pady=(20, 4), sticky="w")

        ctk.CTkLabel(
            sarif_card, text="Exports findings to SARIF JSON for native\nintegration into GitHub Code Scanning & SOC tools.",
            font=ctk.CTkFont(*FONT_SMALL), text_color=TXT_MUTED, anchor="w", justify="left",
        ).grid(row=1, column=0, padx=20, pady=(0, 12), sticky="w")

        ctk.CTkButton(
            sarif_card, text="Export SARIF", height=38,
            corner_radius=BTN_RADIUS,
            fg_color=ACCENT_CYAN, hover_color="#0891B2",
            font=ctk.CTkFont(family=FONT_FAMILY, size=13, weight="bold"),
            command=self._gen_sarif,
        ).grid(row=2, column=0, padx=20, pady=(0, 20), sticky="w")

        # ── Preview panel ──────────────────────────────────────────────
        ctk.CTkLabel(
            wrapper, text="Report Preview",
            font=ctk.CTkFont(*FONT_H3), text_color=TXT_MUTED, anchor="w",
        ).grid(row=3, column=0, padx=30, pady=(8, 2), sticky="nw")

        self.preview_box = ctk.CTkTextbox(
            wrapper, fg_color=BG_CONSOLE, corner_radius=CARD_RADIUS,
            border_color=BORDER_SUBTLE, border_width=1,
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=TXT_SECONDARY, wrap="word",
        )
        self.preview_box.grid(row=4, column=0, columnspan=2, padx=25, pady=(0, 20), sticky="nsew")
        wrapper.grid_rowconfigure(4, weight=1)

        # Load existing report if available
        report_path = PROJECT_ROOT / "compliance_report.md"
        if report_path.is_file():
            try:
                text = report_path.read_text(encoding="utf-8")[:3000]
                self.preview_box.insert("end", text)
            except Exception:
                pass
        else:
            self.preview_box.insert("end", "No report generated yet. Click 'Generate Markdown' above.")
        self.preview_box.configure(state="disabled")

    def _gen_markdown(self):
        try:
            from src.reporting.generate import generate_report
            path, count = generate_report()
            self.rpt_status.configure(
                text=f"✔  Markdown report generated: {path.name}  ({count} findings)",
                text_color=CLR_SAFE,
            )
            # Refresh preview
            self.preview_box.configure(state="normal")
            self.preview_box.delete("1.0", "end")
            text = path.read_text(encoding="utf-8")[:3000]
            self.preview_box.insert("end", text)
            self.preview_box.configure(state="disabled")
        except Exception as exc:
            self.rpt_status.configure(text=f"✘  Error: {exc}", text_color=CLR_CRITICAL)

    def _gen_sarif(self):
        try:
            from src.reporting.sarif_exporter import export_to_sarif
            code = export_to_sarif("results.sarif")
            if code == 0:
                self.rpt_status.configure(
                    text="✔  SARIF report exported: results.sarif",
                    text_color=CLR_SAFE,
                )
            else:
                self.rpt_status.configure(
                    text="✘  SARIF export returned a non-zero code.",
                    text_color=CLR_CRITICAL,
                )
        except Exception as exc:
            self.rpt_status.configure(text=f"✘  Error: {exc}", text_color=CLR_CRITICAL)


def launch_gui():
    """Entry point to start the desktop application."""
    app = AntiFineApp()
    app.mainloop()


if __name__ == "__main__":
    launch_gui()
