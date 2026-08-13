"""AntiFine Native Desktop Application — Ultimate Cyber-Sec OLED UI.

A high-end, commercial-grade cybersecurity dashboard built with CustomTkinter.
Features custom frame-based animations, OLED black themes, and premium spacing.
"""

from __future__ import annotations

import io
import math
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

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  DESIGN TOKENS (Cyber-Sec OLED)                                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝

BG_ROOT       = "#050505"
BG_SIDEBAR    = "#0A0A0A"
BG_CARD       = "#121212"
BG_INPUT      = "#0A0A0A"
BORDER_SUBTLE = "#1E1E1E"
BG_HOVER      = "#181818"

# CTAs
CTA_PRIMARY_BG       = "#003344"
CTA_PRIMARY_TXT      = "#00E5FF"
CTA_PRIMARY_BG_HOV   = "#004C66"
CTA_PRIMARY_TXT_HOV  = "#00FFD1"

CTA_SECONDARY_BG     = "#121212"
CTA_SECONDARY_TXT    = "#A3A3A3"
CTA_SECONDARY_BG_HOV = "#1E1E1E"
CTA_SECONDARY_TXT_HOV= "#FFFFFF"

# Severity palette
CLR_CRITICAL  = "#FF003C"
CLR_HIGH      = "#FF003C"
CLR_MEDIUM    = "#FFB800"
CLR_LOW       = "#0088FF"
CLR_SAFE      = "#00FF66"

SEVERITY_COLORS = {
    "CRITICAL": CLR_CRITICAL,
    "HIGH":     CLR_HIGH,
    "MEDIUM":   CLR_MEDIUM,
    "LOW":      CLR_LOW,
    "INFO":     "#888888",
}

# Text colors
TXT_PRIMARY   = "#FFFFFF"
TXT_SECONDARY = "#888888"
TXT_TERM      = "#A3A3A3"

# Typography
FONT_FAMILY   = "Segoe UI"
FONT_H1       = (FONT_FAMILY, 28, "bold")
FONT_H2       = (FONT_FAMILY, 16, "bold")
FONT_SUB      = (FONT_FAMILY, 14, "normal")
FONT_BODY     = (FONT_FAMILY, 12, "normal")
FONT_TERM     = ("Consolas", 11, "normal")
FONT_BTN      = (FONT_FAMILY, 16, "bold")

# Dimensions
SIDEBAR_W_EXP = 220
SIDEBAR_W_COL = 60

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
                "timestamp FROM scan_results ORDER BY id DESC LIMIT 50"
            ).fetchall()
    except sqlite3.Error:
        return []


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  ANIMATION ENGINE                                                      ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def interpolate_hex(c1: str, c2: str, factor: float) -> str:
    """Interpolate between two 6-digit hex colors."""
    try:
        r1, g1, b1 = int(c1[1:3], 16), int(c1[3:5], 16), int(c1[5:7], 16)
        r2, g2, b2 = int(c2[1:3], 16), int(c2[3:5], 16), int(c2[5:7], 16)
    except ValueError:
        return c2

    r = int(r1 + (r2 - r1) * factor)
    g = int(g1 + (g2 - g1) * factor)
    b = int(b1 + (b2 - b1) * factor)
    return f"#{r:02X}{g:02X}{b:02X}"

class AnimatedButton(ctk.CTkButton):
    """Button with smooth color fading on hover."""

    def __init__(self, master, base_bg, hover_bg, base_txt, hover_txt, duration_ms=150, step_ms=15, **kwargs):
        super().__init__(master, fg_color=base_bg, hover_color=hover_bg, text_color=base_txt, **kwargs)
        self.base_bg = base_bg
        self.hover_bg = hover_bg
        self.base_txt = base_txt
        self.hover_txt = hover_txt
        self.duration_ms = duration_ms
        self.step_ms = step_ms
        self._anim_id = None
        self._current_factor = 0.0
        self._target_factor = 0.0

        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

    def _on_enter(self, event):
        self._target_factor = 1.0
        self._animate()

    def _on_leave(self, event):
        self._target_factor = 0.0
        self._animate()

    def _animate(self):
        if self._anim_id:
            self.after_cancel(self._anim_id)
        
        diff = self._target_factor - self._current_factor
        steps = self.duration_ms / self.step_ms
        if abs(diff) < 0.01:
            self._current_factor = self._target_factor
            self._apply_colors()
            return

        self._current_factor += diff / steps
        self._apply_colors()
        self._anim_id = self.after(self.step_ms, self._animate)

    def _apply_colors(self):
        new_bg = interpolate_hex(self.base_bg, self.hover_bg, self._current_factor)
        new_txt = interpolate_hex(self.base_txt, self.hover_txt, self._current_factor)
        # CustomTkinter hack to override standard hover behavior
        self.configure(fg_color=new_bg, hover_color=new_bg, text_color=new_txt)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  WIDGETS                                                               ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class MetricCard(ctk.CTkFrame):
    """Glass-like metric card (2x2 grid target)."""
    def __init__(self, master, label: str, value: int, accent: str, **kw):
        super().__init__(
            master, corner_radius=15,
            fg_color=BG_CARD, border_color=BORDER_SUBTLE, border_width=1, **kw
        )
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)
        self.grid_columnconfigure(0, weight=1)

        val_lbl = ctk.CTkLabel(
            self, text=str(value),
            font=ctk.CTkFont(family=FONT_FAMILY, size=36, weight="bold"),
            text_color=accent,
        )
        val_lbl.grid(row=1, column=0, pady=(15, 0))

        name_lbl = ctk.CTkLabel(
            self, text=label.upper(),
            font=ctk.CTkFont(family=FONT_FAMILY, size=12),
            text_color=TXT_SECONDARY,
        )
        name_lbl.grid(row=2, column=0, pady=(0, 15))

class SeverityPill(ctk.CTkFrame):
    """Pill badge for findings."""
    def __init__(self, master, text: str, color: str, **kw):
        # We simulate the translucent background with a pre-mixed dark color (approximate 15% opacity on BG_CARD)
        mixed_bg = interpolate_hex(BG_CARD, color, 0.15)
        super().__init__(
            master, corner_radius=10, fg_color=mixed_bg,
            border_color=color, border_width=1, **kw,
        )
        lbl = ctk.CTkLabel(
            self, text=text,
            font=ctk.CTkFont(family=FONT_FAMILY, size=11, weight="bold"),
            text_color=color,
        )
        lbl.grid(padx=12, pady=2)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  MAIN APPLICATION                                                      ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class AntiFineApp(ctk.CTk):
    """Root window and layout orchestrator."""

    def __init__(self):
        super().__init__()

        self.title("AntiFine — Cyber-Sec Auditor")
        self.geometry("1100x750")
        self.minsize(900, 600)
        self.configure(fg_color=BG_ROOT)

        # Borderless look hack for CustomTkinter main window (some platforms)
        try:
            self.wm_attributes("-fullscreen", False)
        except Exception:
            pass

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        try:
            initialize_database()
        except Exception:
            pass

        self._build_sidebar()
        
        self.content = ctk.CTkFrame(self, corner_radius=0, fg_color=BG_ROOT)
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        self._pulse_id = None
        self._sidebar_anim_id = None
        self._is_sidebar_open = True
        self._sidebar_w = SIDEBAR_W_EXP

        self.show_dashboard()

    # ── Sidebar ─────────────────────────────────────────────────────────

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(
            self, width=SIDEBAR_W_EXP, corner_radius=0,
            fg_color=BG_SIDEBAR, border_color=BORDER_SUBTLE, border_width=1,
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1)
        self.sidebar.grid_propagate(False)

        # Header area
        hdr_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        hdr_frame.grid(row=0, column=0, sticky="ew", pady=(20, 30))
        hdr_frame.grid_columnconfigure(1, weight=1)

        self.toggle_btn = ctk.CTkButton(
            hdr_frame, text="☰", width=40, height=40,
            fg_color="transparent", hover_color=BG_HOVER,
            text_color=TXT_PRIMARY, font=ctk.CTkFont(size=20),
            command=self._toggle_sidebar
        )
        self.toggle_btn.grid(row=0, column=0, padx=(10, 5))

        self.logo_lbl = ctk.CTkLabel(
            hdr_frame, text="ANTIFINE",
            font=ctk.CTkFont(family=FONT_FAMILY, size=18, weight="bold"),
            text_color=TXT_PRIMARY,
        )
        self.logo_lbl.grid(row=0, column=1, sticky="w")

        # Nav Buttons
        self.nav_btns = []
        self._add_nav_btn(1, "📊", " Dashboard", self.show_dashboard)
        self._add_nav_btn(2, "🛡️", " Scanner", self.show_scanner)
        self._add_nav_btn(3, "📄", " Reports", self.show_reports)

    def _add_nav_btn(self, row, icon, text, command):
        btn = AnimatedButton(
            self.sidebar, base_bg="transparent", hover_bg=BG_HOVER,
            base_txt=TXT_SECONDARY, hover_txt=TXT_PRIMARY,
            text=f"{icon} {text}", command=command,
            anchor="w", corner_radius=8, height=45,
            font=ctk.CTkFont(family=FONT_FAMILY, size=14)
        )
        btn.grid(row=row, column=0, padx=10, pady=5, sticky="ew")
        btn._text_raw = text
        btn._icon_raw = icon
        self.nav_btns.append(btn)

    def _toggle_sidebar(self):
        if self._sidebar_anim_id:
            self.after_cancel(self._sidebar_anim_id)
        self._is_sidebar_open = not self._is_sidebar_open
        self._animate_sidebar()

    def _animate_sidebar(self):
        target_w = SIDEBAR_W_EXP if self._is_sidebar_open else SIDEBAR_W_COL
        diff = target_w - self._sidebar_w
        if abs(diff) < 2:
            self._sidebar_w = target_w
            self.sidebar.configure(width=int(self._sidebar_w))
            self._update_sidebar_content()
            return

        self._sidebar_w += diff * 0.3
        self.sidebar.configure(width=int(self._sidebar_w))
        self._update_sidebar_content()
        self._sidebar_anim_id = self.after(15, self._animate_sidebar)

    def _update_sidebar_content(self):
        if self._sidebar_w < 120:
            self.logo_lbl.grid_remove()
            for btn in self.nav_btns:
                btn.configure(text=btn._icon_raw)
        else:
            self.logo_lbl.grid()
            for btn in self.nav_btns:
                btn.configure(text=f"{btn._icon_raw} {btn._text_raw}")

    # ── Helpers ─────────────────────────────────────────────────────────

    def _clear_content(self):
        for w in self.content.winfo_children():
            w.destroy()

    def _pulse_indicator(self, widget, active=True, step=0):
        if not active:
            if self._pulse_id:
                self.after_cancel(self._pulse_id)
                self._pulse_id = None
            widget.configure(text_color=TXT_SECONDARY)
            return

        # Sine wave interpolation for pulsing effect
        factor = (math.sin(step) + 1) / 2
        new_color = interpolate_hex(BG_ROOT, CTA_PRIMARY_TXT, factor)
        widget.configure(text_color=new_color)
        self._pulse_id = self.after(30, lambda: self._pulse_indicator(widget, True, step + 0.15))

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  DASHBOARD VIEW                                                 ║
    # ╚══════════════════════════════════════════════════════════════════╝

    def show_dashboard(self):
        self._clear_content()

        wrapper = ctk.CTkScrollableFrame(self.content, fg_color=BG_ROOT, corner_radius=0)
        wrapper.grid(row=0, column=0, sticky="nsew")
        wrapper.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            wrapper, text="Overview Dashboard",
            font=ctk.CTkFont(*FONT_H1), text_color=TXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, padx=40, pady=(40, 5), sticky="w")
        ctk.CTkLabel(
            wrapper, text="Real-time security posture and threat metrics.",
            font=ctk.CTkFont(*FONT_SUB), text_color=TXT_SECONDARY, anchor="w",
        ).grid(row=1, column=0, padx=40, pady=(0, 30), sticky="w")

        # 2x2 Metric Cards
        cards_frame = ctk.CTkFrame(wrapper, fg_color="transparent")
        cards_frame.grid(row=2, column=0, padx=35, sticky="ew")
        cards_frame.grid_columnconfigure((0, 1), weight=1)

        counts = _fetch_severity_counts()
        MetricCard(cards_frame, "CRITICAL", counts["CRITICAL"], CLR_CRITICAL).grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        MetricCard(cards_frame, "HIGH", counts["HIGH"], CLR_HIGH).grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        MetricCard(cards_frame, "MEDIUM", counts["MEDIUM"], CLR_MEDIUM).grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        MetricCard(cards_frame, "LOW", counts["LOW"], CLR_LOW).grid(row=1, column=1, padx=10, pady=10, sticky="nsew")

        # Table
        table_frame = ctk.CTkFrame(wrapper, fg_color=BG_CARD, corner_radius=15, border_color=BORDER_SUBTLE, border_width=1)
        table_frame.grid(row=3, column=0, padx=45, pady=(30, 40), sticky="ew")
        table_frame.grid_columnconfigure(2, weight=1)

        findings = _fetch_all_findings()
        for r, f in enumerate(findings[:10], start=1):
            fid, tid, vuln, sev, status, ts = f
            sev_upper = (sev or "").upper()
            clr = SEVERITY_COLORS.get(sev_upper, TXT_SECONDARY)

            ctk.CTkLabel(table_frame, text=f"#{fid}", font=ctk.CTkFont(*FONT_BODY), text_color=TXT_SECONDARY).grid(row=r, column=0, padx=20, pady=10, sticky="w")
            SeverityPill(table_frame, text=sev_upper, color=clr).grid(row=r, column=1, padx=20, pady=10, sticky="w")
            ctk.CTkLabel(table_frame, text=vuln, font=ctk.CTkFont(*FONT_BODY), text_color=TXT_PRIMARY).grid(row=r, column=2, padx=20, pady=10, sticky="w")

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  SCANNER INTERFACE (War Room)                                   ║
    # ╚══════════════════════════════════════════════════════════════════╝

    def show_scanner(self):
        self._clear_content()

        wrapper = ctk.CTkFrame(self.content, fg_color=BG_ROOT, corner_radius=0)
        wrapper.grid(row=0, column=0, sticky="nsew")
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(4, weight=1)

        header_frame = ctk.CTkFrame(wrapper, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=40, pady=(40, 20), sticky="ew")
        header_frame.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(
            header_frame, text="Vulnerability Scanner",
            font=ctk.CTkFont(*FONT_H1), text_color=TXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")

        self.pulse_lbl = ctk.CTkLabel(
            header_frame, text="● IDLE",
            font=ctk.CTkFont(*FONT_SUB), text_color=TXT_SECONDARY,
        )
        self.pulse_lbl.grid(row=0, column=1, sticky="e")

        # Segmented Control
        self._scan_mode = ctk.StringVar(value="ssrf")
        seg_frame = ctk.CTkFrame(wrapper, fg_color="transparent")
        seg_frame.grid(row=1, column=0, padx=40, pady=(0, 20), sticky="w")

        def _update_segment(*args):
            for rb in rbs:
                if rb.cget("value") == self._scan_mode.get():
                    rb.configure(text_color=CTA_PRIMARY_TXT)
                else:
                    rb.configure(text_color=TXT_SECONDARY)

        rbs = []
        for i, (val, txt) in enumerate([("ssrf", "SSRF Web Audit"), ("iac", "IaC Config Audit"), ("net", "Full Network Audit")]):
            rb = ctk.CTkRadioButton(
                seg_frame, text=txt, variable=self._scan_mode, value=val,
                font=ctk.CTkFont(*FONT_BODY), text_color=TXT_SECONDARY if i>0 else CTA_PRIMARY_TXT,
                fg_color=CTA_PRIMARY_TXT, hover_color=CTA_PRIMARY_TXT, command=_update_segment
            )
            rb.grid(row=0, column=i, padx=(0, 30))
            rbs.append(rb)

        # Input & Button
        input_frame = ctk.CTkFrame(wrapper, fg_color="transparent")
        input_frame.grid(row=2, column=0, padx=40, pady=10, sticky="ew")
        input_frame.grid_columnconfigure(0, weight=1)

        self.scan_entry = ctk.CTkEntry(
            input_frame, height=45, corner_radius=8,
            fg_color=BG_INPUT, border_color=BORDER_SUBTLE, border_width=1,
            placeholder_text="Enter target URL or path (e.g. http://host/api or ./infra)",
            font=ctk.CTkFont(*FONT_BODY), text_color=TXT_PRIMARY,
        )
        self.scan_entry.grid(row=0, column=0, sticky="ew", padx=(0, 20))

        self.start_btn = AnimatedButton(
            input_frame, base_bg=CTA_PRIMARY_BG, hover_bg=CTA_PRIMARY_BG_HOV,
            base_txt=CTA_PRIMARY_TXT, hover_txt=CTA_PRIMARY_TXT_HOV,
            text="START SCAN", height=45, width=150, corner_radius=8,
            font=ctk.CTkFont(*FONT_BTN), command=self._dispatch_scan
        )
        self.start_btn.grid(row=0, column=1)

        # Live Terminal
        self.terminal = ctk.CTkTextbox(
            wrapper, fg_color="#000000", corner_radius=12,
            border_color=BORDER_SUBTLE, border_width=1,
            font=ctk.CTkFont(*FONT_TERM), text_color=TXT_TERM, wrap="word"
        )
        self.terminal.grid(row=4, column=0, padx=40, pady=(20, 40), sticky="nsew")
        
        # Configure text tags for colored logs directly on the underlying tk.Text widget
        self.terminal._textbox.tag_config("info", foreground=TXT_TERM)
        self.terminal._textbox.tag_config("vuln", foreground=CLR_CRITICAL)
        self.terminal._textbox.tag_config("success", foreground=CLR_SAFE)
        
        self._term_write("[INFO] Terminal initialized. Waiting for task...", "info")
        self.terminal.configure(state="disabled")

    def _term_write(self, text: str, tag: str = "info"):
        def _do():
            self.terminal.configure(state="normal")
            self.terminal.insert("end", text + "\n", tag)
            self.terminal.see("end")
            self.terminal.configure(state="disabled")
        if threading.current_thread() is threading.main_thread():
            _do()
        else:
            self.after(0, _do)

    def _dispatch_scan(self):
        mode = self._scan_mode.get()
        target = self.scan_entry.get().strip()

        if mode in ("ssrf", "iac") and not target:
            self._term_write("[ERROR] Target required for this scan mode.", "vuln")
            return

        self.start_btn.configure(state="disabled")
        self.pulse_lbl.configure(text="● RUNNING")
        self._pulse_indicator(self.pulse_lbl, active=True)
        self.terminal.configure(state="normal")
        self.terminal.delete("1.0", "end")
        self.terminal.configure(state="disabled")

        def _worker():
            self._term_write(f"[INFO] Initiating {mode.upper()} scan...", "info")
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
                self._term_write(f"[ERROR] {exc}", "vuln")

            out = buf.getvalue()
            if out:
                for line in out.strip().splitlines():
                    t = "info"
                    if "error" in line.lower() or "insecure" in line.lower():
                        t = "vuln"
                        line = f"[-] {line}"
                    elif "ok" in line.lower() or "success" in line.lower():
                        t = "success"
                        line = f"[+] {line}"
                    else:
                        line = f"[*] {line}"
                    self._term_write(line, t)

            self._term_write("[SUCCESS] Scan sequence terminated.", "success")
            
            def _reset():
                self.start_btn.configure(state="normal")
                self.pulse_lbl.configure(text="● IDLE")
                self._pulse_indicator(self.pulse_lbl, active=False)
            self.after(0, _reset)

        threading.Thread(target=_worker, daemon=True).start()

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  REPORTS VIEW                                                   ║
    # ╚══════════════════════════════════════════════════════════════════╝

    def show_reports(self):
        self._clear_content()

        wrapper = ctk.CTkFrame(self.content, fg_color=BG_ROOT, corner_radius=0)
        wrapper.grid(row=0, column=0, sticky="nsew")
        wrapper.grid_rowconfigure(2, weight=1)
        wrapper.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            wrapper, text="Reports & SARIF",
            font=ctk.CTkFont(*FONT_H1), text_color=TXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, padx=40, pady=(40, 5), sticky="w")
        ctk.CTkLabel(
            wrapper, text="Generate and export compliance evidence.",
            font=ctk.CTkFont(*FONT_SUB), text_color=TXT_SECONDARY, anchor="w",
        ).grid(row=1, column=0, padx=40, pady=(0, 30), sticky="w")

        content_frame = ctk.CTkFrame(wrapper, fg_color="transparent")
        content_frame.grid(row=2, column=0, padx=40, sticky="nsew")
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_rowconfigure(1, weight=1)

        actions_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        actions_frame.grid(row=0, column=0, sticky="ew")

        AnimatedButton(
            actions_frame, base_bg=CTA_SECONDARY_BG, hover_bg=CTA_SECONDARY_BG_HOV,
            base_txt=CTA_SECONDARY_TXT, hover_txt=CTA_SECONDARY_TXT_HOV,
            text="Generate Markdown", height=45, corner_radius=8,
            font=ctk.CTkFont(*FONT_BTN), command=self._gen_markdown
        ).grid(row=0, column=0, padx=(0, 20))

        AnimatedButton(
            actions_frame, base_bg=CTA_PRIMARY_BG, hover_bg=CTA_PRIMARY_BG_HOV,
            base_txt=CTA_PRIMARY_TXT, hover_txt=CTA_PRIMARY_TXT_HOV,
            text="Export SARIF", height=45, corner_radius=8,
            font=ctk.CTkFont(*FONT_BTN), command=self._gen_sarif
        ).grid(row=0, column=1)

        self.rpt_status = ctk.CTkLabel(actions_frame, text="", font=ctk.CTkFont(*FONT_SUB))
        self.rpt_status.grid(row=0, column=2, padx=30)

        self.preview_box = ctk.CTkTextbox(
            content_frame, fg_color=BG_CARD, corner_radius=12,
            border_color=BORDER_SUBTLE, border_width=1,
            font=ctk.CTkFont(*FONT_TERM), text_color=TXT_SECONDARY, wrap="word"
        )
        self.preview_box.grid(row=1, column=0, pady=(30, 40), sticky="nsew")
        
        self._load_report_preview()

    def _load_report_preview(self):
        report_path = PROJECT_ROOT / "compliance_report.md"
        self.preview_box.configure(state="normal")
        self.preview_box.delete("1.0", "end")
        if report_path.is_file():
            try:
                self.preview_box.insert("end", report_path.read_text(encoding="utf-8")[:3000])
            except Exception:
                pass
        else:
            self.preview_box.insert("end", "No report generated yet.")
        self.preview_box.configure(state="disabled")

    def _gen_markdown(self):
        try:
            from src.reporting.generate import generate_report
            path, count = generate_report()
            self.rpt_status.configure(text=f"✔ Markdown generated ({count} findings)", text_color=CLR_SAFE)
            self._load_report_preview()
        except Exception as exc:
            self.rpt_status.configure(text=f"✘ Error: {exc}", text_color=CLR_CRITICAL)

    def _gen_sarif(self):
        try:
            from src.reporting.sarif_exporter import export_to_sarif
            code = export_to_sarif("results.sarif")
            if code == 0:
                self.rpt_status.configure(text="✔ SARIF exported", text_color=CLR_SAFE)
            else:
                self.rpt_status.configure(text="✘ SARIF export failed", text_color=CLR_CRITICAL)
        except Exception as exc:
            self.rpt_status.configure(text=f"✘ Error: {exc}", text_color=CLR_CRITICAL)

def launch_gui():
    app = AntiFineApp()
    app.mainloop()

if __name__ == "__main__":
    launch_gui()
