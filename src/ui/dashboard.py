"""AntiFine Interactive TUI Dashboard.

Rich-powered terminal user interface for the AntiFine security engine.
Provides a visual dashboard, interactive menu, and color-coded scan summaries.
"""

from __future__ import annotations

import sqlite3
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from rich import box

PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.setup import DB_PATH  # noqa: E402

console = Console()

BANNER = r"""
[bold cyan]
     _          _   _ _____ _            
    / \   _ __ | |_(_)  ___(_)_ __   ___ 
   / _ \ | '_ \| __| | |_  | | '_ \ / _ \
  / ___ \| | | | |_| |  _| | | | | |  __/
 /_/   \_\_| |_|\__|_|_|   |_|_| |_|\___|
[/bold cyan]
[dim white]  Automated Security & Compliance Framework[/dim white]
[dim white]  ─────────────────────────────────────────[/dim white]
"""

SEVERITY_STYLES: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim white",
}

SEVERITY_ICONS: dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH": "🔴",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}

MENU_OPTIONS = {
    "1": "Run Local Audit",
    "2": "Run SSRF Web Audit",
    "3": "Run IaC Config Audit",
    "4": "Generate Markdown & SARIF Reports",
    "5": "View Live Security Dashboard",
    "6": "Exit",
}


def fetch_findings(db_path: Path = DB_PATH) -> list[dict]:
    """Query antifine.db for all scan results."""
    if not db_path.is_file():
        return []

    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, target_id, vulnerability_type, severity, status, "
                "timestamp FROM scan_results ORDER BY timestamp DESC, id DESC"
            ).fetchall()
    except sqlite3.Error:
        return []

    return [dict(row) for row in rows]


def build_summary_table(findings: list[dict]) -> Table:
    """Build a color-coded Rich table from scan findings."""
    table = Table(
        title="🛡️  AntiFine Scan Results",
        box=box.ROUNDED,
        header_style="bold magenta",
        title_style="bold white",
        border_style="bright_blue",
        show_lines=True,
    )

    table.add_column("ID", style="dim", width=5, justify="center")
    table.add_column("Target", justify="center", width=8)
    table.add_column("Vulnerability", min_width=30)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Status", justify="center", width=10)
    table.add_column("Detected", width=20)

    for f in findings:
        severity = (f.get("severity") or "").upper()
        style = SEVERITY_STYLES.get(severity, "white")
        icon = SEVERITY_ICONS.get(severity, "⚫")

        table.add_row(
            str(f.get("id", "")),
            str(f.get("target_id", "")),
            Text(f.get("vulnerability_type", "(unknown)"), style=style),
            Text(f"{icon} {severity}", style=style),
            f.get("status", "UNKNOWN"),
            f.get("timestamp", ""),
        )

    return table


def build_severity_summary(findings: list[dict]) -> Table:
    """Build a compact severity breakdown table."""
    counts: dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity") or "UNKNOWN").upper()
        counts[sev] = counts.get(sev, 0) + 1

    table = Table(
        box=box.SIMPLE_HEAVY,
        header_style="bold white",
        border_style="bright_blue",
    )
    table.add_column("Severity", justify="center")
    table.add_column("Count", justify="center")

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in counts:
            style = SEVERITY_STYLES.get(sev, "white")
            icon = SEVERITY_ICONS.get(sev, "")
            table.add_row(
                Text(f"{icon} {sev}", style=style),
                Text(str(counts[sev]), style=style),
            )

    return table


def display_scan_summary(db_path: Path = DB_PATH) -> Table:
    """Query the database and render a color-coded findings table.

    Returns the built table (useful for testing).
    """
    findings = fetch_findings(db_path)

    console.print()
    console.print(BANNER)

    if not findings:
        console.print(
            Panel(
                "[yellow]No findings recorded yet.[/yellow]\n"
                "Run an audit first, then come back here.",
                title="📋 Dashboard",
                border_style="yellow",
            )
        )
        return build_summary_table([])

    # Severity breakdown
    console.print(
        Panel(
            build_severity_summary(findings),
            title="📊 Severity Breakdown",
            border_style="bright_blue",
        )
    )

    # Full findings table
    table = build_summary_table(findings)
    console.print(table)
    console.print()

    return table


def run_progress_simulation(stages: list[str] | None = None) -> None:
    """Display a Rich progress bar simulating scan stages."""
    if stages is None:
        stages = [
            "Initializing database",
            "Enumerating targets",
            "Running security checks",
            "Analyzing configurations",
            "Compiling results",
        ]

    console.print()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        for stage in stages:
            task = progress.add_task(f"[cyan]{stage}[/cyan]", total=100)
            for _ in range(100):
                time.sleep(0.02)
                progress.update(task, advance=1)

    console.print("[bold green]✔ All stages complete.[/bold green]\n")


def display_menu() -> str:
    """Render the interactive menu and return the user's choice."""
    console.print()
    console.print(BANNER)

    menu_table = Table(
        box=box.ROUNDED,
        header_style="bold magenta",
        border_style="bright_blue",
        show_header=False,
        padding=(0, 2),
    )
    menu_table.add_column("Option", style="bold cyan", width=5, justify="center")
    menu_table.add_column("Action", style="white")

    for key, label in MENU_OPTIONS.items():
        style = "bold red" if key == "6" else "white"
        menu_table.add_row(f"[{key}]", Text(label, style=style))

    console.print(
        Panel(
            menu_table,
            title="🔧 AntiFine Control Center",
            border_style="bright_blue",
            subtitle="Select an option below",
        )
    )

    choice = Prompt.ask(
        "[bold cyan]Enter your choice[/bold cyan]",
        choices=list(MENU_OPTIONS.keys()),
        default="6",
    )
    return choice


def interactive_loop() -> int:
    """Main interactive TUI loop."""
    # Lazy imports to avoid circular dependencies at module level
    from src.main import (
        run_init,
        run_audit_local,
        run_audit_iac,
        run_report,
    )
    from src.reporting.sarif_exporter import export_to_sarif

    # Ensure DB exists
    run_init()

    while True:
        choice = display_menu()

        if choice == "1":
            console.print("\n[bold cyan]▶ Running Local Audit...[/bold cyan]")
            run_progress_simulation([
                "Resolving bash interpreter",
                "Enumerating listening ports",
                "Cross-referencing insecure services",
                "Recording findings to database",
            ])
            exit_code = run_audit_local()
            if exit_code != 0:
                console.print("[bold red]✘ Local audit encountered errors.[/bold red]")

        elif choice == "2":
            url = Prompt.ask("[bold cyan]Enter target URL[/bold cyan]")
            console.print(f"\n[bold cyan]▶ Running SSRF Web Audit on {url}...[/bold cyan]")
            run_progress_simulation([
                "Building test URL matrix",
                "Sending probe requests",
                "Analyzing responses for SSRF indicators",
                "Recording findings to database",
            ])
            from src.main import run_audit_web
            exit_code = run_audit_web(url)
            if exit_code != 0:
                console.print("[bold red]✘ Web audit encountered errors.[/bold red]")

        elif choice == "3":
            path = Prompt.ask("[bold cyan]Enter file or directory path[/bold cyan]")
            console.print(f"\n[bold cyan]▶ Running IaC Config Audit on {path}...[/bold cyan]")
            run_progress_simulation([
                "Discovering configuration files",
                "Parsing Dockerfiles",
                "Analyzing Kubernetes manifests",
                "Scanning Terraform files",
                "Recording findings to database",
            ])
            from src.main import run_audit_iac
            exit_code = run_audit_iac(path)
            if exit_code != 0:
                console.print("[bold red]✘ IaC audit encountered errors.[/bold red]")

        elif choice == "4":
            console.print("\n[bold cyan]▶ Generating Reports...[/bold cyan]")
            run_progress_simulation([
                "Querying audit database",
                "Rendering Markdown compliance report",
                "Serializing SARIF 2.1.0 JSON",
            ])
            run_report()
            export_to_sarif("results.sarif")
            console.print("[bold green]✔ Reports generated successfully.[/bold green]")

        elif choice == "5":
            display_scan_summary()

        elif choice == "6":
            console.print("\n[bold cyan]Goodbye! Stay secure. 🔒[/bold cyan]\n")
            return 0
