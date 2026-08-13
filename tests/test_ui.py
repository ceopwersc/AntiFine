"""Tests for the TUI dashboard module."""

import sqlite3
from pathlib import Path
from src.ui.dashboard import build_summary_table, display_scan_summary, fetch_findings


def test_build_summary_table_renders_without_error():
    """Verify the summary table renders correctly with sample data."""
    findings = [
        {
            "id": 1,
            "target_id": 1,
            "vulnerability_type": "SSRF in metadata",
            "severity": "HIGH",
            "status": "OPEN",
            "timestamp": "2026-08-14 00:00:00",
        },
        {
            "id": 2,
            "target_id": 1,
            "vulnerability_type": "Insecure Configuration",
            "severity": "MEDIUM",
            "status": "OPEN",
            "timestamp": "2026-08-14 00:00:00",
        },
    ]
    table = build_summary_table(findings)
    assert table is not None
    assert table.row_count == 2


def test_build_summary_table_empty():
    """Verify the table renders cleanly with no findings."""
    table = build_summary_table([])
    assert table is not None
    assert table.row_count == 0


def test_display_scan_summary_with_empty_db(tmp_path):
    """Verify display_scan_summary runs without exceptions on an empty DB."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE scan_results ("
        "id INTEGER PRIMARY KEY, target_id INTEGER, "
        "vulnerability_type TEXT, severity TEXT, "
        "status TEXT, timestamp TEXT DEFAULT CURRENT_TIMESTAMP)"
    )
    conn.commit()
    conn.close()

    table = display_scan_summary(db_path=db_path)
    assert table is not None


def test_fetch_findings_missing_db(tmp_path):
    """Verify fetch_findings returns empty list for non-existent DB."""
    findings = fetch_findings(db_path=tmp_path / "nonexistent.db")
    assert findings == []


# ── Desktop App Tests ───────────────────────────────────────────────────

def test_desktop_app_module_imports():
    """Verify the desktop_app module can be imported without errors."""
    from src.ui.desktop_app import AntiFineApp, launch_gui, _fetch_severity_counts
    assert AntiFineApp is not None
    assert callable(launch_gui)
    assert callable(_fetch_severity_counts)


def test_desktop_app_severity_counts_missing_db(tmp_path):
    """Verify _fetch_severity_counts returns zeroes for non-existent DB."""
    from src.ui.desktop_app import _fetch_severity_counts
    counts = _fetch_severity_counts(db_path=tmp_path / "nonexistent.db")
    assert counts == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

