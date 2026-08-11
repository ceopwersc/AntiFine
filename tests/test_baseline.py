"""Unit tests for the baseline local audit scanner.

The bash layer is mocked throughout: these tests exercise the Python parsing,
classification, and persistence logic without touching real system state.
"""

from __future__ import annotations

import sqlite3
import subprocess
from pathlib import Path

import pytest

from src.scanners import baseline_audit
from src.scanners.baseline_audit import (
    Finding,
    ListeningPort,
    ScannerError,
    assess_severity,
    identify_insecure_ports,
    parse_port_records,
    record_findings,
    run_baseline_audit,
    run_port_mapper,
)

# Representative port_mapper.sh output: a comment header, two insecure
# services (Telnet, FTP) bound externally, an insecure service on loopback
# (HTTP), and a benign high port that must not be flagged.
SAMPLE_OUTPUT = (
    "#proto\tport\taddress\n"
    "tcp\t21\t0.0.0.0\n"
    "tcp\t23\t0.0.0.0\n"
    "tcp\t80\t127.0.0.1\n"
    "tcp\t22\t0.0.0.0\n"
    "udp\t161\t0.0.0.0\n"
    "tcp\t54321\t127.0.0.1\n"
)


class FakeCompletedProcess:
    """Stand-in for subprocess.CompletedProcess."""

    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


@pytest.fixture
def mock_port_mapper(monkeypatch: pytest.MonkeyPatch):
    """Patch subprocess.run and bash resolution used by the scanner."""

    def _install(stdout: str = SAMPLE_OUTPUT, stderr: str = "", returncode: int = 0):
        calls: list[list[str]] = []

        def fake_run(cmd, *args, **kwargs):
            calls.append(list(cmd))
            return FakeCompletedProcess(stdout, stderr, returncode)

        monkeypatch.setattr(baseline_audit.subprocess, "run", fake_run)
        monkeypatch.setattr(baseline_audit, "resolve_bash", lambda: "/bin/bash")
        return calls

    return _install


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def test_parse_extracts_protocol_port_and_address() -> None:
    ports = parse_port_records(SAMPLE_OUTPUT)

    assert len(ports) == 6
    assert ListeningPort(proto="tcp", port=23, address="0.0.0.0") in ports
    assert ListeningPort(proto="udp", port=161, address="0.0.0.0") in ports
    # Ports must be integers, not strings, for table lookup to work.
    assert all(isinstance(entry.port, int) for entry in ports)


def test_parse_skips_comments_blanks_and_malformed_rows() -> None:
    noisy = (
        "#proto\tport\taddress\n"
        "\n"
        "   \n"
        "tcp\t23\t0.0.0.0\n"
        "garbage line without tabs\n"
        "tcp\tnotaport\t0.0.0.0\n"
        "tcp\t99999\t0.0.0.0\n"      # out of range
        "sctp\t23\t0.0.0.0\n"        # unsupported protocol
        "tcp\t80\n"                  # too few fields
    )

    ports = parse_port_records(noisy)

    assert ports == [ListeningPort(proto="tcp", port=23, address="0.0.0.0")]


def test_parse_deduplicates_identical_records() -> None:
    duplicated = "tcp\t23\t0.0.0.0\n" * 3

    assert len(parse_port_records(duplicated)) == 1


def test_parse_handles_ipv6_addresses() -> None:
    ports = parse_port_records("tcp\t445\t[::]\nudp\t161\t[::1]\n")

    assert ports[0] == ListeningPort(proto="tcp", port=445, address="[::]")
    assert ports[1].is_loopback is True


def test_parse_empty_output_returns_empty_list() -> None:
    assert parse_port_records("") == []
    assert parse_port_records("#proto\tport\taddress\n") == []


# --------------------------------------------------------------------------
# Classification -- the core requirement
# --------------------------------------------------------------------------

def test_identifies_insecure_port_from_mocked_output() -> None:
    """Core check: mocked script output yields the expected Telnet finding."""
    findings = identify_insecure_ports(parse_port_records(SAMPLE_OUTPUT))
    flagged = {(f.port, f.proto): f for f in findings}

    assert (23, "tcp") in flagged, "Telnet on 23/tcp must be flagged"
    telnet = flagged[(23, "tcp")]
    assert telnet.service == "Telnet"
    assert telnet.severity == "CRITICAL"
    assert telnet.vulnerability_type == "Insecure Service: Telnet (23/tcp)"

    assert (21, "tcp") in flagged
    assert flagged[(21, "tcp")].service == "FTP"
    assert (161, "udp") in flagged, "protocol must be tracked, not just port"


def test_secure_and_unknown_ports_are_not_flagged() -> None:
    findings = identify_insecure_ports(parse_port_records(SAMPLE_OUTPUT))
    flagged_ports = {finding.port for finding in findings}

    assert 22 not in flagged_ports, "SSH is encrypted and must not be flagged"
    assert 54321 not in flagged_ports, "unknown high port must not be flagged"


def test_loopback_binding_downgrades_severity() -> None:
    external = identify_insecure_ports(
        [ListeningPort(proto="tcp", port=80, address="0.0.0.0")]
    )
    loopback = identify_insecure_ports(
        [ListeningPort(proto="tcp", port=80, address="127.0.0.1")]
    )

    assert external[0].severity == "MEDIUM"
    assert loopback[0].severity == "LOW"


@pytest.mark.parametrize(
    ("base", "is_loopback", "expected"),
    [
        ("CRITICAL", False, "CRITICAL"),
        ("CRITICAL", True, "HIGH"),
        ("HIGH", True, "MEDIUM"),
        ("INFO", True, "INFO"),          # floors at the bottom of the ladder
        ("UNKNOWN", True, "UNKNOWN"),    # unrecognized severity passes through
    ],
)
def test_assess_severity(base: str, is_loopback: bool, expected: str) -> None:
    assert assess_severity(base, is_loopback) == expected


def test_findings_sorted_most_severe_first() -> None:
    findings = identify_insecure_ports(parse_port_records(SAMPLE_OUTPUT))
    severities = [f.severity for f in findings]
    ranks = [baseline_audit.SEVERITY_LADDER.index(s) for s in severities]

    assert ranks == sorted(ranks)
    assert findings[0].service == "Telnet"


def test_custom_port_table_is_honoured() -> None:
    findings = identify_insecure_ports(
        [ListeningPort(proto="tcp", port=9999, address="0.0.0.0")],
        insecure_ports={9999: ("Test Service", "HIGH")},
    )

    assert len(findings) == 1
    assert findings[0].service == "Test Service"


# --------------------------------------------------------------------------
# Subprocess boundary
# --------------------------------------------------------------------------

def test_run_port_mapper_invokes_script_and_returns_stdout(
    mock_port_mapper, tmp_path: Path
) -> None:
    script = tmp_path / "port_mapper.sh"
    script.write_text("#!/usr/bin/env bash\n")
    calls = mock_port_mapper()

    output = run_port_mapper(script)

    assert output == SAMPLE_OUTPUT
    assert calls == [["/bin/bash", str(script)]]


def test_run_port_mapper_raises_on_missing_script(tmp_path: Path) -> None:
    with pytest.raises(ScannerError, match="not found"):
        run_port_mapper(tmp_path / "does_not_exist.sh")


def test_run_port_mapper_raises_on_nonzero_exit(
    mock_port_mapper, tmp_path: Path
) -> None:
    script = tmp_path / "port_mapper.sh"
    script.write_text("#!/usr/bin/env bash\n")
    mock_port_mapper(stdout="", stderr="no supported tool found", returncode=3)

    with pytest.raises(ScannerError, match="exited with code 3"):
        run_port_mapper(script)


def test_run_port_mapper_raises_on_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    script = tmp_path / "port_mapper.sh"
    script.write_text("#!/usr/bin/env bash\n")

    def fake_run(cmd, *args, **kwargs):
        raise subprocess.TimeoutExpired(cmd, baseline_audit.SCRIPT_TIMEOUT)

    monkeypatch.setattr(baseline_audit.subprocess, "run", fake_run)
    monkeypatch.setattr(baseline_audit, "resolve_bash", lambda: "/bin/bash")

    with pytest.raises(ScannerError, match="timed out"):
        run_port_mapper(script)


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------

def test_record_findings_inserts_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "antifine.db"
    findings = [
        Finding(port=23, proto="tcp", address="0.0.0.0",
                service="Telnet", severity="CRITICAL"),
        Finding(port=21, proto="tcp", address="0.0.0.0",
                service="FTP", severity="HIGH"),
    ]

    inserted = record_findings(findings, db_path=db_path, target_id=1)

    assert inserted == 2
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT target_id, vulnerability_type, severity, status, timestamp "
            "FROM scan_results ORDER BY severity"
        ).fetchall()

    assert len(rows) == 2
    target_ids = {row[0] for row in rows}
    assert target_ids == {1}
    assert any("Telnet (23/tcp)" in row[1] for row in rows)
    assert {row[3] for row in rows} == {"OPEN"}
    # DEFAULT CURRENT_TIMESTAMP must populate without an explicit value.
    assert all(row[4] for row in rows)


def test_record_findings_with_no_findings_writes_nothing(tmp_path: Path) -> None:
    db_path = tmp_path / "antifine.db"

    assert record_findings([], db_path=db_path) == 0
    assert not db_path.exists()


def test_record_findings_raises_on_unwritable_path(tmp_path: Path) -> None:
    unwritable = tmp_path / "not_a_dir.txt"
    unwritable.write_text("this is a file, not a directory")
    findings = [
        Finding(port=23, proto="tcp", address="0.0.0.0",
                service="Telnet", severity="CRITICAL")
    ]

    with pytest.raises(ScannerError):
        record_findings(findings, db_path=unwritable / "antifine.db")


# --------------------------------------------------------------------------
# End-to-end with the bash layer mocked
# --------------------------------------------------------------------------

def test_run_baseline_audit_end_to_end(mock_port_mapper, tmp_path: Path) -> None:
    script = tmp_path / "port_mapper.sh"
    script.write_text("#!/usr/bin/env bash\n")
    db_path = tmp_path / "antifine.db"
    mock_port_mapper()

    findings = run_baseline_audit(
        target_id=1, db_path=db_path, script_path=script, persist=True
    )

    assert {f.port for f in findings} == {21, 23, 80, 161}
    with sqlite3.connect(db_path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
    assert count == len(findings)


def test_run_baseline_audit_dry_run_skips_persistence(
    mock_port_mapper, tmp_path: Path
) -> None:
    script = tmp_path / "port_mapper.sh"
    script.write_text("#!/usr/bin/env bash\n")
    db_path = tmp_path / "antifine.db"
    mock_port_mapper()

    findings = run_baseline_audit(
        target_id=1, db_path=db_path, script_path=script, persist=False
    )

    assert findings
    assert not db_path.exists()


def test_clean_system_produces_no_findings(mock_port_mapper, tmp_path: Path) -> None:
    script = tmp_path / "port_mapper.sh"
    script.write_text("#!/usr/bin/env bash\n")
    mock_port_mapper(stdout="#proto\tport\taddress\ntcp\t22\t0.0.0.0\n")

    findings = run_baseline_audit(
        db_path=tmp_path / "antifine.db", script_path=script, persist=False
    )

    assert findings == []
