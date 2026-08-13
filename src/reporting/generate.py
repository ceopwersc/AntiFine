"""Compliance reporting engine.

Reads recorded findings from the audit database and renders a structured
Markdown compliance report grouped by severity.

Per the project coding standards this module depends on the storage layer
only. It does not import any scanner, and scanners must never import it --
findings reach the report exclusively through the ``scan_results`` table, so
new scanners are picked up with no change here.
"""

from __future__ import annotations

import re
import sqlite3
import sys
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.setup import DB_PATH  # noqa: E402
from src.reporting.knowledge_base import get_remediation  # noqa: E402

REPORT_PATH: Path = PROJECT_ROOT / "compliance_report.md"

#: Presentation order for severity sections. Anything unrecognized is
#: collected under UNCLASSIFIED so no finding is ever dropped from a report.
SEVERITY_ORDER: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
UNCLASSIFIED: str = "UNCLASSIFIED"

SEVERITY_BADGE: dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
    UNCLASSIFIED: "⚫",
}

#: Pulls "(445/tcp)" out of a stored vulnerability_type label.
_PORT_LABEL = re.compile(r"\((?P<port>\d{1,5})/(?P<proto>tcp|udp)\)", re.IGNORECASE)

#: Port-specific remediation guidance. Keyed by port so the reporting engine
#: stays decoupled from the scanner's internal tables.
REMEDIATION_BY_PORT: dict[int, str] = {
    21: "Migrate to SFTP or FTPS; disable the plaintext FTP listener.",
    23: "Disable Telnet entirely and replace it with SSH. Credentials and "
        "session data are transmitted in cleartext.",
    25: "Enforce STARTTLS and require authentication; restrict relay access.",
    69: "Disable TFTP. It provides no authentication; use SCP or HTTPS.",
    80: "Redirect all traffic to HTTPS and enable HSTS; terminate plaintext "
        "HTTP at the edge only.",
    110: "Disable POP3 or require POP3S (995); credentials are sent in cleartext.",
    111: "Restrict rpcbind to trusted networks or disable it if RPC is unused.",
    135: "Block the RPC endpoint mapper at the host firewall; expose it only "
         "to trusted management networks.",
    137: "Disable NetBIOS over TCP/IP on all external interfaces.",
    138: "Disable NetBIOS over TCP/IP on all external interfaces.",
    139: "Disable NetBIOS session service; use SMB over 445 with signing, or "
         "restrict it to trusted networks.",
    143: "Disable IMAP or require IMAPS (993); credentials are sent in cleartext.",
    161: "Upgrade to SNMPv3 with authentication and privacy; never leave "
         "default community strings in place.",
    389: "Require LDAPS or StartTLS; reject unencrypted directory binds.",
    445: "Restrict SMB to trusted networks, enforce signing, and disable "
         "SMBv1 if still enabled.",
    512: "Disable rexec; it transmits credentials in cleartext. Use SSH.",
    513: "Disable rlogin; it transmits credentials in cleartext. Use SSH.",
    514: "Disable rsh. If this is syslog, forward over TLS instead.",
    1433: "Bind to localhost or a management VLAN, enforce TLS, and require "
          "strong authentication.",
    3306: "Bind to localhost where possible and require TLS for remote "
          "connections.",
    3389: "Restrict RDP to VPN or a jump host, enforce NLA, and enable MFA.",
    5432: "Bind to localhost where possible; require TLS and scram-sha-256 auth.",
    5900: "Tunnel VNC over SSH or a VPN and require strong authentication; "
          "never expose it directly.",
    6379: "Enable authentication, bind to localhost, and enable protected mode.",
    11211: "Bind Memcached to localhost; it is unauthenticated and is an "
           "amplification vector when exposed.",
    27017: "Enable authentication and bind to localhost or a private subnet.",
}

#: Fallback guidance when a finding's port is not in the table above.
DEFAULT_REMEDIATION: str = (
    "Review whether this service must listen on an external interface. "
    "Bind it to localhost, restrict it at the firewall, or migrate to an "
    "encrypted equivalent."
)


class ReportError(RuntimeError):
    """Raised when a compliance report cannot be produced."""


@dataclass(frozen=True)
class ScanRecord:
    """One row from the ``scan_results`` table."""

    id: int
    target_id: int
    vulnerability_type: str
    severity: str
    status: str
    timestamp: str

    @property
    def normalized_severity(self) -> str:
        """Severity mapped onto the known ladder, or UNCLASSIFIED."""
        value = (self.severity or "").strip().upper()
        return value if value in SEVERITY_ORDER else UNCLASSIFIED

    @property
    def port(self) -> int | None:
        """Port parsed from the finding label, when present."""
        match = _PORT_LABEL.search(self.vulnerability_type or "")
        return int(match.group("port")) if match else None

    @property
    def remediation(self) -> str:
        """Recommended remediation for this finding."""
        port = self.port
        if port is not None and port in REMEDIATION_BY_PORT:
            return REMEDIATION_BY_PORT[port]
        return DEFAULT_REMEDIATION


def fetch_scan_results(db_path: Path = DB_PATH) -> list[ScanRecord]:
    """Load every row from ``scan_results``.

    Args:
        db_path: SQLite database to read.

    Returns:
        All recorded findings, newest first.

    Raises:
        ReportError: If the database is missing or unreadable.
    """
    if not db_path.is_file():
        raise ReportError(
            f"Database not found at {db_path}. Run '--init' and an audit first."
        )

    try:
        with sqlite3.connect(db_path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT id, target_id, vulnerability_type, severity, status, "
                "timestamp FROM scan_results ORDER BY timestamp DESC, id DESC"
            ).fetchall()
    except sqlite3.Error as exc:
        raise ReportError(f"Could not read findings from {db_path}: {exc}") from exc

    return [
        ScanRecord(
            id=row["id"],
            target_id=row["target_id"],
            vulnerability_type=row["vulnerability_type"] or "(unspecified)",
            severity=row["severity"] or "",
            status=row["status"] or "UNKNOWN",
            timestamp=row["timestamp"] or "",
        )
        for row in rows
    ]


def group_by_severity(
    records: list[ScanRecord],
) -> "OrderedDict[str, list[ScanRecord]]":
    """Bucket findings by severity in presentation order.

    Only non-empty severities appear. Unrecognized severities are grouped
    under UNCLASSIFIED and placed last so nothing is silently omitted.
    """
    buckets: dict[str, list[ScanRecord]] = {}
    for record in records:
        buckets.setdefault(record.normalized_severity, []).append(record)

    ordered: "OrderedDict[str, list[ScanRecord]]" = OrderedDict()
    for severity in (*SEVERITY_ORDER, UNCLASSIFIED):
        bucket = buckets.get(severity)
        if bucket:
            ordered[severity] = sorted(bucket, key=lambda r: (r.port or 0, r.id))
    return ordered


def _escape_cell(text: str) -> str:
    """Make a value safe to embed in a Markdown table cell."""
    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


def render_report(
    records: list[ScanRecord],
    generated_at: datetime | None = None,
    db_path: Path = DB_PATH,
) -> str:
    """Render findings as a Markdown compliance report."""
    moment = generated_at or datetime.now(timezone.utc)
    stamp = moment.strftime("%Y-%m-%d %H:%M:%S UTC")
    grouped = group_by_severity(records)
    targets = sorted({record.target_id for record in records})

    lines: list[str] = [
        "# AntiFine Compliance Report",
        "",
        f"**Generated:** {stamp}  ",
        f"**Source database:** `{db_path.name}`  ",
        f"**Total findings:** {len(records)}  ",
        f"**Targets covered:** {', '.join(str(t) for t in targets) or 'none'}",
        "",
        "---",
        "",
        "## Summary",
        "",
    ]

    if not records:
        lines += [
            "No findings are recorded in the audit database.",
            "",
            "Run `python3 src/main.py --audit-local` to populate results, then "
            "regenerate this report.",
            "",
        ]
        return "\n".join(lines)

    lines += [
        "| Severity | Findings |",
        "| :--- | ---: |",
    ]
    for severity, bucket in grouped.items():
        badge = SEVERITY_BADGE.get(severity, "")
        lines.append(f"| {badge} {severity} | {len(bucket)} |")
    lines += [f"| **Total** | **{len(records)}** |", "", "---", ""]

    lines += ["## Findings by Severity", ""]
    for severity, bucket in grouped.items():
        badge = SEVERITY_BADGE.get(severity, "")
        lines += [
            f"### {badge} {severity} ({len(bucket)})",
            "",
            "| Target | Finding | Status | Detected |",
            "| :--- | :--- | :--- | :--- |",
        ]
        for record in bucket:
            lines.append(
                f"| {record.target_id} "
                f"| {_escape_cell(record.vulnerability_type)} "
                f"| {_escape_cell(record.status)} "
                f"| {_escape_cell(record.timestamp)} |"
            )
        lines.append("")

        for record in bucket:
            lines += [
                f"#### Target {record.target_id}: {record.vulnerability_type}",
                "",
                "**Remediation & Hardening**",
                ""
            ]
            
            kb = get_remediation(record.vulnerability_type)
            lines += [
                f"**Summary:** {kb['summary']}",
                "",
                "**Mitigation:**",
                kb['mitigation'],
                "",
                "**Example:**",
                kb['example'],
                "",
                "---",
                ""
            ]

    lines += [
        "---",
        "",
        "## Notes",
        "",
        "- Severities reflect the exposure observed at scan time. Services "
        "bound only to loopback are reported one level lower than the same "
        "service bound to an external interface.",
        "- This report covers findings recorded in the audit database. It is "
        "not a substitute for an authenticated configuration review.",
        "",
    ]
    return "\n".join(lines)


def generate_report(
    db_path: Path = DB_PATH,
    report_path: Path = REPORT_PATH,
    generated_at: datetime | None = None,
) -> tuple[Path, int]:
    """Build the compliance report and write it to disk.

    Args:
        db_path: SQLite database to read findings from.
        report_path: Markdown file to write.
        generated_at: Timestamp override, primarily for testing.

    Returns:
        A ``(report_path, finding_count)`` tuple.

    Raises:
        ReportError: If findings cannot be read or the report cannot be written.
    """
    records = fetch_scan_results(db_path)
    content = render_report(records, generated_at=generated_at, db_path=db_path)

    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"Could not write report to {report_path}: {exc}") from exc

    return (report_path, len(records))


def main() -> int:
    """Entry point for running this module directly."""
    try:
        path, count = generate_report()
    except ReportError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1

    print(f"[ok] Wrote {count} finding(s) to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
