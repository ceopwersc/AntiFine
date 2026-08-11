"""Baseline local audit scanner.

Enumerates listening TCP/UDP sockets on the local host via
``scripts/port_mapper.sh``, flags services that are known to be plaintext
or historically insecure, and records findings to the audit database.

This scanner is strictly defensive: it inspects local socket state only and
initiates no traffic toward any host. Per the project coding standards it
depends on the storage layer but never on the reporting engine.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.setup import DB_PATH, initialize_database  # noqa: E402

SCRIPT_PATH: Path = PROJECT_ROOT / "scripts" / "port_mapper.sh"

#: Seconds to allow the enumeration script before giving up.
SCRIPT_TIMEOUT: int = 30

#: Severity ladder, most severe first. Used to downgrade loopback-only binds.
SEVERITY_LADDER: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

#: Ports that carry credentials or data in cleartext, or whose services have a
#: long history of weak defaults. Maps port -> (service name, base severity).
#: Base severity assumes the socket is reachable off-host; binds limited to
#: loopback are downgraded one step by :func:`assess_severity`.
INSECURE_PORTS: dict[int, tuple[str, str]] = {
    21: ("FTP", "HIGH"),               # credentials + payload in cleartext
    23: ("Telnet", "CRITICAL"),        # cleartext credentials to a shell
    25: ("SMTP", "MEDIUM"),            # cleartext unless STARTTLS enforced
    69: ("TFTP", "HIGH"),              # no authentication at all
    80: ("HTTP", "MEDIUM"),            # unencrypted transport
    110: ("POP3", "HIGH"),             # cleartext mailbox credentials
    111: ("rpcbind", "MEDIUM"),        # service enumeration surface
    135: ("MSRPC", "MEDIUM"),          # endpoint mapper, broad surface
    137: ("NetBIOS Name Service", "HIGH"),
    138: ("NetBIOS Datagram", "HIGH"),
    139: ("NetBIOS Session", "HIGH"),
    143: ("IMAP", "HIGH"),             # cleartext mailbox credentials
    161: ("SNMP", "HIGH"),             # community strings in cleartext
    389: ("LDAP", "MEDIUM"),           # cleartext directory binds
    445: ("SMB", "HIGH"),              # high-value file sharing surface
    512: ("rexec", "CRITICAL"),
    513: ("rlogin", "CRITICAL"),
    514: ("rsh/syslog", "CRITICAL"),
    1433: ("MSSQL", "MEDIUM"),
    3306: ("MySQL", "MEDIUM"),
    3389: ("RDP", "MEDIUM"),
    5432: ("PostgreSQL", "MEDIUM"),
    5900: ("VNC", "HIGH"),             # weak/absent auth by default
    6379: ("Redis", "HIGH"),           # unauthenticated by default
    11211: ("Memcached", "HIGH"),      # unauthenticated, amplification vector
    27017: ("MongoDB", "HIGH"),        # unauthenticated by default
}

#: Addresses that mean "reachable only from this host".
_LOOPBACK_LITERALS: frozenset[str] = frozenset({"::1", "[::1]", "localhost"})


class ScannerError(RuntimeError):
    """Raised when the baseline audit cannot complete."""


@dataclass(frozen=True)
class ListeningPort:
    """A single listening socket reported by the port mapper."""

    proto: str
    port: int
    address: str

    @property
    def is_loopback(self) -> bool:
        """True when the bind address is reachable only from this host."""
        addr = self.address.strip().lower()
        return addr.startswith("127.") or addr in _LOOPBACK_LITERALS


@dataclass(frozen=True)
class Finding:
    """An insecure service matched against a listening socket."""

    port: int
    proto: str
    address: str
    service: str
    severity: str

    @property
    def vulnerability_type(self) -> str:
        """Human-readable finding label stored in ``scan_results``."""
        return f"Insecure Service: {self.service} ({self.port}/{self.proto})"


def resolve_bash() -> str:
    """Locate a bash interpreter capable of running the port mapper.

    On Windows ``shutil.which("bash")`` commonly resolves to the WSL stub in
    ``System32``, which cannot execute a Windows-path script and reports a
    different network namespace than the host. Git Bash is preferred there.

    Returns:
        Path to a usable bash executable.

    Raises:
        ScannerError: If no suitable interpreter is found.
    """
    if os.name == "nt":
        candidates: list[str] = []
        env_bash = os.environ.get("ANTIFINE_BASH")
        if env_bash:
            candidates.append(env_bash)
        for root in (
            os.environ.get("ProgramFiles", r"C:\Program Files"),
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            os.environ.get("LOCALAPPDATA", ""),
        ):
            if root:
                candidates.append(str(Path(root) / "Git" / "bin" / "bash.exe"))
                candidates.append(str(Path(root) / "Git" / "usr" / "bin" / "bash.exe"))
        for candidate in candidates:
            if candidate and Path(candidate).is_file():
                return candidate

        found = shutil.which("bash")
        # Reject the WSL stub; it cannot run this script meaningfully.
        if found and "system32" not in found.lower():
            return found
        raise ScannerError(
            "No usable bash found. Install Git for Windows, or set ANTIFINE_BASH "
            "to a bash executable that can read Windows paths."
        )

    found = shutil.which("bash") or "/bin/bash"
    if not Path(found).is_file():
        raise ScannerError("No bash interpreter found on PATH.")
    return found


def run_port_mapper(script_path: Path = SCRIPT_PATH) -> str:
    """Execute the port mapper script and return its raw stdout.

    Args:
        script_path: Location of ``port_mapper.sh``.

    Returns:
        The script's stdout as text.

    Raises:
        ScannerError: If the script is missing, times out, or exits non-zero.
    """
    if not script_path.is_file():
        raise ScannerError(f"Port mapper script not found: {script_path}")

    bash = resolve_bash()

    try:
        completed = subprocess.run(
            [bash, str(script_path)],
            capture_output=True,
            text=True,
            timeout=SCRIPT_TIMEOUT,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ScannerError(f"Could not execute {bash}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(
            f"Port mapper timed out after {SCRIPT_TIMEOUT}s"
        ) from exc
    except OSError as exc:
        raise ScannerError(f"Failed to run port mapper: {exc}") from exc

    if completed.returncode != 0:
        detail = (completed.stderr or "").strip() or "no stderr output"
        raise ScannerError(
            f"Port mapper exited with code {completed.returncode}: {detail}"
        )

    return completed.stdout


def parse_port_records(output: str) -> list[ListeningPort]:
    """Parse port mapper output into structured records.

    Ignores comment lines (``#``), blank lines, and malformed rows so that a
    single unexpected line from a system tool cannot abort an audit.

    Args:
        output: Raw stdout from ``port_mapper.sh``.

    Returns:
        Parsed listening sockets, de-duplicated, in first-seen order.
    """
    records: list[ListeningPort] = []
    seen: set[tuple[str, int, str]] = set()

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        fields = line.split("\t")
        if len(fields) != 3:
            continue

        proto_raw, port_raw, address = (field.strip() for field in fields)
        proto = proto_raw.lower()
        if proto not in ("tcp", "udp"):
            continue

        try:
            port = int(port_raw)
        except ValueError:
            continue
        if not 1 <= port <= 65535:
            continue

        key = (proto, port, address)
        if key in seen:
            continue
        seen.add(key)
        records.append(ListeningPort(proto=proto, port=port, address=address))

    return records


def assess_severity(base_severity: str, is_loopback: bool) -> str:
    """Adjust a base severity for the socket's exposure.

    A service bound only to loopback is not reachable off-host, so it is
    downgraded one step rather than reported at full severity.
    """
    if not is_loopback:
        return base_severity
    try:
        index = SEVERITY_LADDER.index(base_severity)
    except ValueError:
        return base_severity
    return SEVERITY_LADDER[min(index + 1, len(SEVERITY_LADDER) - 1)]


def identify_insecure_ports(
    ports: list[ListeningPort],
    insecure_ports: dict[int, tuple[str, str]] | None = None,
) -> list[Finding]:
    """Cross-reference listening sockets against the insecure-port table.

    Args:
        ports: Listening sockets to evaluate.
        insecure_ports: Override table, primarily for testing.

    Returns:
        Findings sorted by severity (most severe first), then port.
    """
    table = INSECURE_PORTS if insecure_ports is None else insecure_ports
    findings: list[Finding] = []

    for entry in ports:
        match = table.get(entry.port)
        if match is None:
            continue
        service, base_severity = match
        findings.append(
            Finding(
                port=entry.port,
                proto=entry.proto,
                address=entry.address,
                service=service,
                severity=assess_severity(base_severity, entry.is_loopback),
            )
        )

    def sort_key(finding: Finding) -> tuple[int, int, str]:
        try:
            rank = SEVERITY_LADDER.index(finding.severity)
        except ValueError:
            rank = len(SEVERITY_LADDER)
        return (rank, finding.port, finding.proto)

    return sorted(findings, key=sort_key)


def record_findings(
    findings: list[Finding],
    db_path: Path = DB_PATH,
    target_id: int = 1,
    status: str = "OPEN",
) -> int:
    """Persist findings to the ``scan_results`` table.

    Args:
        findings: Findings to store.
        db_path: SQLite database file.
        target_id: Audit target the findings belong to.
        status: Lifecycle status recorded against each row.

    Returns:
        Number of rows inserted.

    Raises:
        ScannerError: If the database cannot be written.
    """
    if not findings:
        return 0

    rows = [
        (target_id, finding.vulnerability_type, finding.severity, status)
        for finding in findings
    ]

    try:
        initialize_database(db_path)
        with sqlite3.connect(db_path) as connection:
            connection.executemany(
                "INSERT INTO scan_results "
                "(target_id, vulnerability_type, severity, status) "
                "VALUES (?, ?, ?, ?)",
                rows,
            )
            connection.commit()
    except (sqlite3.Error, OSError) as exc:
        raise ScannerError(f"Could not write findings to {db_path}: {exc}") from exc

    return len(rows)


def run_baseline_audit(
    target_id: int = 1,
    db_path: Path = DB_PATH,
    script_path: Path = SCRIPT_PATH,
    persist: bool = True,
) -> list[Finding]:
    """Run the full baseline audit: enumerate, evaluate, and record.

    Args:
        target_id: Audit target the findings belong to.
        db_path: SQLite database file.
        script_path: Location of the port mapper script.
        persist: When False, skip the database write (dry run).

    Returns:
        The findings identified, most severe first.

    Raises:
        ScannerError: If enumeration or persistence fails.
    """
    output = run_port_mapper(script_path)
    ports = parse_port_records(output)
    findings = identify_insecure_ports(ports)

    if persist:
        record_findings(findings, db_path=db_path, target_id=target_id)

    return findings


def format_summary(findings: list[Finding], scanned: int) -> str:
    """Build a plain-text summary of an audit run."""
    lines = [f"Baseline local audit: {scanned} listening socket(s) enumerated."]
    if not findings:
        lines.append("No insecure or plaintext services detected.")
        return "\n".join(lines)

    lines.append(f"{len(findings)} insecure service(s) flagged:")
    for finding in findings:
        socket = ListeningPort(finding.proto, finding.port, finding.address)
        scope = "loopback only" if socket.is_loopback else "externally bound"
        lines.append(
            f"  [{finding.severity:<8}] {finding.service:<22} "
            f"{finding.port}/{finding.proto} on {finding.address} ({scope})"
        )
    return "\n".join(lines)
