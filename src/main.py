"""AntiFine orchestrator.

Command-line entry point that wires together database initialization and
(eventually) the audit scanners. Run with ``--help`` for usage.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

# Running this file directly puts ``src/`` on sys.path rather than the
# project root, so sibling packages such as ``database`` are added here.
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.setup import initialize_database  # noqa: E402  (needs sys.path above)
from src.reporting.generate import ReportError, generate_report  # noqa: E402
from src.scanners.baseline_audit import (  # noqa: E402
    ScannerError,
    format_summary,
    identify_insecure_ports,
    parse_port_records,
    record_findings,
    run_port_mapper,
)


def build_parser() -> argparse.ArgumentParser:
    """Construct the AntiFine CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="antifine",
        description="AntiFine: automated security and compliance auditing framework.",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Initialize the local SQLite audit database.",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Run the configured audit scanners (not yet implemented).",
    )
    parser.add_argument(
        "--audit-local",
        action="store_true",
        help="Run the baseline local audit: map listening ports and flag "
             "insecure or plaintext services.",
    )
    parser.add_argument(
        "--target-id",
        type=int,
        default=1,
        help="Audit target id to record findings against (default: 1).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report findings without writing them to the database.",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate the Markdown compliance report from recorded findings.",
    )
    return parser


def run_init() -> int:
    """Initialize the audit database, reporting failures to stderr."""
    try:
        path = initialize_database()
    except (sqlite3.Error, OSError) as exc:
        print(f"[error] Database initialization failed: {exc}", file=sys.stderr)
        return 1

    print(f"[ok] Database initialized at {path}")
    return 0


def run_audit() -> int:
    """Placeholder for the full audit pipeline."""
    print("[info] Full audit pipeline is not implemented yet. "
          "Use --audit-local to run the baseline scanner.")
    return 0


def run_audit_local(target_id: int = 1, dry_run: bool = False) -> int:
    """Run the baseline local audit and report its findings."""
    try:
        output = run_port_mapper()
        ports = parse_port_records(output)
        findings = identify_insecure_ports(ports)
        if not dry_run:
            recorded = record_findings(findings, target_id=target_id)
        else:
            recorded = 0
    except ScannerError as exc:
        print(f"[error] Baseline audit failed: {exc}", file=sys.stderr)
        return 1

    print(format_summary(findings, scanned=len(ports)))
    if dry_run:
        print("[info] Dry run: no rows written to the database.")
    else:
        print(f"[ok] Recorded {recorded} finding(s) against target_id={target_id}.")
    return 0


def run_report() -> int:
    """Generate the Markdown compliance report."""
    try:
        path, count = generate_report()
    except ReportError as exc:
        print(f"[error] Report generation failed: {exc}", file=sys.stderr)
        return 1

    print(f"[ok] Wrote {count} finding(s) to {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch to the requested action."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not (args.init or args.audit or args.audit_local or args.report):
        parser.print_help()
        return 0

    exit_code = 0
    if args.init:
        exit_code = run_init()
        if exit_code != 0:
            return exit_code
    if args.audit_local:
        exit_code = run_audit_local(target_id=args.target_id, dry_run=args.dry_run)
        if exit_code != 0:
            return exit_code
    if args.audit:
        exit_code = run_audit()
        if exit_code != 0:
            return exit_code
    if args.report:
        exit_code = run_report()

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
