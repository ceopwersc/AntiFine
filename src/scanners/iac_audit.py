"""Infrastructure-as-Code (IaC) configuration auditor.

Parses Dockerfiles, Kubernetes YAML manifests, and Terraform files to detect
common configuration vulnerabilities.  Each finding is returned as a plain
(vulnerability_type, severity) tuple so that run_iac_audit() remains
backwards-compatible with existing callers.

New callers that want enriched dicts (frameworks, remediation, etc.) should
use run_iac_audit_enriched() and post-process through compliance_mapper.
"""

from __future__ import annotations

import re
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.setup import DB_PATH, initialize_database  # noqa: E402

class IaCScannerError(RuntimeError):
    """Raised when the IaC audit fails."""


# ── Dockerfile analysis ──────────────────────────────────────────────────────

# Patterns for secret-like ENV key names
_SECRET_ENV_PATTERN = re.compile(
    r"^ENV\s+(\w*(PASSWORD|SECRET|TOKEN|KEY|APIKEY|API_KEY|CREDENTIAL|AUTH)\w*)\s+\S+",
    re.IGNORECASE,
)

# Pattern for unpinned / latest-tagged FROM
_UNPINNED_FROM_PATTERN = re.compile(
    r"^FROM\s+(?P<image>[^\s:@]+)(?::(?P<tag>[^\s@]+))?(?:@sha256:\S+)?",
    re.IGNORECASE,
)


def analyze_dockerfile(content: str, filename: str) -> list[tuple[str, str]]:
    """Scan a Dockerfile for security misconfigurations.

    Checks for:
    - USER root / missing USER directive             (CIS Docker 4.1)
    - Missing HEALTHCHECK                            (CIS Docker 4.6)
    - Hardcoded secrets in ENV instructions          (CIS Docker 4.7)
    - Unpinned or ':latest'-tagged base image        (CIS Docker 4.3)
    """
    findings: list[tuple[str, str]] = []
    lines = content.splitlines()

    has_user = False
    has_healthcheck = False

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        upper = line.upper()

        # ── USER directive ────────────────────────────────────────────────
        if upper.startswith("USER "):
            has_user = True
            user = line.split(" ", 1)[1].strip().lower()
            if user in ("root", "0"):
                findings.append(
                    (f"Insecure Configuration (USER root) in {filename}", "HIGH")
                )

        # ── HEALTHCHECK directive ─────────────────────────────────────────
        elif upper.startswith("HEALTHCHECK "):
            has_healthcheck = True

        # ── ENV hardcoded secret detection ────────────────────────────────
        elif upper.startswith("ENV "):
            if _SECRET_ENV_PATTERN.match(line):
                findings.append(
                    (f"Hardcoded Secret in ENV Instruction in {filename}", "CRITICAL")
                )

        # ── FROM unpinned image detection ─────────────────────────────────
        elif upper.startswith("FROM "):
            m = _UNPINNED_FROM_PATTERN.match(line)
            if m:
                tag = (m.group("tag") or "").lower()
                image = m.group("image").lower()
                # Skip scratch / local build-stage aliases
                if image not in ("scratch",) and not line.upper().startswith("FROM --"):
                    if tag in ("latest", "") or tag == "":
                        findings.append(
                            (f"Unpinned Image Tag (latest or missing) in {filename}", "MEDIUM")
                        )

    # ── Post-line checks ──────────────────────────────────────────────────
    if not has_user:
        findings.append(
            (f"Insecure Configuration (Missing USER) in {filename}", "MEDIUM")
        )

    if not has_healthcheck:
        findings.append(
            (f"Insecure Configuration (Missing HEALTHCHECK) in {filename}", "LOW")
        )

    return findings


# ── Kubernetes YAML analysis ─────────────────────────────────────────────────

def analyze_kubernetes(content: str, filename: str) -> list[tuple[str, str]]:
    """Scan a Kubernetes YAML file for security misconfigurations."""
    findings: list[tuple[str, str]] = []

    if "privileged: true" in content:
        findings.append(
            (f"Insecure Configuration (privileged: true) in {filename}", "HIGH")
        )

    if "resources:" not in content or "limits:" not in content:
        findings.append(
            (f"Insecure Configuration (Missing resource limits) in {filename}", "MEDIUM")
        )

    return findings


# ── Terraform analysis ───────────────────────────────────────────────────────

def analyze_terraform(content: str, filename: str) -> list[tuple[str, str]]:
    """Scan a Terraform file for security misconfigurations."""
    findings: list[tuple[str, str]] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line.startswith("#") or line.startswith("//"):
            continue
        if re.search(r'acl\s*=\s*"(public-read|public-read-write)"', line):
            findings.append(
                (f"Insecure S3 Bucket ACL (Public) in {filename}", "HIGH")
            )

    return findings


# ── File dispatcher ──────────────────────────────────────────────────────────

def scan_file(filepath: Path) -> list[tuple[str, str]]:
    """Scan a single file based on its name/extension."""
    try:
        content = filepath.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            content = filepath.read_text(encoding="utf-16")
        except UnicodeDecodeError:
            content = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"[warning] Could not read {filepath}: {exc}", file=sys.stderr)
        return []

    filename = filepath.name
    if "Dockerfile" in filename:
        return analyze_dockerfile(content, filename)
    elif filename.endswith((".yaml", ".yml")):
        return analyze_kubernetes(content, filename)
    elif filename.endswith(".tf"):
        return analyze_terraform(content, filename)

    return []


# ── Public API ───────────────────────────────────────────────────────────────

def run_iac_audit(
    target_path: str,
    db_path: Path = DB_PATH,
    target_id: int = 1,
    persist: bool = True,
) -> list[tuple[str, str]]:
    """Run the IaC audit against a file or directory.

    Returns a list of (vulnerability_type, severity) tuples.
    This signature is preserved for backwards compatibility with existing callers.
    The server-side handler uses persist=False and enriches findings itself.
    """
    path = Path(target_path)
    if not path.exists():
        raise IaCScannerError(f"Target path does not exist: {target_path}")

    all_findings: list[tuple[str, str]] = []

    if path.is_file():
        all_findings.extend(scan_file(path))
    elif path.is_dir():
        for filepath in path.rglob("*"):
            if filepath.is_file() and (
                "Dockerfile" in filepath.name
                or filepath.name.endswith((".yaml", ".yml", ".tf"))
            ):
                all_findings.extend(scan_file(filepath))

    if persist and all_findings:
        rows = [
            (target_id, vuln_type, severity, "OPEN")
            for vuln_type, severity in all_findings
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
            raise IaCScannerError(
                f"Could not write findings to {db_path}: {exc}"
            ) from exc

    return all_findings
