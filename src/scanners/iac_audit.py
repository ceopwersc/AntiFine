"""Infrastructure-as-Code (IaC) configuration auditor.

Parses Dockerfiles and Kubernetes YAML manifests to detect common configuration vulnerabilities.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.setup import DB_PATH, initialize_database  # noqa: E402

class IaCScannerError(RuntimeError):
    """Raised when the IaC audit fails."""

def analyze_dockerfile(content: str, filename: str) -> list[tuple[str, str]]:
    """Scan a Dockerfile for vulnerabilities."""
    findings = []
    lines = content.splitlines()
    has_user = False
    has_healthcheck = False
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
            
        if line.upper().startswith("USER "):
            has_user = True
            user = line.split(" ", 1)[1].strip()
            if user == "root" or user == "0":
                findings.append((f"Insecure Configuration (USER root) in {filename}", "MEDIUM"))
        elif line.upper().startswith("HEALTHCHECK "):
            has_healthcheck = True
            
    if not has_user:
        findings.append((f"Insecure Configuration (Missing USER) in {filename}", "MEDIUM"))
        
    if not has_healthcheck:
        findings.append((f"Insecure Configuration (Missing HEALTHCHECK) in {filename}", "LOW"))
        
    return findings

def analyze_kubernetes(content: str, filename: str) -> list[tuple[str, str]]:
    """Scan a Kubernetes YAML file for vulnerabilities using simple string matching."""
    findings = []
    
    # Very basic string matching for privileged and resources
    if "privileged: true" in content:
        findings.append((f"Insecure Configuration (privileged: true) in {filename}", "HIGH"))
        
    if "resources:" not in content or "limits:" not in content:
        findings.append((f"Insecure Configuration (Missing resource limits) in {filename}", "MEDIUM"))
        
    return findings

def scan_file(filepath: Path) -> list[tuple[str, str]]:
    """Scan a single file based on its name."""
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
    elif filename.endswith(".yaml") or filename.endswith(".yml"):
        return analyze_kubernetes(content, filename)
    
    return []

def run_iac_audit(target_path: str, db_path: Path = DB_PATH, target_id: int = 1, persist: bool = True) -> list[tuple[str, str]]:
    """Run the IaC audit against a file or directory."""
    path = Path(target_path)
    if not path.exists():
        raise IaCScannerError(f"Target path does not exist: {target_path}")
        
    all_findings = []
    
    if path.is_file():
        all_findings.extend(scan_file(path))
    elif path.is_dir():
        for filepath in path.rglob("*"):
            if filepath.is_file():
                if "Dockerfile" in filepath.name or filepath.name.endswith(".yaml") or filepath.name.endswith(".yml"):
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
            raise IaCScannerError(f"Could not write findings to {db_path}: {exc}") from exc
            
    return all_findings
