"""SARIF Exporter.

Serializes audit findings into SARIF 2.1.0 JSON format for CI/CD integration.
"""

from __future__ import annotations

import json
import sys
from urllib.parse import quote
from typing import Any
from pathlib import Path

from database.setup import DB_PATH
from src.reporting.generate import fetch_scan_results, ReportError
from src.services.secret_boundary import sanitize_path, sanitize_text

SARIF_LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
    'INFORMATIONAL': 'note',
    "UNCLASSIFIED": "note"
}

def export_to_sarif(output_file: str, db_path: Path = DB_PATH) -> int:
    """Extract scan results and write them as SARIF 2.1.0 to output_file."""
    try:
        records = fetch_scan_results(db_path)
    except ReportError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1
        
    sarif_data = generate_sarif([
        {
            "vulnerability_type": record.vulnerability_type,
            "severity": record.normalized_severity,
            "frameworks": list(record.frameworks),
            "description": record.description_text,
            "remediation": record.remediation,
            "target": record.target_path,
            "rule_id": record.rule_id, "id": record.finding_id, "line": record.source_line, "column": record.source_column,
            "end_line": record.end_line, "scan_id": record.scan_id, "resource": record.resource,
            'resource_label': record.resource_label, 'family': record.family, 'evidence': record.evidence,
        }
        for record in records
    ])
    
    try:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
        print(f"[ok] Wrote {len(records)} finding(s) to SARIF report at {output_file}")
        return 0
    except OSError as exc:
        print(f"[error] Could not write SARIF report to {output_file}: {exc}", file=sys.stderr)
        return 1

def generate_sarif(findings: list[dict[str, Any]], *, coverage: list | None = None, remediations: list | None = None) -> dict[str, Any]:
    """Generate a SARIF JSON object conforming to OASIS SARIF v2.1.0."""
    rules = []
    results = []
    
    seen_rules = set()
    
    severity_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFORMATIONAL": "note"
    }

    for finding in findings:
        vuln_type = sanitize_text(finding.get("vulnerability_type", "Unknown Vulnerability"), limit=1000)
        severity = finding.get("severity", "LOW").upper()
        level = severity_map.get(severity, "note")
        frameworks = finding.get("frameworks")
        if frameworks is None:
            frameworks = finding.get("compliance_frameworks", [])
        frameworks = [sanitize_text(v) for v in frameworks or []]
        remediation = sanitize_text(finding.get("remediation", ""), limit=4000)
        description = sanitize_text(finding.get("description") or vuln_type, limit=4000)
        
        # Generate a stable rule ID based on the vulnerability type hash
        rule_id = finding.get("rule_id") or "legacy.unknown"
        
        if rule_id not in seen_rules:
            rules.append({
                "id": rule_id,
                "shortDescription": {"text": description},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "frameworks": frameworks,
                    "tags": frameworks
                }
            })
            seen_rules.add(rule_id)
            
        target = sanitize_path(finding.get("target", "project-root"))
        
        results.append({
            "ruleId": rule_id,
            "message": {"text": description},
            "level": level,
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": quote(target.replace("\\", "/"), safe="/:")
                        },
                        "region": {"startLine": max(1, finding.get("line", 1)), "startColumn": max(1, finding.get("column", 1)), "endLine": max(finding.get("line", 1), finding.get("end_line", 1))}
                    }
                }
            ],
            "properties": {
                "frameworks": frameworks,
                "remediation": remediation,
                "finding_id": finding.get("id", ""), "scan_id": finding.get("scan_id", ""), "resource": finding.get("resource", "unknown"),
                'resource_label': sanitize_text(finding.get('resource_label', 'unknown')),
                'evidence': sanitize_text(finding.get('evidence', '')), 'family': finding.get('family', 'unknown')
            }
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AntiFine IaC Scanner",
                        "semanticVersion": "1.0.0",
                        "rules": rules
                    }
                },
                "results": results,
                "properties": {"scan_coverage": coverage or [], 'remediation_history': remediations or [], "compliance_status": "Not evaluated"}
            }
        ]
    }
