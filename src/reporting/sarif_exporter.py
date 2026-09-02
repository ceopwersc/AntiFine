"""SARIF Exporter.

Serializes audit findings into SARIF 2.1.0 JSON format for CI/CD integration.
"""

from __future__ import annotations

import json
import sys
import hashlib
from typing import Any
from pathlib import Path

from database.setup import DB_PATH
from src.reporting.generate import fetch_scan_results, ReportError

SARIF_LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
    "UNCLASSIFIED": "note"
}

def export_to_sarif(output_file: str, db_path: Path = DB_PATH) -> int:
    """Extract scan results and write them as SARIF 2.1.0 to output_file."""
    try:
        records = fetch_scan_results(db_path)
    except ReportError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1
        
    results = []
    for record in records:
        level = SARIF_LEVEL_MAP.get(record.normalized_severity, "note")
        results.append({
            "ruleId": f"AF-TARGET-{record.target_id}",
            "message": {
                "text": record.vulnerability_type
            },
            "level": level
        })
        
    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AntiFine",
                        "informationUri": "https://github.com/ceopwersc/AntiFine",
                        "version": "1.0.0"
                    }
                },
                "results": results
            }
        ]
    }
    
    try:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
        print(f"[ok] Wrote {len(results)} finding(s) to SARIF report at {output_file}")
        return 0
    except OSError as exc:
        print(f"[error] Could not write SARIF report to {output_file}: {exc}", file=sys.stderr)
        return 1

def generate_sarif(findings: list[dict[str, Any]]) -> dict[str, Any]:
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
        vuln_type = finding.get("vulnerability_type", "Unknown Vulnerability")
        severity = finding.get("severity", "LOW").upper()
        level = severity_map.get(severity, "note")
        
        # Generate a stable rule ID based on the vulnerability type hash
        rule_hash = hashlib.md5(vuln_type.encode('utf-8')).hexdigest()[:6]
        rule_id = f"AF-IAC-{rule_hash.upper()}"
        
        if rule_id not in seen_rules:
            rules.append({
                "id": rule_id,
                "shortDescription": {"text": vuln_type},
                "defaultConfiguration": {"level": level}
            })
            seen_rules.add(rule_id)
            
        target = finding.get("target", "project-root")
        
        results.append({
            "ruleId": rule_id,
            "message": {"text": vuln_type},
            "level": level,
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": target
                        }
                    }
                }
            ]
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
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
                "results": results
            }
        ]
    }
