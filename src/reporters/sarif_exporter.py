"""SARIF Generator for AntiFine IaC Scanner."""

from __future__ import annotations
from typing import Any
import hashlib

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
