"""Normalized finding model for AntiFine scanners.

Every scanner, CLI, API endpoint, and exporter uses this single dataclass
so there is exactly one contract for describing a security finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    """A single security finding produced by any AntiFine scanner.

    Attributes:
        rule_name:    Human-readable title of the finding.
        severity:     One of CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL.
        filename:     Source file that was scanned (basename or relative path).
        frameworks:   Compliance framework cross-walk list (e.g. CIS, NIST).
        remediation:  Actionable fix / code snippet.
        description:  Extended human-readable explanation (optional).
    """

    rule_name: str
    severity: str
    filename: str
    frameworks: list[str] = field(default_factory=list)
    remediation: str = ""
    description: str = ""
