"""Safe prompt construction for explanations of deterministic findings."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict

from src.models.finding import Finding

MAX_CODE_CONTEXT = 4000

_SECRET_PATTERNS = (
    (re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED AWS KEY]"),
    (re.compile(r"\bghp_[A-Za-z0-9_]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[A-Za-z0-9]*\b"), "[REDACTED SLACK TOKEN]"),
    (
        re.compile(
            r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
            re.IGNORECASE | re.DOTALL,
        ),
        "[REDACTED PRIVATE KEY]",
    ),
    (
        re.compile(
            r"(?i)\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)"
            r"(\s*[:=]\s*)([\"']?)[^\s\"']+\2"
        ),
        r"\1[REDACTED CREDENTIAL]",
    ),
)

SYSTEM_PROMPT = """You are the AntiFine Security Assistant.

AntiFine is a deterministic local Infrastructure-as-Code security scanner.
The finding metadata supplied by AntiFine is authoritative. Do not invent
facts, change severity, add compliance mappings, or claim that a file was
modified or a vulnerability was fixed. Distinguish detected facts from
general recommendations. You are explaining a finding, not performing
remediation, creating a patch, executing commands, or deciding whether a fix
is safe.

Respond with exactly these concise technical sections:
What was detected
Why it matters
Compliance impact
Recommended action
Developer takeaway

Only discuss frameworks explicitly supplied by AntiFine. Use the remediation
guidance supplied by AntiFine and do not produce replacement code patches.
"""


def sanitize_text(value: str, *, limit: int | None = None) -> str:
    """Redact common credentials and optionally truncate untrusted text."""
    sanitized = value
    for pattern, replacement in _SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    if limit is not None and len(sanitized) > limit:
        sanitized = sanitized[:limit] + "\n[TRUNCATED]"
    return sanitized


def finding_id(finding: Finding) -> str:
    """Return a stable identifier derived from non-secret finding metadata."""
    metadata = "|".join(
        (
            finding.rule_name,
            finding.severity,
            finding.filename,
            ",".join(finding.frameworks),
        )
    )
    return hashlib.sha256(metadata.encode("utf-8")).hexdigest()[:16]


def build_explanation_prompt(finding: Finding, code_context: str | None) -> str:
    """Build a bounded prompt containing only sanitized deterministic data."""
    data = asdict(finding)
    frameworks = ", ".join(sanitize_text(item) for item in finding.frameworks) or "None supplied"
    context = sanitize_text(code_context or "", limit=MAX_CODE_CONTEXT) or "None supplied"
    return (
        "Explain this existing AntiFine finding. Treat every supplied field as "
        "deterministic fact; do not infer a different rule or severity.\n\n"
        f"Rule: {sanitize_text(data['rule_name'])}\n"
        f"Severity: {sanitize_text(data['severity'])}\n"
        f"File: {sanitize_text(data['filename'])}\n"
        f"Frameworks: {frameworks}\n"
        f"Description: {sanitize_text(data['description'])}\n"
        f"AntiFine remediation guidance: {sanitize_text(data['remediation'])}\n"
        f"Sanitized code context:\n{context}"
    )
