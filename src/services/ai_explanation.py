"""Safe prompt construction for explanations of deterministic findings."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict

from src.models.finding import Finding
from src.ai.knowledge_service import RuleMetadata

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
Use this evidence hierarchy: (1) deterministic AntiFine finding/rule data and
framework mappings, (2) retrieved AntiFine documentation, (3) supplied
sanitized context, and (4) general security knowledge. Only the first three
may be described as AntiFine-specific facts; label the last as general
guidance.

Do not invent facts, rule IDs, severity, compliance mappings, or controls.
"Compliance impact" means explain only mappings supplied by AntiFine. Do not infer cross-framework equivalence or add PCI-DSS, NIST, ISO 27001, HIPAA, GDPR,
SOC 2, or any other standard unless explicitly supplied. If unavailable, say:
"I don't have enough AntiFine-specific information to determine that." Never
claim that a file was modified or a vulnerability was fixed. You are
explaining a finding, not performing remediation, creating a patch, executing
commands, or deciding whether a fix is safe.

Respond with exactly these concise technical sections:
What was detected
Why it matters
Compliance impact
Recommended action
Developer takeaway

Only discuss frameworks explicitly supplied by AntiFine. Under Developer
takeaway, distinguish "AntiFine-specific verification" from "General security verification" when needed. Use supplied remediation guidance and do not
produce replacement code patches.
Never invent a rule ID, severity, framework, or remediation. Never claim a
rule exists unless AntiFine supplied it in the rule context. Never generate a
security verdict independently of AntiFine. Clearly label general security
knowledge as general guidance rather than AntiFine-detected fact.
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


def build_explanation_prompt(
    finding: Finding,
    code_context: str | None,
    rule: RuleMetadata | None = None,
) -> str:
    """Build a bounded prompt containing only sanitized deterministic data."""
    data = asdict(finding)
    frameworks = ", ".join(sanitize_text(item) for item in finding.frameworks) or "None supplied"
    context = sanitize_text(code_context or "", limit=MAX_CODE_CONTEXT) or "None supplied"
    rule_context = rule.as_prompt_context() if rule else "No matching AntiFine rule metadata supplied."
    return (
        "Explain this existing AntiFine finding. Treat every supplied field as "
        "deterministic fact; do not infer a different rule or severity.\n\n"
        f"AntiFine rule context:\n{rule_context}\n\n"
        f"Rule: {sanitize_text(data['rule_name'])}\n"
        f"Severity: {sanitize_text(data['severity'])}\n"
        f"File: {sanitize_text(data['filename'])}\n"
        f"Frameworks: {frameworks}\n"
        f"Description: {sanitize_text(data['description'])}\n"
        f"AntiFine remediation guidance: {sanitize_text(data['remediation'])}\n"
        f"Sanitized code context:\n{context}"
    )
