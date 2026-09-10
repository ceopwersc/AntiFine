"""Bounded context construction for local retrieval-assisted prompts."""

from __future__ import annotations

import re

from src.ai.retriever import KnowledgeChunk
from src.models.finding import Finding
from src.models.ai_context import AIContext, AIMessage
from src.services.ai_explanation import sanitize_text

MAX_CONTEXT = 12000
MAX_MESSAGES = 10
MAX_MESSAGE_CHARS = 1200
_FRAMEWORK_PATTERNS = {
    "PCI-DSS": re.compile(r"(?i)\bPCI[\s-]*DSS\b"),
    "NIST": re.compile(r"(?i)\bNIST\b"),
    "ISO 27001": re.compile(r"(?i)\bISO[\s-]*27001\b"),
    "HIPAA": re.compile(r"(?i)\bHIPAA\b"),
    "GDPR": re.compile(r"(?i)\bGDPR\b"),
    "SOC 2": re.compile(r"(?i)\bSOC[\s-]*2\b"),
}
_FRAMEWORK_EXPRESSIONS = {
    "PCI-DSS": r"PCI[\s-]*DSS",
    "NIST": r"NIST",
    "ISO 27001": r"ISO[\s-]*27001",
    "HIPAA": r"HIPAA",
    "GDPR": r"GDPR",
    "SOC 2": r"SOC[\s-]*2",
}
_GENERIC_COMPLIANCE_TERMS = {"security", "compliance", "impact", "this", "it"}


def _value(value: object, limit: int = 1200) -> str:
    """Render one known context value without stringifying arbitrary objects."""
    if value is None:
        return ""
    return sanitize_text(str(value), limit=limit)


def _finding_context_lines(finding: object) -> list[str]:
    fields = (
        ("Rule ID", getattr(finding, "rule_id", None)),
        ("Title", getattr(finding, "title", None)),
        ("Severity", getattr(finding, "severity", None)),
        ("Technology", getattr(finding, "technology", None)),
        ("File", getattr(finding, "file", None)),
        ("Line", getattr(finding, "line", None)),
        ("Status", getattr(finding, "status", None)),
        ("Description", getattr(finding, "description", None)),
        ("Remediation", getattr(finding, "remediation", None)),
    )
    lines = [f"{label}: {_value(value)}" for label, value in fields if value is not None]
    frameworks = getattr(finding, "frameworks", None) or []
    if frameworks:
        lines.append("Frameworks: " + ", ".join(_value(item) for item in frameworks))
    return lines


def format_ai_context(context: AIContext | str | None) -> tuple[str, str]:
    """Convert typed assistant context to bounded, sanitized prompt text."""
    if context is None:
        return "general", "None supplied"
    if isinstance(context, str):
        return "general", sanitize_text(context, limit=4000) or "None supplied"

    sections = [f"Source: {_value(context.source)}"]
    if context.selected_file:
        sections.append(f"Selected file: {_value(context.selected_file)}")
    if context.finding:
        sections.append("Finding:\n" + "\n".join(_finding_context_lines(context.finding)))
    if context.scan:
        sections.append(
            "Scan:\n"
            + "\n".join(
                filter(
                    None,
                    [
                        f"Target path: {_value(context.scan.target_path)}",
                        f"Scan type: {_value(context.scan.scan_type)}",
                        (
                            "Findings:\n"
                            + "\n".join(
                                "\n".join(_finding_context_lines(item))
                                for item in context.scan.findings
                            )
                        )
                        if context.scan.findings
                        else "",
                    ],
                )
            )
        )
    if context.compliance:
        sections.append(
            "Compliance:\n"
            + "\n".join(
                filter(
                    None,
                    [
                        f"Framework: {_value(context.compliance.framework)}",
                        f"Controls: {', '.join(_value(item) for item in context.compliance.controls)}",
                        f"Status: {_value(context.compliance.status)}",
                    ],
                )
            )
        )
    if context.remediation:
        sections.append(
            "Remediation:\n"
            + "\n".join(
                filter(
                    None,
                    [
                        f"Finding ID: {_value(context.remediation.finding_id)}",
                        f"Rule ID: {_value(context.remediation.rule_id)}",
                        f"Action: {_value(context.remediation.action)}",
                        f"Path: {_value(context.remediation.path)}",
                        f"Status: {_value(context.remediation.status)}",
                        f"Diff:\n{_value(context.remediation.diff, 3000)}",
                    ],
                )
            )
        )
    return context.source, "\n".join(sections)[:5000] or "None supplied"


def requested_unmapped_frameworks(
    question: str,
    context: AIContext | str | None,
    retrieved: list[KnowledgeChunk],
) -> list[str]:
    """Return named frameworks that are not authoritative for a finding."""
    if not isinstance(context, AIContext) or context.source != "finding" or not context.finding:
        return []
    authoritative = " ".join(context.finding.frameworks).lower()
    retrieved_frameworks = " ".join(
        framework for chunk in retrieved for framework in chunk.frameworks
    ).lower()
    return [
        name for name, pattern in _FRAMEWORK_PATTERNS.items()
        if pattern.search(question)
        and name.lower() not in authoritative
        and name.lower() not in retrieved_frameworks
    ]


def requested_framework(question: str) -> str | None:
    """Extract a framework named in a compliance-oriented question."""
    for name, pattern in _FRAMEWORK_PATTERNS.items():
        if pattern.search(question):
            return name
    match = re.search(
        r"(?i)\b(?:affect|impact|map(?:ped)? to|align(?:ed)? with)\s+"
        r"([A-Za-z][A-Za-z0-9 ._-]{1,40}?)(?:\?|$)",
        question.strip(),
    )
    if not match:
        return None
    candidate = match.group(1).strip(" ._-")
    return None if candidate.lower() in _GENERIC_COMPLIANCE_TERMS else candidate


def determine_compliance_status(
    question: str,
    context: AIContext | str | None,
    retrieved: list[KnowledgeChunk],
) -> tuple[str, str | None]:
    """Classify compliance evidence for a contextual finding question."""
    if not isinstance(context, AIContext) or context.source != "finding" or not context.finding:
        return "unknown", requested_framework(question)
    requested = requested_framework(question)
    if not requested:
        return "unknown", None
    authoritative = " ".join(context.finding.frameworks).lower()
    retrieved_frameworks = " ".join(
        framework for chunk in retrieved for framework in chunk.frameworks
    ).lower()
    if requested.lower() in authoritative or requested.lower() in retrieved_frameworks:
        return "mapped", requested
    return "not_mapped", requested


def unmapped_compliance_fallback(
    question: str,
    context: AIContext | str | None,
    retrieved: list[KnowledgeChunk],
) -> str | None:
    """Return a safe deterministic answer for an unmapped framework question."""
    status, framework = determine_compliance_status(question, context, retrieved)
    if status != "not_mapped" or not isinstance(context, AIContext) or not context.finding:
        return None
    mappings = ", ".join(context.finding.frameworks) or "no framework mappings"
    rule_id = context.finding.rule_id or "this finding"
    return (
        f"AntiFine maps {rule_id} to {mappings}. No {framework} mapping is "
        "supplied for this finding, so AntiFine cannot determine its impact "
        "from the available evidence."
    )


def sanitize_unmapped_compliance_claims(
    answer: str,
    question: str,
    context: AIContext | str | None,
    retrieved: list[KnowledgeChunk],
) -> str:
    """Remove framework control identifiers when the finding has no mapping."""
    unmapped = requested_unmapped_frameworks(question, context, retrieved)
    if not unmapped:
        return answer
    sanitized = answer
    for framework in unmapped:
        expression = _FRAMEWORK_EXPRESSIONS[framework]
        sanitized = re.sub(
            rf"(?i)\b{expression}\b(?:\s+(?:v?\d+(?:\.\d+)?))?"
            rf"(?:\s+(?:Requirement|Req(?:uirement)?|Control))?\s+\d+(?:\.\d+){{1,3}}\b",
            framework,
            sanitized,
        )
    note = "; ".join(f"AntiFine has no supplied mapping for {framework}" for framework in unmapped)
    return f"{sanitized.rstrip()}\n\n{note}."


def build_context(
    question: str,
    retrieved: list[KnowledgeChunk],
    finding: Finding | None = None,
    code_context: str | None = None,
    structured_context: AIContext | str | None = None,
    messages: list[AIMessage] | None = None,
) -> str:
    """Separate authoritative AntiFine data from general retrieved context."""
    sources = "\n\n".join(
        f"[Source: {chunk.source} | {chunk.title}]\n{sanitize_text(chunk.text, limit=3500)}"
        for chunk in retrieved
    ) or "No matching AntiFine knowledge was retrieved."
    finding_text = "None supplied"
    if finding is not None:
        finding_text = (
            f"Rule: {sanitize_text(finding.rule_name)}\n"
            f"Severity: {sanitize_text(finding.severity)}\n"
            f"File: {sanitize_text(finding.filename)}\n"
            f"Frameworks: {', '.join(sanitize_text(item) for item in finding.frameworks) or 'None supplied'}\n"
            f"Description: {sanitize_text(finding.description)}\n"
            f"Remediation: {sanitize_text(finding.remediation)}"
        )
    context_source, supplied_context = format_ai_context(structured_context)
    authoritative_compliance = "None supplied"
    if isinstance(structured_context, AIContext) and structured_context.source == "finding":
        finding_context = structured_context.finding
        if finding_context and finding_context.frameworks:
            authoritative_compliance = ", ".join(
                _value(item) for item in finding_context.frameworks
            )
        elif finding_context:
            authoritative_compliance = "No framework mappings supplied for this finding"
    compliance_status, compliance_framework = determine_compliance_status(
        question,
        structured_context,
        retrieved,
    )
    history = messages[-MAX_MESSAGES:] if messages else []
    history_text = "\n".join(
        f"{message.role.upper()}: {sanitize_text(message.content, limit=MAX_MESSAGE_CHARS)}"
        for message in history
    ) or "No previous conversation."
    context = (
        "AUTHORITATIVE ANTIFINE DATA\n"
        f"Finding:\n{finding_text}\n"
        f"Sanitized code context:\n{sanitize_text(code_context or '', limit=4000) or 'None supplied'}\n\n"
        f"SUPPLIED STRUCTURED CONTEXT (source: {context_source})\n"
        f"{supplied_context}\n\n"
        "AUTHORITATIVE FINDING COMPLIANCE (allowlist)\n"
        f"{authoritative_compliance}\n"
        f"Compliance status: {compliance_status}\n"
        f"Requested framework: {compliance_framework or 'None detected'}\n"
        "General compliance knowledge is not evidence of a mapping for this "
        "finding. If a requested framework is absent above, say AntiFine has "
        "no supplied mapping for that framework and do not name a control.\n\n"
        "BOUNDED CONVERSATION HISTORY (prior turns; not authoritative)\n"
        f"{history_text}\n\n"
        f"CURRENT QUESTION\n{sanitize_text(question, limit=4000)}\n\n"
        "RETRIEVED ANTIFINE KNOWLEDGE (reference context)\n"
        f"{sources}\n\n"
        "Use only supplied AntiFine facts for AntiFine-specific claims. "
        "Compliance mappings are an allowlist: do not add or infer another "
        "framework or control. If the retrieved context does not answer the "
        "question, say: \"I don't have enough AntiFine-specific information "
        "to determine that.\" General security guidance must be labelled "
        "general guidance.\n"
        "If compliance status is not_mapped, do not provide framework-specific "
        "requirements, controls, identifiers, names, interpretations, or "
        "recommendations. State only that AntiFine has no supplied mapping; "
        "generic security guidance must not mention that framework."
    )
    return context[:MAX_CONTEXT]


def source_metadata(retrieved: list[KnowledgeChunk]) -> list[dict[str, str]]:
    return [{"title": chunk.title, "source": chunk.source} for chunk in retrieved]
