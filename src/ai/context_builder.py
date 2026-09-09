"""Bounded context construction for local retrieval-assisted prompts."""

from __future__ import annotations

from src.ai.retriever import KnowledgeChunk
from src.models.finding import Finding
from src.models.ai_context import AIContext
from src.services.ai_explanation import sanitize_text

MAX_CONTEXT = 12000


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


def build_context(
    question: str,
    retrieved: list[KnowledgeChunk],
    finding: Finding | None = None,
    code_context: str | None = None,
    structured_context: AIContext | str | None = None,
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
    context = (
        "AUTHORITATIVE ANTIFINE DATA\n"
        f"Question: {sanitize_text(question, limit=4000)}\n"
        f"Finding:\n{finding_text}\n"
        f"Sanitized code context:\n{sanitize_text(code_context or '', limit=4000) or 'None supplied'}\n\n"
        f"SUPPLIED STRUCTURED CONTEXT (source: {context_source})\n"
        f"{supplied_context}\n\n"
        "RETRIEVED ANTIFINE KNOWLEDGE (reference context)\n"
        f"{sources}\n\n"
        "Use only supplied AntiFine facts for AntiFine-specific claims. "
        "If the retrieved context does not answer the question, say so."
    )
    return context[:MAX_CONTEXT]


def source_metadata(retrieved: list[KnowledgeChunk]) -> list[dict[str, str]]:
    return [{"title": chunk.title, "source": chunk.source} for chunk in retrieved]
