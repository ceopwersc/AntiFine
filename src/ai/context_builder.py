"""Bounded context construction for local retrieval-assisted prompts."""

from __future__ import annotations

from src.ai.retriever import KnowledgeChunk
from src.models.finding import Finding
from src.services.ai_explanation import sanitize_text

MAX_CONTEXT = 12000


def build_context(
    question: str,
    retrieved: list[KnowledgeChunk],
    finding: Finding | None = None,
    code_context: str | None = None,
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
    context = (
        "AUTHORITATIVE ANTIFINE DATA\n"
        f"Question: {sanitize_text(question, limit=4000)}\n"
        f"Finding:\n{finding_text}\n"
        f"Sanitized code context:\n{sanitize_text(code_context or '', limit=4000) or 'None supplied'}\n\n"
        "RETRIEVED ANTIFINE KNOWLEDGE (reference context)\n"
        f"{sources}\n\n"
        "Use only supplied AntiFine facts for AntiFine-specific claims. "
        "If the retrieved context does not answer the question, say so."
    )
    return context[:MAX_CONTEXT]


def source_metadata(retrieved: list[KnowledgeChunk]) -> list[dict[str, str]]:
    return [{"title": chunk.title, "source": chunk.source} for chunk in retrieved]
