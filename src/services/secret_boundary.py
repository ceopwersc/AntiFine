"""Conservative redaction for untrusted text crossing persistence or AI boundaries."""

from __future__ import annotations

import math
import re
import unicodedata

_KNOWN_PATTERNS = (
    (re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED AWS KEY]"),
    (re.compile(r"\bghp_[A-Za-z0-9_]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[A-Za-z0-9]*\b"), "[REDACTED SLACK TOKEN]"),
    (re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.I | re.S), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"(?i)\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)(\s*[:=]\s*)([\"']?)(?:\[[^\]]+\]|[^\s\"']+)\2"), r"\1[REDACTED CREDENTIAL]"),
)
_CREDENTIAL_CONTEXT = re.compile(r"(?i)(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|credential)")
_TOKEN = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z0-9+/=_-]{24,}(?![A-Za-z0-9_])")


def _entropy(value: str) -> float:
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _redact_entropy(match: re.Match[str], text: str) -> str:
    value = match.group(0)
    if _entropy(value) < 4.2:
        return value
    start, end = match.span()
    context = text[max(0, start - 48):min(len(text), end + 48)]
    # Long, dense credentials are unsafe even without a conventional key label.
    if _CREDENTIAL_CONTEXT.search(context) or (len(value) >= 32 and _entropy(value) >= 4.65):
        return "[REDACTED HIGH-ENTROPY SECRET]"
    return value


def sanitize_text(value: object, *, limit: int | None = None) -> str:
    """Remove credentials, control characters, and conservative secret-like blobs."""
    text = "" if value is None else unicodedata.normalize("NFKC", str(value))
    text = "".join(char for char in text if char in "\n\r\t" or unicodedata.category(char)[0] != "C")
    for pattern, replacement in _KNOWN_PATTERNS:
        text = pattern.sub(replacement, text)
    text = _TOKEN.sub(lambda match: _redact_entropy(match, text), text)
    if limit is not None and len(text) > limit:
        text = text[:limit] + "\n[TRUNCATED]"
    return text


def sanitize_path(value: object, *, limit: int = 512) -> str:
    """Keep useful relative path shape while removing control data and secrets."""
    return sanitize_text(value, limit=limit).replace("\x00", "")
