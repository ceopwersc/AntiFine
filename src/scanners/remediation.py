"""Deterministic, backup-first remediation for supported IaC findings."""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path


class RemediationError(RuntimeError):
    """Raised when a finding cannot be safely remediated."""


@dataclass(frozen=True)
class RemediationResult:
    """Details about one successful in-place remediation."""

    path: Path
    backup_path: Path
    changed: bool
    action: str


def _replace_once(content: str, pattern: str, replacement: str, action: str) -> tuple[str, str]:
    updated, count = re.subn(pattern, replacement, content, count=1, flags=re.MULTILINE)
    if count != 1:
        raise RemediationError(f"Could not find the expected source pattern for: {action}")
    return updated, action


def remediate_file(path: Path, rule_name: str) -> RemediationResult:
    """Apply a narrowly scoped fix and preserve the original as ``.bak``."""
    if not path.is_file():
        raise RemediationError(f"Remediation target is not a file: {path}")

    original = path.read_text(encoding="utf-8")
    lowered = rule_name.lower()
    updated = original
    action = ""

    if "publicly accessible database" in lowered:
        updated, action = _replace_once(
            original,
            r"(?m)^(\s*publicly_accessible\s*=\s*)true\s*$",
            r"\1false",
            "Set publicly_accessible to false",
        )
    elif "privileged container" in lowered or "privileged: true" in lowered:
        updated, action = _replace_once(
            original,
            r"(?m)^(\s*privileged\s*:\s*)true\s*$",
            r"\1false",
            "Disable privileged container execution",
        )
    elif "privilege escalation" in lowered:
        updated, action = _replace_once(
            original,
            r"(?m)^(\s*allowPrivilegeEscalation\s*:\s*)true\s*$",
            r"\1false",
            "Disable privilege escalation",
        )
    elif "user root" in lowered:
        updated, action = _replace_once(
            original,
            r"(?mi)^USER\s+(?:root|0)\s*$",
            "USER appuser",
            "Replace runtime root user",
        )
    elif "missing user" in lowered:
        # In a multi-stage Dockerfile, only the final stage controls runtime
        # privileges; builder-stage USER instructions must not block this fix.
        final_stage = re.split(r"(?mi)^FROM\s+", original)[-1]
        if re.search(r"(?mi)^USER\s+", final_stage):
            raise RemediationError("A USER instruction already exists; no safe insertion is needed")
        final_start = original.rfind("\nFROM ")
        final_content_start = final_start + 1 if final_start >= 0 else 0
        match = re.search(r"(?mi)^(ENTRYPOINT|CMD)\b", original[final_content_start:])
        insertion = "USER appuser\n"
        if match:
            absolute_match = final_content_start + match.start()
            updated = original[:absolute_match] + insertion + original[absolute_match:]
        else:
            updated = original.rstrip() + "\n" + insertion
        action = "Insert non-root USER instruction"
    elif "missing healthcheck" in lowered:
        if re.search(r"(?mi)^HEALTHCHECK\b", original):
            raise RemediationError("A HEALTHCHECK instruction already exists")
        updated = original.rstrip() + (
            "\nHEALTHCHECK --interval=30s --timeout=3s "
            "--start-period=5s --retries=3 CMD true\n"
        )
        action = "Add container HEALTHCHECK instruction"
    else:
        raise RemediationError("This finding has no deterministic auto-fix")

    if updated == original:
        raise RemediationError("The remediation produced no file change")

    backup = path.with_name(path.name + ".bak")
    shutil.copy2(path, backup)
    path.write_text(updated, encoding="utf-8")
    return RemediationResult(path, backup, True, action)
