"""Model prose is advisory; contradictory action/status assertions fail closed."""
import re
from src.services.secret_boundary import sanitize_text

ACTION_CLAIM = re.compile(r"\b(?:i|we|antifine|the (?:file|fix|finding|vulnerability)|this (?:file|fix|finding))\b[^.\n]{0,100}\b(?:applied|modified|changed|fixed|resolved|remediated|verified|rescanned)\b|\b(?:fix|remediation|verification|rescan)\s+(?:is\s+|was\s+|has been\s+)?(?:complete|completed|successful|applied|verified)\b", re.I)
SEVERITY_CLAIM = re.compile(r"\bseverity\s*(?::|is|=|was|should be)\s*\**(critical|high|medium|low|informational)\b", re.I)


def constrain(text: str, severity: str | None = None) -> str:
    safe = sanitize_text(text, limit=12000)
    contradictory = bool(ACTION_CLAIM.search(safe))
    if severity:
        contradictory |= any(m.group(1).upper() != severity.upper() for m in SEVERITY_CLAIM.finditer(safe))
    if contradictory:
        return "Advisory response withheld because it conflicts with deterministic evidence. Review the recorded finding and verification status. No action is performed by Local AI."
    return safe
