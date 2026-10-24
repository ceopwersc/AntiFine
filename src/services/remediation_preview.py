"""Bounded review text built from the exact deterministic candidate."""
import difflib

from src.scanners.remediation import RemediationError
from src.services.secret_boundary import sanitize_text


def review_text(before: str, after: str, line: int, target: str) -> dict:
    old, new = before.splitlines(), after.splitlines()
    changed = [index for index, (left, right) in enumerate(zip(old, new)) if left != right]
    if len(old) != len(new) or len(changed) != 1:
        raise RemediationError('The candidate is not a reviewable single-line scalar edit')
    index = changed[0]
    start, end = max(0, index - 3), min(len(old), index + 4)
    if any(len(value) > 4096 for value in old[start:end] + new[start:end]):
        raise RemediationError('Format the oversized source line before reviewing an automatic fix')
    safe_before = sanitize_text('\n'.join(old[start:end]), limit=32000)
    safe_after = sanitize_text('\n'.join(new[start:end]), limit=32000)
    if safe_before == safe_after:
        raise RemediationError('The proposed change cannot be reviewed safely')
    lines = list(difflib.unified_diff(safe_before.splitlines(), safe_after.splitlines(),
        fromfile=target, tofile=target, lineterm='', n=3))
    # The hunk is a source excerpt; retain its actual file line numbers.
    if len(lines) >= 3:
        lines[2] = f'@@ -{start + 1},{end - start} +{start + 1},{end - start} @@'
    return {'before': safe_before, 'after': safe_after, 'diff': '\n'.join(lines),
        'start_line': start + 1, 'end_line': end, 'changed_line': index + 1}
