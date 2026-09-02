"""High-confidence vendor secret detection and entropy-based credential scanning.

Uses exact vendor signature regexes (AWS, GitHub, Slack, Private Keys) and
character-set adjusted Shannon entropy with false-positive allowlisting.
"""

from __future__ import annotations

import math
import re
import sys
from pathlib import Path

PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.models.finding import Finding  # noqa: E402

# ── Vendor Signature Regexes ──────────────────────────────────────────────
_VENDOR_REGEXES = {
    "AWS Access Key ID": re.compile(r'\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b'),
    "AWS Secret Access Key": re.compile(r'(?i)aws_(?:secret_access_key|key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
    "GitHub Personal Access Token": re.compile(r'\b(ghp_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{82})\b'),
    "Slack API Token": re.compile(r'\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9]*\b'),
    "Generic Private Key": re.compile(r'-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP)? PRIVATE KEY-----')
}

# ── False-Positive Allowlist Patterns ─────────────────────────────────────
_FP_UUID = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
_FP_HEX = re.compile(r'^[0-9a-fA-F]+$')

def calculate_entropy(data: str) -> float:
    """Compute Shannon entropy of *data* in bits per character.

    Formula: H(X) = -Sigma P(x_i) * log2 P(x_i)

    Returns 0.0 for empty or single-character strings.
    """
    if len(data) < 2:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _is_false_positive(value: str) -> bool:
    """Return True if the value matches known non-secret patterns."""
    # Ignore standard UUIDs
    if _FP_UUID.match(value):
        return True
    
    # Ignore pure hex strings of length 40 (SHA1) or 64 (SHA256)
    if (len(value) == 40 or len(value) == 64) and _FP_HEX.match(value):
        return True

    # Ignore base image names or URL paths containing slashes and dots
    if '/' in value and '.' in value:
        return True

    return False


def scan_value_for_secrets(
    value: str,
    key_name: str,
    filename: str,
) -> Finding | None:
    """Scan a string value for vendor secrets and high-entropy credentials.
    
    Returns a Finding if a secret is found, else None.
    """
    # 1. Exact Vendor Signature Match
    for vendor_name, pattern in _VENDOR_REGEXES.items():
        if pattern.search(value) or pattern.search(key_name + "=" + value):
            return Finding(
                rule_name=f"Exact Vendor Match ({vendor_name}) in {filename} [{key_name}]",
                severity="CRITICAL",
                filename=filename,
                frameworks=[
                    "CIS Docker Benchmark 4.7",
                    "CWE-798 (Use of Hard-coded Credentials)",
                    "ISO 27001 A.8.24",
                    "NIST SP 800-190 §3.3.1",
                ],
                remediation=(
                    "Revoke token immediately and inject via external secret manager "
                    "(e.g., AWS Secrets Manager, HashiCorp Vault)."
                ),
            )
            
    # 2. Entropy Check
    stripped = value.strip('"\'  \t')
    if not stripped or len(stripped) < 16:
        return None
        
    if _is_false_positive(stripped):
        return None
        
    h = calculate_entropy(stripped)
    
    # Determine charset and threshold
    is_hex = bool(_FP_HEX.match(stripped))
    threshold = 3.0 if is_hex else 4.2
    
    if h >= threshold:
        return Finding(
            rule_name=(
                f"Statistical Entropy (Shannon H >= {threshold}) in {filename} "
                f"[{key_name}=... H={h:.2f}]"
            ),
            severity="HIGH",
            filename=filename,
            frameworks=[
                "CIS Docker Benchmark 4.7",
                "CWE-312 (Cleartext Storage of Sensitive Information)",
                "ISO 27001 A.8.24",
            ],
            remediation=(
                "Remove the high-entropy value from the configuration file.\n"
                "Use a secrets manager to inject secrets at runtime."
            ),
        )
        
    return None
