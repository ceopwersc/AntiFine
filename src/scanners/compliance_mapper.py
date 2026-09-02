"""Compliance framework mapping logic.

Translates raw vulnerabilities into specific regulatory control failures.
"""

def map_finding_to_framework(vulnerability_type: str) -> str:
    """Map a raw vulnerability type string to a compliance framework.

    Args:
        vulnerability_type: The raw vulnerability description.

    Returns:
        The compliance framework identifier, or 'Unmapped' if no match.
    """
    v = vulnerability_type.lower()

    # ── Docker / CIS Docker Benchmark ───────────────────────────────────────
    if "user root" in v or "root user" in v:
        return "CIS Docker Benchmark 4.1"

    if "missing user" in v:
        return "CIS Docker Benchmark 4.1"

    if "missing healthcheck" in v or "healthcheck" in v:
        return "CIS Docker Benchmark 4.6"

    # ── Kubernetes / CIS Kubernetes Benchmark ────────────────────────────────
    if "privileged: true" in v or "privileged" in v:
        return "CIS Kubernetes Benchmark 5.2.1"

    if "resource limits" in v or "missing resource" in v:
        return "CIS Kubernetes Benchmark 5.2.4"

    # ── Terraform / AWS S3 ───────────────────────────────────────────────────
    if "s3" in v and ("public" in v or "acl" in v):
        return "CIS AWS Foundations Benchmark 2.1.5"

    # ── Web / SSRF / Injection ───────────────────────────────────────────────
    if "ssrf" in v or "injection" in v:
        return "OWASP Top 10, ISO 27001 Control A.14.2.5"

    # ── Exposed ports / plaintext services ──────────────────────────────────
    if "telnet" in v or "ftp" in v or "plaintext" in v:
        return "NIST SP 800-53 SC-8"

    return "Unmapped"
