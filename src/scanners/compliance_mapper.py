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
    vulnerability_type_lower = vulnerability_type.lower()
    
    if "user root" in vulnerability_type_lower or "root user" in vulnerability_type_lower:
        return "CIS Docker Benchmark 4.1"
        
    if "ssrf" in vulnerability_type_lower or "injection" in vulnerability_type_lower:
        return "OWASP Top 10, ISO 27001 Control A.14.2.5"
        
    # Add other mappings here as they arise, e.g., missing limits etc.
    if "privileged: true" in vulnerability_type_lower:
        return "CIS Kubernetes Benchmark 5.2.1"
        
    return "Unmapped"
