"""Tests for the reporting engine components."""

from src.reporting.knowledge_base import get_remediation, FALLBACK_REMEDIATION

def test_get_remediation_known_vuln():
    """Test fetching remediation for a known vulnerability type."""
    # Matches 'SSRF'
    kb = get_remediation("SSRF in AWS Metadata")
    
    assert kb is not None
    assert kb != FALLBACK_REMEDIATION
    assert "Server-Side Request Forgery" in kb["summary"]
    assert "ALLOW" in kb["example"] or "allowlist" in kb["mitigation"].lower()

def test_get_remediation_unknown_vuln():
    """Test fallback remediation for unknown vulnerability."""
    kb = get_remediation("Some random new vulnerability")
    
    assert kb == FALLBACK_REMEDIATION
    assert "unclassified security finding" in kb["summary"]

def test_get_remediation_empty():
    """Test fallback remediation when vulnerability type is empty."""
    kb = get_remediation("")
    
    assert kb == FALLBACK_REMEDIATION
