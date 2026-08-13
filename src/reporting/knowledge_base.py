"""Offline Knowledge Base for Remediation & Hardening.

Provides structured technical remediation guidance for known vulnerabilities.
"""

from __future__ import annotations

KNOWLEDGE_BASE: dict[str, dict[str, str]] = {
    "SSRF": {
        "summary": "Server-Side Request Forgery (SSRF) occurs when a web application fetches a remote resource without validating the user-supplied URL.",
        "mitigation": "1. Validate user input against a strict allowlist of domains or IP addresses.\n2. Ensure the URL scheme is strictly HTTP/HTTPS.\n3. Do not blindly follow redirects.\n4. Run the service in an isolated network environment.",
        "example": "```python\n# Use an allowlist\nALLOWED_DOMAINS = ['api.internal.example.com']\nif url.hostname not in ALLOWED_DOMAINS:\n    raise ValueError('Invalid domain')\n```"
    },
    "Open Plaintext Service": {
        "summary": "The service is transmitting credentials or session data in cleartext, exposing it to interception.",
        "mitigation": "1. Disable plaintext listeners (like FTP, Telnet, or HTTP).\n2. Enforce TLS/HTTPS for all remote connections.\n3. If legacy systems require plaintext, tunnel the traffic through an encrypted VPN or SSH.",
        "example": "```bash\n# Enforce SSH over Telnet\nsystemctl stop telnet.socket\nsystemctl disable telnet.socket\nsystemctl enable --now sshd\n```"
    },
    "Insecure Configuration": {
        "summary": "The service is using default, weak, or overly permissive configurations.",
        "mitigation": "1. Review the configuration file against security best practices.\n2. Disable anonymous or default credentials.\n3. Bind the service to localhost or restrict access via host firewalls.",
        "example": "```ini\n# Bind to localhost (Example for MySQL/PostgreSQL)\nbind-address = 127.0.0.1\n```"
    }
}

FALLBACK_REMEDIATION: dict[str, str] = {
    "summary": "An unclassified security finding was detected.",
    "mitigation": "1. Review whether this service must listen on an external interface.\n2. Bind it to localhost or restrict it at the firewall.\n3. Migrate to an encrypted equivalent if applicable.",
    "example": "```text\n(No specific code example available)\n```"
}

def get_remediation(vuln_type: str) -> dict[str, str]:
    """Retrieve structured remediation data for a given vulnerability type.
    
    Uses substring matching to handle things like 'SSRF (port 80)'.
    """
    if not vuln_type:
        return FALLBACK_REMEDIATION
        
    for known_vuln, kb_data in KNOWLEDGE_BASE.items():
        if known_vuln.lower() in vuln_type.lower():
            return kb_data
            
    return FALLBACK_REMEDIATION
