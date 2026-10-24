"""SOC Alert Dispatcher for external SIEM/SOAR integrations.

Dispatches high-severity vulnerabilities to external webhooks in a structured
JSON format matching enterprise incident schemas.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict

import httpx

logger = logging.getLogger(__name__)

async def dispatch_security_alert(finding: Dict[str, Any], webhook_url: str) -> None:
    """Dispatch a structured JSON security alert to a webhook endpoint.

    Args:
        finding: Dictionary containing finding details. Expected keys:
            - vulnerability_type
            - severity
            - compliance_tags
            - remediation_guidance (optional)
        webhook_url: Target URL for the webhook.
    """
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "SECURITY_ALERT",
        "severity": finding.get("severity", "UNKNOWN"),
        "vulnerability": {
            "title": "Vulnerability Detected",
            "description": finding.get("vulnerability_type", "Unknown vulnerability")
        },
        "compliance_tags": finding.get("compliance_tags", "Unmapped"),
        "remediation_guidance": finding.get("remediation_guidance", "Investigate immediately.")
    }

    import asyncio
    from src.api.security import safe_json
    from src.integrations.webhook_policy import deliver
    try:
        await asyncio.to_thread(deliver, webhook_url, safe_json(payload))
        logger.info("Security alert delivered")
    except Exception:
        logger.warning("Security alert delivery failed or was rejected by policy")
