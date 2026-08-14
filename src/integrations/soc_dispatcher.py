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

    try:
        async with httpx.AsyncClient() as client:
            # 3-second timeout to ensure failed webhook targets never block or crash a scan
            response = await client.post(webhook_url, json=payload, timeout=3.0)
            response.raise_for_status()
            logger.info(f"Successfully dispatched alert to {webhook_url}")
    except httpx.TimeoutException:
        logger.error(f"Timeout dispatching alert to {webhook_url}")
    except httpx.HTTPStatusError as exc:
        logger.error(f"HTTP Error {exc.response.status_code} dispatching alert to {webhook_url}")
    except Exception as exc:
        logger.error(f"Failed to dispatch alert to {webhook_url}: {exc}")
