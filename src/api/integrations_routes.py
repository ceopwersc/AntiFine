"""Credential-free configured integrations; no unsafe URL persistence or logging."""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from src.api.core_routes import repository
from src.integrations.webhook_policy import validate_destination
from src.integrations.soc_dispatcher import dispatch_security_alert

router = APIRouter()


class Webhook(BaseModel):
    url: str = Field(max_length=2048)
    min_severity: str = "HIGH"


@router.get("/api/integrations/webhooks")
def webhooks():
    with repository().connect() as db:
        return {"status": "ok", "webhooks": [dict(r) for r in db.execute("SELECT id,url,min_severity FROM webhooks")]}


@router.post("/api/integrations/webhooks")
async def save(req: Webhook):
    try:
        await run_in_threadpool(validate_destination, req.url)
        if req.min_severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("Invalid severity")
    except (ValueError, OSError):
        raise HTTPException(422, "Webhook destination rejected by policy") from None
    with repository().connect() as db:
        db.execute("INSERT INTO webhooks(url,min_severity) VALUES(?,?) ON CONFLICT(url) DO UPDATE SET min_severity=excluded.min_severity", (req.url, req.min_severity))
    return {"status": "success"}


@router.post("/api/integrations/test")
async def test(req: Webhook, background_tasks: BackgroundTasks):
    try:
        await run_in_threadpool(validate_destination, req.url)
    except (ValueError, OSError):
        raise HTTPException(422, "Webhook destination rejected by policy") from None
    background_tasks.add_task(dispatch_security_alert, {"vulnerability_type": "Synthetic integration test", "severity": "CRITICAL"}, req.url)
    return {"status": "success"}


async def dispatch_for_findings(findings):
    ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    values = await run_in_threadpool(webhooks)
    for webhook in values["webhooks"]:
        for f in findings[:100]:
            if ranks.get(f.severity, 0) >= ranks.get(webhook["min_severity"], 3):
                await dispatch_security_alert({"vulnerability_type": f.rule_name, "severity": f.severity, "compliance_tags": f.frameworks}, webhook["url"])
