"""FastAPI Server for AntiFine Core Engine.

Exposes the AntiFine Python engine capabilities as a local REST API
for decoupling the frontend from the core execution logic.
"""

import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from src.api.security import LocalSecurityMiddleware, ORIGINS
from src.services.settings import workspace_root
from src.services.filesystem import BoundaryError, relative_target
from src.services.workspaces import resolve_workspace
from src.integrations.webhook_policy import validate_destination
from pydantic import BaseModel, Field
import uvicorn

# Ensure the src directory is in the path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.scanners.ssrf_scanner import run_web_audit
from src.scanners.compliance_mapper import get_finding_metadata
from src.services.ollama_service import (
    OllamaConfig,
    OllamaDisabledError,
    OllamaError,
    OllamaService,
)
from src.models.finding import Finding
from src.models.ai_context import AIContext, AIMessage
from src.services.ai_explanation import (
    finding_id,
)
from src.services.secret_boundary import sanitize_path, sanitize_text
from src.services.remediation_explanation import (
    REMEDIATION_REVIEW_SYSTEM_PROMPT,
    build_remediation_review_prompt,
)
from src.ai.knowledge_service import find_rule_for_finding
from src.ai.context_builder import (
    build_context,
    unmapped_compliance_fallback,
    sanitize_unmapped_compliance_claims,
    source_metadata,
)
from src.services.advisory_guard import constrain
from src.ai.prompts import EXPLANATION_SYSTEM_PROMPT, GENERAL_SYSTEM_PROMPT
from src.ai.retriever import retrieve


# ── Initialization ──────────────────────────────────────────────────────────


app = FastAPI(title="AntiFine Core Engine")


class _NoRawAccessLog(logging.Filter):
    def filter(self, record):
        # Uvicorn includes raw query strings and paths. Safe operation/status
        # logging belongs in the application layer, never in this raw channel.
        return False


logging.getLogger("uvicorn.access").addFilter(_NoRawAccessLog())

# Strict CORS: only allow local frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(ORIGINS),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-AntiFine-Request", "X-AntiFine-Token"],
)


from src.api.core_routes import router as core_router
from src.api.integrations_routes import router as integrations_router
app.include_router(core_router)
app.include_router(integrations_router)
app.add_middleware(LocalSecurityMiddleware)

@app.exception_handler(RequestValidationError)
async def validation_error(_request, exc):
    return JSONResponse(status_code=422, content={"detail": "Invalid request fields"})

@app.get("/api/health")
async def health():
    return {"status": "ok"}

# ── Pydantic Models ─────────────────────────────────────────────────────────

class SSRFScanRequest(BaseModel):
    target_url: str = Field(max_length=4000)

class IaCScanRequest(BaseModel):
    target_path: str

class RemediationRequest(BaseModel):
    target_path: str
    rule_name: str

class WebhookModel(BaseModel):
    url: str
    min_severity: str = "HIGH"

class WebhookTestModel(BaseModel):
    url: str

class AITestRequest(BaseModel):
    prompt: str = Field(max_length=12000)

class FindingExplanationRequest(BaseModel):
    finding: Finding
    code_context: str | None = Field(default=None,max_length=4000)

class AIAskRequest(BaseModel):
    question: str = Field(max_length=4000)
    # ``str`` keeps older local clients working while new clients get a
    # validated, structured context contract.
    context: AIContext | str | None = None
    messages: list[AIMessage] = Field(default_factory=list, max_length=10)

class RemediationExplanationRequest(BaseModel):
    finding: Finding
    before: str
    after: str
    diff: str
    remediation: str = ""
    frameworks: list[str] = []
    preview_id: str | None = None


def trusted_finding(supplied: Finding) -> Finding:
    """Client display fields never become authoritative AI context."""
    from dataclasses import fields
    from src.api.core_routes import repository
    try:
        data = repository().get(supplied.id)
    except (ValueError, OSError):
        raise HTTPException(422, "Explanation requires an open backend finding ID") from None
    allowed = {field.name for field in fields(Finding)}
    return Finding(**{key: value for key, value in data.items() if key in allowed})


def trusted_review(req: RemediationExplanationRequest):
    import time
    from src.api.core_routes import repository
    from src.services.settings import data_root
    from src.services.remediation_service import _finding
    identifier = req.preview_id or ""
    if len(identifier) != 64 or any(c not in "0123456789abcdef" for c in identifier):
        raise HTTPException(422, "AI review requires a current deterministic preview")
    try:
        record = json.loads((data_root() / "previews" / (identifier + ".json")).read_text(encoding="utf-8"))
        if record["finding_id"] != req.finding.id or record["expires"] < time.time():
            raise ValueError("Stale preview")
        canonical = trusted_finding(req.finding)
        _, _, _, _, _, before, after, _ = _finding(repository(), canonical.id)
        if canonical.source_digest != record["digest"]:
            raise ValueError("Stale source")
        return canonical, before, after
    except (ValueError, OSError):
        raise HTTPException(422, "AI review requires a reproducible current preview") from None


def canonical_ask_context(context):
    if isinstance(context, AIContext) and context.source == "finding":
        if not context.finding or not context.finding.finding_id:
            raise HTTPException(422, "Finding context requires a backend finding_id")
        from src.models.ai_context import AIFindingContext
        canonical = trusted_finding(Finding("", "", "", id=context.finding.finding_id))
        return AIContext(source="finding", finding=AIFindingContext(
            finding_id=canonical.id, rule_id=canonical.rule_id, title=canonical.rule_name,
            severity=canonical.severity, file=canonical.filename, line=canonical.line,
            frameworks=canonical.frameworks, status=canonical.status, description=canonical.description,
            remediation=canonical.remediation))
    if isinstance(context, AIContext) and context.source != "general":
        return "Unverified user context, advisory only: " + sanitize_text(context.model_dump_json(), limit=4000)
    return context


# ── Severity rank helper ────────────────────────────────────────────────────

_SEVERITY_RANKS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _ollama_error_message(exc: OllamaError) -> str:
    if isinstance(exc, OllamaDisabledError):
        return "Ollama integration is disabled"
    if "not reachable" in str(exc).lower():
        return "Ollama is not reachable"
    return sanitize_text(exc, limit=500)


# ── Webhook URL validation ──────────────────────────────────────────────────

def _validate_webhook_url(url: str) -> None:
    try:
        validate_destination(url)
    except (ValueError, OSError):
        raise HTTPException(status_code=422, detail="Webhook destination rejected by local policy") from None


# ── Path sandboxing ─────────────────────────────────────────────────────────

def _resolve_and_sandbox(target_path: str) -> Path:
    try:
        if target_path.startswith("workspace_") and "/" not in target_path and "\\" not in target_path:
            return resolve_workspace(target_path)
        return relative_target(workspace_root(), target_path)
    except (BoundaryError, OSError, ValueError):
        raise HTTPException(status_code=422, detail="Invalid or unavailable workspace target") from None


# ── Endpoints ───────────────────────────────────────────────────────────────


@app.post("/api/scan/ssrf")
async def run_ssrf_scan(req: SSRFScanRequest, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    from dataclasses import asdict
    from src.api.core_routes import repository
    from src.services.scanning import identity
    from src.api.integrations_routes import dispatch_for_findings
    try:
        observed = await run_in_threadpool(run_web_audit, req.target_url, persist=False)
        scan_id = identity(str(__import__('uuid').uuid4()))
        file_id = identity(req.target_url)
        values = []
        for index, observation in enumerate(observed):
            meta = get_finding_metadata(observation.vulnerability_type)
            f = Finding(observation.vulnerability_type, observation.severity, sanitize_path(req.target_url),
                frameworks=meta['frameworks'], remediation=meta['remediation'], rule_id='network.ssrf',
                resource=f'probe/{index}', file_id=file_id, workspace_id='network', scan_id=scan_id)
            f.id = identity(file_id,f.rule_id,f.resource)
            values.append(f)
        run = {'id':scan_id,'workspace_id':'network','scope_id':file_id,'target':sanitize_path(req.target_url),
            'status':'partial','coverage':[{'file_id':file_id,'file':sanitize_path(req.target_url),'status':'evaluated','rules_evaluated':True}], 'findings_count':len(values)}
        await run_in_threadpool(repository().save_run,run,values)
        background_tasks.add_task(dispatch_for_findings,values)
        return {'status':'partial','scan_id':scan_id,'findings_count':len(values),'findings':[asdict(f) | {'file':f.filename} for f in values],
            'coverage':run['coverage'],'summary':'Network probe observations recorded; coverage is partial and does not establish compliance.'}
    except Exception:
        raise HTTPException(422,'Network scan could not complete safely') from None


@app.get("/api/ai/health")
async def ollama_health() -> Dict[str, Any]:
    """Report optional Ollama availability without affecting AntiFine startup."""
    config = OllamaConfig.from_env()
    response: Dict[str, Any] = {
        "enabled": config.enabled,
        "available": False,
        "provider": "ollama",
        "model": config.model,
    }
    if not config.enabled:
        return response
    try:
        await OllamaService(config).health_check()
        response["available"] = True
    except OllamaError as exc:
        response["error"] = _ollama_error_message(exc)
    return response


@app.post("/api/ai/test")
async def ollama_test(req: AITestRequest) -> Dict[str, str]:
    """Send one explicit, isolated prompt to the configured local model."""
    if not req.prompt.strip():
        raise HTTPException(status_code=422, detail="Prompt must not be empty")
    try:
        response = await OllamaService().generate(sanitize_text(req.prompt, limit=12000))
        return {"response": constrain(response)}
    except OllamaDisabledError as exc:
        raise HTTPException(status_code=503, detail=_ollama_error_message(exc)) from exc
    except OllamaError as exc:
        raise HTTPException(status_code=502, detail=_ollama_error_message(exc)) from exc


@app.post("/api/ai/findings/explain")
async def explain_finding(req: FindingExplanationRequest) -> Dict[str, Any]:
    """Explain an existing deterministic finding using the local model."""
    canonical = await run_in_threadpool(trusted_finding, req.finding)
    service = OllamaService()
    try:
        matched_rule = find_rule_for_finding(canonical)
        query = " ".join(
            filter(
                None,
                [
                    matched_rule.rule_id if matched_rule else "",
                    canonical.rule_name,
                    canonical.severity,
                    *canonical.frameworks,
                ],
            )
        )
        retrieved = retrieve(query, top_k=5)
        explanation = await service.generate(
            build_context(
                "Explain this existing AntiFine finding.",
                retrieved,
                canonical,
                req.code_context,
            ),
            system_prompt=EXPLANATION_SYSTEM_PROMPT,
        )
        return {
            "finding_id": finding_id(canonical),
            "model": service.config.model,
            "provider": "ollama",
            "explanation": constrain(explanation, canonical.severity),
            "generated_locally": True,
            "sources": source_metadata(retrieved),
        }
    except OllamaDisabledError as exc:
        raise HTTPException(status_code=503, detail=_ollama_error_message(exc)) from exc
    except OllamaError as exc:
        raise HTTPException(status_code=502, detail=_ollama_error_message(exc)) from exc


@app.post("/api/ai/ask")
async def ask_ai(req: AIAskRequest) -> Dict[str, Any]:
    """Answer a question using retrieved local AntiFine knowledge."""
    if not req.question.strip():
        raise HTTPException(status_code=422, detail="Question must not be empty")
    req.context = await run_in_threadpool(canonical_ask_context, req.context)
    context_text = build_context(
        req.question,
        [],
        structured_context=req.context,
    )
    rule_id = None
    frameworks = None
    if isinstance(req.context, AIContext) and req.context.source == "finding" and req.context.finding:
        rule_id = req.context.finding.rule_id
        frameworks = req.context.finding.frameworks
    retrieved = retrieve(
        f"{req.question}\n{context_text}",
        top_k=5,
        authoritative_rule_id=rule_id,
        authoritative_frameworks=frameworks,
    )
    try:
        service = OllamaService()
        answer = await service.generate(
            build_context(
                req.question,
                retrieved,
                structured_context=req.context,
                messages=req.messages,
            ),
            system_prompt=GENERAL_SYSTEM_PROMPT,
        )
        fallback = unmapped_compliance_fallback(req.question, req.context, retrieved)
        answer = fallback or sanitize_unmapped_compliance_claims(
            answer, req.question, req.context, retrieved
        )
        answer = constrain(answer, req.context.finding.severity if isinstance(req.context, AIContext) and req.context.finding else None)
        return {
            "answer": answer,
            "model": service.config.model,
            "provider": "ollama",
            "sources": source_metadata(retrieved),
        }
    except OllamaDisabledError as exc:
        raise HTTPException(status_code=503, detail=_ollama_error_message(exc)) from exc
    except OllamaError as exc:
        raise HTTPException(status_code=502, detail=_ollama_error_message(exc)) from exc


@app.post("/api/ai/remediation/explain")
async def explain_remediation(req: RemediationExplanationRequest) -> Dict[str, Any]:
    """Explain an existing deterministic remediation without changing it."""
    canonical, before, after = await run_in_threadpool(trusted_review, req)
    service = OllamaService()
    try:
        explanation = await service.generate(
            build_remediation_review_prompt(
                canonical,
                before,
                after,
                "BEFORE\n" + before + "\nAFTER\n" + after,
                canonical.remediation,
                canonical.frameworks,
            ),
            system_prompt=REMEDIATION_REVIEW_SYSTEM_PROMPT,
        )
        if not explanation.strip():
            raise OllamaError("Ollama returned an empty remediation explanation")
        return {
            "finding_id": finding_id(canonical),
            "model": service.config.model,
            "provider": "ollama",
            "explanation": constrain(explanation, canonical.severity),
            "generated_locally": True,
        }
    except OllamaDisabledError as exc:
        raise HTTPException(status_code=503, detail=_ollama_error_message(exc)) from exc
    except OllamaError as exc:
        raise HTTPException(status_code=502, detail=_ollama_error_message(exc)) from exc


# ── Execution ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
