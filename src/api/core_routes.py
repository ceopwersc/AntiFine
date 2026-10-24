"""Thin workstation routes over deterministic orchestration and storage services."""
from dataclasses import asdict
import uuid
import hashlib
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from src.services.filesystem import BoundaryError, relative_target
from src.services.settings import workspace_root, database_path, data_root
from src.services.workspaces import store_uploads, resolve_workspace
from src.services.scan_repository import ScanRepository
from src.services.scanning import scan_target
from src.services import remediation_service
from src.reporting.sarif_exporter import generate_sarif
from src.reporting.generate import generate_report

router = APIRouter()


def repository():
    return ScanRepository(database_path())


class ScanRequest(BaseModel):
    target_path: str = Field(max_length=1024)


class FixRequest(BaseModel):
    finding_id: str | None = Field(default=None, max_length=128)
    preview_id: str | None = Field(default=None, max_length=128)
    target_path: str | None = None
    rule_name: str | None = None


@router.post("/api/scan/upload")
async def upload(files: list[UploadFile] = File(...), relative_paths: str = Form("[]")):
    try:
        identifier = await run_in_threadpool(store_uploads, files, relative_paths)
        return {"status": "success", "target_path": identifier, "workspace_id": identifier}
    except BoundaryError as exc:
        raise HTTPException(413 if "quota" in str(exc) else 400, str(exc)) from None
    except (OSError, ValueError):
        raise HTTPException(400, "Upload could not be stored safely") from None
    finally:
        for file in files:
            await file.close()


@router.post("/api/scan/iac")
async def scan(req: ScanRequest, background_tasks: BackgroundTasks):
    try:
        if req.target_path.startswith("workspace_"):
            root = resolve_workspace(req.target_path)
            target, workspace_id = root, req.target_path
        else:
            root = workspace_root()
            target, workspace_id = relative_target(root, req.target_path), "local"
        run, values = await run_in_threadpool(scan_target, root, target, workspace_id, repository())
        from src.api.integrations_routes import dispatch_for_findings
        background_tasks.add_task(dispatch_for_findings, values)
        return {"status": run["status"], "target": run["target"], "scan_id": run["id"],
            "findings_count": len(values), "findings": [asdict(f) | {"file": f.filename, "compliance_framework": f.frameworks[0] if f.frameworks else ""} for f in values],
            "coverage": run["coverage"], "summary": f"Scan {run['status']}: {len(values)} finding(s). Only evaluated rules are covered; no compliance certification is inferred."}
    except (ValueError, OSError):
        raise HTTPException(422, "Invalid target or scan limits exceeded") from None


@router.get("/api/findings")
async def findings():
    return {"findings": await run_in_threadpool(repository().findings)}


@router.get("/api/findings/secrets")
async def secret_findings():
    values = await run_in_threadpool(repository().findings, open_only=True)
    return {"status": "ok", "findings": [f for f in values if f["rule_id"].startswith("secrets.") or (f["rule_id"] == "legacy.unknown" and any(x in f["rule_name"].lower() for x in ("secret", "vendor match", "entropy", "token")))]}


@router.get("/api/scan/history")
async def history():
    return {"status": "ok", "scans": await run_in_threadpool(repository().history)}


@router.get("/api/dashboard")
async def dashboard():
    values = await run_in_threadpool(repository().findings, open_only=True)
    counts = {s: sum(f["severity"] == s for f in values) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")}
    mappings = {v: "Mapped finding; control evaluation unavailable" for f in values for v in f["frameworks"] if v != "Unmapped"}
    return {"status": "ok", "counts": counts, "compliance": mappings, "total_findings": len(values),
        "total_secrets": sum(f["rule_id"].startswith("secrets.") for f in values)}


@router.get("/api/analytics/dashboard")
async def analytics():
    data = await dashboard()
    return {"status": "ok", "overall_compliance_score": None, "compliance_status": "Not evaluated",
        "severity_breakdown": [{"name": k.title(), "value": v} for k,v in data["counts"].items()], "historical_trends": [],
        "coverage": await run_in_threadpool(repository().history)}


@router.post("/api/scan/iac/remediation/preview")
async def preview(req: FixRequest):
    if not req.finding_id:
        raise HTTPException(422, "Scan first and supply finding_id; title-based remediation is unsupported")
    try:
        return await run_in_threadpool(remediation_service.preview, repository(), req.finding_id)
    except (ValueError, OSError):
        raise HTTPException(422, "Preview unavailable: manual-only, stale, or unconfirmed finding") from None


@router.post("/api/scan/iac/remediate")
async def apply(req: FixRequest):
    if not req.finding_id or not req.preview_id:
        raise HTTPException(422, "Apply requires finding_id and preview_id from a current preview")
    try:
        return await run_in_threadpool(remediation_service.apply, repository(), req.finding_id, req.preview_id)
    except (ValueError, OSError):
        raise HTTPException(409, "Apply rejected: stale/concurrent source, invalid preview, or failed verification. Rescan and review again.") from None


@router.get("/api/scan/iac/export/sarif")
async def sarif():
    values = await run_in_threadpool(repository().findings, open_only=True)
    runs = await run_in_threadpool(repository().history)
    return generate_sarif([f | {"vulnerability_type": f["rule_name"], "target": f["file"]} for f in values], coverage=runs)


@router.post("/api/report/generate")
async def report():
    identifier = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    directory = data_root() / "reports"
    directory.mkdir(exist_ok=True, mode=0o700)
    try:
        path, count = await run_in_threadpool(generate_report, database_path(), directory / (identifier + ".md"))
        return {"status": "completed", "results": {"markdown": {"status": "success", "file": path.name, "findings": count}}}
    except Exception:
        raise HTTPException(500, "Report generation failed") from None


@router.get("/api/reports/{filename}")
async def report_download(filename: str):
    import re
    if not re.fullmatch(r"[0-9a-f]{64}\.md", filename):
        raise HTTPException(404, "Report unavailable")
    path = data_root() / "reports" / filename
    if not path.is_file():
        raise HTTPException(404, "Report unavailable")
    return FileResponse(path, media_type="text/markdown", filename="antifine-evidence.md")
