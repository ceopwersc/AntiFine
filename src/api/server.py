"""FastAPI Server for AntiFine Core Engine.

Exposes the AntiFine Python engine capabilities as a local REST API
for decoupling the frontend from the core execution logic.
"""

import ipaddress
import sqlite3
import sys
from pathlib import Path
from typing import Dict, Any
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# Ensure the src directory is in the path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.setup import DB_PATH, initialize_database
from src.scanners.ssrf_scanner import run_web_audit
from src.scanners.iac_audit import run_iac_audit
from src.scanners.compliance_mapper import map_finding_to_framework, get_finding_metadata
from src.reporting.generate import generate_report
from src.reporting.sarif_exporter import export_to_sarif
from src.integrations.soc_dispatcher import dispatch_security_alert


# ── Initialization ──────────────────────────────────────────────────────────

try:
    initialize_database()
except Exception:
    pass

app = FastAPI(title="AntiFine Core Engine")

# Strict CORS: only allow local frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Pydantic Models ─────────────────────────────────────────────────────────

class SSRFScanRequest(BaseModel):
    target_url: str

class IaCScanRequest(BaseModel):
    target_path: str

class WebhookModel(BaseModel):
    url: str
    min_severity: str = "HIGH"

class WebhookTestModel(BaseModel):
    url: str


# ── Severity rank helper ────────────────────────────────────────────────────

_SEVERITY_RANKS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# ── Webhook URL validation ──────────────────────────────────────────────────

def _validate_webhook_url(url: str) -> None:
    """Reject dangerous webhook URLs (file://, private IPs, etc.)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=422, detail=f"Unsupported URL scheme: {parsed.scheme}. Only http/https allowed.")
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=422, detail="Webhook URL must have a hostname.")
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_reserved:
            raise HTTPException(status_code=422, detail=f"Webhook URL must not target private/loopback IPs: {hostname}")
    except ValueError:
        # hostname is a domain name, not an IP — that's fine
        pass


def _dispatch_alerts_for_rows(rows: list, background_tasks: BackgroundTasks):
    """Dispatch webhook alerts using >= severity rank comparison."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            webhooks = conn.execute("SELECT url, min_severity FROM webhooks").fetchall()
    except Exception:
        webhooks = []
        
    if not webhooks:
        return
        
    for row in rows:
        target_id, vuln_type, severity, status, *rest = row
        sev_rank = _SEVERITY_RANKS.get(severity.upper(), 0)
        for url, min_severity in webhooks:
            min_rank = _SEVERITY_RANKS.get(min_severity.upper(), 3)
            if sev_rank >= min_rank:
                finding_dict = {
                    "vulnerability_type": vuln_type,
                    "severity": severity,
                    "compliance_tags": rest[0] if rest else "Unmapped",
                }
                background_tasks.add_task(dispatch_security_alert, finding_dict, url)


# ── Path sandboxing ─────────────────────────────────────────────────────────

def _resolve_and_sandbox(target_path: str) -> Path:
    """Resolve a scan target path and ensure it stays within PROJECT_ROOT."""
    target = Path(target_path)
    if target.is_absolute():
        raise HTTPException(
            status_code=422,
            detail="Absolute paths are not allowed. Provide a path relative to the project root."
        )
    resolved = (PROJECT_ROOT / target).resolve()
    if not str(resolved).startswith(str(PROJECT_ROOT.resolve())):
        raise HTTPException(
            status_code=422,
            detail="Path traversal detected. Target must be within the project root."
        )
    if not resolved.exists():
        raise HTTPException(
            status_code=422,
            detail=f"Target path not found: '{target_path}' (resolved to '{resolved}')."
        )
    return resolved


# ── Endpoints ───────────────────────────────────────────────────────────────

@app.get("/api/analytics/dashboard")
async def get_analytics_dashboard() -> Dict[str, Any]:
    if not DB_PATH.is_file():
        return {
            "status": "ok", 
            "overall_compliance_score": 100,
            "severity_breakdown": [
                {"name": "Critical", "value": 0},
                {"name": "High", "value": 0},
                {"name": "Medium", "value": 0},
                {"name": "Low", "value": 0}
            ],
            "historical_trends": []
        }
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            # Weighted compliance score based on severity
            rows = conn.execute(
                "SELECT UPPER(severity) AS sev, COUNT(*) FROM scan_results "
                "WHERE status='OPEN' GROUP BY sev"
            ).fetchall()
            
            penalty = 0
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for sev, cnt in rows:
                if sev in counts:
                    counts[sev] = cnt
                if sev == "CRITICAL":
                    penalty += cnt * 20
                elif sev == "HIGH":
                    penalty += cnt * 10
                elif sev == "MEDIUM":
                    penalty += cnt * 5
                elif sev == "LOW":
                    penalty += cnt * 1
            
            score = max(0, 100 - penalty)
            
            severity_breakdown = [
                {"name": "Critical", "value": counts["CRITICAL"]},
                {"name": "High", "value": counts["HIGH"]},
                {"name": "Medium", "value": counts["MEDIUM"]},
                {"name": "Low", "value": counts["LOW"]},
            ]
            
            # Historical Trends (last 7 dates with data)
            trend_rows = conn.execute(
                "SELECT DATE(timestamp) as date, COUNT(*) FROM scan_results GROUP BY date ORDER BY date DESC LIMIT 7"
            ).fetchall()
            historical_trends = [{"date": r[0], "count": r[1]} for r in reversed(trend_rows)]
            
            return {
                "status": "ok",
                "overall_compliance_score": score,
                "severity_breakdown": severity_breakdown,
                "historical_trends": historical_trends
            }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.get("/api/dashboard")
async def get_dashboard() -> Dict[str, Any]:
    """Return an aggregated summary of vulnerabilities from the database."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    compliance_status = {}
    if not DB_PATH.is_file():
        return {"status": "ok", "counts": counts, "compliance": compliance_status}
        
    try:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT UPPER(severity) AS sev, COUNT(*) "
                "FROM scan_results GROUP BY sev"
            ).fetchall()
            for sev, cnt in rows:
                if sev in counts:
                    counts[sev] = cnt
                    
            # Fetch compliance frameworks
            comp_rows = conn.execute(
                "SELECT compliance_framework, COUNT(*) "
                "FROM scan_results WHERE compliance_framework IS NOT NULL AND compliance_framework != 'Unmapped' "
                "GROUP BY compliance_framework"
            ).fetchall()
            for fw, cnt in comp_rows:
                if fw:
                    compliance_status[fw] = "Failing" if cnt > 0 else "Passing"
                    
    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")
        
    return {"status": "ok", "counts": counts, "compliance": compliance_status}


@app.post("/api/scan/ssrf")
async def run_ssrf_scan(req: SSRFScanRequest, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    """Execute the SSRF scanner against a target URL."""
    try:
        # Trigger the web audit logic asynchronously
        findings = run_web_audit(req.target_url, persist=False)
        rows = []
        for finding in findings:
            vuln_type = finding.vulnerability_type
            framework = map_finding_to_framework(vuln_type)
            rows.append((1, vuln_type, finding.severity, "OPEN", framework))
            
        if rows:
            with sqlite3.connect(DB_PATH) as conn:
                conn.executemany(
                    "INSERT INTO scan_results "
                    "(target_id, vulnerability_type, severity, status, compliance_framework) "
                    "VALUES (?, ?, ?, ?, ?)",
                    rows,
                )
                conn.commit()
            _dispatch_alerts_for_rows(rows, background_tasks)
                
        return {"status": "success", "message": f"SSRF scan completed for {req.target_url}"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/scan/iac")
async def run_iac_scan(req: IaCScanRequest, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    """Execute the IaC scanner against a local file or directory.

    Resolves relative paths against the project root. Sandboxed to PROJECT_ROOT.
    Persists every finding (with compliance framework tag) to antifine.db
    and dispatches webhook alerts for HIGH/CRITICAL findings.
    """
    try:
        resolved = _resolve_and_sandbox(req.target_path)

        # ── Run the scanner (no internal persistence — we handle it here) ──────
        raw_findings = run_iac_audit(str(resolved), persist=False)

        # ── Build enriched response + DB rows from Finding objects ──────────────
        enriched: list[Dict[str, Any]] = []
        rows = []
        for finding in raw_findings:
            # Use the Finding's own frameworks/remediation if present,
            # otherwise fall back to the compliance mapper for legacy rules.
            if finding.frameworks:
                primary_framework = finding.frameworks[0]
                frameworks_list = finding.frameworks
                remediation = finding.remediation
                description = finding.description or finding.rule_name
            else:
                meta = get_finding_metadata(finding.rule_name)
                primary_framework = meta["primary_framework"]
                frameworks_list = meta["frameworks"]
                remediation = meta["remediation"]
                description = meta["description"]

            enriched.append({
                "rule_name": finding.rule_name,
                "severity": finding.severity,
                "compliance_framework": primary_framework,
                "frameworks": frameworks_list,
                "description": description,
                "remediation": remediation,
            })
            rows.append((1, finding.rule_name, finding.severity, "OPEN", primary_framework, finding.filename))

        # ── Deduplicate: remove old findings for this target, then insert fresh ─
        if rows:
            try:
                initialize_database()
                with sqlite3.connect(DB_PATH) as conn:
                    # Delete previous findings for the same target path
                    target_filenames = {finding.filename for finding in raw_findings}
                    for tf in target_filenames:
                        conn.execute(
                            "DELETE FROM scan_results WHERE target_path = ?",
                            (tf,),
                        )
                    conn.executemany(
                        "INSERT INTO scan_results "
                        "(target_id, vulnerability_type, severity, status, compliance_framework, target_path) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        rows,
                    )
                    conn.commit()
            except sqlite3.Error as db_exc:
                print(f"[warn] DB write failed: {db_exc}", file=sys.stderr)

            _dispatch_alerts_for_rows(rows, background_tasks)

        findings_count = len(enriched)
        return {
            "status": "completed",
            "target": str(resolved),
            "findings_count": findings_count,
            "findings": enriched,
            "summary": (
                f"Audit complete: {findings_count} compliance violation{'s' if findings_count != 1 else ''} identified."
                if findings_count > 0
                else "Audit complete: no violations detected. Target appears compliant."
            ),
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/integrations/webhooks")
async def get_webhooks() -> Dict[str, Any]:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute("SELECT id, url, min_severity FROM webhooks").fetchall()
            webhooks = [{"id": r[0], "url": r[1], "min_severity": r[2]} for r in rows]
            return {"status": "ok", "webhooks": webhooks}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.post("/api/integrations/webhooks")
async def save_webhook(req: WebhookModel) -> Dict[str, Any]:
    _validate_webhook_url(req.url)
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO webhooks (url, min_severity) VALUES (?, ?) "
                "ON CONFLICT(url) DO UPDATE SET min_severity=excluded.min_severity",
                (req.url, req.min_severity)
            )
            conn.commit()
        return {"status": "success", "message": "Webhook saved"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.post("/api/integrations/test")
async def test_webhook(req: WebhookTestModel, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    _validate_webhook_url(req.url)
    finding_dict = {
        "vulnerability_type": "Test Alert - AntiFine System Check",
        "severity": "CRITICAL",
        "compliance_tags": "None",
        "remediation_guidance": "Ignore this alert. It is a test."
    }
    background_tasks.add_task(dispatch_security_alert, finding_dict, req.url)
    return {"status": "success", "message": "Test alert dispatched"}

@app.get("/api/scan/iac/export/sarif")
async def export_iac_sarif() -> Dict[str, Any]:
    """Export all open IaC findings in SARIF 2.1.0 format."""
    try:
        from src.reporting.sarif_exporter import generate_sarif
        if not DB_PATH.is_file():
            return generate_sarif([])
            
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT vulnerability_type, severity, compliance_framework, target_path "
                "FROM scan_results WHERE status='OPEN'"
            ).fetchall()
            
        findings = []
        for row in rows:
            vuln_type = row[0]
            severity = row[1]
            fw = row[2]
            target_path = row[3] if len(row) > 3 and row[3] else "project-root"
            
            from src.scanners.compliance_mapper import get_finding_metadata
            meta = get_finding_metadata(vuln_type)
            
            findings.append({
                "vulnerability_type": vuln_type,
                "severity": severity,
                "compliance_framework": fw,
                "frameworks": meta["frameworks"],
                "remediation": meta["remediation"],
                "target": target_path,
            })
            
        sarif_report = generate_sarif(findings)
        return sarif_report
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/report/generate")
async def generate_reports() -> Dict[str, Any]:
    """Trigger the generation of both Markdown and SARIF reports."""
    results = {}
    
    try:
        md_path, md_count = generate_report()
        results["markdown"] = {"status": "success", "file": str(md_path), "findings": md_count}
    except Exception as exc:
        results["markdown"] = {"status": "error", "message": str(exc)}
        
    try:
        code = export_to_sarif("results.sarif")
        if code == 0:
            results["sarif"] = {"status": "success", "file": "results.sarif"}
        else:
            results["sarif"] = {"status": "error", "message": f"SARIF exporter returned non-zero code: {code}"}
    except Exception as exc:
        results["sarif"] = {"status": "error", "message": str(exc)}
        
    return {"status": "completed", "results": results}


# ── Execution ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
