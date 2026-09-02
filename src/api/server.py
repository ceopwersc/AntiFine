"""FastAPI Server for AntiFine Core Engine.

Exposes the AntiFine Python engine capabilities as a local REST API
for decoupling the frontend from the core execution logic.
"""

import sqlite3
import sys
from pathlib import Path
from typing import Dict, Any

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

# Add CORS middleware for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Local development
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

def _dispatch_alerts_for_rows(rows: list, background_tasks: BackgroundTasks):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            webhooks = conn.execute("SELECT url, min_severity FROM webhooks").fetchall()
    except Exception:
        webhooks = []
        
    if not webhooks:
        return
        
    for row in rows:
        target_id, vuln_type, severity, status, framework = row
        for url, min_severity in webhooks:
            if severity.upper() == "CRITICAL" or severity.upper() == min_severity.upper() or min_severity.upper() == "ALL":
                finding_dict = {
                    "vulnerability_type": vuln_type,
                    "severity": severity,
                    "compliance_tags": framework
                }
                background_tasks.add_task(dispatch_security_alert, finding_dict, url)


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
            # 1. Overall Compliance Score
            failures = conn.execute(
                "SELECT COUNT(*) FROM scan_results WHERE compliance_framework IS NOT NULL AND compliance_framework != 'Unmapped' AND status='OPEN'"
            ).fetchone()[0]
            score = max(0, 100 - (failures * 5))
            
            # 2. Severity Breakdown
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            rows = conn.execute(
                "SELECT UPPER(severity) AS sev, COUNT(*) FROM scan_results WHERE status='OPEN' GROUP BY sev"
            ).fetchall()
            for sev, cnt in rows:
                if sev in counts:
                    counts[sev] = cnt
            severity_breakdown = [
                {"name": "Critical", "value": counts["CRITICAL"]},
                {"name": "High", "value": counts["HIGH"]},
                {"name": "Medium", "value": counts["MEDIUM"]},
                {"name": "Low", "value": counts["LOW"]},
            ]
            
            # 3. Historical Trends (last 7 dates with data)
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

    Resolves relative paths against the project root so that inputs like
    'test_dockerfile' or './k8s/deployment.yaml' work from any CWD.
    Persists every finding (with compliance framework tag) to antifine.db
    and dispatches webhook alerts for HIGH/CRITICAL findings.
    """
    try:
        # ── Resolve path: prefer absolute, fall back to PROJECT_ROOT-relative ──
        target = Path(req.target_path)
        if not target.is_absolute():
            resolved = PROJECT_ROOT / target
        else:
            resolved = target

        if not resolved.exists():
            raise HTTPException(
                status_code=422,
                detail=f"Target path not found: '{req.target_path}' "
                       f"(resolved to '{resolved}'). "
                       f"Provide an absolute path or a path relative to the project root."
            )

        # ── Run the scanner (no internal persistence — we handle it here) ──────
        raw_findings = run_iac_audit(str(resolved), persist=False)

        # ── Enrich each finding with full compliance cross-walk + remediation ──
        enriched: list[Dict[str, Any]] = []
        rows = []
        for vuln_type, severity in raw_findings:
            meta = get_finding_metadata(vuln_type)
            primary_framework = meta["primary_framework"]
            enriched.append({
                "rule_name": vuln_type,
                "severity": severity,
                "compliance_framework": primary_framework,   # kept for UI compat
                "frameworks": meta["frameworks"],            # full cross-walk list
                "description": meta["description"],
                "remediation": meta["remediation"],
            })
            rows.append((1, vuln_type, severity, "OPEN", primary_framework))

        # ── Persist to database ───────────────────────────────────────────────
        if rows:
            try:
                initialize_database()  # ensure DB and tables exist
                with sqlite3.connect(DB_PATH) as conn:
                    conn.executemany(
                        "INSERT INTO scan_results "
                        "(target_id, vulnerability_type, severity, status, compliance_framework) "
                        "VALUES (?, ?, ?, ?, ?)",
                        rows,
                    )
                    conn.commit()
            except sqlite3.Error as db_exc:
                # Log but don't abort — still return findings to the UI
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
            # Join with a dummy target 'project-root' since target path is not in scan_results
            rows = conn.execute(
                "SELECT vulnerability_type, severity, compliance_framework "
                "FROM scan_results WHERE status='OPEN'"
            ).fetchall()
            
        findings = []
        for vuln_type, severity, fw in rows:
            findings.append({
                "vulnerability_type": vuln_type,
                "severity": severity,
                "compliance_framework": fw,
                "target": "project-root"
            })
            
        sarif_report = generate_sarif(findings)
        
        # FastAPI will automatically serialize dict to JSON response with application/json
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
