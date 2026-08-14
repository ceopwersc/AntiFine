"""FastAPI Server for AntiFine Core Engine.

Exposes the AntiFine Python engine capabilities as a local REST API
for decoupling the frontend from the core execution logic.
"""

import sqlite3
import sys
from pathlib import Path
from typing import Dict, Any

from fastapi import FastAPI, HTTPException
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
from src.scanners.compliance_mapper import map_finding_to_framework
from src.reporting.generate import generate_report
from src.reporting.sarif_exporter import export_to_sarif


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


# ── Endpoints ───────────────────────────────────────────────────────────────

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
async def run_ssrf_scan(req: SSRFScanRequest) -> Dict[str, Any]:
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
                
        return {"status": "success", "message": f"SSRF scan completed for {req.target_url}"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/scan/iac")
async def run_iac_scan(req: IaCScanRequest) -> Dict[str, Any]:
    """Execute the IaC scanner against a local file or directory."""
    try:
        findings = run_iac_audit(req.target_path, persist=False)
        rows = []
        for vuln_type, severity in findings:
            framework = map_finding_to_framework(vuln_type)
            rows.append((1, vuln_type, severity, "OPEN", framework))
            
        if rows:
            with sqlite3.connect(DB_PATH) as conn:
                conn.executemany(
                    "INSERT INTO scan_results "
                    "(target_id, vulnerability_type, severity, status, compliance_framework) "
                    "VALUES (?, ?, ?, ?, ?)",
                    rows,
                )
                conn.commit()
                
        return {"status": "success", "message": f"IaC scan completed for {req.target_path}"}
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
