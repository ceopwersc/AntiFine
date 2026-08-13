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
from src.main import run_audit_web, run_audit_iac
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
    if not DB_PATH.is_file():
        return {"status": "ok", "counts": counts}
        
    try:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT UPPER(severity) AS sev, COUNT(*) "
                "FROM scan_results GROUP BY sev"
            ).fetchall()
            for sev, cnt in rows:
                if sev in counts:
                    counts[sev] = cnt
    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")
        
    return {"status": "ok", "counts": counts}


@app.post("/api/scan/ssrf")
async def run_ssrf_scan(req: SSRFScanRequest) -> Dict[str, Any]:
    """Execute the SSRF scanner against a target URL."""
    try:
        # Trigger the web audit logic asynchronously
        run_audit_web(req.target_url)
        return {"status": "success", "message": f"SSRF scan completed for {req.target_url}"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/scan/iac")
async def run_iac_scan(req: IaCScanRequest) -> Dict[str, Any]:
    """Execute the IaC scanner against a local file or directory."""
    try:
        run_audit_iac(req.target_path)
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
