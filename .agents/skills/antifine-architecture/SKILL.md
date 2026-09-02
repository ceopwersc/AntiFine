---
name: antifine-architecture
description: Comprehensive knowledge base containing the architecture, scanning logic, and state of the AntiFine IaC project. Read this to understand the processes and code structure of AntiFine.
---

# AntiFine Architecture & Process Knowledge Base

This skill provides a deep dive into the AntiFine IaC scanning tool. Use this context when building new scanners, updating rules, or fixing CI/CD issues.

## 1. Core Architecture
- **Orchestrator**: Python 3 backend using FastAPI (`src/api/server.py`) and a headless CLI gating script (`src/cli/gate.py`).
- **Data Model**: All scanners return a unified `Finding` dataclass (defined in `src/models/finding.py`) to eliminate type conflicts.
- **Scanner Engine**: `src/scanners/iac_audit.py` dispatches files to specific analyzers (`analyze_dockerfile`, `analyze_terraform`, `analyze_kubernetes`, `analyze_generic_secrets`).
- **Secret Scanner**: `src/scanners/secret_scanner.py` centrally handles high-confidence vendor regexes and character-set adjusted Shannon entropy filtering.
- **Compliance Mapper**: `src/scanners/compliance_mapper.py` translates findings into rich structures with frameworks (e.g., CIS Benchmarks, NIST SP 800-190) and remediation guidance.
- **Reporting**: `src/reporting/sarif_exporter.py` translates findings to OASIS SARIF v2.1.0 JSON format for CI/CD ingestion, injecting compliance framework and remediation metadata natively.
- **Frontend Workspace**: React/Vite application (`frontend/`) heavily utilizing Tailwind CSS (dark-mode cybersecurity aesthetic) and Lucide icons. `Dashboard.tsx` serves as an interactive Remediation Workspace with real-time KPI filtering, on-demand scanning, and a slide-over code remediation drawer.

## 2. CI/CD & Gating (`src/cli/gate.py`)
- The primary automated gate runs headlessly via `python -m src.cli.gate --file <path> --fail-on <severity>`.
- The CLI safely parses the unified `Finding` model to calculate compliance scores and blocks builds accordingly.
- Headless execution is protected by lazy-loading the Tkinter/customtkinter GUI in `src/main.py`.

## 3. Scanner Pipelines
### Dockerfile
- Enforces multi-stage build awareness.
- `USER root` is informational in intermediate stages but highly restricted in the final stage.
- Only the final runtime stage requires a `HEALTHCHECK`.

### Kubernetes
- Uses `yaml.safe_load_all()` for structural parsing of multi-document manifests.
- Traverses `Pod`, `Deployment`, `DaemonSet`, `Job`, etc. to find the `PodSpec`.
- Enforces the **PSS Restricted Profile** (CRITICAL: privileged container/host namespaces; HIGH: dropping capabilities; MEDIUM: read-only filesystem/resource limits).

### Terraform
- Uses `python-hcl2` for native structural parsing of `.tf` ASTs.
- Enforces high-risk AWS resource constraints:
  - **aws_security_group**: Restricts `0.0.0.0/0` ingress to sensitive ports (22, 3389) (CRITICAL).
  - **aws_db_instance**: Blocks `publicly_accessible = true` (CRITICAL).
  - **aws_s3_bucket**: Requires embedded or companion Server-Side Encryption (HIGH) and Public Access Block (HIGH).

### Secrets
- Scans YAML/HCL string values and generic config files (`.env`, `.conf`, `.json`).
- Ignores UUIDs, SHA hashes, and Docker ARGs to reduce false positives using a highly tuned Shannon entropy filter.

## 4. Agent Instructions
- **Continuous Documentation**: You MUST always update `README.md` and any relevant skills files (like this one) after every prompt to ensure documentation stays perfectly in sync with the codebase.
- **Committing**: After successful tests, use `git add <files>` and `git commit -m "Auto-commit: <desc>"`. DO NOT use `git add .` or commit `.env` or local DB files.
