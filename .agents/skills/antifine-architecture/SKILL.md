---
name: antifine-architecture
description: Comprehensive knowledge base containing the architecture, scanning logic, and state of the AntiFine IaC project. Read this to understand the processes and code structure of AntiFine.
---

# AntiFine Architecture & Process Knowledge Base

This skill provides a deep dive into the AntiFine IaC scanning tool. Use this context when building new scanners, updating rules, or fixing CI/CD issues.

## 1. Core Architecture
- **Orchestrator**: Python 3 backend using FastAPI (`src/api/server.py`) and a headless CLI gating script (`src/cli/gate.py`).
- **Scanner Engine**: `src/scanners/iac_audit.py` dispatches files to specific analyzers (`analyze_dockerfile`, `analyze_terraform`, `analyze_kubernetes`, `analyze_generic_secrets`).
- **Secret Scanner**: `src/scanners/secret_scanner.py` centrally handles high-confidence vendor regexes and character-set adjusted Shannon entropy filtering.
- **Compliance Mapper**: `src/scanners/compliance_mapper.py` translates findings into rich structures with frameworks (e.g., CIS Benchmarks, NIST SP 800-190) and remediation guidance.
- **Reporting**: `src/reporters/sarif_exporter.py` translates findings to OASIS SARIF v2.1.0 JSON format for CI/CD ingestion.

## 2. CI/CD & Gating (`src/cli/gate.py`)
- The primary automated gate runs headlessly via `python -m src.cli.gate --file <path> --fail-on <severity>`.
- The CLI parses a **Union** of finding types: `tuple[str, str]` (legacy scanners) and `dict` (rich scanners like Kubernetes). It handles this safely to calculate scores.
- Headless execution is protected by lazy-loading the Tkinter/customtkinter GUI in `src/main.py`.

## 3. Scanner Pipelines
### Dockerfile
- Enforces multi-stage build awareness.
- `USER root` is informational in intermediate stages but highly restricted in the final stage.
- Only the final runtime stage requires a `HEALTHCHECK`.

### Kubernetes
- Uses `yaml.safe_load_all()` for structural parsing of multi-document manifests.
- Traverses `Pod`, `Deployment`, `DaemonSet`, `Job`, etc. to find the `PodSpec`.
- Enforces the **PSS Restricted Profile**:
  - `hostPID`/`hostIPC`/`hostNetwork` must not be true (CRITICAL).
  - `securityContext.privileged` must not be true (CRITICAL).
  - `securityContext.readOnlyRootFilesystem` must be true (MEDIUM).
  - `capabilities.drop` must contain `ALL` (HIGH).
  - Dangerous capabilities (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`) must not be added (HIGH).
  - Resource limits (`cpu`, `memory`) must be defined (MEDIUM).
- Returns findings as `dict` objects containing `rule_name`, `severity`, `frameworks`, and `remediation`.

### Secrets
- Scans YAML string values and generic config files (`.env`, `.conf`, `.json`).
- Ignores UUIDs, SHA hashes, and Docker ARGs to reduce false positives using a highly tuned Shannon entropy filter.

## 4. Agent Instructions
- **Updating this Skill**: If you (the agent) modify the architecture, add a new scanner, or change the return types, YOU MUST update this `SKILL.md` file to reflect the new state so future agents retain the knowledge.
- **Committing**: After successful tests, use `git add <files>` and `git commit -m "Auto-commit: <desc>"`. DO NOT use `git add .` or commit `.env` or local DB files.
