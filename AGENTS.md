# AntiFine agent handoff

AntiFine is a local-first infrastructure-security workstation. It
deterministically scans Terraform, Dockerfiles, Kubernetes YAML, and supported
configuration files; persists findings locally; maps findings to supported
compliance metadata; previews and applies narrow allowlisted remediations; and
exports reports/SARIF. Optional local Ollama explains existing findings and
answers bounded questions.

## Non-negotiable boundaries

- The deterministic scanner is authoritative for findings, severity,
  compliance mappings, and remediation eligibility.
- AI/Ollama is optional and advisory. It cannot scan, modify files, execute
  commands, change severity/compliance/remediation, create mappings, or approve
  fixes.
- Remediation is deterministic, allowlisted, backup-first, and followed by a
  deterministic rescan. A fix is verified only when no finding remains.
- Raw secrets may exist temporarily during scanner detection, but must not
  reach SQLite, APIs, browser state, reports, SARIF, logs, RAG, or Ollama.
- Read `DESIGN.md` before frontend work. Do not change application behavior
  while editing this handoff.

## Architecture

- Backend: FastAPI app at `src/api/server.py`, normally started with
  `python -m uvicorn src.api.server:app --host 127.0.0.1 --port 8000`.
- Frontend: React/Vite/TypeScript under `frontend/src/`, normally started with
  `npm run dev -- --host 127.0.0.1 --port 5173`.
- Persistence: SQLite initialized by `database/setup.py`; default scan table
  is `scan_results`.
- Scanners: `src/scanners/` return `src/models/finding.py::Finding`.
- Remediation: `src/scanners/remediation.py` performs only supported,
  deterministic Terraform, Dockerfile, and Kubernetes edits.
- Reporting: `src/reporting/generate.py` renders Markdown;
  `src/reporting/sarif_exporter.py` emits SARIF 2.1.0.
- AI: `src/services/ollama_service.py`, `src/services/ai_explanation.py`,
  `src/services/remediation_explanation.py`, `src/ai/context_builder.py`,
  `src/ai/retriever.py`, and `src/ai/knowledge/`.

## Current state

A01–A16 remediation is implemented; see `docs/SECURITY_REMEDIATION.md` for the matrix, actual validation and remaining platform/integration limits.

- Security boundaries: authenticated loopback HTTP; explicit Host/Origin checks; private expiring uploads; reparse-safe paths; bounded isolated scanners; DNS-pinned allowlisted webhooks.
- Findings: explicit rule IDs, opaque file/finding IDs, resource locators, source regions/digests, scan coverage, transactional lifecycle and immutable run evidence (schema v3).
- Remediation: only backend finding IDs and current preview IDs authorize exact scalar fixes; immutable private backups; atomic writes; rescan/persistence and rollback. Unsafe generic Docker fixes are manual-only.
- Reporting: stable SARIF identities/regions and private authenticated Markdown evidence; no PDF implementation. Mappings never establish certification.
- Frontend: typed identities, reloadable persisted findings, split workflow components, visible preview failure, gated Apply, dialog keyboard support and responsive checks.
- Tests: isolated pytest and real Playwright harnesses exist. CI runs backend/security/CLI checks, frontend lint/typecheck/build and repeated browser workflows.

Raw source and backups must remain outside frontend/static roots. Never use redacted display paths to locate files. Reject unsupported or stale remediation rather than falling back to free-text rule titles. AI remains advisory and cannot approve or apply changes.

Existing user artifacts `DESIGN.md`, `compliance_report.md`, `results.sarif` and real databases must be preserved. Repository test fixtures are synthetic only. Do not assert live webhook/Ollama verification, full PSS/framework coverage or remote CI results from offline/local tests.

## Validation

From the repository root:

```bash
python -m pytest -q
cd frontend
npm run lint
npm run build
npm run test:e2e -- --repeat-each=2
```

Use temporary synthetic fixtures only. Never use real credentials or send
secret-containing source to Ollama.

## Project guidance

Read the relevant skill before specialized work:

- `.github/skills/iac-security/SKILL.md`
- `.github/skills/security-code-review/SKILL.md`
- `.github/skills/security-e2e-testing/SKILL.md`
- `.github/skills/compliance-review/SKILL.md`
- `.github/skills/secret-security/SKILL.md`
- `.github/skills/ai-security/SKILL.md`
- `.github/skills/kubernetes-security/SKILL.md`
- `.github/skills/cloud-security/SKILL.md`

`DESIGN.md` is authoritative for frontend visual and interaction decisions.
`.github/copilot-instructions.md` contains the project-wide engineering
guardrails. See `docs/CODEX_HANDOFF.md` for the detailed architecture and
historical phase record.
