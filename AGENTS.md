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

### COMPLETED

- Terraform, Dockerfile, Kubernetes, generic secret, and SSRF scanning paths.
- Backup-first allowlisted remediation and rescan verification.
- Authoritative multi-framework compliance persistence in
  `scan_results.compliance_frameworks`; legacy primary
  `compliance_framework` remains compatibility-only.
- Non-destructive legacy database migration.
- SARIF and Markdown consumption of persisted mappings without text-based
  compliance reconstruction.
- Centralized secret-boundary sanitization in
  `src/services/secret_boundary.py`, including known credentials,
  conservative high-entropy/context handling, control-character cleanup, and
  safe paths.
- Sanitization at AI, RAG, parser-error, persistence, report, SARIF, and API
  boundaries.
- Backend-backed safe Secret view at `/api/findings/secrets`; values are
  withheld.
- AI/RAG safety rules, local lexical retrieval, bounded request-supplied chat
  history, and no persistent AI memory.
- Workstation UI redesign and Scan → Finding → Drawer → Review Fix → Diff →
  Apply → Rescan → Verified workflow.
- Focused backend suite currently passes; frontend build and lint pass.

### IN PROGRESS

- PR `ceopwersc/AntiFine#1`, branch `ceopwersc-verify-tooling`, is open.
- Current development phase is hardening and verification after compliance and
  secret lifecycle audits.
- Formal Playwright specs are not yet present; browser verification has been
  performed manually against local services.

### KNOWN ISSUES

- No PDF reporting implementation exists; do not claim PDF evidence support.
- Some non-core UI pages/history/analytics remain static or partly
  presentation-driven where no backend contract exists.
- The frontend uses a local in-memory finding model and scan response
  normalization; do not let it invent compliance or compliance status.
- Secret sanitization is conservative and pattern/context based, not a proof
  that arbitrary hostile text is non-secret. Preserve the fail-safe boundary
  when extending it.
- `/api/ai/test` is sanitized but remains an explicit local development/test
  endpoint; do not turn it into a general remote prompt proxy.
- Existing user artifacts `DESIGN.md`, `compliance_report.md`, and
  `results.sarif` may be dirty/untracked. Do not overwrite them casually.

### NEXT PRIORITIES

1. Add a real Playwright test harness with synthetic fixtures and console/
   network assertions for the critical workflows.
2. Replace remaining static presentation pages with evidence-backed API
   contracts or clearly label them unavailable.
3. Continue security review of path handling, parser errors, logging, webhook
   payloads, and all future persistence fields.
4. Keep compliance mappings and secret metadata source-backed when adding
   controls or exporters.

## Validation

From the repository root:

```bash
python -m pytest -q
cd frontend
npm run lint
npm run build
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
