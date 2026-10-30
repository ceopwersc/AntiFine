---
name: antifine-architecture
description: Comprehensive knowledge base containing the architecture, scanning logic, and state of the AntiFine IaC project. Read this to understand the processes and code structure of AntiFine.
---

# AntiFine Architecture & Process Knowledge Base

This skill provides a deep dive into the AntiFine IaC scanning tool. Use this context when building new scanners, updating rules, or fixing CI/CD issues.

## 1. Current architecture

Read `docs/CODEX_HANDOFF.md` and `docs/SECURITY_REMEDIATION.md` for the schema-v5 implementation and verified A01–A16 behavior.

`docs/PROJECT_OVERVIEW.md` explains the product purpose, intended users, supported workflow, architecture, recorded validation and maturity limits. Keep its capability claims and dated evidence consistent with the implementation and `docs/PRODUCT_ROADMAP.md`.

`README.md` is the public entry point for verified setup, CLI/API contracts, supported checks, storage/migration behavior and explicit limitations. Keep its coverage claims tied to source: directory discovery inventories unsupported entries with explicit coverage, automatic fixes cover only allowlisted observed booleans, and older CLI/UI surfaces are distinct from the release-verified workstation.

- FastAPI composes thin core/integration routes and optional AI endpoints. Local security middleware requires a per-launch capability and loopback/Host/Origin validation.
- Private workspaces live outside web roots. Filesystem operations reject path escapes, links, junctions, reparse points and ambiguous Windows names, and revalidate reads/writes.
- Windows short-name aliases are canonicalized only after checking original path components for reparse traversal. Real short-name and prefix-sibling filesystem regressions cover this boundary.
- Scan workers have bounded bytes, nodes, depth, documents, file/finding counts, concurrency, wall time, CPU and memory. Deterministic findings have explicit rule IDs, file IDs, resource locators, source regions, digests and stable IDs.
- SQLite schema v5 preserves legacy evidence, adds scan-run history, reconciles evaluated files transactionally, preserves failed-file evidence, and records independent run snapshots and immutable approval/verification events in remediation_runs. The additive v3 migration retains history; enumeration completeness is independent of unsupported-file coverage. Privacy migration scrubs legacy display values and retires credential-bearing integrations without reconstructing mappings.
- Preview/apply uses a real persisted finding plus a current preview ID. A bounded sanitized unified diff binds source and candidate digests. Pending evidence precedes writes; final evidence commits with the rescan; introduced findings trigger rollback. Exact parsed scalar fixes are limited to selected RDS/Kubernetes cases. Docker fixes and shared/ambiguous YAML source are manual-only. Backups are private, immutable and versioned; writes are atomic with deterministic verification and rollback.
- Frontend workflow components and hooks use typed backend identities and persisted reload; client display values never authorize edits.
- SARIF and Markdown use persisted source/mapping/scan evidence; PDF is absent. Mapping and risk heuristics are not compliance certification.
- Ollama explains backend findings and validated previews only. It cannot write source, execute commands, approve fixes or alter deterministic state. History is bounded and not permanently persisted.

## 2. Validation and supported runtime

Python 3.12/3.14 and Node 24 are release-check targets. Install pinned `requirements-dev.lock` and `npm ci`. Run pytest, lint, typecheck, build and repeated Playwright tests. All tests use private temporary data, never the developer database or real credentials. CI covers Windows/Linux backend targets and a Linux browser job. Local tests do not establish remote CI or live model/webhook behavior.

Before release commits, review the index for credentials and generated/private artifacts and validate the selected source independently of unrelated local edits. Preserve unrelated changes; never force-push. Follow an explicit user-supplied commit message when one is provided.

Repository hygiene decisions are recorded in `docs/REPOSITORY_CLEANUP.md`. Generated root reports are untracked while local originals are protected. Never equate ignored state with deletion permission: preserve databases, credentials, legacy uploads, source backups and ambiguous user tools/assets. Keep the maintained security/SARIF/browser suites and their synthetic fixtures.

## 3. API and safety contracts

Uploads use `/api/scan/upload`; scan accepts an authorized relative target or private workspace ID. Preview requires `finding_id`; apply additionally requires `preview_id` and strict boolean `approved: true`. Title-based remediation must remain rejected. `verified` is true only after a complete zero-finding rescan. Preserve distinct INFORMATIONAL severity and explicit unsupported/error coverage.

## 4. Agent Instructions
- **Continuous Documentation**: You MUST always update `README.md` and any relevant skills files (like this one) after every prompt to ensure documentation stays perfectly in sync with the codebase.
- **Committing**: After successful tests, use `git add <files>` and `git commit -m "Auto-commit: <desc>"`. DO NOT use `git add .` or commit `.env` or local DB files.

## 5. Sprint 1 workflow

Terraform rules live in `terraform_rules.py`; explicit rule descriptions/evidence defaults live in `rule_catalog.py`. Resource-address hashes keep supported Terraform finding identities stable when declarations move. Duplicate addresses fail closed. CLI gates reject unsupported/partial input unless `--allow-unsupported` explicitly chooses supported-only coverage with no errors.

`remediation_preview.py` builds bounded review excerpts; `remediation_apply.py` owns approved backup/write/rescan/evidence. `POST /api/scan/demo` copies only the bundled dev/prod fixtures into private storage. `POST /api/findings/{id}/rescan` uses backend file identity. FindingsPanel, FindingDrawer, CoveragePanel and RemediationModal present actual persisted state; source display paths never authorize writes. Approval starts unchecked on each mounted preview. See `docs/PRODUCT_ROADMAP.md` for limitations and validation.

## 6. Sprint 2 recovery

Read `docs/SAFE_RECOVERY.md`. Backup I/O is centralized in `backup_store.py`; new remediation records bind workspace/root ownership. `recovery_inspection.py` resolves backend file identity and version/integrity; `restoration_service.py` requires explicit current-preview confirmation, creates a safety backup, reuses the file lock and atomic write, and persists real rescans with separate `restoration_runs` events. Restore never implies security verification. Legacy/unprovable ownership, interrupted events, stale locks or changed source fail closed as Needs review; no automatic force-clear/reconciliation exists. New Recovery UI/API is additive; schema-v4 evidence is preserved by migration to v5. Keep AI outside recovery authority.
