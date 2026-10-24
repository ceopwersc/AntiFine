# AntiFine engineering handoff — 24 October 2026

The A01–A16 implementation replaces the unsafe title/path workflow with backend-owned finding identities, source-bound previews, private immutable backups and deterministic persisted verification. See `docs/SECURITY_REMEDIATION.md` for the full remediation matrix and test evidence.

## Trust boundaries and module ownership

- `src/api/server.py`: application composition, local status, bounded AI routes and the network-scan compatibility route. No import-time database initialization.
- `src/api/security.py`: loopback/Host/Origin checks, per-launch HttpOnly capability sessions, bounded requests, safe JSON serialization and safe operation/status logs. Raw Uvicorn access logging is suppressed.
- `src/api/core_routes.py`: typed scan, finding, preview/apply, history, dashboard and export routes.
- `src/api/integrations_routes.py`, `src/integrations/webhook_policy.py`: explicit destinations, DNS validation, pinned HTTPS and no redirect/proxy inheritance.
- `src/services/filesystem.py`: resolved ancestry, pre-normalization component checks, reparse/link rejection and bounded, revalidated source reads.
- `src/services/workspaces.py`, `private_permissions.py`: private imports, quotas, expiration and POSIX/Windows permissions.
- `src/services/scanning.py`, `scan_worker.py`, `worker_limits.py`: coverage-aware orchestration in killable workers; CPU, wall-time, memory, byte, file and finding bounds.
- `src/services/scan_repository.py`: additive schema v4, transactional current findings and independent scan-run/evidence history; privacy migration for legacy display fields/integrations.
- `src/scanners/iac_audit.py`, `terraform_rules.py`, `rule_catalog.py`, `kubernetes_rules.py`, `structures.py`, `secret_scanner.py`: explicit deterministic rule IDs, exact parsed source spans, bounded YAML and supported secret parsing.
- `src/services/remediation_service.py`, `remediation_preview.py`, `remediation_apply.py`, `src/scanners/remediation.py`: current finding/preview authorization, exact scalar candidate, immutable backups, concurrency guard, atomic write and rollback/verification.
- `src/reporting/`: persisted evidence/mappings, stable SARIF rule IDs/regions and Markdown coverage. PDF is absent.
- `src/services/advisory_guard.py`, AI/context services: optional advisory text, immutable backend evidence, redaction and contradiction handling. AI cannot write source, execute commands or approve remediation.
- `frontend/src/types.ts`, hooks and components: typed backend identities; persistent reload; separate scan, remediation, AI and activity components; visible preview failures and accessible dialogs.

## Contracts and compatibility

`POST /api/scan/upload` returns an opaque private workspace ID. Scan that ID through `/api/scan/iac`. Preview uses `finding_id`; apply uses `finding_id`, `preview_id` and strict `approved: true`. Old free-text title/target remediation calls fail with 422 and must migrate. Never add a title-based compatibility bypass.

Raw filesystem references remain internal. Display paths are redacted and cannot authorize file operations. Finding IDs remain stable for the same workspace/file/rule/resource; previews also bind the exact source digest. Imported-directory findings refer to individual files.

Automatic fixes are limited to selected public RDS booleans and selected Kubernetes privilege booleans. Docker remediation is manual-only until image/user/health preconditions can be established safely. Shared YAML source anchors are manual-only.

`verified` requires a complete file rescan with zero findings. Other remaining findings produce an applied/unverified result. Scan coverage and mappings do not imply compliance certification.

Legacy evidence remains visible but non-actionable until rescanned. Privacy migration redacts legacy text and disables credential-bearing webhook URLs; it does not invent mappings. Tests configure temporary roots/database before imports. Preserve existing user `DESIGN.md`, `compliance_report.md`, `results.sarif` and real databases.

## Supported validation

Python 3.12/3.14 and Node 24 are release-check targets. Use pinned `requirements-dev.lock`, `npm ci`, pytest, lint, typecheck, build and the repeated Playwright suite. CI defines Windows/Linux backend jobs and a Linux browser job. Local Windows verification is recorded in the remediation document; remote CI execution remains a separate release check.

Live Ollama/webhook delivery, formal framework certification, a Terraform plan evaluator, container image builds and PDF exports are not claimed by the test suite. Windows symbolic-link creation may need a privilege absent from a test account; actual junction rejection is tested without that privilege, with POSIX symlink tests available on Linux.

## Sprint 1 extension

Terraform semantic resource keys, unsupported-file/rule-family coverage, a private safe demo, explicit approval and immutable pending/final verification events now support the complete local workflow. The v3-to-v4 migration preserves earlier findings and scan snapshots. Read `docs/PRODUCT_ROADMAP.md` for the current scope, actual validation and deferred work. A pending event after a crash requires operator review; there is no automatic restore or crash recovery UI.
