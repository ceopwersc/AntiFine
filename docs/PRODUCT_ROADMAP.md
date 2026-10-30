# AntiFine product scope and roadmap — Sprints 1–2

AntiFine serves engineering teams of 5–30 developers using AWS Terraform and GitHub with limited dedicated DevSecOps support. The first commercial use case is a trusted local developer workstation: identify a supported source misconfiguration, understand the exact resource, approve a narrow deterministic edit, verify it, and export recorded evidence.

## Implemented vertical slice

1. **Import:** choose files or a project directory, preserving relative paths and identical basenames. The safe demo copies two synthetic Terraform files into private storage. Local-path mode scans only authorized workspace-relative paths and edits actual local source when approved.
2. **Scan:** bounded isolated workers preserve deterministic Docker, Kubernetes, Terraform and secret checks. Each selected file records evaluated, unsupported or error coverage and attempted/evaluated rule families. Unsupported project entries produce partial coverage. CLI gates fail incomplete/unsupported coverage unless the operator explicitly chooses `--allow-unsupported`; errors and empty evaluation still fail.
3. **Investigate:** backend finding/file/rule IDs, Terraform semantic resource keys, source regions/digests, deterministic explanations/evidence and supplied mappings appear in the findings table/drawer. Filters cover severity, file identity, lifecycle status and rule family. Findings and the latest run reload from SQLite.
4. **Preview and approve:** supported RDS and Kubernetes scalar edits produce bounded, sanitized unified diffs with actual source line numbers, file/resource identity and conditions. Approval starts unchecked. The server requires strict `approved: true`, a real open finding and the current preview; titles and display paths cannot authorize writes.
5. **Apply and verify:** source/candidate digests, per-file locking, immutable original-byte backups and atomic writes protect the target. The backend records approval/pending verification before writing. A deterministic file rescan must evaluate the target, remove the original finding and introduce no new finding. Failures attempt safe rollback and persist failure evidence. A zero-finding file records verified resolved; an original finding resolved alongside remaining findings records resolved with findings.
6. **Export:** private authenticated Markdown and SARIF include current open findings, recorded scan coverage and recent immutable remediation history with backup and verification scan IDs. The history view exposes real scan identities and coverage. Reports are evidence of recorded source checks, never certification.

The Sprint 1 SQLite migration v4 adds explanatory metadata, enumeration completeness and remediation events while preserving v3 findings and immutable run snapshots. Older rows need a rescan for new metadata. Fully enumerated directory scans reconcile removed files even when unrelated unsupported entries make coverage partial; failed-file evidence stays open.

## Verification

Local Windows/Python 3.14 and Node 24 validation uses pinned dependencies, temporary synthetic source/databases and the real production frontend preview. The audit baseline had 115 pytest passes and one skip. Sprint validation recorded **129 pytest passes and one Windows symbolic-link privilege skip**, strict frontend lint/typecheck/build passes, and **20 Playwright passes** (10 cases repeated twice, no retries). The Windows short-name and junction tests actually run; the symlink test remains visibly skipped on this account. Final selected-source verification is performed independently of unrelated working-tree changes.

| Required scenario | Executed regression evidence |
|---|---|
| A: public RDS import through export | `test_sprint_workflow.py`, `p0-remediation.spec.ts`, safe demo browser case: exact resource, approval, backup, deterministic rescan, persistence and actual Markdown/SARIF downloads |
| B: identical basenames | Nested same-size `dev/main.tf` and `prod/main.tf`; exact second resource edit leaves its sibling resource and other file unchanged |
| C: malformed, hostile, unsupported input | Existing path/parser/YAML/worker/security suites; mixed malformed/unsupported browser case; CLI coverage policy regressions |
| D: stale preview | Backend rejection plus real browser concurrent source edit, 409 response, unchanged source, disabled Apply and real backend rescan |
| E: reload | Resolved and resolved-with-findings statuses, coverage, finding IDs and immutable verification events survive browser/repository reload |

These results do not establish live Ollama/webhook operation or a remote CI result. Check the specific feature commit's GitHub Actions run separately. Two third-party TestClient/AnyIO deprecation warnings remain visible.

## MVP limitations

- Static selected rules only: no Terraform plan, module/variable resolution, cloud-state evaluation, complete PSS/framework coverage or certification. A resource key identifies a static declaration; duplicate addresses fail closed. Some generic/secret regions remain structural or file-level.
- Automatic fixes cover observed RDS public-access and selected Kubernetes privilege booleans. S3, ingress, Docker, missing fields, ambiguous/shared YAML and secrets need manual action. Secret heuristics can flag prose or other non-secret values; values are withheld and credential rotation is external.
- Imports are private copies that expire after 24 hours and have file/byte quotas. Fixing a copy does not update the original checkout. Reimport creates a new workspace identity. Select a focused infrastructure folder; dependency/cache directories are excluded. Directory discovery is bounded, so large projects can require a narrower scope.
- Private backups retain raw original source. Sprint 2 adds guarded inspection and confirmed original-file restoration with safety copies, real rescans and separate schema-v5 evidence. Archival/quota management and ambiguous interrupted-state reconciliation remain manual. Legacy backups without provable ownership are blocked. See [safe recovery](SAFE_RECOVERY.md). Concurrent outside writes can prevent safe rollback.
- Recent history and remediation exports are bounded to 100 records. Current-finding exports are not full immutable historical snapshot exports; old verification refers to its recorded scan, not live infrastructure. Evidence artifacts are unsigned and report retention is manual.
- One trusted local operator and loopback services only. No hosted multi-user isolation or public reverse-proxy deployment. OS administrator/same-account adversaries are outside the protection model.
- AI is optional and advisory. No live model or external delivery claim is inferred from mocked security tests. PDF, report browsing/retention UI and complete legacy UI parity remain absent.

## Recommended next sprint

The guarded backup inspection/restore vertical slice is implemented in Sprint 2. Next prioritize reviewed interrupted-operation reconciliation, expired-import guidance, project-scoped history and deliberate export-back of approved imported changes. Include real crash/disk-full/concurrent-writer tests and review against the existing deterministic authority, source-version and secret boundaries.

Then pilot with small synthetic and consented Terraform repositories to measure false positives, coverage limits and time from finding to verified fix. Expand source-aware rules only with precise identity, guidance, safe failure states and regression evidence.

## Deferred

Billing, enterprise SSO/RBAC, hosted customer-source storage, cloud account ingestion, broad integrations, Terraform plan/deployment execution, signed evidence/certification claims, autonomous agents and AI-generated automatic patches are outside Sprint 1.
