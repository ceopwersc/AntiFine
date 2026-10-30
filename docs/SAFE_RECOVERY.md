# Safe remediation recovery — Sprint 2

Development baseline confirmed on 30 October 2026: `169ee31c49516da44bf113571e4eb728d6caff6a`, on `codex/sprint-1-workflow`. That HEAD includes a documentation commit after the Sprint 1 application baseline `e0da954`; it was not inferred from the overview's older baseline. Recovery work is on `codex/sprint-2-recovery`.

## Existing state traced before implementation

- Approved remediation creates a random opaque backup ID and an immutable private `backups/<id>.bak` containing original bytes. The original quota is 128 MiB; source files are bounded to 2 MiB.
- Pending/final remediation events associate the backup with an operation, finding, file ID, original digest and candidate digest. Legacy events lack a binding to the owning workspace root.
- Apply reproduces a real persisted finding, binds the preview to source/candidate digests, takes `<source>.antifine-lock`, checks paths, uses atomic replacement, rescans and attempts a version-checked rollback on failure.
- A durable pending event can remain after interruption. A stale lock can also remain after process termination. Neither proves that a source change or verification completed.
- The earlier API exposed remediation history and backup IDs, but had no inspection/restore operation. The UI had no backup browser. Recovery and backup archival were manual filesystem tasks.

The implementation adds inspection, confirmed restoration and separate evidence to this workflow. Scanner rules, remediation eligibility and AI authority are unchanged.

## Operator workflow

1. Open **Recovery**. Recent remediation backups show source/resource, operation and backup identity, timestamp, availability and recovery state.
2. Choose **Inspect backup**. Review finding/file/workspace identities, original/remediated/current source digests, availability and the reason restoration is available or blocked.
3. For a restorable backup, inspect the bounded sanitized reverse diff and choose **Review restore**. This creates a ten-minute backend preview bound to that exact backup, owner and current source version.
4. Explicitly confirm that original source is being restored and may reintroduce security findings. The confirmation starts unchecked.
5. Choose **Restore original and rescan**. The backend revalidates all conditions under the existing per-file lock, preserves the current bytes in a separate immutable safety backup, records pending restoration and atomically restores the original.
6. Review the actual deterministic rescan. A restored original can reopen the finding. The outcome is source restoration, never a verified security remediation.

Refreshing or reloading reads persisted evidence. Restoration history shows separate pending, restored, failed and needs-review events. Scan history labels these runs **Restoration rescan**. Markdown and SARIF include restoration history alongside prior remediation evidence.

## API contracts

All routes use existing loopback/Host/Origin/session-or-capability authorization. There is no anonymous backup access, raw backup download, arbitrary path selection or AI restoration endpoint.

| Method | Route | Contract |
|---|---|---|
| GET | `/api/backups` | Latest 100 remediation backups with inspection metadata and current recovery assessment |
| GET | `/api/backups/{backup_id}` | Inspect one backend-known backup, including sanitized reverse diff when reviewable |
| POST | `/api/backups/{backup_id}/restore/preview` | Revalidate inspection and create a current restore preview; no source write |
| POST | `/api/backups/{backup_id}/restore` | Require strict `confirmed: true` and a valid restore `preview_id`; restore and deterministically rescan |
| GET | `/api/restorations` | Latest 100 immutable restoration events |

Restore request:

```json
{"preview_id":"<64 lowercase hexadecimal characters>","confirmed":true}
```

Extra request fields are rejected. Callers cannot supply a target path, workspace override, replacement bytes or a claimed source digest. Preview IDs for remediation and restoration are stored separately and cannot substitute for one another.

Inspection includes `backup_id`, `remediation_id`, `finding_id`, `file_id`, opaque `workspace_id`, sanitized relative `file`, rule/resource labels, timestamp, version digests, `backup_status`, `can_restore`, `state`, `reason`, `warning`, sanitized `changes` and the latest restoration event. It never returns the private backup path or workspace root.

Successful restoration returns `status: "restored"`, a `restoration_id`, original and pre-restore backup IDs, real `scan_id`, coverage, finding count, whether the original finding reopened, `verified: false` and the security warning. HTTP 200 means that restoration and its rescan were recorded; it is not a security pass.

- **401:** existing API authorization failed.
- **404:** malformed or unassociated backup identity.
- **409:** stale/expired review, unsafe source/backup/owner, interrupted operation, unavailable storage or failed restoration/rescan. Inspect the current evidence before another attempt.
- **422:** invalid request fields, non-boolean confirmation or confirmation not explicitly true.

## Safety checks

### Ownership and source identity

A backup must have consistent persisted owner records and an associated backend finding/file identity. New remediation events include workspace identity and a one-way fingerprint of the canonical owning workspace root. Source location comes from backend file identity within that root; display paths never authorize I/O.

Legacy backups remain inspectable. Automatic restoration is blocked when the original workspace-root binding cannot be proven. The implementation does not reconstruct that authority from a display path, current environment or a caller assertion.

### Immutable originals and version checks

The stored original must match its recorded original digest. The live source must match the completed remediation's recorded candidate digest. Restore previews additionally bind operation, finding, file, workspace, root and both versions. Conditions are checked again after acquiring the same lock used by remediation, and atomic replacement rechecks the expected source digest.

Missing, oversized, unreadable, linked or corrupted backup data cannot authorize restoration. Unavailable/expired workspaces and missing targets are blocked; no replacement workspace or new target file is silently created. Already successfully restored backups are not replayed; subsequent remediation creates its own new backup.

Before restoring, the current remediated source is saved as a new immutable safety backup. The original backup is read-only throughout restoration. Both copies count toward the existing backup quota. No raw source is persisted in the event ledger, preview metadata, UI, reports or AI context.

### Verification, failure and rollback

The restoration rescan must completely evaluate exactly the owned file. The restored source digest is checked after scanning. Real findings are persisted transactionally with the final restoration event, including reopened original findings. Reintroduced findings are expected evidence of restoring insecure source; they are never relabeled as successful security remediation.

An ordinary failure attempts to atomically return the file to the pre-restore bytes. Rollback only writes when the current digest still matches the restored original; an outside edit is preserved. A matching unchanged pre-restore version needs no rollback write. The safety backup and original backup remain immutable.

Filesystem validation, digest rechecks, locks and atomic replacement retain the existing Windows/Linux protection model. They are not a formal sandbox against an administrator or hostile same-account process, or a proof that all filesystem races are eliminated.

## Persistence and interrupted operations

Schema v5 adds `restoration_runs` and indexes while preserving schema-v4 findings, run snapshots and remediation events. Existing HTTP remediation contracts retain their behavior and gain ownership metadata on newly recorded events. Finding DTOs gain additive restoration and recovery-state metadata.

Restoration events have independent event IDs and a shared `restoration_id`. Each records the parent remediation, source identity, original/safety backup references, version digests, strict confirmation, outcome and rescan evidence. A pending event is durable before any source write. A completed event and the rescan's finding reconciliation commit together.

| State | Meaning and response |
|---|---|
| `restorable` | Current source, owner and immutable backup match recorded versions; explicit preview/confirmation is still required |
| `restored` | Original source was restored and rescanned; inspect the resulting findings |
| `needs_review` | Safety cannot currently be proven; no restore authorization is issued |
| Latest unresolved `restore_pending` event | No durable final outcome; surfaced as Needs review rather than inferred success. Earlier pending events with a completed final outcome appear as Restoration started in history. |
| `restore_failed` event | Ordinary failure with a recorded safe rollback; a fresh inspection/review can establish whether retry is possible |
| `restore_needs_review` event | Failure could not safely roll back, or source state is otherwise unresolved; further writes are blocked |

Unfinished remediation/restoration events block new automated writes on that file. A read-only rescan does not silently acknowledge an interrupted operation. Stale locks are displayed and are never automatically removed by recovery. There is no automatic destructive crash recovery or UI action that force-clears ambiguous evidence.

## Testing

Synthetic backend regressions cover successful authorized restoration, strict confirmation, unauthenticated access, unknown/cross-backup previews, forbidden paths/overrides, ownership mismatches, changed roots, invalid workspaces, legacy metadata, missing/corrupt backups, expiry, exact LF/CRLF/BOM preservation and nested same-basename imports.

Fault tests interrupt before/after source replacement, fail rescanning/persistence, fail after atomic replacement and inject an outside edit before rollback. They verify durable Needs review states, safety copies, unchanged immutable originals, blocked follow-up writes and restart persistence. Migration tests retain schema-v4 findings and immutable evidence.

Real Playwright workflows cover inspection through confirmed restore, finding reopening, history/reload, actual Markdown/SARIF downloads, stale source, missing/corrupt backups and a service interruption against the harness's private synthetic storage. Dialog keyboard focus and the supported viewport sizes are exercised.

Run the normal backend suite and frontend lint/typecheck/build, then the repeated isolated Playwright suite. These tests do not establish live Ollama/webhook operation or a remote CI result for Sprint 2.

## Remaining limits

- Backups lacking provable owner metadata, expired imports, missing source and stale/ambiguous operations need manual operator review. There is no force-restore or arbitrary-path fallback.
- Recovery is for complete original files from supported deterministic remediation, not arbitrary snapshots, individual hunks or older generic backups.
- Restoration preserves original source bytes, including BOM/newlines. It retains the current file mode through the existing atomic writer rather than reconstructing historical timestamps, ownership or ACL metadata.
- The safety copy can be inspected by an operator in private storage; this slice does not add an automatic redo or restore-from-safety-copy workflow.
- There is no automated acknowledgement/reconciliation of interrupted events or stale locks. Manual review and operational recovery remain necessary for those cases.
- Backup quota exhaustion blocks restoration before a source write. Archival, orphaned safety-copy cleanup and retention remain operator tasks; no backup is silently deleted to make room.
- Recent UI/API evidence collections are bounded to 100 records. This is not comprehensive project lifecycle, signed evidence, historical snapshot export or restore-to-original-checkout functionality.

See the [project overview](PROJECT_OVERVIEW.md), [roadmap](PRODUCT_ROADMAP.md) and [engineering handoff](CODEX_HANDOFF.md) for the surrounding product and trust boundaries.

## Recorded local validation

Validation used an exported Git index with pinned dependencies, isolated synthetic storage, Windows/Python 3.14 and Node 24. The unrelated local Ollama edit was excluded. Results: **157 pytest passes and one Windows symlink privilege skip**, two visible third-party deprecation warnings, strict frontend lint/typecheck/build passes, and **30 Playwright passes** (15 cases repeated twice, no retries, zero final failed or flaky cases).

An initial browser run encountered 11/45-minute execution stalls despite its 45-second test limit; traces and failures were preserved. A complete clean rerun passed, followed by another complete passing run after correcting the historical-pending label and adding its regression assertion. Security checks, preview expiry and test timeouts were retained.

The live workstation database changed while the development services were running before isolated validation. Its current contents were preserved in a private pre-v5 snapshot. The live database remained unchanged during isolated validation, and unrelated user files were retained. Local results do not establish remote CI; merge checks are assessed separately for the pushed commit.

## Files changed in the recovery slice

- [.agents/skills/antifine-architecture/SKILL.md](../.agents/skills/antifine-architecture/SKILL.md)
- [AGENTS.md](../AGENTS.md)
- [README.md](../README.md)
- [docs/CODEX_HANDOFF.md](../docs/CODEX_HANDOFF.md)
- [docs/PRODUCT_ROADMAP.md](../docs/PRODUCT_ROADMAP.md)
- [docs/PROJECT_OVERVIEW.md](../docs/PROJECT_OVERVIEW.md)
- [docs/SAFE_RECOVERY.md](../docs/SAFE_RECOVERY.md)
- [frontend/src/App.css](../frontend/src/App.css)
- [frontend/src/App.tsx](../frontend/src/App.tsx)
- [frontend/src/api.ts](../frontend/src/api.ts)
- [frontend/src/components/ActivityPages.tsx](../frontend/src/components/ActivityPages.tsx)
- [frontend/src/components/RecoveryPage.tsx](../frontend/src/components/RecoveryPage.tsx)
- [frontend/src/types.ts](../frontend/src/types.ts)
- [frontend/tests/e2e/sprint2-recovery.spec.ts](../frontend/tests/e2e/sprint2-recovery.spec.ts)
- [src/api/core_routes.py](../src/api/core_routes.py)
- [src/api/recovery_routes.py](../src/api/recovery_routes.py)
- [src/api/server.py](../src/api/server.py)
- [src/reporting/generate.py](../src/reporting/generate.py)
- [src/reporting/sarif_exporter.py](../src/reporting/sarif_exporter.py)
- [src/services/backup_store.py](../src/services/backup_store.py)
- [src/services/recovery_inspection.py](../src/services/recovery_inspection.py)
- [src/services/remediation_apply.py](../src/services/remediation_apply.py)
- [src/services/restoration_service.py](../src/services/restoration_service.py)
- [src/services/scan_repository.py](../src/services/scan_repository.py)
- [tests/test_recovery.py](../tests/test_recovery.py)
- [tests/test_recovery_interruptions.py](../tests/test_recovery_interruptions.py)
- [tests/test_scan_lifecycle.py](../tests/test_scan_lifecycle.py)
- [tests/test_sprint_workflow.py](../tests/test_sprint_workflow.py)
