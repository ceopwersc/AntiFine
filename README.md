# AntiFine

Local security engineering for Terraform, Kubernetes, Dockerfiles and supported configuration files. Findings, severities, mappings and remediation eligibility come from deterministic rules. Optional local Ollama provides advisory explanations and has no write or command tools.

## Runtime and installation

Supported release-check targets: Python 3.12 and 3.14; Node.js 24. The current local verification environment is Windows with Python 3.14 and Node 24. CI also checks Linux.

```bash
python -m venv .venv
# Activate .venv using your shell, then:
python -m pip install -r requirements-dev.lock
cd frontend
npm ci
```

From the repository root, start the API:

```bash
python -m uvicorn src.api.server:app --host 127.0.0.1 --port 8000 --no-access-log
```

In `frontend/`, run `npm run dev -- --host 127.0.0.1 --port 5173` and open http://127.0.0.1:5173. Vite proxies `/api` to the loopback backend. For a production-bundle local check, run `npm run build` followed by `npm run preview -- --host 127.0.0.1 --port 5173`.

The workstation accepts loopback clients only. Its browser establishes a per-launch HttpOnly, SameSite session through `POST /api/session`, with an approved Origin and `X-AntiFine-Request: 1`. Other API routes require the session cookie or an explicitly configured `X-AntiFine-Token`. Native API clients can configure `ANTIFINE_API_TOKEN` in the backend process environment; never put the value in source control. `/api/health` is the sole unauthenticated status endpoint. CORS is not authentication. Public hosting or a remote reverse proxy is unsupported.

## Supported deterministic checks

- Terraform: public IPv4/IPv6 SSH/RDP and all-protocol ingress, public databases, and the implemented S3 encryption/public-access rules. Static source analysis does not evaluate Terraform plans, providers, variables or every cloud control.
- Dockerfiles: effective root user (including user/group syntax), image tags, final-stage healthcheck state, ENV/ARG secrets and intermediate-stage informational findings. `HEALTHCHECK NONE` is disabled. Generic user creation and fake healthchecks are manual-only.
- Kubernetes: supported PodSpecs in Pods, Deployments, ReplicaSets, ReplicationControllers, StatefulSets, DaemonSets, Jobs and CronJobs; regular, init and ephemeral containers; inherited Pod-level non-root/seccomp settings; selected host, privilege, capability, filesystem and resource checks. This is partial PSS coverage, not full certification.
- Secrets: vendor signatures and entropy checks in HCL/YAML, nested JSON objects/arrays, `.env` and `.conf` assignments. Malformed input and unsupported files have explicit coverage/error states. False-positive exclusions and conservative redaction are not proof that arbitrary text cannot contain a secret.

Only evaluated rules produce evidence. A clean result does not certify an entire framework. `INFORMATIONAL` remains distinct. Mappings are persisted metadata, never inferred control passes or a compliance score.

## Scan, review and apply

1. Import files with `POST /api/scan/upload` (`files`, optional JSON `relative_paths`), or select a relative server-local path.
2. Call `POST /api/scan/iac` with `target_path`: a relative path or the returned opaque `workspace_*` ID.
3. Use the backend finding `id` for `POST /api/scan/iac/remediation/preview` (`finding_id`).
4. Inspect the sanitized deterministic diff. Apply through `POST /api/scan/iac/remediate` with `finding_id` and `preview_id`.
5. The backend checks the finding, exact source version and resource, creates an immutable private backup, atomically applies the change and reparses/rescans. A changed source invalidates the preview.

Title-based remediation requests are deliberately rejected with 422. Supported automatic fixes currently change an observed boolean for a selected public RDS instance or a selected Kubernetes privilege flag. Shared YAML source anchors and ambiguous/unsupported cases are manual-only. AI never selects or approves a fix.

An applied change with other findings remaining returns `verified: false`. A file is verified only after a complete deterministic rescan has zero findings. Failed verification restores the original if the source has not concurrently changed. Backups remain recoverable under opaque IDs outside the web root; previous backups are never overwritten.

The CLI is independent of HTTP sessions:

```bash
python -m src.cli.gate --file path/to/source.tf --fail-on HIGH
```

It exits 1 for threshold violations, unsupported input or incomplete evaluation, and 0 for covered files meeting the threshold. Legacy `--min-score` is a risk heuristic, not compliance certification.

## Storage, exports and upgrades

- Default SQLite database: repository `antifine.db`; override with `ANTIFINE_DB_PATH`.
- Authorized local source root: repository root; override with `ANTIFINE_WORKSPACE_ROOT`.
- Private imports/backups/previews/reports: `%LOCALAPPDATA%/AntiFine` on Windows or `~/.local/share/AntiFine`; override with `ANTIFINE_DATA_DIR` outside the checkout. Owner-only POSIX permissions or protected owner/SYSTEM Windows DACLs apply.
- Uploads expire after 24 hours. File, workspace and total import quotas are enforced. Previews expire after ten minutes. Immutable backups have a 128 MiB quota and require deliberate operator archival when full.
- `GET /api/findings` reloads persisted evidence. `GET /api/scan/history` lists real runs, including clean/partial runs and coverage. Successfully evaluated files reconcile previous findings; failed files retain evidence. Same-basename files remain distinct.
- `GET /api/scan/iac/export/sarif` exports current open findings with stable rule IDs, source regions and scan metadata. `POST /api/report/generate` creates private Markdown evidence; authenticated `/api/reports/{filename}` downloads it. Exports do not reconstruct mappings from titles.
- There is no PDF implementation or PDF endpoint.

Schema version 3 adds identities, scan runs and immutable per-run evidence. Legacy findings/mappings are preserved as legacy/manual-only evidence until rescanned. The privacy migration redacts legacy display fields, securely clears replaced SQLite cells and disables credential-bearing legacy webhook URLs. Close older writers before upgrade and keep any operator-required backup in private storage; reconfigure disabled integrations. No developer database is touched by tests.

## Optional AI and integrations

Set `OLLAMA_ENABLED=true`, `OLLAMA_BASE_URL=http://127.0.0.1:11434`, `OLLAMA_MODEL` and `OLLAMA_TIMEOUT` through the process environment or a local ignored `.env`. AI health, general questions, finding explanations and preview explanations are optional. Finding explanations use persisted metadata; remediation explanations require a current preview. Client-supplied severities and fabricated diffs cannot become authoritative. Contradictory completion/severity claims are withheld. Conversation history is bounded and not persisted as permanent memory.

Webhooks require credential-free HTTPS URLs, port 443 and an exact hostname in `ANTIFINE_WEBHOOK_ALLOWLIST` (comma-separated). Every DNS answer must be public; the validated address is pinned for delivery while retaining TLS hostname/certificate validation. Redirects and inherited proxies are not used. Existing credential-bearing URLs must be reconfigured outside AntiFine, such as through a trusted gateway. Real webhook delivery and live model generation are not part of automated tests.

## Validation

```bash
python -m pytest -q
cd frontend
npm run lint
npm run typecheck
npm run build
npx playwright install chromium
npm run test:e2e -- --repeat-each=2
npm audit
```

Playwright launches isolated real backend storage and the built frontend preview. Its workflows cover local and nested imports, preview rejection, apply/backup/rescan, refresh, source confidentiality, keyboard navigation, supported widths, history filters and report errors. The backend suite covers scanner bypasses, hostile YAML, process limits, migrations, redaction, exact/stale remediation, exports and CLI policy.

Release commits include reviewed source, tests, migrations, configuration, dependency locks and documentation. Local credentials, databases, generated evidence, backups and temporary workspaces are excluded; preserve unrelated working-tree edits when preparing a release.

See [the remediation record](docs/SECURITY_REMEDIATION.md) for the A01–A16 matrix and verification limits, [the handoff](docs/CODEX_HANDOFF.md) for module ownership and [DESIGN.md](DESIGN.md) for UI guidance.
