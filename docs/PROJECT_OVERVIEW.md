# AntiFine project overview

Reviewed: 30 October 2026. Application baseline: Sprint 1, commit [`e0da954`](https://github.com/ceopwersc/AntiFine/commit/e0da954be83e2b5eeea8e5b30da584bbcbba1f61).

## 1. What is AntiFine?

AntiFine is a local infrastructure-security workstation for developers and small DevOps teams. It reads supported infrastructure configuration files, identifies selected security risks, explains the affected source and resource, previews narrow deterministic corrections, and records the result of verification after an approved change.

Its central workflow is:

**Import → Scan → Investigate → Preview → Approve → Apply → Verify → Export evidence**

Infrastructure as Code (IaC) means describing infrastructure in files, such as Terraform resources, Kubernetes manifests and Dockerfiles. AntiFine checks those files before deployment or during a source review. For example, it can identify an RDS declaration with public accessibility enabled or a Kubernetes container explicitly running in privileged mode.

The deterministic scanner uses programmed rules and parsers. It owns findings, severity, compliance mappings and remediation eligibility. Optional AI explains existing evidence; it has no authority to approve or apply an edit.

## 2. What problem does it solve?

A team reviewing infrastructure needs answers to several connected questions:

- Which supported source settings deserve attention?
- Which file and resource produced each finding?
- Why does the setting matter, and what should the developer change?
- Can the proposed change be reviewed before any source is modified?
- Did the change actually remove the original finding under the implemented checks?
- What evidence can be retained for an engineering or security review?

AntiFine brings those steps into one local application. Its value is the connection between a finding, an exact proposed change, explicit operator approval, a recoverable original and a recorded deterministic rescan.

The results describe recorded source checks. They do not prove the security of a deployed cloud environment, establish compliance certification or guarantee that a team will avoid regulatory penalties.

## 3. Who is it for?

The initial intended customer is an engineering team with approximately 5–30 developers, AWS infrastructure managed through Terraform, GitHub-based development and limited dedicated DevSecOps support. This is the product's target audience, not a statement about an existing customer base.

Practical users include developers reviewing an infrastructure change, DevOps engineers checking a project before deployment, and security engineers collecting traceable evidence of supported checks and corrections. The browser workstation serves interactive investigation; the command-line severity gate can serve automated checks.

The current deployment model is one trusted local operator. Shared organizational accounts, enterprise identity, multi-user permissions and public hosting are outside the implemented model.

## 4. What can it scan?

| Input | Implemented checks | Interpretation and limits |
|---|---|---|
| Terraform `.tf` | Selected unrestricted IPv4/IPv6 administrative or all-protocol AWS ingress, public RDS configuration, missing recognized S3 encryption/public-access-block declarations, and parsed-value secrets | Static source analysis. No Terraform plan, module/variable resolution, provider execution or deployed-state assessment. A source finding does not establish actual internet reachability. S3 checks inspect recognized configuration/reference presence. |
| Dockerfiles | Explicit root or missing user, selected user/group syntax, unpinned/latest image references, missing or disabled final-stage healthchecks, and selected ENV/ARG secrets | No image build, inherited-image inspection, account-existence proof or healthcheck execution. Intermediate build stages can produce informational findings. |
| Kubernetes YAML | Selected host namespaces, privileged containers, privilege escalation, non-root settings, writable root filesystem, capabilities, seccomp, resource limits and secrets | Supports recognized workload structures and regular/init/ephemeral containers. Coverage is a selected policy set, not complete Kubernetes Pod Security Standards coverage or a live cluster assessment. |
| JSON, `.env`, `.env.*`, `.conf` | Supported nested strings, assignments, vendor credential signatures and entropy heuristics | Detection is bounded to implemented parsers and patterns. Heuristics can have false positives and false negatives. |

Secret signatures include implemented AWS key forms, GitHub tokens, selected Slack tokens and private-key headers. Detecting a pattern does not prove a credential is active. Credential revocation and rotation remain external operator tasks.

Each scan records file coverage, including evaluated, unsupported and error states, with attempted/evaluated rule families where available. A completed scan means the implemented evaluation finished; findings can still remain. Unsupported input and parser failure must not become a silent security pass.

The CLI fails incomplete or unsupported coverage by default. `--allow-unsupported` explicitly chooses a supported-files-only decision, still requiring at least one evaluated file, complete enumeration and no evaluation errors. The severity threshold continues to apply.

## 5. How does a real workflow work?

1. **Import or select source.** Import files or a project directory into private local storage, or select an authorized server-local path. Directory imports preserve relative paths, including files with identical basenames.
2. **Scan.** Bounded worker processes parse supported files and apply deterministic rules. The backend assigns finding, file, rule and scan identities and records coverage.
3. **Investigate.** Search or filter by severity, file identity, status and rule family. Open the finding drawer for its resource, location, explanation, sanitized evidence, guidance, supplied mappings and verification state.
4. **Preview.** For an eligible finding, review a sanitized source excerpt and unified diff. The preview identifies the exact source version, resource and rule.
5. **Approve.** The operator explicitly approves the displayed change. The backend also requires approval; a client-side checkbox alone is not the authorization boundary.
6. **Apply safely.** The backend checks the persisted finding and preview, validates source and candidate digests, obtains the file lock, creates an immutable private backup and performs an atomic replacement.
7. **Verify.** The modified file is reparsed and rescanned. The original finding must disappear, the file must actually be evaluated and no new finding may be introduced. Failed verification attempts a safe rollback and records failure.
8. **Retain evidence.** Persisted results survive browser reloads. Markdown and SARIF exports include supported finding/coverage data and recent remediation evidence with backup and verification scan identifiers.

### Example: an RDS source setting

This scan-only example is an incomplete Terraform declaration:

```hcl
resource "aws_db_instance" "customer_demo" {
  publicly_accessible = true
}
```

The implemented `terraform.public-database` rule identifies the resource and offers this narrow correction when its exact source preconditions are satisfied:

```diff
-  publicly_accessible = true
+  publicly_accessible = false
```

The operator reviews and approves the edit before it is applied. A complete rescan with zero remaining findings verifies the file. If the selected finding disappears but another finding remains, the recorded outcome is **resolved with findings** and `verified` remains false. Changing this source setting does not deploy Terraform or change an existing AWS database.

Importing a project creates a private copy. Fixing that copy does not update the original checkout. Choosing a server-local path instead applies an approved edit to the actual authorized file.

## 6. Which fixes are automatic?

| Finding/source condition | Current automatic correction |
|---|---|
| Supported Terraform RDS `publicly_accessible = true` | Change the selected observed boolean to `false` |
| Supported Kubernetes `securityContext.privileged: true` | Change the selected observed boolean to `false` |
| Supported explicit Kubernetes `securityContext.allowPrivilegeEscalation: true` | Change the selected observed boolean to `false` |

Missing fields, ambiguous or shared YAML source, S3 and ingress findings, Docker user/healthcheck findings and secret findings require manual action. Automatic remediation is deliberately limited to allowlisted edits that can be derived and targeted safely.

A preview is bound to both source and candidate digests. If the source changes after preview, apply is rejected and the operator must rescan and review again. A finding title or a redacted display path cannot authorize a write.

## 7. How is it built?

| Layer | Technology and responsibility | Main source |
|---|---|---|
| Browser interface | React, TypeScript, Vite and Tailwind; import, investigation, review, approval and exports | [frontend/src](../frontend/src/) |
| Local API | Python, FastAPI, Pydantic and Uvicorn; request validation, session authorization and orchestration | [src/api](../src/api/) |
| Deterministic analysis | Terraform HCL/Lark, bounded YAML/JSON handling, Docker parsing and secret rules | [src/scanners](../src/scanners/) |
| Application services | Filesystem boundaries, private workspaces, worker limits, scan lifecycle and approved remediation | [src/services](../src/services/) |
| Persistence | SQLite with additive schema v4 migrations and transactional evidence updates | [scan_repository.py](../src/services/scan_repository.py), [database](../database/) |
| Reporting | Markdown evidence and SARIF 2.1.0 for downstream code-scanning tools | [src/reporting](../src/reporting/) |
| Optional explanation | Local Ollama, sanitized context and retrieval from bundled documentation | [src/ai](../src/ai/), [ollama_service.py](../src/services/ollama_service.py) |
| Validation | pytest, JSON Schema, Oxlint, TypeScript, Playwright and GitHub Actions | [tests](../tests/), [browser tests](../frontend/tests/e2e/), [CI workflow](../.github/workflows/security.yml) |

The browser sends requests through Vite's local `/api` proxy. FastAPI delegates source evaluation to bounded child processes; the parent persists the results. The remediation service reproduces the selected finding and uses the deterministic edit engine. The reporting layer reads persisted evidence.

There is no need for a Terraform executable, Docker daemon, Kubernetes cluster or cloud account for core source scanning. Supported runtime targets are Python 3.12/3.14 and Node.js 24.

## 8. What does the application remember?

SQLite separates several kinds of state:

- `scan_results`: current finding records and lifecycle state.
- `scan_runs`: identifiable scan runs and coverage.
- `scan_evidence`: independent per-run finding snapshots.
- `remediation_runs`: immutable approval, pending-verification and final outcome events.

Findings include machine-readable rule IDs, opaque file/finding IDs, source locations/digests and resource metadata. Supported Terraform resource-address keys retain finding identity when declarations are reordered within the same workspace/file. Reimporting a project creates a new workspace identity.

The interface distinguishes open findings, automatic-fix availability, manual action, pending verification, verified resolution, resolution with remaining findings and failed verification. A later scan can also reopen a finding. These states describe recorded evidence rather than continuously monitored live infrastructure.

Source imports, previews, original-byte backups and generated reports live outside frontend/static roots. By default, private storage is under `%LOCALAPPDATA%/AntiFine` on Windows or `~/.local/share/AntiFine` elsewhere. The default database is the repository's local `antifine.db`; environment variables can change these locations.

Imports expire after 24 hours and previews after ten minutes. Backups remain until operator archival. Recent history and remediation API/export collections are bounded to 100 records; generated report retention is manual.

## 9. What role does AI play?

Ollama can explain an existing finding, discuss an existing deterministic preview and answer bounded questions using supplied evidence and bundled knowledge. It is optional; deterministic scanning and supported fixes work with AI disabled.

AI cannot create authoritative findings, change severity or mappings, approve an edit, execute commands, modify source or declare a verification result. Backend finding identity and preview validation remain authoritative even if the caller submits misleading display text.

AI output is advisory prose. Its accuracy and availability are separate from scanner correctness. Sprint 1 security tests used mocked model responses; live Ollama generation was not established by those tests.

## 10. How does it protect source and secrets?

The application includes authenticated loopback HTTP, explicit Host/Origin validation, authorized workspace paths, Windows reparse/link and path-escape rejection, private expiring uploads, request/file quotas and bounded scanner processes.

Supported downstream boundaries apply centralized sanitization before displaying or persisting sensitive text. Findings and exports carry safe metadata rather than credential values. Original source bytes necessarily remain in selected files, private imports and backups, so those local artifacts still require protection. Conservative redaction is not a guarantee for every arbitrary hostile string.

Approved edits use source-version checks, private immutable backups, atomic replacement and deterministic verification. A pending event is recorded before the source write; successful final evidence commits with the rescan. Rollback avoids overwriting a concurrent outside edit when it cannot safely restore the original.

Optional webhooks require allowlisted HTTPS destinations, validated public DNS answers, pinned delivery addresses and redirect/proxy restrictions. The older SSRF probing surface makes active network requests. Core offline IaC analysis does not require these integrations.

These controls support a trusted local workstation. They do not establish isolation from an administrator or hostile process running under the same OS account, and the current application is not configured for public multi-user hosting.

The [A01–A16 remediation record](SECURITY_REMEDIATION.md) describes the repository's audit fixes, regression evidence and remaining platform/integration limits. It should not be interpreted as independent certification.

## 11. How mature is the project?

The assessment supported by the reviewed implementation is **a functional early MVP with a tested local end-to-end workflow**. Its strongest area is controlled remediation: a developer can connect a finding to a precise proposed edit, an explicit approval, a recoverable original and a persisted rescan result.

Other strengths are separation of deterministic authority from AI, explicit partial/error coverage, source/resource identity, durable evidence and tests that exercise real browser/API/filesystem behavior.

The largest gaps concern analysis breadth, recovery and the lifecycle of imported projects. A controlled evaluation against representative repositories would help establish usability and false-positive rates. Existing automated tests do not establish customer adoption, market demand, broad production readiness or certification.

### Recorded validation for the Sprint 1 baseline

| Check | Recorded outcome |
|---|---|
| Local backend/security/CLI/migration suite | 129 passed, one Windows symbolic-link privilege skip; two third-party TestClient/AnyIO deprecation warnings |
| Real browser workflows | 20 passed: ten cases repeated twice, with no failed or flaky cases in the final run |
| Frontend lint, TypeScript and production build | Passed |
| Headless CLI compatibility gate | Passed |
| Dependency checks | `pip check` passed; `npm audit` reported zero vulnerabilities in that verification run |
| Remote GitHub CI for `e0da954` | All five jobs passed: Linux/Windows backend jobs on Python 3.12/3.14 and the Linux browser job |

The [recorded GitHub Actions run](https://github.com/ceopwersc/AntiFine/actions/runs/40110846040) belongs to the stated commit. These are historical results, not a new full test execution for this documentation update or a claim about future dependency security. Live Ollama generation and external webhook delivery were not verified by the mocked integration tests.

The workflow tests cover public RDS remediation through evidence export, identical-basename/same-size files, malformed/unsupported input, stale-source rejection and persisted findings/verification after reload. Existing suites also cover hostile paths, parsers, secret boundaries, authorization and scanner limits.

## 12. What still needs development?

| Area | Current limitation and practical effect |
|---|---|
| Terraform understanding | No plan, provider, variable or module evaluation; findings describe selected static source checks |
| Rule coverage | Selected AWS, Docker, Kubernetes and secret checks; no complete framework or deployed-environment assessment |
| Automatic fixes | Only the supported observed booleans above; other findings need an operator-derived change |
| Imported projects | Fixes affect a private copy; there is no deliberate export-back workflow to update the original checkout |
| Recovery | Backup inspection/restore and quota archival are manual; interrupted pending operations require review |
| Project/history management | Reimports create new identities, histories are bounded and current exports are not full historical snapshot exports |
| Evidence management | Unsigned artifacts, manual report retention, no PDF implementation or complete report-browsing UI |
| Shared operation | No enterprise SSO/RBAC, hosted multi-user isolation or supported public deployment |
| Commercial packaging | Billing and enterprise administration are deferred; the README records that licensing is unspecified and no LICENSE file is present |

The immediate product direction in the [roadmap](PRODUCT_ROADMAP.md) is recovery and project lifecycle: backup inspection/restore, interrupted-operation reconciliation, clearer expired-import handling, project-scoped history and deliberate export of approved imported changes back to the operator's repository.

Representative project pilots can then measure false positives, coverage boundaries and time from finding to verified correction. Broader rules should retain exact identity, safe failure states and meaningful regression evidence.

## 13. How can someone try it?

Follow the [README installation and quick start](../README.md#quick-start). The standard local endpoints are:

- Workstation: <http://127.0.0.1:5173>
- Backend health: <http://127.0.0.1:8000/api/health>

From the repository root, start the API in a Python environment with the pinned dependencies:

```bash
python -m uvicorn src.api.server:app --host 127.0.0.1 --port 8000 --no-access-log
```

In a second terminal, start the frontend:

```bash
npm --prefix frontend run dev -- --host 127.0.0.1 --port 5173 --strictPort
```

Open **Scan → Try safe Terraform demo**. It creates private copies of the bundled [synthetic Terraform project](../examples/terraform-workflow/README.md). Inspect the public database finding, review the diff, explicitly approve it, apply, verify, reload and download evidence. The fixture is incomplete and intended for scanning only; do not deploy it.

For an automated source check, the maintained CLI accepts a severity policy:

```bash
python -m src.cli.gate --file examples/terraform-workflow/dev/main.tf --fail-on HIGH
```

This vulnerable example is expected to fail the gate. A gate success means evaluated supported files met that policy; it is not a compliance certificate.

## 14. Further reading

- [README](../README.md): supported installation, configuration, CLI/API contracts and operating limits.
- [Product roadmap](PRODUCT_ROADMAP.md): Sprint 1 scope, verification, next priorities and deferred capabilities.
- [Engineering handoff](CODEX_HANDOFF.md): module ownership, trust boundaries and compatibility.
- [Security remediation record](SECURITY_REMEDIATION.md): A01–A16 implementation matrix and historical evidence.
- [Design system](../DESIGN.md): workstation interaction and visual principles.
