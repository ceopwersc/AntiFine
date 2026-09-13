---
name: security-e2e-testing
description: Test AntiFine's real browser workflows with Playwright as a senior QA and security engineer.
---

# AntiFine security E2E testing

Load this skill for browser-based verification of AntiFine. A feature is not functional merely because a button renders, an `onClick` exists, a toast appears, or a modal opens. Demonstrate the operation with real interaction, network evidence, visible state, and backend state where appropriate.

## Verification method

For every important action:

1. Navigate to the actual page.
2. Identify the accessible interactive element.
3. Click, type, select, upload, or use the keyboard.
4. Observe the expected network request and response.
5. Observe application state and the visible result.
6. Verify the resulting backend state when the action crosses an API boundary.
7. Collect console errors, page errors, unhandled rejections, and unexpected failed requests.

Do not mark an action successful from UI text alone. Treat 404, 401, 403, 422, 500, timeout, CORS, and malformed-response behavior as test evidence, distinguishing expected validation failures from regressions.

## Application coverage

Cover every actual view/route in the implementation, adapting if the app uses client-side page state:

`/` · `/scan` · `/findings` · `/remediation` · `/compliance` · `/secrets` · `/history` · `/reports` · `/ai` · `/settings`

For every sidebar item, top navigation, breadcrumb, tab, link, or command-palette action, verify navigation, page content, no unexpected console errors, and no unexpected network failures.

## P0 workflows

### Deterministic security workflow

Test with a safe temporary vulnerable fixture:

`Scan → Finding → Investigate → Review Fix → Diff → Apply → Backup → Verification scan → Resolved`

Verify the actual scan and remediation endpoints, request payloads, successful responses, deterministic before/after diff, backup creation, rescan, and finding status change. The UI must not claim success before backend confirmation. `findings_count == 0` or the repository's equivalent deterministic verification is required for Fixed/Verified. Remaining findings must keep the finding open and show explicit failure.

Also verify remediation safety: only the intended fixture changes, unrelated files remain unchanged, arbitrary targets are rejected, backups are created as expected, and failed remediation never produces false success.

### AI workflow

Test:

`Finding → Ask AntiFine → Ollama → explanation`

Also cover finding explanation, remediation explanation, context transfer, bounded conversation history, sources, regenerate, copy, Clear context, and New chat. Verify Ollama available, unavailable, and disabled behavior. AI failure must not break deterministic scanning.

Use synthetic prompt-injection content in Terraform comments, YAML comments, and Dockerfile comments, such as instructions to lower severity or report compliance. Assert deterministic severity, finding state, compliance mappings, and remediation status remain unchanged; AI must not claim a file changed or a rescan occurred.

### Compliance workflow

Test:

`Compliance → related finding → remediation`

Assert displayed mappings originate from AntiFine metadata, related findings are correct, supported control links/actions work, and unknown mappings are not fabricated. AI-generated compliance text must never be rendered as deterministic truth.

## Scan and finding coverage

Use safe fixtures with no real secrets. Test:

- file picker and drag/drop where supported;
- file removal and clear queue;
- duplicate and unsupported files;
- malformed Terraform/YAML;
- valid Terraform, Kubernetes, and Dockerfiles;
- scan progress, completion, empty results, partial/error results, and backend unavailable;
- search and combined severity/framework/technology/status filters;
- sorting, row selection, drawer open/close, rule-ID copy, remediation action, AI explanation, and Ask AntiFine context.

Search and filters must alter results. Rows must open the correct finding, not merely any drawer.

## Secret safety

Use synthetic credentials only. Verify masking and reveal behavior when implemented, ensure raw values do not appear in UI, logs, or test output, and confirm AI requests receive redacted values. Never commit credentials or use production infrastructure.

## Accessibility and responsive behavior

Use keyboard interaction where practical: Tab, Shift+Tab, Enter, Space, Escape, and relevant arrow keys. Verify visible focus, meaningful labels, reachable controls, dialog focus behavior, and Escape close behavior.

Run critical workflows at:

- 1280×800
- 1440×900
- 1920×1080
- 1024×768
- 768×1024

Check overflow, drawer/modal behavior, table usability, code readability, sidebar collapse, and accessible buttons.

## Repair workflow

When a UI defect is found:

1. Reproduce it in Playwright and capture the page, element, expected result, actual result, console output, and network behavior.
2. Diagnose the root cause from the implementation and API contract.
3. Make the smallest safe fix without replacing working backend behavior with mocks.
4. Add or update the regression test.
5. Re-run the same test and the critical-path workflow.
6. Run relevant existing tests and check for unrelated regressions.

Classify failures:

- **P0** — core Scan → Finding → Remediation → Rescan security workflow broken;
- **P1** — important navigation, findings, AI, compliance, or reporting functionality broken;
- **P2** — history, settings, or secondary interaction broken;
- **P3** — minor UI or accessibility issue.

Every discovered failure should include page, element, expected, actual, probable cause, severity/priority, and test name.

## Test organization and artifacts

Prefer the existing test framework and avoid duplicate infrastructure. If the repository uses Playwright specs, organize coverage under `tests/e2e/` with focused navigation, overview, scan, findings, remediation, compliance, secrets, history, reports, and AI specs as appropriate.

Capture screenshots, traces, console errors, and failed requests on failure when useful for diagnosis. Wait for observable state changes instead of arbitrary sleeps. Assert both the request and user-visible result for API-backed actions.

## Security boundary

The browser suite must never use real secrets, weaken security checks, bypass deterministic verification, treat AI output as authoritative, or automatically approve risky remediation.

Operate as:

`DISCOVER → REPRODUCE → DIAGNOSE → FIX → TEST → REGRESS`
