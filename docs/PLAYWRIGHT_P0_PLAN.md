# Playwright P0 plan

## Architecture and test environment

AntiFine is a client-side React/Vite application (`frontend/src/main.tsx` and
`frontend/src/App.tsx`) that calls the FastAPI service at
`http://localhost:8000/api` through `frontend/src/api.ts`.  It has no URL
router; the sidebar changes local React page state.  The P0 test will run
Chromium against a Vite server on `127.0.0.1:5173` and a FastAPI server on
`127.0.0.1:8000`.

No relevant frontend/backend service was running at discovery time. Playwright
should therefore launch both processes through `webServer`, rather than rely
on a developer's already-running services. The backend command is
`python -m uvicorn src.api.server:app --host 127.0.0.1 --port 8000`; the
frontend command is `npm run dev -- --host 127.0.0.1 --port 5173` from
`frontend`.

## Fixture strategy

The P0 fixture will be a synthetic Terraform `aws_db_instance` with
`publicly_accessible = true`. `analyze_terraform()` has an existing
deterministic CRITICAL rule, `Publicly Accessible Database (...)`, and
`remediate_file()` has the matching allowlisted transformation to
`publicly_accessible = false`.

Each test run will copy this fixture to an ignored directory below the project
root (the API rejects paths outside it). The test will use only the copied
path, assert that a `.bak` file was created, and restore/remove the generated
fixture in cleanup. No production file or real credential is involved.

## Exact API sequence

1. `POST /api/scan/iac` with `{ "target_path": <relative fixture path> }`.
2. The response must contain a CRITICAL public-database finding and the
   authoritative frameworks/remediation metadata.
3. `POST /api/scan/iac/remediate` with the same target and returned rule name.
4. The response must contain `findings_count: 0`, an observable backup path,
   and the deterministic action.
5. `POST /api/scan/iac` again with the same target must return zero findings.

The UI currently calls only steps 1 and 3. It changes the selected finding to
`Fixed` after the remediation response says `findings_count === 0`; it does
not issue a separate browser rescan request.

## Current data-contract mismatches to expose

- The scan API returns `rule_name`, `severity`, `frameworks`, `description`,
  and `remediation`, but not an ID, line, source excerpt, proposed after
  excerpt, status, scan ID, or timestamp. `ScanWorkspace` fabricates or
  defaults all of those fields in `frontend/src/App.tsx`.
- The chosen/dropped file is only added to a browser queue. Its bytes are
  never sent to FastAPI. The API scan target remains the manually editable
  server-local path.
- The remediation modal's diff is sourced from fabricated empty `before` and
  `after` fields, so the current browser cannot prove the exact deterministic
  change before applying it.
- `App.tsx` contains static scan IDs/times/activity, static history records,
  and static sidebar counts. These must be reported separately, not treated
  as P0 scan evidence.
- The current UI has no backend history/findings load contract; only the
  in-memory result of the current scan populates the Findings page.

## Selectors and test IDs

The harness will prefer role/name selectors for existing accessible controls.
Stable `data-testid` attributes are needed for the scan target, file input,
run-scan button, findings table/row, drawer, review-fix button, remediation
diff, apply-fix button, and verification state. They will be additive only and
will not alter product behavior.

## Proposed files

- `playwright.config.ts`
- `frontend/tests/e2e/p0-remediation.spec.ts`
- `frontend/tests/e2e/helpers/fixture.ts`
- `tests/fixtures/public-database.tf`
- existing semantic roles, with a single unique `.diff-view` structural locator
  for the rendered before/after columns
- `docs/PLAYWRIGHT_P0_REPORT.md`

## Assertions, risks, and acceptance criteria

The test will capture browser console/page errors, failed API responses, and
the scan/remediation/rescan request/response sequence. It will retain a trace
and screenshot on failure. It will assert the file copy, `.bak`, and final
fixture contents directly only inside the isolated fixture directory.

Primary risks are Windows process startup/cleanup, the API's project-root path
sandbox, and current missing evidence fields. The first test run must fail if
the UI has no real deterministic diff or does not perform a visible rescan;
those must not be mocked. The smallest follow-up product change may only add
backend-sourced finding evidence and a real post-remediation rescan state.

Acceptance requires a Chromium browser to load Scan, select the synthetic
fixture through the displayed chooser, send the actual scan request, display
backend-derived CRITICAL/rule/framework data, open the drawer and review
modal, show the deterministic `true` to `false` diff, explicitly apply the
fix, observe the backup, make a successful rescan request, and display the
original finding as verified/resolved without unexpected console or API
failures. Static overview/history/count data is explicitly excluded from this
proof and must be flagged.
