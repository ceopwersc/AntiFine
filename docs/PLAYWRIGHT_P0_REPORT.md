# Playwright P0 report

## Setup and command

The harness is configured in `frontend/playwright.config.ts`. It starts FastAPI
and Vite itself, so it does not rely on a developer process. Run it from the
frontend package:

```powershell
npx playwright test --config playwright.config.ts
```

The executed browser is Playwright Chromium. Failures retain a screenshot and
trace under `frontend/test-results/` (ignored by Git).

## Workflow result

The P0 workflow passes against a generated copy of
`tests/fixtures/public-database.tf`:

1. The browser opens Scan and selects the synthetic Terraform file.
2. It sends `POST /api/scan/iac` for the isolated project-relative target.
3. The response supplies the CRITICAL public-database rule and authoritative
   framework metadata; the browser displays that evidence and opens its drawer.
4. `POST /api/scan/iac/remediation/preview` supplies the exact allowlisted
   `publicly_accessible = true` to `false` preview.
5. An explicit browser click sends `POST /api/scan/iac/remediate`; the test
   observes the `.bak` file in the isolated fixture directory.
6. The UI performs a further `POST /api/scan/iac` verification request and
   marks the finding fixed only after it returns zero findings.

The test captures browser console/page errors and API responses. The passing
run had no unexpected console errors or API responses at status 400 or above.

## Initial failure and fix

The first meaningful run failed at the remediation diff: the scan response did
not contain source evidence/proposed replacement and the modal rendered empty
before/after columns. The narrow fix was a read-only
`/api/scan/iac/remediation/preview` endpoint backed by the existing
allowlisted remediation transformation. The modal loads that preview and
performs a fresh API rescan after an otherwise successful remediation.

## Static/data-contract mismatches still present

- File chooser/drag-and-drop only creates browser metadata. It does not upload
  or import bytes; the scan request contains only the manually supplied
  server-local `target_path`.
- `ScanWorkspace` still invents an ID, line, status, detection timestamp, and
  default source fields because the scan API does not return them.
- Findings table metadata uses fixed `scan_8f31c2`; overview activity and
  operational timestamps are fixed text; sidebar Findings/Secrets counts are
  fixed at 5/2; `HistoryPage` is a fixed `scans` array. None is used to prove
  the P0 remediation result.
- There remains no evidence-backed scan-history API/UI contract.

## Files involved

- Scan/upload normalization: `frontend/src/App.tsx`, `frontend/src/api.ts`
- Deterministic preview/apply/rescan: `src/scanners/remediation.py`,
  `src/api/server.py`, `frontend/src/App.tsx`
- Test harness: `frontend/playwright.config.ts`,
  `frontend/tests/e2e/p0-remediation.spec.ts`, and
  `frontend/tests/e2e/helpers/fixture.ts`

## Remaining concerns and recommended order

The new preview returns sanitized content, but preview sizes remain capped at
12,000 characters; the centralized sanitizer is conservative rather than a
proof against all secret-like text. Keep extending synthetic leak tests.

Next, define a real scan-session/findings/history contract before replacing
the static overview/history/count data. Separately, either implement a
sandboxed upload/import contract or relabel/remove the chooser so it does not
imply file transfer.
