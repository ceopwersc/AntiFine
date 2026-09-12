# AntiFine UI functionality audit

Audit date: 2026-09-13  
Frontend: Vite development server at `127.0.0.1:5173`  
Backend: FastAPI at `127.0.0.1:8000`

## Inventory and results

| Page | Element | Problem | Severity | Fix | Test result |
|---|---|---|---|---|---|
| Shell | Settings navigation | The visible Settings button did not change the application view. | P1 | Added a real Settings page and active navigation state. | WORKING: opens Settings |
| Shell | Top-bar Search hint | Displayed a shortcut for behavior that was only implemented inside Ask AntiFine. | P2 | Removed the misleading global affordance. | WORKING: no dead search control |
| Overview | Finding queue and severity actions | Navigation actions did not claim to apply a filter. | P2 | Kept them as navigation actions and removed no-op affordances elsewhere. | WORKING: opens Findings |
| Scan | Scan failure | A failed API request loaded representative mock findings and looked successful. | P0 | Failures now remain errors; no findings are inserted and no success state is shown. | WORKING: 422 displays error and does not load mock data |
| Scan | Policy/secret toggles | These are scanner policy defaults, not browser settings, and were not interactive. | P2 | Kept them as non-interactive status indicators. | WORKING: no false control |
| Findings | Table rows | Rows were mouse-only despite being presented as interactive. | P1 | Added keyboard focus and Enter/Space activation. | WORKING: keyboard opens drawer |
| Findings | Pagination | Next appeared enabled but had no implementation. | P2 | Disabled the unavailable pagination controls. | WORKING: no dead action |
| Findings | Export | Export button had no operation. | P2 | Removed the no-op action until a findings-specific export contract exists. | WORKING: no dead action |
| Finding drawer | Ask AntiFine handoff | Context was not verifiable from the drawer alone. | P1 | Preserved finding context and verified the Ask page shows the finding identifier. | WORKING: drawer → Ask AntiFine |
| Compliance | Export evidence | Button had no handler. | P1 | Wired it to the existing Markdown report endpoint with loading/error status. | WORKING: POST `/api/report/generate` returns 200 |
| Compliance | More/View controls | Buttons had no data or handlers. | P2 | Removed misleading controls rather than inventing unsupported behavior. | WORKING: no dead action |
| Secrets | Configure/View playbook | No settings or playbook endpoint exists. | P2 | Removed unsupported actions. | WORKING: page is read-only and explicit |
| History | Export history | Button had no handler. | P1 | Wired it to the existing report endpoint with loading/error status. | WORKING: report request returns 200 |
| History | Refresh and row chevrons | No history API or detail view was connected. | P2 | Removed unsupported affordances. | WORKING: no dead action |
| Reports | Historical download rows | Rows were static placeholders with no artifact URLs. | P1 | Replaced them with an explicit current-artifact message; generated reports still download. | WORKING: Markdown and SARIF requests return 200; SARIF downloaded |
| Ask AntiFine | Disabled Ollama | Disabled state incorrectly offered a retry in earlier behavior. | P1 | Preserved configured-off state without retry. | WORKING: disabled state, zero retry buttons |
| Ask AntiFine | Clipboard copy | Success state could be shown when clipboard was unavailable or rejected. | P2 | Added capability check and explicit error handling. | WORKING: success only after write |
| Settings | Table density | No persistence surface existed. | P2 | Added a local-browser preference with `localStorage` persistence. | WORKING: survives reload |

## Routes tested

The application uses client-side page state rather than URL routes. These views were opened through the sidebar:

- Overview
- Scan
- Findings
- Compliance
- Secrets
- Scan history
- Reports
- Ask AntiFine
- Settings

## Critical-path browser checks

- Scan → real API request → successful result rendering.
- Scan → invalid target → HTTP 422 → visible error with no fabricated findings.
- Findings → keyboard-focused row → Finding Drawer.
- Finding Drawer → Ask AntiFine context handoff.
- Reports → Markdown generation and SARIF export; both returned HTTP 200 and SARIF downloaded.
- Settings → density change → page reload → value persisted.
- Ask AntiFine with Ollama disabled → disabled state rendered without retry.

The only browser console error observed during the audit was the expected browser resource error for the intentionally invalid scan request (`POST /api/scan/iac` returning HTTP 422). Successful-path checks produced no application console errors.
