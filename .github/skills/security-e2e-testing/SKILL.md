---
name: security-e2e-testing
description: Verify AntiFine end-to-end with Playwright, including security workflows, browser states, API failures, accessibility, and responsive behavior.
---

# AntiFine security E2E testing

Load this skill when testing AntiFine through its real browser UI. A rendered button is not proof that a feature works: perform the interaction and verify the resulting UI state, network behavior, and persisted or navigated outcome.

## Required verification

- Use Playwright against the running React/Vite frontend and real FastAPI/Ollama integrations where available.
- Exercise real clicks, typing, keyboard activation, file selection, drawer/modal transitions, retries, and navigation; do not validate only component markup.
- Collect browser console messages and inspect unexpected errors.
- Collect failed network requests and response status/details; distinguish expected validation failures from regressions.
- Cover every reachable route/view and verify each advertised button or action has a meaningful result.
- Test keyboard focus, Enter/Space activation, Escape/close behavior, labels, and usable focus states.
- Test the supported viewport sizes, including desktop and a narrower responsive viewport.
- Check loading, success, empty, disabled, timeout, backend-unavailable, malformed-input, and error states where the feature exposes them.
- Never use real secrets or disclose sensitive infrastructure contents in fixtures, logs, screenshots, or test output.

## Critical AntiFine workflows

### Deterministic remediation

Verify the complete workflow, not just the presence of controls:

`Scan → Finding → Finding Drawer → Review Fix → Diff → Apply → Rescan → Verified`

Use a safe temporary vulnerable IaC fixture. Assert that:

- the scan request succeeds and the finding is visible;
- the correct finding row opens the existing drawer;
- Review Fix shows the real deterministic before/after content;
- Apply sends the expected remediation request;
- a backup is created and reported;
- the target is rescanned;
- the finding becomes Fixed/Verified only when deterministic verification reports zero remaining findings;
- remaining findings keep the item open and display an explicit verification failure.

Do not treat a successful HTTP response alone as proof that remediation worked. Do not accept a UI-only status change without the backend verification result.

### Finding explanation

Verify:

`Finding → Ask AntiFine → Ollama → explanation`

Assert finding context is handed off, the assistant request contains the expected bounded context/messages, loading and disabled-Ollama states are explicit, errors are actionable, and a successful explanation is clearly advisory. Do not require Ollama for unrelated deterministic scanner tests; mock or use the documented local service boundary without inventing a success response.

### Compliance and remediation

Verify:

`Compliance → related finding → remediation`

Confirm the UI uses authoritative AntiFine finding/compliance data, preserves unmapped-framework behavior, and never turns generic documentation into a finding mapping. Remediation remains deterministic and reviewable.

## Test discipline

When repairing a broken UI:

1. Reproduce the failure in the browser and capture the actual state, console output, and network request.
2. Identify the root cause from the implementation and API contract.
3. Implement the smallest fix without replacing backend functionality with mocks.
4. Repeat the same browser interaction and verify the resulting state, including negative/error paths.
5. Add or update a regression test that would fail if the defect returns.

Prefer stable accessible roles, labels, and visible text over brittle CSS selectors. Wait for observable state changes rather than arbitrary sleeps. Assert both the request and the user-visible result when an action crosses the API boundary.

## Reporting

For each tested workflow record the route, viewport, fixture/setup, actions, expected result, observed result, console errors, failed requests, and any limitation caused by an unavailable backend service. Separate verified behavior from untested or unsupported behavior. Never mark a feature working merely because it rendered.

