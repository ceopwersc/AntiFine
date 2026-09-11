---
title: AntiFine Design System
version: 1.0.0
product: AntiFine
mode: dark-first
platform: web
primary-audience: developers-and-security-engineers
---

# AntiFine Design System

AntiFine is a developer-first, locally hosted Infrastructure-as-Code security platform. It analyzes Terraform, Dockerfiles, Kubernetes manifests, and secrets; maps findings to security frameworks; provides deterministic remediation; and optionally provides local AI assistance through Ollama.

This document is the **single visual and interaction source of truth** for the AntiFine frontend.

## Current direction: Local security workstation

This section supersedes earlier dashboard-oriented composition guidance. AntiFine is a local security engineering workstation, closer to an IDE, Git client, terminal, scanner, and code-review tool than a SaaS dashboard.

**THESIS:** Make evidence and action the interface. The first viewport should expose scan state and findings, not a hero metric, chart, or decorative card grid.

**OWN-WORLD:** Near-black graphite canvas, compact split-pane and table layouts, 1px separators, monospace technical metadata, restrained blue-violet selection, and severity colors used only as small semantic signals. Surfaces should feel like editor chrome and review panes.

**STORY:** An engineer sees what was scanned, what is open, where it is in the repository, which rule fired, what compliance evidence exists, and what deterministic change can be reviewed and applied.

**FIRST VIEWPORT:** A local workspace header and operational scan strip at the top; below it, a dense current-findings queue with severity, rule ID, file path, line, framework, status, and an inline code excerpt. Overview and Findings are evidence-first routes.

**FORM:** Workstation console, not marketing dashboard. Prefer tables, split panes, toolbars, code blocks, tabs, and separators. Reject oversized grade cards, score rings, decorative charts, gradients, icon-led cards, excessive rounded containers, and large empty areas.

### Workstation rules

- Workspace identity is explicit: `AntiFine · LOCAL WORKSPACE`, `FastAPI · 127.0.0.1:8000`, and `Ollama · Local`.
- Use monospace for rule IDs, file paths, line numbers, scan IDs, framework IDs, code, and operational metadata.
- Overview answers: what is open now, what scan is running, what changed, and where to act next. It does not lead with a score visualization.
- Findings is the primary workflow: **Finding → Code → Rule → Compliance → Remediation → Diff → Apply → Rescan**.
- Keep tables compact and scannable. A row may carry multiple metadata fields inline; avoid turning each datum into a card.
- Use icons only when they clarify navigation or state. Never use an icon as decoration inside every metric.
- AI is secondary and local. It must not visually compete with deterministic findings, remediation, or diff review.
- Operational state is visible and plain: local, connected, scanning, complete, failed, or unavailable.
- Interaction states remain explicit: hover, keyboard focus, selected row, loading, success, error, and disabled.

## Design North Star

AntiFine should feel like a tool a senior engineer could use every day:

**precise · fast · dense · trustworthy · local · technical · calm · inspectable**

The product should communicate security seriousness without using cliché cybersecurity aesthetics.

### Avoid

- Cyberpunk or hacker-movie styling
- Matrix backgrounds
- Neon green as a primary brand treatment
- Excessive gradients or glow
- Giant shield/lock illustrations
- Generic SaaS stock illustrations
- Huge decorative hero sections
- Excessive rounded cards
- AI-first visual treatment
- Decorative charts without analytical value
- Generic SaaS KPI grids and score dashboards
- Friendly marketing greetings or invented workspace brands

### Inspirations, not copies

Use the quality bar of modern developer tools such as Linear, Sentry, GitHub Security, Vercel, and IDE interfaces. Do not reproduce their branding or layouts.

---

# 1. Visual Language

## 1.1 Surface hierarchy

Use a restrained dark graphite palette with subtle elevation.

| Token | Value | Usage |
|---|---|---|
| `bg.canvas` | `#0B0D10` | Global application background |
| `bg.sidebar` | `#090B0E` | Fixed navigation |
| `bg.surface` | `#101318` | Primary panels |
| `bg.surfaceElevated` | `#151922` | Drawers, modals, elevated cards |
| `bg.input` | `#0D1015` | Inputs, search, code chrome |
| `border.subtle` | `#20252E` | Default borders |
| `border.strong` | `#2A313C` | Focused/selected borders |
| `text.primary` | `#F4F6F8` | Main text |
| `text.secondary` | `#A7AFBB` | Supporting text |
| `text.muted` | `#737D8A` | Metadata, timestamps |
| `text.disabled` | `#4F5762` | Disabled controls |

Do not introduce arbitrary colors outside the token system without a documented reason.

## 1.2 Accent

AntiFine uses one restrained product accent for active UI states, links, selections, and primary actions. Prefer a cool blue-violet family that separates product interaction from security severity.

Recommended tokens:

| Token | Value | Usage |
|---|---|---|
| `accent.default` | `#7C8CFF` | Primary interactive accent |
| `accent.hover` | `#94A0FF` | Hover |
| `accent.strong` | `#6678FF` | Active/pressed |
| `accent.soft` | `rgba(124,140,255,0.12)` | Soft background |
| `accent.border` | `rgba(124,140,255,0.35)` | Accent border |

Accent is **not** a severity color.

## 1.3 Semantic security colors

Use semantic colors sparingly and only for security state.

| Token | Value | Meaning |
|---|---|---|
| `severity.critical` | `#F05D5E` | Immediate/high-risk security issue |
| `severity.high` | `#F29E4C` | High risk |
| `severity.medium` | `#D9B44A` | Moderate risk |
| `severity.low` | `#6FA8DC` | Lower risk/informational |
| `state.success` | `#55B985` | Resolved/passed |
| `state.warning` | `#D9A441` | Warning/attention |
| `state.error` | `#E46B6B` | Error/failure |
| `state.info` | `#6FA8DC` | Informational |

Do not flood whole cards with severity colors. Prefer small badges, indicators, borders, or text accents.

## 1.4 Compliance grades

Compliance grades use semantic color progression:

- A: success family
- B: green/teal success family
- C: warning family
- D: orange warning family
- F: error/critical family

Grade color should support, not replace, the actual letter/score.

---

# 2. Typography

## 2.1 UI font

Use a clean modern sans-serif with strong readability at dense sizes.

Recommended family:

`Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`

## 2.2 Monospace font

Use a professional monospace font for:

- code
- rule IDs
- file names
- paths
- line numbers
- diff content
- technical metadata

Recommended:

`ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace`

## 2.3 Type scale

| Role | Size | Weight | Line height |
|---|---:|---:|---:|
| Page title | 24px | 600 | 32px |
| Section title | 17px | 600 | 24px |
| Card title | 14px | 600 | 20px |
| Body | 14px | 400 | 21px |
| Dense body | 13px | 400 | 19px |
| Label | 12px | 500 | 16px |
| Caption | 11px | 500 | 15px |
| Code | 13px | 400 | 20px |
| Code compact | 12px | 400 | 18px |

Use sentence case. Avoid all-caps headings except very small labels/badges where useful.

---

# 3. Spacing and Shape

Use a 4px base spacing grid.

Preferred spacing values:

`4, 8, 12, 16, 20, 24, 32, 40, 48`

### Radius

AntiFine is compact and technical; avoid overly pill-shaped UI.

- Small control: `6px`
- Standard card/input: `8px`
- Drawer/modal: `10px`
- Large surface: `12px`
- Pills/badges: `9999px` only when semantically appropriate

### Borders

Use 1px borders with low contrast.

A component should usually use **either** elevation **or** a border, not heavy combinations of both.

---

# 4. Layout

## 4.1 Application shell

Desktop-first layout:

```text
┌───────────────┬─────────────────────────────────────────┐
│               │ top bar                                 │
│   sidebar     ├─────────────────────────────────────────┤
│               │                                         │
│               │ page content                            │
│               │                                         │
└───────────────┴─────────────────────────────────────────┘
```

Recommended dimensions:

- Sidebar: 232px expanded
- Sidebar collapsed: 64px
- Top bar: 56px
- Page horizontal padding: 24px on desktop
- Main content max width: 1440px where appropriate

## 4.2 Density

AntiFine is a developer tool. Prefer **information density over empty space**, while retaining clear grouping and breathing room.

Do not create oversized cards simply to fill space.

## 4.3 Responsive behavior

Primary targets:

- 1280px
- 1440px
- 1600px
- 1920px

At narrower widths:

- collapse the sidebar
- allow tables to scroll horizontally when necessary
- turn drawers into full-screen panels
- preserve code readability
- stack multi-column cards logically

Do not sacrifice technical content just to force mobile card layouts.

---

# 5. Navigation

## 5.1 Sidebar

Order:

1. Overview
2. Scan
3. Findings
4. Remediation
5. Compliance
6. Secrets
7. History
8. Reports
9. Ask AntiFine

Bottom:

- system/connection status
- settings
- version

Active state:

- subtle accent background
- accent icon/text
- no glowing effect

Hover:

- slight surface lift/change
- no layout shift

## 5.2 Top bar

Include only high-value actions:

- breadcrumbs/current page
- global search
- keyboard shortcut hint
- primary scan action where appropriate
- AI/connection status
- settings or utility actions

Keep the top bar visually quiet.

---

# 6. Core Components

## 6.1 Buttons

Variants:

- Primary: accent fill
- Secondary: surface + border
- Ghost: transparent
- Danger: subtle error treatment
- Destructive: reserved for irreversible actions

States:

- default
- hover
- active
- focus
- loading
- disabled

Never hide loading feedback during asynchronous actions.

## 6.2 Inputs

Inputs should have:

- subtle dark background
- visible focus ring using accent
- compact height
- clear placeholder
- error state

Search inputs should support keyboard focus and shortcuts.

## 6.3 Badges

Use badges for:

- severity
- status
- technology
- framework
- local AI provider

Badges should be compact and readable.

## 6.4 Cards

Cards should group information, not decorate it.

Avoid nesting many cards inside cards.

## 6.5 Tables

Tables are a primary AntiFine interaction surface.

Requirements:

- compact rows
- sticky or clear header
- subtle row separators
- hover state
- selected state
- keyboard focus
- sortable headers where applicable
- filter controls above the table
- empty state

Every important row should be actionable.

## 6.6 Drawers

Use drawers for contextual inspection without losing the user's position.

Finding Drawer should slide from the right on desktop and become a full-screen panel at smaller widths.

Escape closes the drawer. Focus should move into the drawer and return to the triggering element on close.

---

# 7. Finding UX

Findings are the center of the AntiFine product.

## 7.1 Finding hierarchy

Always show in this order:

1. Severity
2. Rule ID
3. Title
4. Technology/file/location
5. Deterministic description
6. Affected code/resource
7. Compliance mappings
8. Deterministic remediation
9. Optional AI assistance

## 7.2 Finding row

Minimum information:

- severity
- rule ID
- title
- resource/file
- framework or status

Clicking a row opens the Finding Drawer.

## 7.3 Finding Drawer

Recommended structure:

```text
Header
  severity / rule / title / status

Overview
  what AntiFine detected
  why rule triggered

Location
  file / line / resource

Code
  syntax-highlighted excerpt

Compliance
  authoritative mappings only

Remediation
  deterministic fix availability
  Review Fix

Local AI
  Explain with Local AI
  Ask AntiFine about this
```

The deterministic finding is the primary truth.

---

# 8. Remediation and Diff

The remediation experience is AntiFine's signature interaction.

## 8.1 Design goal

The user must understand:

**exactly what AntiFine will change, why it will change it, and what happens after applying it.**

## 8.2 Diff viewer

Support:

- side-by-side mode
- unified mode
- line numbers
- file path
- added lines
- removed lines
- unchanged sections
- copy actions

Added/removed colors should be subtle but obvious.

## 8.3 Remediation hierarchy

```text
DETERMINISTIC FIX

Before / After

Why this fix

Backup: filename.bak

[Apply Fix]
```

The primary CTA is **Apply Fix**.

AI explanation is secondary.

## 8.4 After applying

Use a clear sequential success state:

- Backup created
- File updated
- Verification scan running
- Finding resolved

Never claim a fix succeeded until AntiFine's deterministic verification completes.

---

# 9. Code Viewer

Code should resemble a professional IDE rather than a generic code card.

Requirements:

- monospace
- line numbers
- syntax highlighting
- horizontal scrolling
- readable contrast
- file path header
- copy action
- optional line highlight

Do not use huge code font or unnecessary decorations.

---

# 10. Compliance UI

Compliance is about **mapping and evidence**, not generic framework marketing.

Show:

- framework
- control
- status
- related findings
- remediation state

Never allow AI-generated mappings to visually appear alongside authoritative mappings without a clear distinction.

Suggested status:

- Passed
- Failed
- Not evaluated
- Unknown

`Unknown` must mean that AntiFine truly lacks sufficient deterministic evidence.

---

# 11. Secrets UI

Never display complete secrets by default.

Use masked values, e.g.:

`AKIA••••••••••••`

Use clear disclosure controls only when appropriate.

Secret pages should visually emphasize:

- secret type
- severity
- file/location
- confidence/detection tier
- remediation guidance

Never expose sensitive values in toasts, URLs, logs, or casual UI text.

---

# 12. Local AI UI

AntiFine AI is an **optional local assistant**, not the security authority.

## 12.1 AI identity

Always show:

`Local AI · Ollama`

and when useful:

`qwen2.5:7b`

Use actual backend health state. Never display “Online” from static mock state.

## 12.2 AI hierarchy

```text
Deterministic AntiFine Finding
        ↓
Optional AI explanation
```

AI should be visually secondary to security findings and remediation.

## 12.3 AI states

Provide:

- available
- unavailable
- disabled
- loading
- success
- error
- retry

Unavailable state example:

**Local AI unavailable**

`AntiFine's deterministic analysis remains fully operational.`

## 12.4 AI source display

When sources are available, show a compact Sources area containing:

- title
- source path
- rule ID where applicable

Do not expose internal prompts.

## 12.5 AI disclaimers

Use concise wording:

`AI-generated explanation based on AntiFine's deterministic findings and local knowledge.`

Do not use language implying that the model made the security decision.

---

# 13. Ask AntiFine

Ask AntiFine is a developer assistant embedded into the security workflow.

## Context hierarchy

When opened from a specific location, show the context:

- Finding: rule/severity/file
- Scan: scan ID/grade/summary
- Compliance: framework/control
- Remediation: finding/diff
- Dashboard: current summary

Display a compact context chip with `Clear context`.

## Suggested prompts

Finding:

- Why is this critical?
- Explain the compliance impact.
- Explain the deterministic remediation.
- What should I verify after fixing it?

Scan:

- Summarize this scan.
- What should I investigate first?

Compliance:

- Why is this control failing?

Remediation:

- What exactly changes?
- What should I verify after applying it?

## Chat behavior

- Enter sends
- Shift+Enter adds newline
- Cmd/Ctrl+K may open the command palette
- Escape closes overlays where appropriate

Conversation history is session-local and bounded.

---

# 14. Dashboard

Overview is an operational console, not an analytics dashboard. It should answer three questions immediately:

1. What scan ran and what is its current state?
2. Which findings need engineering attention now?
3. Where do I open the code and review the deterministic fix?

Required hierarchy:

### Local workspace strip

Show the latest scan ID, target/type, duration or timestamp, finding count, engine state, and local service state.

### Current findings queue

Use a compact table or list with severity, rule ID, finding title, file path, line number, framework, and status. Rows open the Finding Drawer.

### Scan activity

Show the latest operational events and whether the local scanner is idle, running, complete, or failed.

### Severity distribution

Use small inline counts only. Do not use a score ring, large grade card, decorative chart, or KPI card grid as the primary composition.

The product's security grade, if exposed elsewhere, is secondary metadata. Findings and scan state are the primary dashboard content.


---

# 15. Scan Workspace

Scanning is a workflow, not merely an upload form.

Flow:

```text
Choose / Drop Files
      ↓
Scan Configuration
      ↓
Run Scan
      ↓
Live Progress
      ↓
Results
      ↓
Findings
```

The progress view should show meaningful steps:

- parsing
- rule evaluation
- secret scanning
- compliance mapping
- report generation

Avoid fake progress unrelated to real scan phases.

---

# 16. Reports

Reports UI should be practical.

Supported outputs:

- SARIF 2.1.0
- Executive PDF

Show:

- report type
- generation time
- scan ID
- status
- action

Generation must visibly transition through loading and success/error states.

---

# 17. Feedback and State

## Toasts

Keep toasts compact and short-lived.

Examples:

- `Finding resolved`
- `Fix applied successfully`
- `Report generated`
- `Copied to clipboard`
- `Local AI unavailable`

## Empty states

Empty states should explain what happened and what the user can do next.

Example:

**No open findings**

`Your latest scan has no unresolved security findings.`

## Error states

Never use vague errors like `Something went wrong`.

Show:

- what failed
- affected operation
- retry action where possible

---

# 18. Motion

Motion should communicate state, not decorate the interface.

Preferred:

- 120–220ms micro transitions
- drawer slide
- fade/opacity for status
- progress animation
- subtle success transition

Avoid:

- bouncing UI
- parallax
- continuous decorative animation
- excessive glow

Respect `prefers-reduced-motion`.

---

# 19. Accessibility

Minimum requirements:

- visible keyboard focus
- semantic buttons/links
- accessible form labels
- sufficient text contrast
- logical tab order
- Escape handling for overlays
- reduced motion support
- screen-reader-friendly status messages

Never rely on color alone to communicate severity or state.

---

# 20. Interaction Rules

Every visible interactive element must have a defined behavior.

### Required states

Buttons:

`default → hover → active → loading → success/error → disabled`

Inputs:

`default → focus → filled → error → disabled`

Rows:

`default → hover → selected → keyboard focus`

Async actions must not freeze unrelated parts of the UI.

### Core AntiFine journey

```text
Scan
  ↓
Findings
  ↓
Inspect
  ↓
Understand
  ↓
Review deterministic fix
  ↓
Optional local AI explanation
  ↓
Apply fix
  ↓
Rescan
  ↓
Verify
```

The interface should make this journey obvious.

---

# 21. AI Safety Presentation

AI must never visually override authoritative AntiFine data.

Authoritative:

- severity
- finding
- rule ID
- framework mapping
- remediation diff
- remediation status
- scan result

AI:

- explanation
- contextual guidance
- summarization
- documentation Q&A

Never use an AI-generated statement as the primary source for a security badge, compliance grade, or remediation state.

---

# 22. Component Naming

Prefer reusable components with explicit responsibilities:

- `AppShell`
- `Sidebar`
- `TopBar`
- `PageHeader`
- `MetricCard`
- `GradeCard`
- `FindingTable`
- `FindingRow`
- `FindingDrawer`
- `SeverityBadge`
- `StatusBadge`
- `FrameworkBadge`
- `CodeViewer`
- `DiffViewer`
- `RemediationPanel`
- `ComplianceTable`
- `ScanProgress`
- `FileDropzone`
- `AIExplanation`
- `AIStatus`
- `AskAntiFine`
- `SourceList`
- `Toast`
- `CommandPalette`

Reuse components rather than duplicating markup between pages.

---

# 23. Engineering Rules for UI Implementation

- Do not put business logic inside presentational components.
- Keep API calls in the service layer.
- Keep state shared through the existing state architecture.
- Do not duplicate mock data in multiple components.
- Use design tokens rather than arbitrary CSS values where possible.
- Preserve existing API contracts unless explicitly changing them.
- Never replace working deterministic backend behavior for visual convenience.
- Avoid giant components; split complex views into reusable components.
- Keep UI responsive without making the desktop security workflow less dense.

---

# 24. Definition of Done

A UI change is complete when:

- It follows the visual tokens in this document.
- It has hover/focus/loading/error/success states where applicable.
- It is keyboard accessible.
- It does not contradict the deterministic security engine.
- It works with real backend data when the endpoint exists.
- It does not rely on hardcoded fake connection status.
- It does not expose secrets.
- It feels consistent with the rest of AntiFine.

**AntiFine should look like a serious security engineering instrument, not a generic dashboard.**
