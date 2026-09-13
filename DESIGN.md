# AntiFine — Design System

**Version:** 1.0
**Status:** Approved direction — supersedes all prior visual language
**Audience:** Frontend engineers, AI coding agents, design reviewers

---

## 0. What this document replaces

The current AntiFine UI reads as a generic AI-generated SaaS dashboard: oversized rounded cards, a giant circular score graphic, decorative charts, excess blue/purple, and marketing copy. None of that is a security product's job. This document defines a new system built from a different premise: **AntiFine is a workstation, not a website.**

Every rule below exists to answer one question consistently: *does this help an engineer investigate and fix an infrastructure finding faster?* If a pattern doesn't clear that bar, it isn't in this system.

---

## 1. Design Principles

These are load-bearing. When a new screen doesn't have explicit guidance below, resolve it against these ten principles, in order:

1. **Information density over decoration.** Default to showing more real data in less space, not fewer things with more air.
2. **Technical context over marketing language.** Every string is a fact, a state, or an action — never a pitch.
3. **Tables over card grids.** A list of things with comparable attributes is a table. Cards are for a single object's full detail, not a collection.
4. **Code over illustrations.** When something needs explaining, show the actual Terraform/Dockerfile/YAML, not an icon that stands for it.
5. **Operational state over visual effects.** Color, motion, and emphasis exist to report status (scanning, critical, applied, stale) — never to decorate.
6. **Deterministic security over AI.** The rule engine's verdict is the primary content on every screen. AI output is always visually subordinate and always labeled as AI.
7. **Developer workflow over analytics.** AntiFine is closer to a code review tool than a BI dashboard. Optimize for "find it, understand it, fix it, verify it" — not for charts about charts.
8. **Trust over flashiness.** A security tool that looks expensive-flashy reads as unserious. Quiet and exact reads as competent.
9. **Consistency over novelty.** One severity badge shape, one table pattern, one drawer pattern, reused everywhere. Novelty is spent, not distributed.
10. **Speed over animation.** State changes should be near-instant. Motion is used only where it communicates something changing, never as texture.

---

## 2. Visual Personality

**Is:** technical, precise, quiet, dense, sophisticated, trustworthy, serious, operational.
**Is not:** playful, futuristic, glossy, neon, marketing-heavy, "AI-generated-SaaS."

Reference class for behavior and density (not visual style): IDEs, Git clients, GitHub Security tab, Sentry, Linear, terminal tools, infrastructure consoles. AntiFine should feel like it was designed by the same team that built its own scanning engine — not handed to a design agency afterward.

---

## 3. Color System

Dark-first, obsidian/graphite foundation. **One accent hue only** — the prior direction's "excessive blue/purple" problem was never the hue itself, it was using it decoratively (gradients, glows, big filled buttons, tinted card backgrounds). Here the accent is reserved almost exclusively for interactive/focus state, so it reads as a signal, not a paint job.

### 3.1 Base surfaces

| Token | Hex | Usage |
|---|---|---|
| `color.bg.canvas` | `#0A0C0F` | App background, behind everything |
| `color.bg.surface` | `#101318` | Sidebar, top bar, table backgrounds, panels |
| `color.bg.elevated` | `#151922` | Cards used for single-object detail (finding summary block, scan config), popovers |
| `color.bg.overlay` | `#171B24` | Modals, drawers — one step lighter than elevated so they read as "on top" without a shadow |
| `color.bg.inset` | `#0D0F13` | Code blocks, diff viewer, terminal-like regions (recessed, not raised) |
| `color.bg.hover` | `#171B22` | Row/item hover fill |
| `color.bg.selected` | `#1A2130` | Selected table row / active list item (accent-tinted at ~8%) |

### 3.2 Borders

| Token | Hex | Usage |
|---|---|---|
| `color.border.hairline` | `#1B1F27` | Internal dividers: table row separators, list separators |
| `color.border.default` | `#252A33` | Component edges: cards, inputs, tables, drawers |
| `color.border.strong` | `#333A47` | Hover/active state on bordered components |
| `color.border.focus` | `#6C8EEA` | Focus ring only |

### 3.3 Text

| Token | Hex | Usage |
|---|---|---|
| `color.text.primary` | `#E7EAF0` | Headings, body, finding titles, code |
| `color.text.secondary` | `#8A919E` | Supporting text, table secondary columns, descriptions |
| `color.text.muted` | `#5D6470` | Metadata, timestamps, placeholder text |
| `color.text.disabled` | `#454B56` | Disabled control labels |
| `color.text.inverse` | `#0A0C0F` | Text on filled accent/status backgrounds |
| `color.text.link` | `#6C8EEA` | Inline links, references (`TF-AWS-004`-style rule links) |

### 3.4 Accent (interactive signal — use sparingly)

| Token | Hex | Usage |
|---|---|---|
| `color.accent.default` | `#6C8EEA` | Primary button fill, active nav item, focus ring, links, checked state |
| `color.accent.hover` | `#84A0F0` | Hover on accent-filled elements |
| `color.accent.muted-bg` | `#6C8EEA` @ 12% | Active nav row background, selected-tab underline zone |

Do not use the accent for decorative fills, backgrounds of non-interactive containers, or chart color unless the chart is literally about interactive-vs-not.

### 3.5 Semantic status (security domain — the real color story of this product)

These are the colors that matter most in AntiFine. They must be legible at small sizes (12px badge text) and distinguishable from each other and from the accent.

| Token | Hex | Fill (10% on `bg.surface`) | Usage |
|---|---|---|---|
| `color.status.critical` | `#F14C63` | `#F14C63` @ 10% | Critical severity |
| `color.status.high` | `#F2914F` | `#F2914F` @ 10% | High severity |
| `color.status.medium` | `#E8C158` | `#E8C158` @ 10% | Medium severity |
| `color.status.low` | `#7C8A9E` | `#7C8A9E` @ 10% | Low severity — deliberately steel/neutral, not another warm color, so the eye doesn't treat it as urgent |
| `color.status.success` | `#52BF8B` | `#52BF8B` @ 10% | Resolved, applied, passing control, scan complete |
| `color.status.warning` | `#E8C158` | shared with medium | Non-severity warnings (e.g. stale scan, backup pending) |
| `color.status.info` | `#6C8EEA` | `#6C8EEA` @ 10% | Neutral technical notices, shares the accent hue intentionally — info is "interactive-adjacent," not alarming |

Status color is always paired with a text label. Never color-only.

### 3.6 Disabled & overlay

| Token | Hex | Usage |
|---|---|---|
| `color.disabled.bg` | `#12151B` | Disabled control fill |
| `color.disabled.border` | `#1D212A` | Disabled control border |
| `color.overlay.scrim` | `#06070A` @ 72% | Backdrop behind modals |

### 3.7 Rules

- No gradients, anywhere, on any surface.
- No neon glow, no glassmorphism, no glowing borders or shadows.
- No secondary decorative accent hue — status colors carry all the "color interest" in this product, by design, because they carry real meaning.
- Charts (where they exist at all, see §9) reuse status colors, never invent a new categorical palette.

---

## 4. Typography

**UI face:** Geist. **Code face:** Geist Mono.

Why: Geist is narrower and more neutral than Inter/system-ui defaults, so dense tables and metadata-heavy rows don't feel like a consumer app; it was evaluated against IBM Plex Sans (slightly too "corporate-report") and system-ui (inconsistent across OSes, undermines the deliberate technical feel). Geist Mono was evaluated against JetBrains Mono; Geist Mono was chosen for tighter default line-height and closer visual weight-match to Geist UI, so code blocks and UI text sit together without feeling like two different products. Fallback stack: `Geist, -apple-system, "Segoe UI", sans-serif` / `"Geist Mono", "SF Mono", Consolas, monospace`.

No display/hero typography. The largest text in the product is the page title.

| Token | Size | Weight | Line-height | Letter-spacing | Usage |
|---|---|---|---|---|---|
| `type.page-title` | 20px | 600 | 28px | 0 | Page-level heading ("Findings", "Remediation") |
| `type.section-heading` | 14px | 600 | 20px | 0 | Drawer/section headers ("Why Detected", "Deterministic Remediation") |
| `type.body` | 13px | 400 | 20px | 0 | Descriptions, explanatory text, drawer prose |
| `type.body-strong` | 13px | 600 | 20px | 0 | Emphasized inline body text |
| `type.label` | 12px | 500 | 16px | 0.01em | Form labels, table headers, filter labels |
| `type.caption` | 11px | 400 | 14px | 0.01em | Secondary captions under controls |
| `type.metadata` | 11px | 400 | 14px | 0.02em | Timestamps, file paths, rule IDs outside code blocks |
| `type.code` | 13px | 400 | 20px | 0 | Code viewer, diff viewer body |
| `type.code-small` | 12px | 400 | 18px | 0 | Inline code, drawer code excerpts |
| `type.table` | 13px | 400 | 18px | 0 | Table cell text |
| `type.table-header` | 11px | 500 | 16px | 0.02em | Table column headers (sentence case, not tracked-out caps — see §14) |

Table headers use sentence case ("Severity", "File", not "SEVERITY", "FILE"). Tracked-out all-caps eyebrow labels are a template tell (see §14) and are not used anywhere in this system, including table headers — weight and a hairline border under the header row carry the hierarchy instead.

Line length for prose blocks (drawer explanations, AI answers): cap at ~72 characters via container width, not `ch` hacks that fight code blocks.

---

## 5. Spacing

Base unit: **4px**. Scale: `4 · 8 · 12 · 16 · 20 · 24 · 32 · 40 · 48 · 64`.

| Token | Value | Usage |
|---|---|---|
| `space.page-margin` | 24px | Outer margin of main content area |
| `space.content-padding` | 20px | Padding inside a page's primary content region |
| `space.surface-padding` | 16px | Padding inside elevated cards (finding summary, scan config panel) |
| `space.table-row-y` | 8px | Vertical padding per table row (dense) |
| `space.table-row-x` | 12px | Horizontal padding per table cell |
| `space.section-gap` | 32px | Gap between major page sections |
| `space.sidebar-padding` | 12px | Sidebar internal padding |
| `space.sidebar-item-y` | 6px | Vertical padding per nav item |
| `space.code-padding` | 16px | Code/diff viewer padding |
| `space.drawer-padding` | 20px | Finding drawer section padding |
| `space.control-padding-y` | 6px | Button/input vertical padding (compact controls throughout) |
| `space.control-padding-x` | 10px | Button/input horizontal padding |

Table row height target: **32px** default density, **28px** in "compact" mode (toggle available in Findings and Secrets — see §13.9).

---

## 6. Shape Language

Restrained radii. Nothing is rounded by default; radius is applied only where it clarifies what's a discrete, draggable/clickable object vs. a structural region.

| Token | Value | Usage |
|---|---|---|
| `radius.surface` | 6px | Elevated cards, panels |
| `radius.input` | 4px | Text inputs, selects, search |
| `radius.button` | 4px | Buttons, icon buttons |
| `radius.badge` | 3px | Rectangular badges (framework, status tags in tables) |
| `radius.pill` | 999px | Compact severity/status pills only — reserved, not used for general tags |
| `radius.modal` | 8px | Modal dialogs |
| `radius.drawer` | 0px | Finding drawer is edge-attached (right side, full height) — no radius, it's structurally part of the shell, not a floating object |
| `radius.tooltip` | 4px | Tooltips |

Tables, the app shell, sidebar, top bar, and status bar all have **0px radius** — they're structure, not objects.

---

## 7. Borders & Elevation

Depth comes from **1px borders and surface-luminance steps**, not shadows.

- Surfaces step up in lightness: `canvas (#0A0C0F) → surface (#101318) → elevated (#151922) → overlay (#171B24)`. Each step is a deliberate, small luminance increase — enough to read as "in front of," not enough to look lit.
- Every discrete component (card, input, table, drawer, modal) gets a `1px solid color.border.default` edge. That edge does the elevation work a shadow would otherwise do.
- The **only** permitted shadow is a single soft drop shadow behind modals and the finding drawer, used purely to separate them from page content that may still be visible/scrollable behind: `0 8px 24px rgba(0,0,0,0.4)`. No shadows on cards, buttons, table rows, or badges — ever.
- No glassmorphism (no backdrop-blur-as-aesthetic). The modal scrim is a flat dark fill, not a blurred one.

---

## 8. Iconography

- Icon set: a single consistent outline icon set (e.g. Lucide), 16px in dense contexts (table cells, nav), 20px in section headers. No filled/duotone icons, no custom illustrated icons.
- Icons are functional labels for actions and states (search, filter, copy, chevron, external-link, warning-triangle for critical) — never decorative accompaniments to headings or empty states. If removing the icon loses no information, remove it.
- Severity is communicated primarily through the `SeverityBadge` text + color, not through icon shape. Icons don't duplicate what a badge already says.

---

## 9. Charts — used only when they carry security meaning

Per principle 7, AntiFine is not an analytics product. Charts appear in exactly three places, and nowhere else:

1. **Findings-over-time** (Overview, optional, collapsed by default): a thin sparkline-style line chart, single line, status-colored by trend direction (red if critical count is rising), max height 48px. Not a hero element.
2. **Severity distribution** (Overview): a **horizontal stacked bar**, not a donut — a single row showing proportion of Critical/High/Medium/Low, using status colors, with the counts printed as numbers alongside. This replaces "giant circular score graphics" entirely.
3. **Scan duration/technology breakdown** (Scan history, optional): a compact horizontal bar list, effectively a table with an inline bar — not a separate chart widget.

No donut/pie charts. No 3D charts. No chart exists solely to fill empty space — if a table row of numbers communicates the same thing, use the table.

---

## 10. Application Shell

```
┌──────────────┬──────────────────────────────────────────────────┐
│  AntiFine    │  Findings                            [Search] [⌘K]│  ← Top bar, 48px
│  LOCAL       ├──────────────────────────────────────────────────┤
│  WORKSPACE   │                                                    │
│              │                                                    │
│  Overview    │              Main content                         │
│  Scan        │                                                    │
│  Findings    │                                                    │
│  Remediation │                                                    │
│  Compliance  │                                                    │
│  Secrets     │                                                    │
│  History     │                                                    │
│  Reports     │                                                    │
│              │                                                    │
│  Ask         │                                                    │
│  AntiFine    │                                                    │
│              │                                                    │
├──────────────┼──────────────────────────────────────────────────┤
│ Local Engine │                                                    │
│ FastAPI ·    │                                                    │
│ 127.0.0.1:   │                                                    │
│ 8000         │                                                    │
│ ● Local AI   │                                                    │
│ Ollama ·     │                                                    │
│ qwen2.5:7b   │                                                    │
│ Settings     │                                                    │
└──────────────┴──────────────────────────────────────────────────┘
```

**Sidebar** (`bg.surface`, 220px wide, fixed, `border-right: 1px solid border.default`):
- Wordmark row: "AntiFine" (`type.section-heading`) + "LOCAL WORKSPACE" (`type.caption`, `text.muted` — this is the one intentional small-caps label in the product, used once, because it's genuinely a workspace-mode indicator, not decoration).
- Nav group 1 (primary workflow): Overview, Scan, Findings, Remediation, Compliance, Secrets, History, Reports. Each item: 16px icon + label, `type.body`, `space.sidebar-item-y` vertical padding, active state = `accent.muted-bg` fill + `color.accent.default` left border (2px) + `text.primary`; inactive = `text.secondary`; hover = `bg.hover`.
- Nav group 2 ("Intelligence"): Ask AntiFine — visually identical row style to group 1, no special AI styling, just placed in its own labeled group so it reads as a distinct workflow, not a different product bolted on.
- **Status footer** (pinned bottom, `border-top: 1px solid border.default`, `type.metadata`):
  - `Local Engine` label + `FastAPI · 127.0.0.1:8000` with a small solid status dot (green when reachable, `status.critical` red when the backend is unreachable).
  - `Local AI` label + `Ollama · qwen2.5:7b` with a status dot (green when Ollama responds, `text.muted` grey dot with label "Offline" when not — AI being offline is never an error state, just muted).
  - `Settings` as a final row, same style as nav items.

This footer is the single most important trust signal in the shell: it makes "this all runs on your machine" a persistent, factual, un-ignorable piece of UI rather than a claim on a marketing page.

**Top bar** (`bg.surface`, 48px, `border-bottom: 1px solid border.default`): page title (`type.page-title`) left-aligned, global search + command palette trigger (`⌘K`) right-aligned. No breadcrumb decoration, no user-avatar-and-notification-bell cluster unless multi-user auth actually exists — don't build chrome for features that don't exist.

**Main content**: `space.page-margin` (24px) outer padding, `space.content-padding` inside primary panels.

**Status bar** (optional, bottom of main content on data-heavy pages only, e.g. Findings): shows row count / selection count / last scan time — `type.metadata`, `bg.surface`, `border-top: 1px solid border.default`, 28px tall.

---

## 11. Page Designs

### 11.1 Overview — "What needs attention?"

Not an analytics dashboard. Top of page is a single **compact stat row** (not cards): Security Grade, Critical, High, Medium, Low, Secrets Found, Last Scan — each as a `Metric` component (see §13) in a single bordered row, divided by hairline vertical rules, not six separate floating cards. Below that:

- **Severity distribution** bar (§9.2).
- **Open Findings** — a dense table (top 10 by severity, "View all →" to Findings page). Real table, real rows, not a preview card.
- **Technology breakdown** — compact table: Framework | Files scanned | Findings. Not a pie chart.
- **Recent scans** — table: Timestamp | Duration | Files | New findings | Status.

Everything above the fold is scannable in under five seconds and every number is a link into the relevant filtered view.

### 11.2 Scan

Workspace layout, two panels:
- Left: file drop zone (dashed `border.default`, not accent-colored — it's a neutral operational control, not a CTA) + file list (dense table: path, framework detected, size) + framework selection (checkboxes, not toggle-cards) + "Run Scan" primary button.
- Right (or below on narrow widths): live scan log — a monospace, terminal-style scrolling panel on `bg.inset`, printing real operation lines as they happen:
  ```
  Parsing...
  Rules...
  Secrets...
  Compliance...
  Generating findings...
  ```
  This is a log, not a progress-bar-with-mascot. Each line gets a timestamp prefix (`type.metadata`) and a trailing status (`● done` in `status.success`, or a spinner glyph while active — see §16 for the only allowed loading motion). On completion, show a compact result summary row (counts by severity) with a "View Findings" button — not a new screen takeover.

### 11.3 Findings

The core investigation workspace. Single dense table, full width, sticky header.

**Columns:** Severity · Rule · Title · Resource · File · Line · Framework · Status

- Search bar + filter chips (severity, framework, status, rule) above the table, `type.body`, compact height (32px).
- Column headers sortable (click, `↑`/`↓` glyph appears on active sort column only).
- Row height 32px default / 28px compact toggle.
- Row hover: `bg.hover`. Row selection (checkbox column, appears on hover or when any row is selected): `bg.selected`.
- Keyboard: `↑`/`↓` moves focus row, `Enter` opens drawer, `x` toggles selection, `/` focuses search — documented in a `?` shortcuts overlay, not hidden.
- Clicking a row opens the **Finding Drawer** (§11.4) from the right edge; it does not navigate away from the table (table scroll position and filters persist).
- Pagination or virtualized scroll for large result sets — no "load more" button pattern; prefer virtualization so keyboard nav feels like scrolling a file, not paging a website.

### 11.4 Finding Drawer

Right-edge panel, ~480px wide, full height, `bg.overlay`, `border-left: 1px solid border.default`, the one place in the product that gets the soft drop shadow (§7).

Vertical hierarchy, top to bottom:

1. **Header block**: `SeverityBadge` + Rule ID (`type.metadata`, monospace) + close button. Title below in `type.section-heading`. Technology `FrameworkBadge`, File path + line number (`type.metadata`, clickable → opens in Code Viewer at that line).
2. **Why Detected** — `type.body` prose, factual, one to three sentences, no hedging language.
3. **Affected Resource** — key/value technical metadata (resource type, resource name, provider).
4. **Relevant Code** — embedded `CodeViewer` excerpt (§13.13), read-only, line highlighted.
5. **Compliance** — table of mapped controls (Framework | Control ID), each linking to Compliance page filtered to that control.
6. **Deterministic Remediation** — the fix summary + "Review Fix →" button that opens the full Remediation flow (§11.5). This block visually dominates: it sits above the AI section, has a `status.success`-tinted left border (2px) to mark it as the actionable, trusted path.
7. **Local AI Explanation** (collapsed by default, user expands) — clearly separated by a hairline divider and a small header row: "Local AI" label + "Ollama · qwen2.5:7b" metadata (`type.caption`, `text.muted`) + a "Generated locally" tag. Text itself in `type.body` but in `text.secondary` (one shade quieter than the deterministic sections) to reinforce visual secondary status. No avatar, no chat bubble, no colored background.

### 11.5 Remediation

Git/IDE-style review flow: **Finding → Review Fix → Before/After → Apply → Backup → Rescan → Resolved.** Render this as a horizontal step tracker at the top of the page (plain text + connecting hairline, current step in `text.primary` + `accent.default` underline, future steps in `text.muted` — not a colorful stepper widget with circles and gradients).

Main panel: **`DiffViewer`** (§13.14) — side-by-side, syntax-highlighted, line numbers, unchanged context collapsed by default with "Show N unchanged lines," removed lines on a subtle `status.critical` @ 6% row tint with `−` gutter marker, added lines on `status.success` @ 6% row tint with `+` gutter marker. File path + Rule ID pinned above the diff.

Below the diff: **Remediation Explanation** (deterministic, factual — "Adds `server_side_encryption_configuration` block using AES256"), then AI explanation collapsed underneath the same way as in the drawer.

Primary actions, right-aligned above the diff: **Apply Fix** (primary button, `accent.default` fill) with backup filename shown inline in `type.metadata` next to it (`→ backup: main.tf.bak`), then after applying, a **Run Verification Scan** button appears. Status of each step (Applied / Backed up / Rescanning / Resolved) shown as small `StatusBadge`s in the step tracker, not a separate celebratory screen.

### 11.6 Code Viewer

Standalone and embedded (drawer, diff) variants share one component. Monospace (`type.code`), line numbers in `text.muted` on a slightly recessed gutter, `bg.inset` background, syntax highlighting limited to a **restrained 5–6 color set** mapped to token type (keyword, string, comment, constant, punctuation) — not a rainbow theme; comments in `text.muted`, strings in `status.success`-adjacent muted green, keywords in `text.primary` bold, nothing else colored. Copy button top-right (icon button, appears on hover). Horizontal scroll for long lines rather than wrapping (wrapping breaks line-number correspondence). File path pinned as a header row above the code region.

### 11.7 Compliance

Investigation table, not a card grid of framework logos.

**Columns:** Framework · Control · Requirement · Status · Findings · Remediation

- `Status` uses `StatusBadge` (Pass / Fail / Partial — status colors: success/critical/high).
- `Findings` column shows a count, clickable → filters Findings page to that control.
- Clicking a row expands inline (accordion) or opens a lightweight side panel showing the requirement text and the related finding list — reuse the drawer pattern from §11.4 rather than inventing a new panel type.
- All compliance data displayed comes from deterministic AntiFine mappings; nothing here is AI-generated, and nothing on this page carries an AI label.

### 11.8 Secrets

Same table pattern as Findings, domain-specific columns: **Pattern · Entropy Score · Rule · File · Line · Severity · Status**.

- Secret values are **always masked** by default: show fixed-width mask (`••••••••3f2a`, last 4 chars only, monospace) — never render full secret text in the DOM by default.
- A per-row "Reveal" action requires explicit click (icon button, not a hover-reveal — hover-reveal risks shoulder-surfing/screen-share exposure) and auto-re-masks after a short timeout or navigation away.
- Entropy Score shown as a plain number (`type.table`, monospace) plus threshold context in a tooltip, not a gauge/meter graphic.

### 11.9 Ask AntiFine

Deliberately not a chatbot UI. No avatar, no bubble colors, no "AI" hero branding.

Layout: a technical command console, not a messaging app.

- **Header**: "Local AI" (`type.section-heading`) + "Ollama · qwen2.5:7b" (`type.metadata`, `text.muted`) + connection status dot, matching the sidebar footer's language exactly (consistency = trust).
- **Context indicator**: a pinned, dismissible chip block showing what the question is scoped to, e.g.:
  ```
  Context: TF-AWS-004 · CRITICAL · terraform/main.tf:42
  ```
  Rendered as plain metadata text with a `SeverityBadge`, `border: 1px solid border.default`, `radius.surface` — not a colorful "AI context card." "Clear context" and "New chat" sit as small text-buttons beside it.
- **Conversation**: question/answer pairs rendered as left-aligned blocks with a thin left border (2px, `text.muted` for the user's question, `color.accent.default` @ 40% for the AI's answer) — no chat bubbles, no alternating alignment, no avatars. Each answer includes a **Sources** line underneath (`type.metadata`, links to the specific findings/rules/code it drew from) and a **Regenerate** icon button.
- **Input**: fixed bottom, monospace-adjacent single-line-to-multiline text input, `bg.surface`, `border.default`, send via `Enter` (`Shift+Enter` for newline) — console-like, not a rounded pill chat input.

---

## 12. AI Visual Hierarchy

This is enforced structurally everywhere AI appears, not just described:

```
Deterministic AntiFine finding
        ↓
Deterministic remediation
        ↓
Optional AI explanation
```

Rules, applied consistently:
- AI content is **always** below, or visually subordinate to (via `text.secondary`, muted left-border weight, or a collapsed-by-default state), the deterministic content on the same screen.
- AI content is **always** labeled: "Local AI," "Generated locally," "AI-generated explanation," or "Based on AntiFine findings" — one of these four strings, consistently, never a generic "✨ AI" badge.
- AI never gets its own color. It uses `text.secondary`/`text.muted` and the neutral `status.info` (which shares the accent hue) only if a status treatment is unavoidable — never a unique purple/pink "AI accent."
- No robot avatars, no sparkle/magic-wand iconography, no gradient text, no "typing…" bouncing-dot animation (use the same restrained spinner as scan progress, §16).
- AI is never the sole source of a security verdict anywhere in the product. Every AI-touched screen shows the deterministic finding or remediation it is explaining, in the same view.

---

## 13. Component Library

For each: purpose, anatomy, sizing, type, color, states, interaction, accessibility.

### 13.1 Button
- **Purpose:** primary/secondary actions.
- **Anatomy:** optional 16px leading icon + label.
- **Sizing:** height 28px (compact) / 32px (default). Horizontal padding `space.control-padding-x`.
- **Variants:** Primary (`accent.default` fill, `text.inverse` label), Secondary (`bg.elevated` fill, `border.default`, `text.primary`), Ghost (transparent, `text.secondary`, fill appears on hover), Destructive (border/text in `status.critical`, fill only on hover).
- **States:** default / hover (+6% lightness or `accent.hover`) / active (−4% lightness) / focus (2px `border.focus` ring, 2px offset) / disabled (`disabled.bg`/`disabled.border`/`text.disabled`, no pointer) / loading (label replaced by inline spinner, width preserved).
- **A11y:** real `<button>`, visible focus ring never suppressed, `aria-busy` when loading.

### 13.2 IconButton
- 28×28px hit target minimum even if the icon is 16px, `radius.button`. Same state model as Button. Always has an `aria-label` — icon-only controls are never unlabeled.

### 13.3 Input
- Height 32px, `radius.input`, `bg.surface`, `border.default`. Focus: `border.focus` + ring. Error: `border` → `status.critical`, helper text below in `status.critical`/`type.caption`. Placeholder in `text.muted`.

### 13.4 Search
- Input variant with leading 16px search icon, trailing clear (×) icon when populated, optional `⌘K` hint chip at rest (`type.caption`, `text.muted`, right-aligned inside the field).

### 13.5 Select
- Same shell as Input, trailing chevron. Dropdown panel: `bg.elevated`, `border.default`, `radius.surface`, options 32px tall, hover `bg.hover`, selected option checked with a 16px check icon (not a filled background swap that hides the label color contrast).

### 13.6 Checkbox
- 16×16px, `radius.badge`-scale (3px), `border.default` unchecked; checked = `accent.default` fill + white check glyph. Indeterminate = accent fill + dash. Focus ring same as Button.

### 13.7 Toggle
- Track 32×18px, thumb 14px. Off = `bg.elevated`/`border.default` track, thumb `text.muted`. On = `accent.default` track, thumb `text.inverse`. Used sparingly — most binary choices in this product are checkboxes or filters, not toggles (toggles imply a persistent setting, not a filter).

### 13.8 Badge (generic) / SeverityBadge / StatusBadge / FrameworkBadge
- **Badge base:** `radius.badge`, `type.label` at 11px, horizontal padding 6px, height 18–20px.
- **SeverityBadge:** filled 10%-tint background of the matching `status.*` color, 1px border at full-opacity status color, text in full-opacity status color. Label = "Critical/High/Medium/Low" exactly, never abbreviated to letters/dots.
- **StatusBadge:** same visual recipe, used for workflow state (Open/Resolved/Ignored/Applied/Pass/Fail).
- **FrameworkBadge:** neutral — `bg.elevated`, `border.default`, `text.secondary` — frameworks (Terraform/Docker/K8s) are metadata, not severity, so they never borrow a status color.

### 13.9 Metric
- Used only in the Overview stat row (§11.1), never as a floating "KPI card." Anatomy: label (`type.label`, `text.muted`) above value (`type.page-title`-weight but 18px, `text.primary`, or `status.*` color for severity counts). No icon, no background fill, no border of its own — separated from siblings by a shared row border and a hairline vertical divider only.

### 13.10 Table
- Header row: `bg.surface`, `border-bottom: 1px solid border.default`, `type.table-header`, sortable columns get hover affordance + sort glyph.
- Body rows: `border-bottom: 1px solid border.hairline`, `type.table`, height per §5. Hover `bg.hover`. Selected `bg.selected`. Keyboard-focused row gets `border.focus` as an inset outline (2px, offset −2px) so it's visible without disturbing row height.
- Density toggle where noted (Findings, Secrets): default 32px / compact 28px.
- Pagination (where virtualization isn't used): simple prev/next + page count in `type.metadata`, right-aligned below table — no page-number-button strip.

### 13.11 FindingRow
- A `Table` row specialization: leading `SeverityBadge`, Rule ID in monospace `type.metadata`, Title in `type.table`, Resource/File/Line in `type.metadata`, trailing `FrameworkBadge` + `StatusBadge`. Entire row clickable to open the drawer; individual monospace fields (file/rule) are separately copyable via hover-reveal copy icon.

### 13.12 FindingDrawer
- See §11.4 for full spec. Component contract: accepts a finding ID, is independently scrollable, persists parent table scroll/filter state, closes on `Esc` or scrim click (scrim is transparent/absent here since it doesn't block the table — drawer simply overlays the right portion).

### 13.13 CodeViewer
- See §11.6. Props: file path, language, line range, highlighted line(s), read-only. Always keyboard-scrollable, always has a copy action.

### 13.14 DiffViewer
- See §11.5. Props: file path, rule ID, before/after content, context-line collapse state. Gutter shows line numbers for both sides in split view; unified fallback for narrow widths (<1024px, see §17).

### 13.15 Modal
- `bg.overlay`, `radius.modal`, max-width 480–640px depending on content, centered, single drop shadow (§7), scrim `color.overlay.scrim`. Used only for genuinely blocking confirmations (e.g. "Apply fix without reviewing diff?") — not for anything that could be a drawer or inline panel instead.

### 13.16 Drawer
- Generic right-edge panel pattern underlying `FindingDrawer` and Compliance detail (§11.7). `bg.overlay`, `radius.drawer` (0), left border, single drop shadow.

### 13.17 Toast
- Bottom-right stack, `bg.elevated`, `border.default`, `radius.surface`, `type.body`, left-edge 3px status-color bar (success/critical/info) instead of a full-colored background. Auto-dismiss 4s, hoverable to pause, manual close icon.

### 13.18 Tooltip
- `bg.elevated`, `border.default`, `radius.tooltip`, `type.caption`, max-width 240px, appears after ~400ms hover delay, no arrow decoration beyond a 6px CSS triangle in matching border color.

### 13.19 Tabs
- Underline style: `type.label`, `text.secondary` inactive, `text.primary` + 2px `accent.default` underline active. No pill/segmented-control chrome — underline tabs read as structural navigation, pills read as marketing toggle switches.

### 13.20 CommandPalette
- Triggered by `⌘K`. Modal-style overlay, top-anchored (not centered), `bg.overlay`, search input at top (`type.body`, larger 14px), results list below grouped by type (Findings / Pages / Actions), `type.table`-scale rows, arrow-key navigable, `Enter` to execute, `Esc` to close.

### 13.21 ScanProgress
- Lives inside the Scan workspace log (§11.2). Not a progress bar with percentage — a scrolling operation log with per-line status glyphs. If a percentage is genuinely available from the backend, show it as plain `type.metadata` text ("Parsing... 412/900 resources"), never a filled bar with gradient.

### 13.22 AIExplanation
- Wraps any AI-generated text block. Anatomy: header ("Local AI" + model metadata + "Generated locally" tag), collapsible body in `text.secondary`, `Sources` line, `Regenerate` icon button. Always rendered after, and visually quieter than, the deterministic content it accompanies (§12).

### 13.23 ContextIndicator
- Chip-style block used in Ask AntiFine (§11.9): plain metadata row with `SeverityBadge` + rule/file/line, `border.default`, `radius.surface`, dismissible via a small "Clear context" text button.

### 13.24 EmptyState
- No illustration. `type.section-heading` stating the actual state ("No findings match these filters" / "No scans yet"), one line of `type.body` guidance, one action button if applicable ("Clear filters" / "Run first scan"). Left-aligned within the content region, not centered-with-giant-icon.

### 13.25 ErrorState
- Same layout discipline as EmptyState. States the failure factually ("Scan failed: could not parse `main.tf` — invalid HCL syntax") with the actual error detail available (expandable), plus a retry action. Never "Oops! Something went wrong."

### 13.26 Skeleton
- Flat `bg.elevated` blocks at `radius.input`/`radius.surface` matching the shape of the content loading in, subtle opacity pulse only (§16) — no shimmer/gradient sweep.

---

## 14. Interaction States

Every interactive component defines all of: default, hover, active, focus, selected, disabled, loading, success, error. The concrete values are specified per-component in §13; the system-wide rules are:

- **Focus** is always a visible 2px `border.focus` ring with 2px offset — never suppressed via `outline: none` without a replacement, on any element, including inside the code/diff viewers.
- **Hover** always uses a background-luminance step (`bg.hover`) or border-luminance step (`border.strong`), never a color hue change, so hover never gets confused with status/severity color.
- **Selected** always uses `bg.selected` (accent-tinted), distinct from hover, so multi-select in tables is legible while hovering elsewhere.
- **Loading** never blocks the whole screen for a sub-second operation; use inline spinners/skeletons scoped to the changing region.
- **Success/Error** as transient states (form submit, apply fix) resolve to a `Toast` or an inline `StatusBadge` change — not a full-screen confetti/checkmark moment.

---

## 15. Accessibility

- **Keyboard:** every workflow (browse findings, open drawer, apply fix, run scan, ask AI) must be completable without a mouse. Table row navigation, drawer open/close, command palette, and form controls all define explicit key handling (documented per-component above).
- **Focus treatment:** as in §14 — always visible, always a consistent ring style, never color-only.
- **Contrast:** all text/background pairs in §3 meet WCAG AA at minimum for their usage (body text ≥4.5:1, large/label text ≥3:1); status colors on their 10%-tint badge backgrounds are verified against `bg.surface`/`bg.elevated`, not just against white.
- **ARIA:** tables use proper `role="table"`/row/cell semantics or native `<table>`; the drawer uses `role="dialog"` with `aria-labelledby` pointing at the finding title; toasts use `role="status"`/`aria-live="polite"`; the AI conversation region uses `aria-live="polite"` for new answers so screen readers announce responses without interrupting typing.
- **Reduced motion:** `prefers-reduced-motion` disables the drawer slide-in (instant show instead), the diff reveal animation, and the scan-log line-appear transition — spinners remain (they convey ongoing state, not decoration) but stop any non-essential easing.
- **Semantic HTML:** real `<button>`, `<input>`, `<table>`, `<nav>` throughout; no `<div onClick>` interactive elements.

---

## 16. Motion

Restrained, state-communicating only. Default duration 120–160ms, `ease-out` for entrances, `ease-in` for exits. Allowed:

- **Drawer transition:** slide in from right, 160ms.
- **Hover:** background/border luminance step, 100ms, no scale/transform.
- **Scan progress:** log lines appear via a quick 100ms fade (not a typewriter effect); a single small rotating spinner glyph (not a full loading screen) marks the in-progress line.
- **Diff reveal:** collapsed context lines expand with a 150ms height transition.
- **Toast:** slide + fade in, 160ms; fade out on dismiss.

Not allowed anywhere: bounce/spring easing, floating/parallax effects, glow pulses, gradient sweeps, decorative on-load stagger animations across cards or table rows.

---

## 17. Responsive

Desktop-first; primary target widths 1280 / 1440 / 1600 / 1920.

- **1024px:** sidebar collapses to icon-only (48px, labels in tooltip on hover); tables drop lowest-priority column (e.g. Framework in Findings) before wrapping anything; DiffViewer switches from side-by-side to unified (single column, `+`/`−` gutter markers still present).
- **768px:** sidebar becomes an overlay drawer triggered by a top-bar menu icon rather than persistent; Finding Drawer becomes full-width instead of 480px fixed; Overview stat row wraps to two rows of metrics (still a bordered row group, not cards).
- **Mobile:** out of primary scope (this is a local engineering tool), but must not break: tables scroll horizontally within their container rather than reflowing into stacked "cards" — preserving column alignment and monospace data is more important than fitting the viewport. Code/diff viewers keep horizontal scroll, never wrap code.

Never convert tables, code, or diffs into card-per-row layouts at any breakpoint — that reintroduces the exact card-heavy pattern this system exists to remove.

---

## 18. Content Language

Voice: technical, active, factual. AntiFine states what happened and what to do next — it doesn't narrate feelings about it.

**Avoid:** "Good morning," "Great job!," "Smart insights," "AI magic," "Your security journey," exclamation points, and any copy that addresses the user's day rather than their infrastructure.

**Prefer:** "Security Overview," "Open Findings," "Deterministic Remediation," "Scan Results," "Rules Evaluated," "Finding Details," "Review Fix," "Verification Scan."

Rules:
- Buttons name the action's result, not a generic verb: "Apply Fix," "Run Scan," "Clear Filters" — not "Submit," "Go," "OK" alone.
- An action's name stays identical through its whole lifecycle: the "Apply Fix" button produces a toast that says "Fix applied," not "Success!" or "Done!"
- Errors state the fact and, where known, the cause: "Scan failed: could not parse `main.tf` — invalid HCL syntax," not "Something went wrong."
- Empty states are instructions, not apologies: "No findings match these filters" + "Clear filters," not "Nothing here yet! 🎉"
- No exclamation points in system-generated copy anywhere in the product.
- Table headers and labels use sentence case, not tracked-out ALL CAPS (the one exception, "LOCAL WORKSPACE," is a deliberate one-off workspace-mode indicator, not a pattern to repeat).
- No middle-dot-joined marketing strings ("Fast · Secure · Reliable"). The only permitted middle-dot usage is genuinely structural metadata ("FastAPI · 127.0.0.1:8000," "Ollama · qwen2.5:7b") describing two real, distinct facts — not a rhythm device.

---

## 19. Do / Don't

| Do | Don't |
|---|---|
| Use tables for any collection of comparable items | Use a grid of rounded cards for a collection |
| Show real counts, real file paths, real rule IDs | Show generic "insights" or vague summaries |
| Let borders and luminance steps carry depth | Use large soft shadows or floating-card aesthetics |
| Label AI output every time it appears | Let AI text look identical to deterministic output |
| Use one accent hue, sparingly, for interaction only | Use the accent as a decorative fill or gradient source |
| Write button labels that name the result | Write "Submit," "OK," or "Go" |
| Use a horizontal stacked bar for severity mix | Use a donut/pie/circular score graphic |
| Keep row density high, 28–32px rows | Add generous card padding "for breathing room" |
| Use monospace for anything technical (paths, IDs, code) | Use the UI font for rule IDs or file paths |
| Collapse AI explanations by default | Auto-expand AI content above the deterministic verdict |

---

## 20. Implementation Guidance

- Implement all tokens in §3–§7 as CSS custom properties (or Tailwind theme extension) named exactly as the dotted tokens above, e.g. `--color-status-critical`, `--space-content-padding`, `--radius-surface`, so any AI coding agent implementing a component can map directly from this document to code without inventing values.
- Build `SeverityBadge`, `StatusBadge`, and `Table`/`FindingRow` first — they're reused on Overview, Findings, Secrets, Compliance, and the Drawer, so getting them exactly right once removes most inconsistency risk.
- Build the sidebar status footer (§10) early and wire it to real health-check endpoints for the FastAPI backend and Ollama — this is the product's core trust signal and should never be a static/fake element.
- `DiffViewer` and `CodeViewer` should share a single syntax-highlighting and line-number implementation (props differ, rendering core doesn't) to guarantee visual consistency between the two.
- Do not introduce any component, color, or copy pattern not specified here without checking it against §19's Do/Don't table and the ten principles in §1 first.

---

## 21. Why This Reads as Professional Security Software, Not an AI-Generated Dashboard

**Removed the giant circular score and decorative charts.** A single number in a circle is a marketing device — it doesn't help someone triage. The stacked severity bar plus a real findings table gives the same "state of the world" information in a form an engineer can act on immediately, which is the actual job of a security tool's home screen.

**Replaced card grids with tables everywhere a collection appears.** Cards imply "these are separate little products/features to browse." Findings, secrets, and compliance controls are homogeneous technical records with the same attributes — that's structurally a table, and treating it as one is what makes the product feel like GitHub Security or Sentry rather than a landing page.

**Cut the accent color down to one hue used only for interaction**, and let the *status* colors (critical/high/medium/low/success) carry the product's visual identity instead. This is the single biggest fix for "excessive blue/purple," because the problem was never the hue — it was using an interactive accent as general-purpose brand paint. Now color in AntiFine always means something specific.

**Elevation via borders and luminance steps instead of shadows** removes the "floating card" look that is the most immediate tell of a generated SaaS UI, and reads instead like the flat, structural surfaces of a code editor or terminal multiplexer.

**AI is structurally subordinate everywhere**, both visually (quieter text color, secondary position, collapsed by default) and verbally (always labeled "Local," always paired with the deterministic verdict it's explaining). This is the direct visual expression of the product's real value proposition — a deterministic engine you can trust, with optional local AI assistance — rather than an AI product with a security theme.

**The local-first status footer is persistent, factual UI, not a claim.** Showing `FastAPI · 127.0.0.1:8000` and `Ollama · qwen2.5:7b` with live status dots, permanently, in the sidebar, does more to establish trust than any amount of "Your data never leaves your machine" copy would — because it's evidence, not marketing.

**Content language cut every trace of consumer-SaaS warmth** ("Good morning," exclamation points, "smart insights") in favor of exact technical statements, matching how the audience — security and infrastructure engineers — actually wants to be told what's wrong and what to do about it.
