# Accessibility Audit — 2026-03-17

**Tool**: axe-core 4.10.0 (WCAG 2A, 2AA, 2.1AA, best-practice ruleset)
**Pages audited**: https://gosqlx.dev (homepage), https://gosqlx.dev/docs/getting-started
**Auditor**: Claude Code automated audit

---

## axe-core Violations Summary

| Page | Critical | Serious | Moderate | Minor | Passes | Incomplete |
|------|----------|---------|----------|-------|--------|------------|
| Homepage (`/`) | 0 | 1 | 0 | 1 | 38 | 1 |
| `/docs/getting-started` | 0 | 2 | 1 | 1 | 40 | 0 |

**Total unique violations across both pages: 4 distinct rules triggered**

---

## Detailed Violations

### Homepage Violations

#### serious: scrollable-region-focusable
- **Description**: Ensure elements that have scrollable content are accessible by keyboard
- **WCAG Criterion**: WCAG 2.1 SC 2.1.1 (Keyboard, Level A)
- **Nodes affected**: 1
- **Example HTML**: `<pre class="p-4 text-[13px] leading-relaxed font-mono text-zinc-400 overflow-x-auto max-h-[320px]">`
- **Fix**: Add `tabindex="0"` to each `<pre>` block that has `overflow-x-auto` or `overflow-y-auto` so keyboard users can scroll into the region. For the hero code block and AST output panel specifically.

#### minor: image-redundant-alt
- **Description**: Ensure image alternative text is not repeated as adjacent visible text
- **WCAG Criterion**: Best practice (not a hard WCAG fail, but degrades screen-reader UX)
- **Nodes affected**: 2 (both logo images — header and footer)
- **Example HTML**: `<img alt="GoSQLX" ...>` inside `<a>` that also contains `<span>GoSQLX</span>`
- **Fix**: Set `alt=""` on the logo `<img>` when the adjacent `<span>GoSQLX</span>` text is already present, making the image purely decorative. The link itself is adequately labelled by the text node.

---

### /docs/getting-started Violations

#### serious: color-contrast
- **Description**: Ensure the contrast between foreground and background colors meets WCAG 2 AA minimum contrast ratio thresholds (4.5:1 for normal text, 3:1 for large text)
- **WCAG Criterion**: WCAG 2.1 SC 1.4.3 (Contrast Minimum, Level AA)
- **Nodes affected**: 19
- **Example HTML**:
  - `<a class="hover:text-white transition-colors" href="/docs">Docs</a>` — nav links at ~65% lightness on dark background
  - `<span>Getting Started</span>` — breadcrumb text
- **Fix**: Nav link color `lab(65.6464 ...)` (~`#9ca3af` / zinc-400) on the dark `#18181b` background gives approximately 3.5:1 — below 4.5:1 required for 14px normal text. Increase to `text-zinc-300` (`#d4d4d8`) or lighter to achieve ≥4.5:1. Breadcrumb spans and sidebar section labels have the same issue.

#### serious: scrollable-region-focusable
- **Description**: Same as homepage — `<pre>` code blocks with overflow are not keyboard-reachable
- **WCAG Criterion**: WCAG 2.1 SC 2.1.1 (Keyboard, Level A)
- **Nodes affected**: 13 (all code blocks on the getting-started page)
- **Example HTML**:
  - `<pre><code class="language-bash">go install ...</code></pre>`
  - `<pre>` (inline code blocks throughout)
- **Fix**: Same as homepage — add `tabindex="0"` to all `<pre>` elements that may overflow. Consider a shared `CodeBlock` component that applies this automatically.

#### moderate: landmark-unique
- **Description**: Ensure landmarks are unique — two `<nav>` elements on the page share the same role with no distinguishing accessible name
- **WCAG Criterion**: WCAG 2.1 SC 1.3.6 (Identify Purpose, Level AAA) / Best practice
- **Nodes affected**: 1
- **Example HTML**: `<nav class="mx-auto max-w-7xl flex items-center ...">`
- **Fix**: Add `aria-label` to each `<nav>` to distinguish them. E.g., `aria-label="Primary"` on the top navbar, `aria-label="Docs sidebar"` on the docs sidebar nav, `aria-label="Breadcrumb"` on breadcrumb navigations.

#### minor: image-redundant-alt
- **Description**: Same as homepage — logo image alt duplicates adjacent text
- **WCAG Criterion**: Best practice
- **Nodes affected**: 2 (header and footer logo)
- **Fix**: Same as homepage — set `alt=""` on the logo `<img>`.

---

## Structural Checks

### Heading Hierarchy — Homepage

```
H1: Parse SQL at the speed of Go
H2: Built for Production
  H3: Multi-Dialect
  H3: Thread-Safe
  H3: Zero-Copy
  H3: Object Pooling
  H3: Security Scanner
  H3: MCP Server
H2: Simple, Powerful API
H2: AI-Ready SQL Tools
H2: IDE Integration
H2: Ready to parse SQL at the speed of Go?
H3: Product        (footer)
H3: Resources      (footer)
H3: Community      (footer)
```

**Assessment**: Hierarchy is well-formed. Single H1, logical H2 sections, H3 subsections. No heading levels are skipped. Footer H3s are semantically reasonable as section labels. No issues found.

---

### Skip Link

- **Status**: MISSING — no skip-to-main-content link found on homepage or docs page
- **WCAG Criterion**: WCAG 2.1 SC 2.4.1 (Bypass Blocks, Level A)
- **Impact**: Keyboard-only users must tab through the entire navigation bar on every page load before reaching main content.
- **Fix**: Add a visually-hidden skip link as the very first focusable element in `<body>`, revealed on focus:

```jsx
// In your root layout (e.g., app/layout.tsx), before <Header />:
<a
  href="#main-content"
  className="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-indigo-600 focus:text-white focus:rounded"
>
  Skip to main content
</a>
```

Then add `id="main-content"` to the `<main>` element.

---

### Image Alt Text — Homepage

| Image | Alt Text | Status |
|-------|----------|--------|
| Logo (header) | "GoSQLX" | Redundant — adjacent span also says "GoSQLX"; use `alt=""` |
| GitHub Stars badge | "GitHub Stars" | OK |
| Tests badge | "Tests" | OK |
| Go Report Card badge | "Go Report Card" | OK |
| GoDoc badge | "GoDoc" | OK |
| Logo (footer) | "GoSQLX" | Redundant — same issue as header logo; use `alt=""` |

**Overall**: All images have `alt` attributes present. The only issue is the two logo instances where the alt duplicates visible text (see violation above). Feature-section icons appear to be SVG/CSS, not `<img>` tags — not audited here but should be checked if they convey meaning.

---

### Focus Indicators

- **Focus CSS rules found via stylesheet inspection**: None detected from accessible stylesheets (external Next.js chunks are cross-origin and unreadable by `cssRules`)
- **Tailwind default**: Tailwind v3 removes the browser default `outline` on focus for many elements (`outline: 2px solid transparent`). The site uses `focus-visible:ring-*` utilities in Tailwind, which are applied via class strings in components.
- **Observed in snapshot**: Interactive elements (buttons, links, nav items) do not expose explicit focus-ring class names in the axe output.
- **Recommendation**: Audit interactively by tabbing through the page. Confirm `focus-visible:ring-2 focus-visible:ring-indigo-500` (or equivalent) is applied to all interactive elements: nav links, CTA buttons ("Get Started", "Try Playground"), tab switcher buttons ("Parse", "Format", "Validate", "Lint"), and footer links.
- **Known gap**: The API tab buttons (`<button "Parse">`, `<button "Format">` etc.) in the homepage code demo should be verified to have visible focus rings.

---

## Color Contrast Analysis

Based on computed styles captured from the live page:

| Element | Color (approx hex) | Background | Estimated Ratio | WCAG AA Pass? |
|---------|-------------------|------------|-----------------|---------------|
| Nav links (Docs, Playground, Blog…) | ~`#a1a1aa` (zinc-400) | `#18181b` (zinc-950) | ~3.5:1 | FAIL (need 4.5:1 for 14px) |
| "Get Started" button text | ~`#000000` | `#ffffff` | 21:1 | PASS |
| Code panel labels (query.sql, AST Output) | ~`#71717a` (zinc-500) | dark panel bg | ~3.0:1 | FAIL (need 4.5:1 for 12px) |
| Footer links | ~`#a1a1aa` (zinc-400) | `#18181b` | ~3.5:1 | FAIL (need 4.5:1 for 14px) |
| Logo text "GoSQLX" (nav) | ~`#fafafa` (zinc-50) | `#18181b` | ~17:1 | PASS |

> Note: Ratios estimated using the WCAG relative luminance formula on the captured RGB values. Exact values depend on actual rendered background. The dark-themed site uses zinc-400/zinc-500 text on zinc-950 backgrounds throughout — this color pairing recurs at least 19 times (per axe node count on docs page).

---

## Priority Fixes (WCAG 2.1 AA Compliance)

Ranked by severity and user impact:

1. **Add skip-to-main-content link** — WCAG 2.4.1 (Level A) — Effort: **Low**
   - Affects all keyboard and screen-reader users on every page. Single change in root layout. No visual impact for mouse users.

2. **Fix color contrast for nav links, breadcrumbs, code labels** — WCAG 1.4.3 (Level AA) — Effort: **Low/Med**
   - 19+ affected nodes on docs pages. Change `text-zinc-400` → `text-zinc-300` (or lighter) for all body/nav link text on dark backgrounds. Update the Tailwind color tokens used for secondary text in the dark theme. This fixes the most-cited violation by axe.

3. **Add `tabindex="0"` to all scrollable `<pre>` code blocks** — WCAG 2.1.1 (Level A) — Effort: **Low**
   - Affects 1 element on homepage, 13 on docs page (all code examples). Create a shared `CodeBlock` component (or update the existing one) to always include `tabindex="0"` when `overflow-*` is applied. Keyboard users currently cannot scroll horizontally into long code examples.

4. **Add `aria-label` to distinguish multiple `<nav>` landmarks** — Best practice / WCAG 1.3.6 — Effort: **Low**
   - Affects docs pages with sidebar. Adds `aria-label="Primary"` to header nav, `aria-label="Documentation sidebar"` to sidebar nav. One-line fix per nav element.

5. **Fix redundant logo alt text** — Best practice — Effort: **Low**
   - Change `alt="GoSQLX"` to `alt=""` on logo `<img>` in header and footer links where the adjacent `<span>GoSQLX</span>` text provides the accessible name.

---

## Additional Observations

- **Console errors**: Two errors on every page load — `_vercel/insights/script.js` 404 and a CSP block on an external analytics script. These do not affect accessibility but indicate a broken analytics integration.
- **Stats section counter animation**: The animated counters ("0+" ops/sec, "0μs" latency) start at 0 before animating to real values. Screen readers will announce "0" initially. Consider using `aria-live="polite"` with a debounced update, or providing static values with a `<noscript>` fallback.
- **Interactive code demo (homepage)**: The tab buttons ("Parse", "Format", "Validate", "Lint") lack visible labels for two of the four buttons in the axe snapshot (`button "Format"`, `button "Validate"`, `button "Lint"` have no text in some states). Confirm these have accessible names in all states.
- **"Open Full Playground" link**: Contains an `<img>` with no captured alt in the axe snapshot — verify this is `alt=""` with `aria-hidden="true"` since the link text already conveys the purpose.
