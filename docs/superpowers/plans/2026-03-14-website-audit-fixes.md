# Website Audit Fixes — Implementation Plan

> **For agentic workers:** Use parallel agents where noted. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all CRITICAL, HIGH, and MEDIUM issues from the comprehensive website audit.

**Scope:** 19 fixes across 5 parallel work streams. LOW issues deferred.

---

## Stream 1: Critical Fixes (sequential)

### Fix 1: Broken internal links in docs

**Files:** Create `website/src/plugins/remark-fix-links.mjs`

- [ ] Create a remark plugin that rewrites relative `.md` links (e.g., `USAGE_GUIDE.md`) to website routes (`/GoSQLX/docs/usage_guide/`)
- [ ] Register in `astro.config.mjs` as a markdown remark plugin
- [ ] Test: verify Getting Started page links resolve

### Fix 2: Footer links point to specific pages

**Files:** Modify `website/src/components/Footer.astro`

- [ ] Change "Getting Started" href to `/GoSQLX/docs/getting_started/`
- [ ] Change "API Reference" href to `/GoSQLX/docs/api_reference/`

### Fix 3: Playground responsive layout

**Files:** Modify `website/src/components/Playground.tsx`

- [ ] Change `w-1/2` splits to `w-full md:w-1/2` with `flex-col md:flex-row`
- [ ] Add proper min-height for mobile stacking

---

## Stream 2: Performance (parallelizable)

### Fix 4: Lazy-load WASM on homepage

**Files:** Modify `website/src/pages/index.astro`

- [ ] Change `client:only="react"` to `client:visible` on HeroPlayground
- [ ] This defers WASM loading until the hero scrolls into view (which is immediate on desktop but saves mobile users who bounce)

### Fix 5: Fix font loading

**Files:** Modify `website/src/layouts/BaseLayout.astro`, `website/src/styles/global.css`

- [ ] Remove `@import url(...)` from global.css
- [ ] Add `<link rel="preconnect" href="https://fonts.googleapis.com">` to BaseLayout head
- [ ] Add `<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>` to BaseLayout head
- [ ] Add `<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@500;700&family=Instrument+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap">` to BaseLayout head
- [ ] Trim font weights to only those actually used

### Fix 6: Add preconnect hints

**Files:** Modify `website/src/layouts/BaseLayout.astro`

- [ ] Add `<link rel="dns-prefetch" href="https://img.shields.io">`

### Fix 7: Badge layout shift

**Files:** Modify `website/src/components/SocialProof.astro`

- [ ] Add `height="20" width="100"` to each badge img (approximate widths)

---

## Stream 3: Design Consistency (parallelizable)

### Fix 8: Replace raw hex colors with design tokens

**Files:** Modify multiple components

- [ ] Navbar: `bg-[#0f172a]` → `bg-slate-900`, `border-[#334155]` → `border-elevated`
- [ ] FeatureCards: `bg-[#1e293b]` → `bg-surface`
- [ ] CodeExamples: `bg-[#0c1322]` → `bg-[#0c1322]` (keep — unique section bg, add to tailwind config as `bg-deeper`)
- [ ] CodeExamples code block: `bg-[#0d1117]` → add as `bg-code` token
- [ ] VscodeSection: `bg-[#1e293b]` → `bg-surface`, `bg-[#0d1117]` → `bg-code`

### Fix 9: Fix blog gray→slate palette

**Files:** Modify `website/src/pages/blog/index.astro`, `website/src/pages/blog/[slug].astro`

- [ ] Replace all `text-gray-*` with `text-slate-*`
- [ ] Replace all `bg-gray-*` with `bg-slate-*` or `bg-surface`
- [ ] Replace `border-gray-*` with `border-slate-*` or `border-elevated`

### Fix 10: VS Code page icons → SVG

**Files:** Modify `website/src/pages/vscode.astro`

- [ ] Replace HTML entity emojis with SVG icons matching the homepage FeatureCards style
- [ ] Use colored circle backgrounds consistent with FeatureCards

### Fix 11: Add og:image meta tag

**Files:** Modify `website/src/layouts/BaseLayout.astro`

- [ ] Add `<meta property="og:image" content="https://ajitpratap0.github.io/GoSQLX/images/logo.png">`

---

## Stream 4: Accessibility (parallelizable)

### Fix 12: Add `<main>` landmarks

**Files:** Modify `index.astro`, `playground.astro`, `vscode.astro`, `benchmarks.astro`

- [ ] Wrap page content in `<main>` element on each page

### Fix 13: Add keyboard focus styles

**Files:** Modify `website/src/styles/global.css`

- [ ] Add `button:focus-visible { outline: 2px solid #3b82f6; outline-offset: 2px; }` globally
- [ ] Remove `outline: "none"` from SqlEditor component, replace with styled focus ring

### Fix 14: Add ARIA roles to tab interfaces

**Files:** Modify `Playground.tsx`, `HeroPlayground.tsx`, `CodeExamples.astro`

- [ ] Add `role="tablist"` to tab bar container
- [ ] Add `role="tab"` and `aria-selected` to tab buttons
- [ ] Add `role="tabpanel"` to tab content container

---

## Stream 5: Security + QA (parallelizable)

### Fix 15: WASM polling timeout

**Files:** Modify `website/src/components/WasmLoader.tsx`

- [ ] Add 15-second timeout to the polling loop
- [ ] After timeout, reject the promise with a clear error message

### Fix 16: Add CSP meta tag

**Files:** Modify `website/src/layouts/BaseLayout.astro`

- [ ] Add `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' https://img.shields.io https://goreportcard.com https://*.shields.io data:; connect-src 'self'">`

### Fix 17: Create custom 404 page

**Files:** Create `website/src/pages/404.astro`

- [ ] Create branded 404 page using BaseLayout
- [ ] "Page not found" message with link back to homepage and docs

### Fix 18: Hero playground output height

**Files:** Modify `website/src/components/HeroPlayground.tsx`

- [ ] Change fixed `height: "210px"` to `maxHeight: "250px"` with overflow-auto
- [ ] Or use `min-height: 180px; max-height: 300px`

### Fix 19: AnalyzeTab CSS fix

**Files:** Modify `website/src/components/playground/AnalyzeTab.tsx`

- [ ] Remove conflicting `inline-block` from score value element

---

## Parallelization

```
Stream 1 (Critical):    Fixes 1-3  — must go first
Stream 2 (Perf):        Fixes 4-7  — parallel with 3-5
Stream 3 (Design):      Fixes 8-11 — parallel with 3-5
Stream 4 (A11y):        Fixes 12-14 — parallel with 3-5
Stream 5 (Security+QA): Fixes 15-19 — parallel with 3-5
```

All 5 streams can run in parallel after Fix 1-3 are merged.
