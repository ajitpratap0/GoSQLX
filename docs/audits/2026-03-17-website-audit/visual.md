# Visual & Responsive Audit — 2026-03-17

## Screenshots Taken

| Page | 320px | 390px | 768px | 1280px | 1440px |
|------|-------|-------|-------|--------|--------|
| Homepage | ✓ | ✓ | ✓ | ✓ | ✓ |
| Playground | ✓ | - | ✓ | - | ✓ |
| Docs (getting-started) | ✓ | - | - | - | ✓ |
| Blog | ✓ | - | - | - | ✓ |
| Benchmarks | ✓ | - | - | - | ✓ |

Screenshots saved in `screenshots/` directory.

---

## Issues Found

| Page | Viewport | Issue | Severity |
|------|----------|-------|----------|
| Homepage | All | Sections below hero (stats, features, API, MCP, IDE sections) render as empty dark rectangles — content is invisible against the background. DOM confirms elements exist but are not visible. | **Critical** |
| Homepage | 320px | H1 heading (`text-5xl`) overflows the viewport right edge — "Parse SQL at the speed of Go" clips | **Critical** |
| Homepage | 320px | Hero code demo (`PRE.p-4`, `DIV.glass`, `DIV.grid`) all overflow right edge | **Critical** |
| Homepage | 390px | H1 heading clips right edge; hero code panel text overflows | **High** |
| Homepage | All | Stats counter shows "0+" ops/sec, "0μs" latency, "0%" SQL-99, "0" dialects — animated counters never increment (JS intersection observer not firing or animation broken) | **High** |
| Benchmarks | 1440px | Third stat card ("20K+ Concurrent Ops Tested") overflows the right edge of viewport — 3-column grid wider than container | **High** |
| Benchmarks | 320px | Only first stat card visible; second and third stat cards and entire benchmark table are invisible (massive empty dark area) | **Critical** |
| Playground | 320px | Header toolbar clips: "WASM Ready" label wraps to two lines and overflows right edge | **High** |
| Playground | 320px, 768px | SQL input editor collapsed to minimal height (1 line visible) — editor panel has no `min-height` at small viewports | **High** |
| Playground | 320px, 768px | AST tree output overflows right edge (`DistinctOnColumns` and other keys cut off) | **Medium** |
| Playground | All | Large empty dark area below the editor panel — playground container not set to `min-height: 100vh` | **Medium** |
| Blog | 320px | Post titles truncated with ellipsis ("Custom Dom...", "Website Polish ...", "Product Webs...") — important context lost | **Medium** |
| Homepage | All | Large empty dark areas below each section — suspected z-index layering issue or missing background colors on section containers; sections appear to exist but are transparent/invisible | **Critical** |
| All pages | All | Console errors: `_vercel/insights/script.js` 404 (Vercel Analytics script missing) and `Refused to execute script` (MIME type checking — a script being loaded with wrong content-type) | **Medium** |

---

## Horizontal Overflow at 320px (Homepage)

Elements overflowing the 320px viewport right edge (detected via `getBoundingClientRect()`):

- `DIV.absolute` — likely a background/decorative layer
- `DIV.relative` — hero section wrapper
- `DIV.mb-6` — hero content container
- **`H1.text-5xl`** — main headline (no `text-wrap: balance` or `max-width` constraint)
- **`SPAN.bg-gradient-to-r`** — gradient text in headline
- `P.text-lg` — hero subtitle paragraph
- `DIV.flex` — CTA button row
- `DIV.relative` — code demo wrapper
- **`DIV.glass`** — code panel (fixed width not capped)
- `DIV.grid` — side-by-side SQL/AST grid
- `DIV.text-left` — code panel inner
- **`PRE.p-4`** — code block (no `overflow-x: auto`)

Root cause: The hero section uses a fixed-width or large `min-width` grid that does not collapse at narrow viewports. The `text-5xl` class (Tailwind: `font-size: 3rem`) is likely not overridden with a smaller size for mobile.

---

## Navigation Behavior

- **Mobile (320px, 390px):** Hamburger "Toggle menu" button present — correct. Full nav links are hidden and replaced with toggle. This works correctly.
- **Tablet (768px):** Full navigation bar visible with all links (Docs, Playground, Blog, VS Code, Benchmarks) — correct. No overflow.
- **Desktop (1280px, 1440px):** Full nav bar with all links + GitHub icon + "Get Started" CTA button. Clean and well-spaced.

---

## Overall Design Assessment

**Visual consistency:** The dark theme is applied consistently across all pages. Typography hierarchy (h1 > h2 > h3, code blocks) is well-defined and uses a coherent monospace/sans-serif pairing.

**Typography legibility at small sizes:** At 320px, body text and list items in docs are readable. The main usability blocker is the overflowing hero elements, not body text sizing.

**Dark theme implementation:** Works correctly for navbar, footer, docs content, and blog list. The critical failure is that section backgrounds on the homepage appear to be the same dark color as their content containers, making sections invisible — likely `opacity: 0` from a scroll-triggered animation that never fires in headless/non-scroll contexts, or a CSS animation class that requires IntersectionObserver to trigger.

**Notable positives:**
- Hamburger navigation correctly implemented at mobile breakpoints
- Docs page with sidebar is well-structured and readable at all tested sizes
- Blog list is clean and usable at desktop
- Playground WASM loads and works at 768px+
- Footer links are well-organized and legible at all sizes
- Playground toolbar and nav are clean at 1440px

**Notable negatives:**
- Homepage sections below the hero are effectively invisible at all viewport widths (Critical — this affects every visitor)
- No `overflow-x: hidden` on the body/html to prevent horizontal scroll at 320px
- Stats counters stuck at 0 (likely intersection observer not firing on initial load)
- Benchmarks stat grid overflows at wide desktop viewports
- Playground has no mobile-optimized layout (editor height collapses)
- Blog titles need `white-space: normal` with proper truncation strategy or wrapping

---

## Priority Fixes

1. **Homepage sections invisible** — All viewports — `/` — Sections below the hero have invisible content. Check for `opacity: 0` / `translate-y` scroll animation initial states that require IntersectionObserver. Either ensure animations fire on load or remove animation from critical content.

2. **Homepage horizontal overflow at 320–390px** — 320px, 390px — `/` — Add `overflow-x: hidden` to `html`/`body`. Change `H1` from `text-5xl` (3rem) to `text-3xl`/`text-4xl` at `sm:` breakpoint. Add `max-w-full overflow-x-auto` to the hero code demo grid.

3. **Benchmarks stat card overflow** — 1440px — `/benchmarks` — The 3-column stats grid uses a fixed width exceeding the container. Add `grid-cols-3` with proper `gap` and ensure no card has a `min-width` that breaks the layout.

4. **Benchmarks table invisible at 320px** — 320px — `/benchmarks` — The benchmark table is not mobile-responsive. Add `overflow-x: auto` wrapper around the `<table>` or convert to a card-based layout at `sm:` breakpoint.

5. **Stats counters stuck at 0** — All — `/` — Counter animation relies on IntersectionObserver. The elements may have `opacity: 0` as initial state and the observer callback never fires. Ensure a fallback: if IntersectionObserver is unavailable or the element is already in view, run the counter animation immediately.

6. **Playground editor height at mobile** — 320px, 390px — `/playground` — Set a `min-height` (e.g., `min-h-[200px]`) on the SQL input textarea/editor container at all breakpoints so the editor is usable.

7. **Blog post titles truncating at 320px** — 320px — `/blog` — Allow titles to wrap to two lines (`white-space: normal; overflow: hidden` with `line-clamp-2`) rather than single-line ellipsis, so the full title is visible.

8. **Vercel Analytics 404** — All — All pages — `/_vercel/insights/script.js` returns 404. Enable Vercel Web Analytics in the project dashboard, or remove the analytics initialization code to eliminate the console error.

---

## Console Errors (All Pages)

- `Failed to load resource: 404` — `https://gosqlx.dev/_vercel/insights/script.js` — Vercel Analytics not enabled in project settings
- `Refused to execute script` — MIME type mismatch on a script resource — likely a service worker or WASM-related script served with incorrect `Content-Type`
- `[Vercel Web Analytics] Failed to load script` — downstream effect of the 404 above
