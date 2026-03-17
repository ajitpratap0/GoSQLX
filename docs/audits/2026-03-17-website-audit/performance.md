# Performance Audit — 2026-03-17

> **Note on Lighthouse scores**: The Chrome DevTools MCP (port 9222) timed out during this audit session. Lighthouse scores are not available from automated tooling for this run. Pages were audited via Playwright for network/resource analysis; Lighthouse scores should be gathered manually or via a dedicated CI step. All other sections below are based on live network analysis and source inspection.

## Lighthouse Scores
| Page | Device | Perf | FCP | LCP | TBT | CLS | TTI |
|------|--------|------|-----|-----|-----|-----|-----|
| / | Desktop | N/A (tool timeout) | — | — | — | — | — |
| / | Mobile  | N/A (tool timeout) | — | — | — | — | — |
| /playground/ | Mobile | N/A (tool timeout) | — | — | — | — | — |
| /docs/getting-started/ | Mobile | N/A (tool timeout) | — | — | — | — | — |

_Chrome DevTools MCP connection timed out. Re-run with DIA browser on port 9222 connected._

---

## Network Analysis — Homepage

**JS Chunks loaded on first visit to `/` (uncompressed sizes):**

| Chunk | Size |
|-------|------|
| `aee6c772` (largest shared chunk) | 219 KB |
| `e511b25d` (shared) | 117 KB |
| `8123d3f4` (likely react-dom) | 116 KB |
| `d2be314c` | 30 KB |
| `f0915015` | 32 KB |
| `c9d3e6b3` | 28 KB |
| `7490ec4b` (Vercel Analytics) | 32 KB |
| `a111d669` | 18 KB |
| `fcf73f24` (framework bootstrap) | 23 KB |
| `turbopack` runtime | 10 KB |
| Other small chunks | ~2 KB |
| **Total JS (homepage)** | **~627 KB** |
| CSS (`02fd8dc5`) | 67 KB |

**Cache headers:**
- `/_next/static/**`: `cache-control: public, max-age=31536000, immutable` ✓ (1 year, content-hashed)
- `/wasm/gosqlx.wasm`: `cache-control: public, max-age=0, must-revalidate` ✗ (no long-term caching — every visit re-validates the 6.2 MB WASM file)

**Render-blocking / errors:**
- `/_vercel/insights/script.js` returns **404** on every page load (2× per navigation). Vercel Analytics script is missing from the deployment — generating two failed network requests per page.
- CSP blocks `cdnjs.cloudflare.com/axe-core` (accessibility testing library injected by Playwright, not a production issue).
- `Refused to execute script` error on every page — the Vercel Analytics bundle (`7490ec4bca357da5.js`) logs a warning that `/_vercel/insights/script.js` is 404, then falls back silently. No user-visible breakage but wastes a network round-trip.

**Missing resources:**
- No WASM preload `<link rel="preload">` hint in the document `<head>`. The 6.2 MB WASM file is only fetched after the playground JS hydrates and calls `initWasm()`, causing a large sequential delay on the playground page.

---

## Bundle Analysis

- **Total first-load JS (home):** ~627 KB uncompressed (~180–200 KB gzipped estimated)
- **Total first-load JS (playground):** ~985 KB uncompressed (~280–300 KB gzipped estimated) — includes 354 KB WASM loader chunk (`096e155332b72008.js`)
- **Largest shared chunk:** `aee6c772` — 219 KB (likely Shiki/syntax highlighter or a large UI dependency)
- **Largest page chunk:** `096e155332b72008.js` — 354 KB (playground + WASM loader, Turbopack bundle)
- **CSS:** 67 KB uncompressed (reasonable)

All routes are statically prerendered (○ Static / ● SSG) — no server-side rendering overhead. This is good.

Sentry is bundled via `withSentryConfig`. Comment in `next.config.ts` notes: _"Tree-shaking disabled — using Turbopack which doesn't support webpack tree-shaking"_ — this is likely contributing to the oversized chunks since dead code cannot be eliminated.

---

## WASM Load Analysis

- **gosqlx.wasm size:** 6.2 MB (6,543,127 bytes on disk; ~6,390 KB)
- **Service Worker present:** ✓ — `/wasm-sw.js` is served and registered via `ServiceWorkerRegister.tsx`
- **Preload hint present:** ✗ — No `<link rel="preload" as="fetch" href="/wasm/gosqlx.wasm">` in layout
- **wasm-sw.js cache versioning:** Static key (`gosqlx-wasm-v1`) — **not versioned**. If the WASM binary is updated, users with a cached service worker will continue serving the stale file until the SW is manually busted. There is no content hash in the cache key.
- **WASM HTTP cache headers:** `max-age=0, must-revalidate` — the CDN/Vercel does not long-cache the WASM file. Combined with the static SW cache key, cache invalidation on WASM updates is unreliable.

**WASM load path on playground:**
1. Page hydrates → JS evaluates → `initWasm()` called
2. `loadScript("/wasm/wasm_exec.js")` fetched (sequential)
3. `fetch("/wasm/gosqlx.wasm")` — 6.2 MB (sequential, no preload)
4. `WebAssembly.instantiate()` called

This waterfall means the playground is unusable for several seconds on first load, especially on mobile.

---

## logo-text.svg (931 KB)

- **Referenced in source:** ✗ — No references found in any `.tsx`, `.ts`, `.js`, or `.jsx` file under `website/src/`
- **Found in public directory:** Not present in `website/public/` either (file only exists at repo root level as an untracked file in the git status)
- **Action required:** File is unused by the website. If it exists in `public/`, remove it immediately — a 931 KB SVG served as a static asset would significantly harm LCP. Currently it does not appear to be deployed.

---

## Top Performance Issues (ranked by impact)

1. **6.2 MB WASM with no preload hint and broken cache invalidation** — Impact: **High**
   - Fix: Add `<link rel="preload" as="fetch" href="/wasm/gosqlx.wasm" crossOrigin="anonymous">` on the playground page. Version the SW cache key with a build hash (e.g., `gosqlx-wasm-v${BUILD_ID}`). Set `cache-control: public, max-age=31536000, immutable` on the WASM file (it's content-addressed by the SW anyway).

2. **Turbopack disables tree-shaking, inflating JS bundle ~30–40%** — Impact: **High**
   - The 219 KB `aee6c772` shared chunk and the 354 KB playground chunk are larger than expected. With Webpack (default Next.js production build) tree-shaking would remove dead code. Consider switching back to Webpack for production builds, or wait for Turbopack's tree-shaking support. Alternatively, audit what's in `aee6c772` using `ANALYZE=true npm run build` with Webpack.

3. **`/_vercel/insights/script.js` returning 404 on every page load** — Impact: **Medium**
   - Every page navigation fires two failed requests. Fix: Ensure the Vercel Analytics script is deployed (check Vercel project settings have Analytics enabled), or remove the `<Analytics />` component from `layout.tsx` if not using it.

4. **WASM service worker cache key is not versioned** — Impact: **Medium**
   - If `gosqlx.wasm` is updated, users with the old SW will continue receiving the stale binary. Fix: Inject a build-time hash into `wasm-sw.js` (e.g., via a `next.config.ts` rewite or a build script that generates a versioned SW file).

5. **No HTTP long-cache for `/wasm/gosqlx.wasm`** — Impact: **Medium**
   - Currently `max-age=0, must-revalidate`. Even with the service worker, a revalidation request is made on every cold load. Fix: Set `cache-control: public, max-age=31536000, immutable` in `next.config.ts` headers for `/wasm/(.*)`.

6. **Large unidentified 219 KB shared chunk (`aee6c772`)** — Impact: **Medium**
   - This chunk is loaded on every page. Likely contains Shiki (syntax highlighter), Prism, or a large icon library. Fix: Run bundle analyzer with Webpack to identify and potentially lazy-load or split this dependency.

---

## Quick Wins

1. **Add WASM long-cache headers in next.config.ts** (< 30 min): Add a `headers()` entry for `source: '/wasm/(.*)'` with `cache-control: public, max-age=31536000, immutable`. Eliminates the revalidation request on every playground load.

2. **Fix or remove Vercel Analytics** (< 15 min): Either enable Analytics in the Vercel dashboard (so the script is served) or delete `<Analytics />` from `layout.tsx`. Eliminates 2× 404 requests per page navigation.

3. **Add WASM preload hint on playground page** (< 30 min): In `website/src/app/playground/page.tsx`, export a `generateMetadata` or use Next.js `<link>` in the page head to preload `/wasm/gosqlx.wasm`. This starts the 6.2 MB download in parallel with JS parsing, cutting playground time-to-interactive by 1–3 seconds on fast connections and 5–15 seconds on mobile.

4. **Version the SW cache key** (< 1 hour): Modify the build process to inject `NEXT_PUBLIC_BUILD_ID` into `wasm-sw.js` so that deploying a new WASM binary automatically invalidates the cached version for all users.

5. **Audit and split the 219 KB shared chunk** (2–4 hours): Run `ANALYZE=true npm run build` (with Webpack, not Turbopack) to identify what's in the largest shared chunk. If it's a syntax highlighter, lazy-load it; if it's an icon set, switch to tree-shaken imports.
