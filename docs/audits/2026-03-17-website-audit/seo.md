# SEO Audit — 2026-03-17

## Metadata Audit

| Page | Title ✓/✗ | Description ✓/✗ | Canonical ✓/✗ | og:image ✓/✗ | JSON-LD ✓/✗ |
|------|-----------|-----------------|---------------|--------------|-------------|
| `/` (Homepage) | ✓ | ✓ | ✗ MISSING | ✓ | ✗ MISSING |
| `/docs/getting-started/` | ✓ | ✓ (generic) | ✗ MISSING | ✓ (inherited) | ✗ MISSING |
| `/playground/` | ✓ | ✓ | ✗ MISSING | ✓ (inherited) | ✗ MISSING |
| `/blog/v1-12-0/` | ✓ | ✓ | ✗ MISSING | ✗ MISSING | ✗ MISSING |

**Raw values found:**

### Homepage (`/`)
- Title: "GoSQLX - Production-Ready SQL Parsing SDK for Go"
- Description: "High-performance, zero-copy SQL parsing SDK for Go. Thread-safe with multi-dialect support for PostgreSQL, MySQL, SQLite, SQL Server, Oracle, and Snowflake."
- og:url: `https://gosqlx.dev` (hardcoded in layout.tsx line 20 — not per-page)
- og:type: `website`
- twitter:card: `summary_large_image`

### Docs page (`/docs/getting-started/`)
- Title: "GoSQLX - Getting Started with GoSQLX in 5 Minutes"
- Description: "GoSQLX documentation - Getting Started with GoSQLX in 5 Minutes" (template only, no unique value)
- og:title: "GoSQLX - Production-Ready SQL Parsing SDK for Go" ← **WRONG: inherits homepage OG title**
- og:url: `https://gosqlx.dev` ← **WRONG: should be page URL**
- `generateMetadata` in `docs/[...slug]/page.tsx` sets `title` and `description` only — no OG overrides

### Playground (`/playground/`)
- Title: "GoSQLX - SQL Playground"
- og:title: "GoSQLX - Production-Ready SQL Parsing SDK for Go" ← **WRONG: inherits homepage OG title**
- og:url: `https://gosqlx.dev` ← **WRONG: should be page URL**

### Blog post (`/blog/v1-12-0/`)
- Title: "GoSQLX - v1.12.0 — Custom Domain & Remote MCP Server"
- Description: "GoSQLX v1.12.0 — Custom Domain & Remote MCP Server release notes."
- og:type: `article` ✓ (blog page.tsx line 27)
- og:image: **MISSING** — blog `generateMetadata` does not include `images`
- og:url: **MISSING** — blog `generateMetadata` does not include `url`
- twitter:title: "GoSQLX - Production-Ready SQL Parsing SDK for Go" ← **WRONG: inherits layout default**

---

## Canonical Analysis

- Homepage canonical: **MISSING** — no `<link rel="canonical">` emitted
- Docs pages canonical: **MISSING** — `generateMetadata` in `docs/[...slug]/page.tsx` sets only `title` and `description`, no `alternates.canonical`
- Blog pages canonical: **MISSING** — `generateMetadata` in `blog/[slug]/page.tsx` sets no `alternates.canonical`
- Playground canonical: **MISSING**

**Root cause:** `layout.tsx` does not set `alternates.canonical` in the base metadata, and no page-level `generateMetadata` adds `alternates: { canonical: '...' }`. Next.js App Router emits canonical tags only when `alternates.canonical` is explicitly set in the `Metadata` object.

**Impact:** Without canonical tags, search engines may index duplicate URLs (trailing slash vs. no slash, `http` vs `https`, www vs. non-www). Docs pages with query parameters (e.g., anchor links) may create duplicate content entries.

---

## Structured Data (JSON-LD)

- Organization markup: **MISSING**
- SoftwareApplication: **MISSING**
- Article (blog posts): **MISSING**
- BreadcrumbList (docs): **MISSING**

No `<script type="application/ld+json">` blocks were found on any audited page. There are no JSON-LD injection points in `layout.tsx` or any page-level component.

**Impact of missing structured data:**
- No rich results eligibility for software/library cards in Google Search
- Blog posts cannot display article rich snippets (author, date, breadcrumb in SERPs)
- Docs pages miss BreadcrumbList which improves click-through rates by showing path in SERPs
- SoftwareApplication schema on homepage could surface star ratings, pricing, and OS info in search results
- Organization schema with `sameAs` links (GitHub, npm) builds entity authority in Google's Knowledge Graph

---

## Sitemap

- URL: `https://gosqlx.dev/sitemap.xml` — HTTP **200** ✓
- Total URLs: **51**
- Coverage:
  - `/` ✓ (1 page)
  - `/docs/*` ✓ (21 pages including tutorials, migrations, editor integrations)
  - `/blog/*` ✓ (15 posts, v0.9.0 through v1.12.0)
  - `/playground` ✓
  - `/benchmarks` ✓
  - `/vscode` ✓
  - `/privacy` ✓
- Lastmod format: ISO 8601 (`YYYY-MM-DDTHH:MM:SS.000Z`) ✓

**Issues:**
1. **Sitemap URL mismatch (CRITICAL):** `robots.txt` declares `Sitemap: https://gosqlx.dev/sitemap-index.xml` but that URL returns **HTTP 404**. The actual sitemap is at `https://gosqlx.dev/sitemap.xml`. Googlebot follows the robots.txt directive first — this means the sitemap is not being discovered via robots.txt.
2. Sitemap URLs use no-trailing-slash format (e.g., `https://gosqlx.dev/docs/getting-started`) but the server returns 200 for both slash and non-slash versions with no redirect between them. If canonical tags are added, they should match the sitemap URL format.

---

## Robots.txt

- URL: `https://gosqlx.dev/robots.txt` — HTTP 200 ✓
- `User-agent: *` / `Allow: /` — correct, no pages blocked
- Sitemap directive: `Sitemap: https://gosqlx.dev/sitemap-index.xml`
- **Issue (CRITICAL):** Points to `sitemap-index.xml` which returns 404. Should be `https://gosqlx.dev/sitemap.xml`.

---

## Redirects

- `/docs/getting-started` (no trailing slash) → HTTP **200** directly (no redirect)
- No 301 redirect from non-slash to slash (or vice versa)
- **Issue:** Both `/docs/getting-started` and `/docs/getting-started/` likely serve the same content. Without canonicals, this is a duplicate content risk. Next.js App Router with `trailingSlash: false` (the default) typically canonicalizes to no-slash, but since canonical tags are absent, Google must guess.

---

## Open Graph

- All pages have og:image: **Partial** — homepage, docs, and playground inherit the global `og-image.png` from `layout.tsx`; blog posts have **no og:image** (blog `generateMetadata` does not include `images`)
- Unique og:image per page: **No** — all non-blog pages share one static `/images/og-image.png`; blog posts have none
- og:url matches page URL: **No** — all pages inherit `og:url: https://gosqlx.dev` from `layout.tsx` line 20; individual page `generateMetadata` functions do not override `openGraph.url`

**Root cause in code:**
- `layout.tsx` sets `openGraph.url: 'https://gosqlx.dev'` as a global default
- `docs/[...slug]/page.tsx` `generateMetadata` returns only `{ title, description }` — no `openGraph` override
- `blog/[slug]/page.tsx` `generateMetadata` returns `openGraph` with `title`, `description`, `type`, `publishedTime` but omits `url` and `images`

---

## Priority Fixes (ranked by SEO impact)

1. **Fix robots.txt sitemap directive** — change `sitemap-index.xml` to `sitemap.xml`
   - Impact: **High** — Googlebot is currently unable to discover the sitemap via robots.txt; this directly limits crawl coverage
   - Effort: **Low** — one-line change in `public/robots.txt` or Next.js config

2. **Add per-page canonical tags via `alternates.canonical`** — add to base metadata in `layout.tsx` and override in each page's `generateMetadata`
   - Impact: **High** — prevents duplicate content dilution from slash/no-slash variants; required for proper link equity consolidation
   - Effort: **Low-Medium** — update `layout.tsx` base metadata and 3–4 `generateMetadata` functions

3. **Fix og:url and og:image inheritance on inner pages** — docs and blog `generateMetadata` must include `openGraph.url` (set to the page's own URL) and `openGraph.images`; blog posts especially need og:image for social sharing previews
   - Impact: **High** — when blog posts are shared on social media, they currently show no preview image; all inner pages incorrectly attribute link authority to the homepage URL in OG graph crawlers
   - Effort: **Low-Medium** — update `generateMetadata` in `blog/[slug]/page.tsx` and `docs/[...slug]/page.tsx`

4. **Add JSON-LD structured data** — at minimum: `SoftwareApplication` on homepage, `Article` on blog posts with author/date, `BreadcrumbList` on docs pages
   - Impact: **Medium** — unlocks rich results eligibility; improves click-through rates from SERPs
   - Effort: **Medium** — requires new components or inline JSON in each page template

5. **Fix Twitter card inheritance** — blog posts show the generic site-level `twitter:title` instead of the post title; add `twitter` override in blog `generateMetadata`
   - Impact: **Medium** — affects Twitter/X share previews for release announcements
   - Effort: **Low** — add `twitter` field to blog `generateMetadata` return value

6. **Improve docs page descriptions** — current template `"GoSQLX documentation - ${doc.title}"` is low-signal; use the first paragraph of each doc as the description
   - Impact: **Medium** — meta descriptions are used as SERP snippet text; generic descriptions reduce click-through rate
   - Effort: **Medium** — requires extracting first paragraph from MDX content at build time
