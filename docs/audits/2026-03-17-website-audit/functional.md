# Functional Audit — 2026-03-17

## Navigation Links
| URL | HTTP Status | Content OK | Notes |
|-----|-------------|------------|-------|
| / | 200 | ✓ | Counter stats animate from 0 (JS-dependent, expected) |
| /docs/ | 200 | ✓ | |
| /playground/ | 200 | ✓ | WASM loads; editor and 4 tabs render |
| /blog/ | 200 | ✓ | 10 posts visible on page |
| /vscode/ | 200 | ✓ | |
| /benchmarks/ | 200 | ✓ | |
| /privacy/ | 200 | ✓ | |

## Documentation Pages (11/11 returning 200)
| URL | Status | Content OK |
|-----|--------|------------|
| /docs/getting-started/ | 200 | ✓ |
| /docs/usage-guide/ | 200 | ✓ |
| /docs/api-reference/ | 200 | ✓ |
| /docs/cli-guide/ | 200 | ✓ |
| /docs/error-codes/ | 200 | ✓ |
| /docs/sql-compatibility/ | 200 | ✓ |
| /docs/linting-rules/ | 200 | ✓ |
| /docs/lsp-guide/ | 200 | ✓ |
| /docs/mcp-guide/ | 200 | ✓ |
| /docs/production-guide/ | 200 | ✓ |
| /docs/performance-tuning/ | 200 | ✓ |

## Blog Posts (14/14 returning 200)
- Total posts in sitemap: 14
- All returning 200: ✓
- Posts checked:
  - /blog/v1-12-0 — 200 ✓
  - /blog/v1-11-1 — 200 ✓
  - /blog/v1-11-0 — 200 ✓
  - /blog/v1-10-4 — 200 ✓
  - /blog/v1-10-3 — 200 ✓
  - /blog/v1-10-2 — 200 ✓
  - /blog/v1-10-1 — 200 ✓
  - /blog/v1-10-0 — 200 ✓
  - /blog/v1-9-3  — 200 ✓
  - /blog/v1-9-2  — 200 ✓
  - /blog/v1-0-2  — 200 ✓
  - /blog/v1-0-1  — 200 ✓
  - /blog/v1-0-0  — 200 ✓
  - /blog/v0-9-0  — 200 ✓

## WASM Playground
- Page loads: ✓
- Editor renders: ✓ (CodeMirror textbox with sample SQL present)
- WASM initialized: ✓ ("WASM Ready" status shown after load; initial state shows "Downloading SQL parser... 0%")
- Console errors during load: `_vercel/insights/script.js` 404 (see JS Console Errors); axe-core CSP block (dev tool, not user-facing)
- Tabs visible: AST, Format, Lint, Analyze (all 4 present and selectable)
- Dialect selector: Generic, PostgreSQL, MySQL, SQLite, SQL Server, Oracle

## JavaScript Console Errors
| Page | Error/Warning | Source |
|------|---------------|--------|
| / | `Failed to load resource: 404` | `https://gosqlx.dev/_vercel/insights/script.js` |
| / | `Refused to execute script — MIME type 'text/html' not executable` | `https://gosqlx.dev/_vercel/insights/script.js` |
| / | `[Vercel Web Analytics] Failed to load script` | `_next/static/chunks/7490ec4bca357da5.js:2` |
| /playground/ | Same `_vercel/insights/script.js` 404 and MIME type errors | Same as above |
| /playground/ | `Loading axe-core violates CSP directive 'script-src'` | Blocked external CDN script (likely dev/testing tool) |
| /docs/getting-started/ | Same `_vercel/insights/script.js` 404 and MIME type errors | Same as above |

Note: The `_vercel/insights/script.js` 404 appears on every page and indicates Vercel Analytics is misconfigured or the script is not deployed. This causes a non-fatal but noisy console error on all pages.

## Trailing Slash Redirects
- `/docs/getting-started` → `/docs/getting-started/`: HTTP 200 ✓ (Next.js serves both without redirect; canonical URL used by server is without trailing slash)
- `/blog` → `/blog/`: HTTP 200 ✓ (same behavior)

Note: Both paths return 200 directly rather than 301 redirecting to the canonical form. This is Next.js default behavior and not a bug, but may result in duplicate content for SEO if not configured with canonical tags.

## 404 Handling
- Returns 404 for unknown URL: ✗ — **HTTP 200 returned for `/this-page-does-not-exist-xyz123`**
  - The custom 404 page renders with HTTP 200 instead of HTTP 404
  - This is a critical issue: search engines and crawlers will index non-existent pages as valid content
  - Confirmed: `/docs/getting-started/CLI_GUIDE.md` (broken link) also returns HTTP 200 with 404 page content

## Sentry Tunnel
- `/monitoring` route: ✗ — HTTP 404 returned
  - The Sentry monitoring tunnel endpoint does not exist at this path
  - If Sentry error monitoring is configured, it may not be routing through a tunnel

## GitHub Links
- Correct repo (ajitpratap0/GoSQLX): ✗
- All GitHub links site-wide point to **`github.com/ajitpsingh/GoSQLX`** instead of `github.com/ajitpratap0/GoSQLX`
- Affected links (present on every page in header and footer):
  - `https://github.com/ajitpsingh/GoSQLX` (main repo link)
  - `https://github.com/ajitpsingh/GoSQLX/issues`
  - `https://github.com/ajitpsingh/GoSQLX/discussions`
  - `https://github.com/ajitpsingh/GoSQLX/releases`
  - `https://github.com/ajitpsingh/GoSQLX/blob/main/CHANGELOG.md`
- Note: The doc page content (e.g., getting-started article body) correctly uses `ajitpratap0/GoSQLX` for `go get`/`go install` commands. Only the nav/footer template links are wrong.

## Broken Internal Links
The `/docs/getting-started/` page contains relative `.md` file links that resolve to 404 pages (rendered with HTTP 200):
- `CLI_GUIDE.md` → resolves to `/docs/getting-started/CLI_GUIDE.md` → 404 content
- `USAGE_GUIDE.md` → same pattern → 404 content
- `LSP_GUIDE.md` → same pattern → 404 content
- `TROUBLESHOOTING.md` → same pattern → 404 content
- `MCP_GUIDE.md` → same pattern → 404 content
- `LINTING_RULES.md` → same pattern → 404 content
- `CONFIGURATION.md` → same pattern → 404 content
- `API_REFERENCE.md` → same pattern → 404 content
- `SQL_COMPATIBILITY.md` → same pattern → 404 content
- `../examples/` → relative path → likely 404

These appear to be unconverted markdown cross-references from the source `.md` files. The correct paths are the `/docs/<slug>/` URLs.

## Issues Found

1. **Wrong GitHub repository owner in all nav/footer links** — All GitHub links use `ajitpsingh/GoSQLX` instead of `ajitpratap0/GoSQLX`. Affects every page header, footer, and the Changelog link. — Severity: **High**

2. **Custom 404 page returns HTTP 200** — Unknown URLs and broken links return HTTP 200 with 404 page content instead of a proper HTTP 404 response. This causes search engines to index error pages and breaks standard HTTP semantics. — Severity: **High**

3. **Vercel Analytics script 404 on all pages** — `/_vercel/insights/script.js` returns 404, causing 2 console errors on every page load. Analytics data is not being collected. — Severity: **Medium**

4. **Broken relative `.md` links in /docs/getting-started/** — At least 10 internal links use raw markdown filenames (e.g., `CLI_GUIDE.md`) instead of web paths (e.g., `/docs/cli-guide/`). These lead to the 404 page. — Severity: **Medium**

5. **Sentry /monitoring route missing** — The `/monitoring` endpoint returns HTTP 404. If Sentry is configured to use a tunnel, it is not working. — Severity: **Low** (only relevant if Sentry tunnel is actively relied upon)

6. **axe-core CSP violation on /playground/** — An external CDN script (`cdnjs.cloudflare.com/axe-core`) is blocked by the Content Security Policy. This is likely a development/accessibility testing tool that should not be present in production. — Severity: **Low**
