# Content Audit — 2026-03-17

## Version Currency
- Latest release in CHANGELOG: **v1.12.1** (2026-03-15 — Website Performance & Mobile Optimization)
- Version displayed on homepage: **v1.12.1** — ✓
- Latest blog post: **v1.12.0** — does NOT cover v1.12.1 ✗

## Blog Post Coverage

All blog posts live in `website/src/content/blog/`.

| Release | Blog Post Exists |
|---------|-----------------|
| v0.9.0  | ✓ (v0-9-0.md) |
| v1.0.0  | ✓ (v1-0-0.md) |
| v1.0.1  | ✓ (v1-0-1.md) |
| v1.0.2  | ✓ (v1-0-2.md) |
| v1.1.0  | ✗ missing |
| v1.2.0  | ✗ missing |
| v1.3.0  | ✗ missing |
| v1.4.0  | ✗ missing |
| v1.5.0  | ✗ missing |
| v1.5.1  | ✗ missing |
| v1.6.0  | ✗ missing |
| v1.7.0  | ✗ missing |
| v1.8.0  | ✗ missing |
| v1.9.0  | ✗ missing |
| v1.9.2  | ✓ (v1-9-2.md) |
| v1.9.3  | ✓ (v1-9-3.md) |
| v1.10.0 | ✓ (v1-10-0.md) |
| v1.10.1 | ✓ (v1-10-1.md) |
| v1.10.2 | ✓ (v1-10-2.md) |
| v1.10.3 | ✓ (v1-10-3.md) |
| v1.10.4 | ✓ (v1-10-4.md) |
| v1.11.0 | ✓ (v1-11-0.md) |
| v1.11.1 | ✓ (v1-11-1.md) |
| v1.12.0 | ✓ (v1-12-0.md) |
| v1.12.1 | ✗ missing (latest release) |

**Missing blog posts (9 releases):** v1.1.0, v1.2.0, v1.3.0, v1.4.0, v1.5.0, v1.5.1, v1.6.0, v1.7.0, v1.8.0, v1.9.0, v1.12.1

Note: v1.1.0 through v1.9.0 are all missing but these span 2025-01-03 to 2026-02-28 — the blog appears to have started coverage at v1.9.2. v1.12.1 is the most important gap as it is the current latest release.

## Docs Completeness

Docs are sourced from the `docs/` directory at repo root (not from `website/src/content/docs/` — that directory does not exist). The sidebar in `website/src/lib/constants.ts` maps slugs to files.

### Sidebar slugs → source files

| Slug | File | Exists |
|------|------|--------|
| getting-started | docs/GETTING_STARTED.md | ✓ |
| cli-guide | docs/CLI_GUIDE.md | ✓ |
| usage-guide | docs/USAGE_GUIDE.md | ✓ |
| api-reference | docs/API_REFERENCE.md | ✓ |
| architecture | docs/ARCHITECTURE.md | ✓ |
| configuration | docs/CONFIGURATION.md | ✓ |
| error-codes | docs/ERROR_CODES.md | ✓ |
| sql-compatibility | docs/SQL_COMPATIBILITY.md | ✓ |
| linting-rules | docs/LINTING_RULES.md | ✓ |
| lsp-guide | docs/LSP_GUIDE.md | ✓ |
| mcp-guide | docs/MCP_GUIDE.md | ✓ |
| security | docs/SECURITY.md | ✓ |
| production-guide | docs/PRODUCTION_GUIDE.md | ✓ |
| performance-tuning | docs/PERFORMANCE_TUNING.md | ✓ |
| tutorials/01-sql-validator-cicd | docs/tutorials/01-sql-validator-cicd.md | ✓ |
| tutorials/02-custom-sql-formatter | docs/tutorials/02-custom-sql-formatter.md | ✓ |
| migration/from-jsqlparser | docs/migration/FROM_JSQLPARSER.md | ✓ |
| migration/from-pg-query | docs/migration/FROM_PG_QUERY.md | ✓ |
| migration/from-sqlfluff | docs/migration/FROM_SQLFLUFF.md | ✓ |
| editors/vscode | docs/editors/vscode.md | ✓ |
| editors/neovim | docs/editors/neovim.md | ✓ |
| editors/jetbrains | docs/editors/jetbrains.md | ✓ |

- Sidebar items: **22 slugs**
- All source files present: **22/22** ✓
- Missing content files: **none**
- Orphaned files in `docs/` (present but not in sidebar): COMPARISON.md, FUZZ_TESTING_GUIDE.md, MIGRATION.md, MULTI_ROW_INSERT.md, performance_regression_testing.md, SECURITY_SETUP.md, sql99-compliance-analysis.md, TROUBLESHOOTING.md, UPGRADE_GUIDE.md (these are internal/developer docs, not end-user docs — acceptable)

## Link Audit

### Internal Links Checked (from homepage)

| URL | Status | Found On |
|-----|--------|----------|
| /docs/getting-started | 200 ✓ | Homepage (Get Started CTA, nav) |
| /playground | 200 ✓ | Homepage (Try Playground CTA, nav) |
| /docs/cli-guide | 200 ✓ | Homepage footer nav |
| /vscode | 200 ✓ | Homepage nav |
| /benchmarks | 200 ✓ | Homepage nav |
| /docs | 200 ✓ | Homepage nav |
| /blog | 200 ✓ | Homepage nav |
| /privacy | 200 ✓ | Homepage footer |
| /docs/api-reference | 200 ✓ | Homepage footer nav |

### Broken Links Found
None detected — all 9 tested internal links return HTTP 200.

## Asset Audit

| Asset | Size | Used In | Action |
|-------|------|---------|--------|
| logo-text.svg | 931 KB | **Not used anywhere** in `website/src/` | **Remove** — dead asset, enormous SVG |
| logo.svg | 309 KB | **Not used anywhere** in `website/src/` | **Remove** — dead asset, large SVG |
| logo.png | 44 KB | Not referenced (logo.webp used instead) | **Remove** — redundant |
| logo.webp | 8.3 KB | Navbar.tsx, Footer.tsx | ✓ Keep — only active logo |
| og-image.png | 157 KB | meta tag | ✓ OK — 1200×670px (standard OG size is 1200×630; 670px height is 3px taller than spec but renders fine) |

**Total wasted assets: 1.28 MB** (logo-text.svg + logo.svg + logo.png are unused)

OG image dimensions: 1200×670px. Standard OG spec is 1200×630px. The 40px height difference is minor and will not cause issues in most social previews, but could be cropped on some platforms.

Favicon: `/favicon.png` — 5,608 bytes, served correctly as `image/png`.
Apple Touch Icon: `/apple-touch-icon.png` — 29,395 bytes, served correctly as `image/png`.

## CNAME File
- Present: ✓ — Content: `gosqlx.dev`
- Now on Vercel: file is harmless but unnecessary. Vercel manages DNS/domain configuration independently; CNAME was used for GitHub Pages. Safe to remove.

## Redirects (next.config.ts)
- 11 redirect rules configured (1 catch-all `/(.*) → /`, 10 underscore-to-hyphen doc redirects)
- Sample test: `/docs/getting_started` → `308` → `/docs/getting-started` ✓
- All underscore variants redirect correctly via 308 Permanent Redirect

## TODO/Placeholder Text
- No TODO/FIXME/placeholder/lorem ipsum found in user-facing content (`website/src/content/`)
- TODO references in blog post v1-9-2.md are **descriptive** (describing past code cleanup work), not unfinished content markers — acceptable
- Internal docs (`docs/sql99-compliance-analysis.md`) contain TODO markers in planning tables — these are not served to website visitors

## Priority Fixes

1. **Remove unused large assets** — `logo-text.svg` (931 KB), `logo.svg` (309 KB), `logo.png` (44 KB) are unreferenced in source. Total ~1.28 MB of dead weight in the public directory. **Severity: Medium** (affects bundle/build time and repo size, not user-visible)

2. **Missing blog post for v1.12.1** (current latest release) — homepage shows v1.12.1 but no blog post exists. **Severity: Low-Medium** (cosmetic gap; blog/changelog shows the release notes)

3. **Blog coverage gap v1.1.0–v1.9.0** — 9 releases (Jan 2025–Feb 2026) have no blog posts. These represent major features: Parser Enhancements, Multi-Dialect Engine, WASM Playground, LSP Server. **Severity: Low** (historical, unlikely to be retroactively backfilled)

4. **CNAME file cleanup** — `website/public/CNAME` is a GitHub Pages artifact, now unused on Vercel. **Severity: Low** (harmless but creates confusion)

5. **OG image dimensions** — 1200×670px vs recommended 1200×630px. Minor non-compliance with Open Graph spec. **Severity: Low** (does not affect rendering in practice)
