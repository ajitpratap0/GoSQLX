# GoSQLX Marketing & Launch Plan
> **Created**: 2026-03-22 | **Status**: DRAFT — review before action | **Version**: v1.13.0

---

## Executive Summary

GoSQLX has the strongest technical foundation of any actively-maintained Go SQL parser in 2026. All major competitors are stale or not standalone. The product was built — it was never announced. This plan fixes that.

**Current state**: 60 stars, 0 Reddit/HN posts, 1 Medium article (March 2025), 0 pkg.go.dev importers. Already listed in Awesome Go and featured in Golang Weekly Issue 594 (March 20, 2026).

**Goal**: 500+ stars within 60 days of launch push. Establish GoSQLX as the default Go SQL parsing toolkit.

---

## Competitive Context

| Library | Stars | Status | Limitation |
|---|---|---|---|
| xwb1989/sqlparser | 1,600 | Stale (~2021) | MySQL only, no DDL, no maintenance |
| pingcap/parser | 1,443 | Deprecated | Absorbed into TiDB monorepo |
| blastrain/vitess-sqlparser | 491 | Abandoned (2020) | Go module issues, unmaintained |
| pganalyze/pg_query_go | 826 | Active | CGo required, PostgreSQL only |
| **GoSQLX** | **60** | **Active (v1.13.0)** | **Multi-dialect, full toolkit, zero CGo** |

**Positioning**: GoSQLX is the only Go-native, multi-dialect SQL parser that bundles a formatter, linter, security scanner, LSP server, VS Code extension, WASM playground, MCP server, and CLI — all from a single module.

**AI differentiator**: The only Go SQL parser with an MCP server. Uniquely positioned for AI/LLM teams validating AI-generated SQL.

---

## 🔴 BLOCKER — Fix WASM Before Launch

### Problem
Production playground at gosqlx.dev/playground returns HTTP 404 for `gosqlx.wasm`.

### Root Cause (Hypothesis)
Vercel's GitHub auto-deploy integration fires on every merge to `main` (without the WASM build step), overwrites the `website.yml` CI deployment that *does* build WASM. The 6.5MB `.wasm` file is gitignored so Vercel's integration deploys without it.

### Fix Options

**Option A** (recommended): Disable Vercel's automatic GitHub integration for production
- Go to Vercel Dashboard → Project → Settings → Git → "Ignored Build Step"
- Or set `VERCEL_SKIP_DEPLOY=1` in the auto-deploy, let `website.yml` own production exclusively

**Option B**: Override Vercel's build command to build WASM
- Add a `vercel.json` build command that runs `cd wasm && make build && cp playground/gosqlx.wasm ../public/wasm/`
- Removes dependency on CI build step

**Option C**: Serve WASM from Vercel Blob
- Upload `gosqlx.wasm` to Vercel Blob in CI, serve from Blob URL
- Decouples WASM from deployment

**Decision needed**: Option A, B, or C?

---

## Phase 1 — Foundation (Day 1-2, before any noise)

All fixes are non-code or small edits. No new features.

### 1.1 WASM Fix (see above)
**Owner**: Claude | **Effort**: 1-2h | **Blocker**: Yes

### 1.2 Add Live GitHub Star Button to Hero
Replace the static badge image with a live `iframe`/API-driven star count + "Star on GitHub" CTA button in the hero section.

**File**: `website/src/components/home/Hero.tsx`
**Effort**: Small | **Impact**: Every visit becomes a star opportunity

### 1.3 Social Sharing on Blog Posts
Add Twitter/X, LinkedIn, and HackerNews share buttons to each blog/changelog post.

**Files**: `website/src/app/blog/[slug]/page.tsx` or blog layout
**Effort**: Small | **Impact**: Each release post becomes shareable content

### 1.4 Playground Post-Use CTA
After a user parses SQL in the playground, show a conversion prompt:
```
Ready to use this in your project?
go get github.com/ajitpratap0/GoSQLX  [copy]
```
**File**: `website/src/components/playground/Playground.tsx`
**Effort**: Small | **Impact**: Converts playground visitors to installers

### 1.5 Fix Color Contrast (WCAG)
Tab buttons "Format", "Validate", "Lint" and code syntax spans (`text-accent-indigo`, `text-zinc-500`) fail WCAG AA 4.5:1 contrast ratio against dark background. Fixes Lighthouse accessibility from 96 → 100.

**File**: `website/src/components/home/Hero.tsx` (code demo section)
**Effort**: Small | **Impact**: Accessibility + Lighthouse score

### 1.6 Newsletter / Email Capture
Add a minimal "Get release announcements" signup. Options:
- Link to GitHub Releases RSS (zero effort)
- Embed a free Buttondown or Resend form (low effort, builds a direct audience)

**Effort**: Small | **Impact**: Builds owned distribution channel

---

## Phase 2 — Content (Week 1-2)

### 2.1 Update & Cross-Post Medium Article
The original Medium article (March 2025) has stale perf numbers (946K ops/sec) and predates v1.13.0 features (ClickHouse, LSP, MCP). The article may be paywalled (403 on fetch).

**Actions**:
1. Update perf numbers: 946K → 1.40M ops/sec
2. Add sections: ClickHouse dialect, LSP semantic tokens, MCP server, WASM playground
3. Remove/update the "not a replacement for sqlx" framing — it's correct but undersells the toolkit scope
4. Cross-post free version to dev.to (dev.to reaches 1M+ developers, not paywalled)

**Effort**: Medium | **Impact**: Fixes stale #1 Google result for "GoSQLX"

### 2.2 Comparison Article (HN-bait)
**Title**: "I benchmarked every Go SQL parser and built my own: xwb1989, pg_query_go, TiDB, and GoSQLX compared"

**Angle**: Honest, data-driven, shows trade-offs. Not promotional — GoSQLX wins on breadth and maintenance; pg_query_go wins on PostgreSQL accuracy; TiDB wins on MySQL import count. Explains why each exists and when to use each.

**Publish on**: dev.to (primary), cross-post to Medium, submit to Golang Weekly
**Effort**: Medium | **Expected Reach**: 5,000–30,000 views | **SEO**: ranks for "go sql parser"

### 2.3 Deep-Dive Technical Article
**Title**: "Zero-copy SQL tokenization in Go: how sync.Pool gives you 1.4M ops/sec"

**Angle**: Implementation walkthrough — tokenizer design, object pooling, benchmarking methodology. Shows the engineering rigor behind the numbers. This is what makes r/golang and HN engage vs. just upvote.

**Publish on**: dev.to, pitch to go.dev/blog (golang-blog@google.com)
**Effort**: Medium | **Expected Reach**: 5,000–50,000 if on go.dev/blog

---

## Phase 3 — Launch Push (Week 2, coordinate on ONE day)

Hit HN + Reddit + Gopher Slack on the same day. Cross-platform same-day momentum → GitHub Trending → self-reinforcing star growth.

### 3.1 Show HN Post

**Title options** (choose one):
- "Show HN: GoSQLX – SQL parser, linter, formatter, LSP, and MCP server in one Go module"
- "Show HN: GoSQLX – I built a SQL toolkit for Go that does 1.4M parses/sec with zero CGo"
- "Show HN: Validating AI-generated SQL in Go – GoSQLX with MCP server support"

**Body must include**:
- Why recursive descent over yacc (engineering decision, not marketing)
- How sync.Pool/zero-copy achieves 1.4M ops/sec (with code)
- Honest limitations (85% SQL-99 compliance, what's missing)
- Link to WASM playground (must be working)
- Benchmark table vs. competitors

**Best time to post**: Tuesday–Thursday, 8–10am US Eastern

### 3.2 r/golang Post (same day)

**Title**: "I built a SQL toolkit for Go – parser, formatter, linter, LSP server, and WASM playground in one module [Show & Tell]"

**Content**:
- Terminal gif of `gosqlx lint query.sql` in action
- WASM playground link
- VSCode extension install one-liner
- MCP server for AI workflows
- Honest benchmark numbers

**Flair**: Show & Tell | **Best time**: Same day as HN, 30min after HN post

### 3.3 Gopher Slack (same day)
Post in `#database` and `#show-and-tell`:
> "Hey, I've been working on GoSQLX — a multi-dialect SQL parser/linter/formatter for Go with an LSP server and MCP integration. Just hit v1.13.0 with ClickHouse support. Show HN post: [link]. Would love feedback from folks using SQL tools in Go."

---

## Phase 4 — Ecosystem (Ongoing)

### 4.1 Build Example Repos (pkg.go.dev importers)
**Problem**: 0 importers on pkg.go.dev. This is the #1 trust signal gap for enterprise adopters.

**Repos to build**:
1. `gosqlx-examples` — canonical usage examples, each as a runnable Go program
2. `gosqlx-gorm-linter` — middleware that lints GORM queries before execution
3. `gosqlx-github-action` (already exists as `action.yml`, improve docs/discoverability)

**Effort**: High | **Impact**: pkg.go.dev import count, enterprise trust, organic discoverability

### 4.2 Submit Technical Article to Golang Weekly
Issue 594 was a brief roundup mention. A featured technical piece (the comparison article or deep-dive) gets 5–15x more engagement.

**Contact**: kristina@cooperpress.com
**Timing**: After comparison article is published on dev.to

### 4.3 Pitch to go.dev/Blog
The LSP implementation or zero-copy tokenization article fits the go.dev/blog editorial standard. Requires polished technical writing and novel Go-specific insight.

**Contact**: golang-blog@google.com
**Timeline**: 2–3 months (long lead time)

### 4.4 ClickHouse Community
GoSQLX is one of very few Go parsers with native ClickHouse support. Post in the ClickHouse Discord/community forum — this is an underserved audience with no Go-native alternative.

### 4.5 Additional MCP Directories
Currently listed on Glama. Also submit to:
- smithery.ai
- Any other MCP server directories as the ecosystem grows

### 4.6 Add Missing GitHub Topics
Current topics (20): good but missing `sql-formatter`, `lsp`, `mcp-server`, `language-server`, `clickhouse`

### 4.7 Website: Blog vs Changelog
The `/blog/` URL currently serves only release notes titled "Changelog". Educational posts (tutorials, comparison articles) would drive organic search traffic that changelogs never will.

**Options**:
- Add `/articles/` section for educational content, keep `/blog/` as changelog
- Or rename `/blog/` → `/changelog/` and create a new `/blog/` for articles

---

## Messaging Framework

### One-liner
> The SQL toolkit for Go — parse, format, lint, and analyze SQL at 1.4M ops/sec with multi-dialect support.

### For r/golang / HN
> Zero-dependency, zero-CGo, race-free SQL parser for Go with 8 dialects (PostgreSQL, MySQL, MariaDB, SQLite, SQL Server, Oracle, Snowflake, ClickHouse), a built-in linter, formatter, security scanner, LSP server, VS Code extension, and MCP server for AI workflows.

### Against competitors
> Every other Go SQL parser is either stale (xwb1989, blastrain), embedded in a full DB engine (TiDB, Vitess), or CGo-only (pg_query_go). GoSQLX is the only actively maintained, standalone, pure-Go multi-dialect SQL toolkit.

### For AI/LLM developers
> GoSQLX validates AI-generated SQL before it hits your database. MCP server integration means your LLM agent can lint, format, and security-scan SQL in the tool loop.

---

## Success Metrics

| Metric | Current | 30-day target | 90-day target |
|---|---|---|---|
| GitHub stars | 60 | 300 | 1,000 |
| pkg.go.dev importers | 0 | 5 | 20 |
| Binary downloads (latest release) | 0 | 50 | 200 |
| Inbound GitHub issues (external) | 0 | 5 | 20 |
| Golang Weekly features | 1 (brief) | 1 (editorial) | 2 |
| Blog/article views | — | 10,000 | 50,000 |

---

## Open Decisions

- [ ] **WASM fix**: Option A (disable Vercel auto-deploy), B (custom build command), or C (Vercel Blob)?
- [ ] **Launch timing**: How many days for Phase 1 fixes before Phase 3 launch push?
- [ ] **HN title**: Engineering focus, breadth focus, or AI/MCP focus?
- [ ] **Medium article**: Update existing or write fresh "v1.13.0 launch" piece?
- [ ] **Example repos**: Which use cases? (GORM linter, SQL migration analyzer, CI GitHub Action?)
- [ ] **Blog split**: Add `/articles/` or rename `/blog/` → `/changelog/`?
- [ ] **Email list**: Buttondown/Resend form or just GitHub Releases RSS link?

---

## Notes
- This plan was drafted 2026-03-22 based on parallel agent research (GitHub audit, content search, CDP website audit, competitive landscape analysis)
- Do not merge to main or tag until open decisions are resolved
- The playground WASM must be verified working before any launch push
