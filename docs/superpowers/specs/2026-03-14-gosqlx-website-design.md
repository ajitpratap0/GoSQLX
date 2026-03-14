# GoSQLX Website — Design Spec

## Overview

A full product website for GoSQLX: marketing landing page, interactive WASM-powered SQL playground, documentation hub, and supporting pages. Built with Astro, deployed on GitHub Pages.

**Goal**: Let visitors experience GoSQLX instantly through an interactive playground, while providing polished documentation and performance data to drive adoption.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Framework | Astro | Ships zero JS by default, React islands for interactive parts, fast builds |
| Styling | Tailwind CSS | Utility-first, dark theme support, consistent design tokens |
| Visual style | Dark + Data-Driven | Performance metrics front and center; matches Go performance brand |
| Homepage hero | Playground-first | Visitors interact before they scroll; strongest differentiator |
| Playground tech | Go WASM | Same parser running in browser; no server needed |
| Docs | Astro Content Collections | Reads existing `docs/*.md` directly; auto-sidebar |
| Search | Pagefind | Static search index, no server, fast |
| Code editor | CodeMirror 6 | SQL syntax highlighting, lightweight |
| Deployment | GitHub Pages | Free, automatic via GitHub Actions |
| URL | `ajitpratap0.github.io/GoSQLX` | No custom domain needed initially |
| Base path | Astro `base: '/GoSQLX'` | Required for GitHub Pages subpath deployment |

## Pages

| Page | Route | Description |
|---|---|---|
| Home | `/` | Hero playground + features + stats + code examples |
| Playground | `/playground` | Full-page interactive SQL playground with 4 tabs |
| Docs | `/docs/*` | Rendered from existing `docs/*.md` via Content Collections |
| Blog/Changelog | `/blog` | Rendered from CHANGELOG.md entries |
| VS Code Extension | `/vscode` | Features, screenshots, install button |
| Benchmarks | `/benchmarks` | Performance charts, comparison tables |

## Homepage Scroll Flow

1. **Nav bar** — Logo, Docs, Playground, Blog, VS Code, GitHub stars badge
2. **Hero: Mini playground** — SQL input (left) / AST+Format+Lint+Analyze output (right). "Try it now" tagline. Powered by WASM.
3. **Stats bar** — 1.25M+ ops/sec, <1μs latency, 85% SQL-99, 6 dialects. Animated count-up on scroll into view.
4. **Feature cards** — Multi-dialect, Thread-safe, Zero-copy, Object pooling, Security scanner, MCP Server
5. **Code examples** — Tabbed code snippets: Parse, Format, Validate, Lint
6. **VS Code extension** — Screenshot + "Install in VS Code" CTA button
7. **Social proof** — GitHub stars count, Go Report Card A+, test badges
8. **Footer** — Navigation links, license, GitHub link

## Playground Design

### Layout

- **Left panel**: SQL editor (CodeMirror 6 with SQL syntax highlighting)
- **Right panel**: Tabbed output with 4 tabs
- **Top bar**: Dialect selector dropdown (PostgreSQL, MySQL, SQLite, SQL Server, Oracle, Generic)

### Tabs

| Tab | Output |
|---|---|
| AST | Tree view with collapsible nodes, syntax-colored by node type |
| Format | Formatted SQL output with diff highlighting vs input |
| Lint | Violations list with severity badges, line numbers, suggestions |
| Analyze | Score cards (security, performance, complexity) + recommendations |

### WASM Integration

- Compile to WASM: `GOOS=js GOARCH=wasm go build -o gosqlx.wasm ./wasm/main.go`
- Expose 4 JS-callable functions via `js.Global().Set()`
- Bundle Go's `wasm_exec.js` runtime glue
- WASM binary loaded async on playground mount with loading spinner
- Expected raw binary ~10-20MB; with gzip/brotli compression ~3-6MB transfer size
- Lazy-loaded only when playground is visible (Intersection Observer)
- Show loading progress bar during WASM fetch

### WASM Entry Point (`wasm/main.go`)

Imports:
- `pkg/gosqlx` — for `Parse()` and `Format()`
- `pkg/linter` — for `linter.New().LintString()` (no `Lint()` in gosqlx)
- `pkg/advisor` — for `optimizer.AnalyzeSQL()` (no `Analyze()` in gosqlx)
- `pkg/sql/security` — for security scan results

Registered JS functions:

- `gosqlxParse(sql, dialect)` → JSON AST on success, `{"error": "message", "position": {...}}` on parse failure
- `gosqlxFormat(sql, dialect)` → `{"result": "formatted sql"}` on success, `{"error": "message"}` on failure
- `gosqlxLint(sql, dialect)` → `{"violations": [{"rule": "L007", "severity": "warning", "line": 4, "column": 18, "message": "...", "suggestion": "..."}]}`
- `gosqlxAnalyze(sql, dialect)` → `{"security": {"findings": [...], "total_count": 0, "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0}, "optimization": {"score": 85, "query_complexity": "moderate", "suggestions": [{"category": "performance", "message": "...", "severity": "medium"}]}}`

The Analyze tab UI maps these to visual score cards: security score is derived as `100 - (critical*25 + high*10 + medium*5 + low*1)` (clamped to 0). Optimization score and query complexity come directly from `pkg/advisor`.

Dialect mapping: The dialect string from JS (`"generic"`, `"postgresql"`, etc.) maps to `keywords.SQLDialect` via a lookup map in `wasm/main.go`. `"generic"` maps to `keywords.DialectGeneric`.

Error handling: All 4 functions return JSON objects. Errors are returned as `{"error": "message"}` — never thrown as JS exceptions. The playground UI checks for the `error` field and displays it inline.

## Docs Integration

- Astro Content Collections reading from `docs/` directory
- Existing docs lack Astro frontmatter — use a content config with a custom schema that auto-generates `title` from the first `# heading` in each file (via remark plugin)
- Auto-generated sidebar navigation from file structure
- Grouped by category: Getting Started, Core, Reference, Advanced, Tutorials, Migration, Editors
- Search via Pagefind (static search index built at build time)
- Syntax highlighting for Go and SQL code blocks (Shiki, built into Astro)

## Blog/Changelog Strategy

The `/blog` page renders from `CHANGELOG.md`, which is a single file with version-header sections. Implementation:

- A build-time script (`website/scripts/split-changelog.js`) parses `CHANGELOG.md` and extracts each `## [X.Y.Z]` section into a separate markdown file under `website/src/content/blog/`
- Each generated file gets frontmatter: `title`, `date`, `version`
- This runs as a pre-build step in the Astro build pipeline
- The blog index page lists entries reverse-chronologically

## Design Tokens

| Token | Value | Usage |
|---|---|---|
| `--bg-primary` | `#0f172a` (slate-900) | Page background |
| `--bg-surface` | `#1e293b` (slate-800) | Cards, panels |
| `--bg-elevated` | `#334155` (slate-700) | Borders, dividers |
| `--text-primary` | `#f8fafc` (slate-50) | Headings, body |
| `--text-secondary` | `#94a3b8` (slate-400) | Descriptions, labels |
| `--text-muted` | `#475569` (slate-600) | Hints, captions |
| `--accent-orange` | `#f97316` | Brand accent, perf metrics |
| `--accent-blue` | `#3b82f6` | CTAs, Go brand color |
| `--accent-green` | `#22c55e` | Success states, SQL-99 |
| `--accent-purple` | `#a78bfa` | Dialect count, secondary |
| `--font-code` | JetBrains Mono / Fira Code | Code blocks, editor |
| `--font-body` | Inter / system-ui | Body text, headings |

## Project Structure

```
website/
├── astro.config.mjs          # Astro config, Tailwind, React integration
├── tailwind.config.mjs        # Dark theme, design tokens
├── package.json
├── public/
│   ├── wasm/                  # gosqlx.wasm + wasm_exec.js
│   ├── images/                # Logo, og-image, screenshots
│   └── favicon.svg
├── src/
│   ├── layouts/
│   │   ├── BaseLayout.astro   # Shell: head, nav, footer
│   │   └── DocsLayout.astro   # Docs shell: sidebar + content
│   ├── pages/
│   │   ├── index.astro        # Homepage
│   │   ├── playground.astro   # Full-page playground
│   │   ├── vscode.astro       # VS Code extension page
│   │   ├── benchmarks.astro   # Performance charts
│   │   └── blog/
│   │       └── index.astro    # Changelog/blog listing
│   ├── content/
│   │   └── docs/              # Symlink → ../../docs/ or content config
│   ├── components/
│   │   ├── Navbar.astro       # Top navigation
│   │   ├── Footer.astro       # Site footer
│   │   ├── StatsBar.astro     # Animated metrics counter
│   │   ├── FeatureCards.astro  # Feature grid
│   │   ├── CodeExamples.astro # Tabbed code snippets
│   │   ├── Playground.tsx     # React island — main playground
│   │   ├── SqlEditor.tsx      # CodeMirror 6 wrapper
│   │   └── WasmLoader.tsx     # WASM initialization + JS bridge
│   └── styles/
│       └── global.css         # Tailwind directives, custom styles
└── wasm/
    ├── main.go                # WASM entry point
    └── build.sh               # Build script: GOOS=js GOARCH=wasm
```

## CI/CD

New workflow `.github/workflows/website.yml`:

1. **Build WASM**: Run `wasm/build.sh` → produces `gosqlx.wasm`
2. **Copy WASM**: Move to `website/public/wasm/`
3. **Build site**: `cd website && npm ci && npm run build`
4. **Deploy**: Upload `website/dist/` to GitHub Pages

**Triggers**: Push to `main` when paths match `website/**`, `docs/**`, or `wasm/**`.

**GitHub Pages config**: Set source to GitHub Actions in repo settings.

## Dependencies

### Website (`website/package.json`)

| Package | Purpose |
|---|---|
| `astro` | Static site generator |
| `@astrojs/react` | React integration for playground islands |
| `@astrojs/tailwind` | Tailwind CSS integration |
| `react`, `react-dom` | Playground interactive components |
| `@codemirror/lang-sql` | SQL syntax highlighting |
| `codemirror` | Code editor for playground |
| `pagefind` | Static search |

### WASM (`wasm/`)

No external dependencies — uses `pkg/gosqlx` directly. Requires Go 1.23+.

## Out of Scope (Future)

- Custom domain (can add CNAME later)
- Blog posts beyond changelog (can add MDX content later)
- User accounts / saved queries
- Server-side rendering
- Analytics (can add Plausible/Fathom later)
- i18n / localization
