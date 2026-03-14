# GoSQLX Website Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the GoSQLX product website with interactive WASM playground, documentation hub, and marketing pages using Astro + React + Tailwind.

**Architecture:** Astro static site with React islands for interactive playground. Existing WASM module (`wasm/main.go`) already exposes 4 JS functions — we reuse it. Docs rendered from existing `docs/*.md` via Content Collections. Dark data-driven theme. Deployed to GitHub Pages via GitHub Actions.

**Tech Stack:** Astro 5, React 19, Tailwind CSS 3, CodeMirror 6, Go WASM (extended), Pagefind, GitHub Pages

**Key Existing Assets:**
- `wasm/main.go` — currently exposes `gosqlxParse`, `gosqlxFormat`, `gosqlxLint`, `gosqlxValidate` (needs extension: add `gosqlxAnalyze` + dialect parameter to all functions)
- `wasm/playground/` — existing basic HTML playground (reference, not reused directly)
- `wasm/Makefile` — `make build` produces `gosqlx.wasm`
- `docs/` — 32+ markdown files covering all documentation
- `.github/logo.png` — project logo

**Spec:** `docs/superpowers/specs/2026-03-14-gosqlx-website-design.md`

---

## Chunk 1: Project Scaffold + Layout Shell

### Task 1: Initialize Astro Project

**Files:**
- Create: `website/package.json`
- Create: `website/astro.config.mjs`
- Create: `website/tailwind.config.mjs`
- Create: `website/tsconfig.json`
- Create: `website/src/styles/global.css`
- Create: `website/.gitignore`

- [ ] **Step 1: Scaffold Astro project**

```bash
cd /Users/ajitpratapsingh/dev/GoSQLX
npm create astro@latest website -- --template minimal --no-install --no-git --typescript strict
```

- [ ] **Step 2: Install dependencies**

```bash
cd website
npm install @astrojs/react @astrojs/tailwind react react-dom tailwindcss@3 @tailwindcss/typography
npm install -D @types/react @types/react-dom
```

- [ ] **Step 3: Configure Astro**

Edit `website/astro.config.mjs`:
```js
import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
import tailwind from '@astrojs/tailwind';

export default defineConfig({
  site: 'https://ajitpratap0.github.io',
  base: '/GoSQLX',
  integrations: [react(), tailwind()],
  output: 'static',
});
```

- [ ] **Step 4: Configure Tailwind with design tokens**

Edit `website/tailwind.config.mjs`:
```js
export default {
  content: ['./src/**/*.{astro,html,js,jsx,ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        surface: '#1e293b',
        elevated: '#334155',
        'accent-orange': '#f97316',
        'accent-blue': '#3b82f6',
        'accent-green': '#22c55e',
        'accent-purple': '#a78bfa',
      },
      fontFamily: {
        code: ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
        body: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [require('@tailwindcss/typography')],
};
```

- [ ] **Step 5: Create global CSS**

Create `website/src/styles/global.css`:
```css
@tailwind base;
@tailwind components;
@tailwind utilities;

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');

body {
  @apply bg-slate-900 text-slate-50 font-body;
}
```

- [ ] **Step 6: Verify build**

```bash
cd website && npm run build
```
Expected: Build succeeds, `dist/` directory created.

- [ ] **Step 7: Commit**

```bash
git add website/
git commit -m "feat(website): scaffold Astro project with Tailwind and React"
```

---

### Task 2: Base Layout + Navbar + Footer

**Files:**
- Create: `website/src/layouts/BaseLayout.astro`
- Create: `website/src/components/Navbar.astro`
- Create: `website/src/components/Footer.astro`
- Create: `website/src/pages/index.astro` (placeholder)
- Copy: `.github/logo.png` → `website/public/images/logo.png`

- [ ] **Step 1: Copy logo**

```bash
mkdir -p website/public/images
cp .github/logo.png website/public/images/logo.png
```

- [ ] **Step 2: Create Navbar component**

Create `website/src/components/Navbar.astro`:
- Logo (left) linking to `/`
- Nav links: Docs, Playground, Blog, VS Code, Benchmarks
- GitHub stars badge (right) — link to repo
- Sticky top, dark background with border-bottom
- Mobile hamburger menu

- [ ] **Step 3: Create Footer component**

Create `website/src/components/Footer.astro`:
- Three columns: Product (links), Resources (docs links), Community (GitHub, Discussions)
- Copyright line with Apache-2.0
- Dark background matching theme

- [ ] **Step 4: Create BaseLayout**

Create `website/src/layouts/BaseLayout.astro`:
- HTML head: meta tags, OG tags, favicon, global CSS import
- Slot for page content between Navbar and Footer
- `<html lang="en" class="dark">` for Tailwind dark mode

- [ ] **Step 5: Create placeholder homepage**

Create `website/src/pages/index.astro`:
```astro
---
import BaseLayout from '../layouts/BaseLayout.astro';
---
<BaseLayout title="GoSQLX - High-Performance SQL Parser for Go">
  <main class="container mx-auto px-4 py-20">
    <h1 class="text-4xl font-bold text-center">GoSQLX</h1>
    <p class="text-slate-400 text-center mt-4">Site under construction</p>
  </main>
</BaseLayout>
```

- [ ] **Step 6: Verify dev server**

```bash
cd website && npm run dev
```
Expected: Site loads at localhost:4321 with nav, placeholder content, footer.

- [ ] **Step 7: Commit**

```bash
git add website/
git commit -m "feat(website): add BaseLayout, Navbar, and Footer components"
```

---

## Chunk 2: WASM Integration + Playground

### Task 3: Extend WASM Module (Add Analyze + Dialect Support)

**Files:**
- Modify: `wasm/main.go`

The existing `wasm/main.go` exposes 4 functions (`gosqlxParse`, `gosqlxFormat`, `gosqlxLint`, `gosqlxValidate`) that only accept a `sql` string. We need to:
1. Add `gosqlxAnalyze` function (imports `pkg/advisor` and `pkg/sql/security`)
2. Add a `dialect` parameter to all 5 functions
3. Map dialect strings to `keywords.SQLDialect` constants

- [ ] **Step 1: Add dialect mapping**

Add to `wasm/main.go`:
```go
import "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"

var dialectMap = map[string]string{
    "generic":    keywords.DialectGeneric,
    "postgresql": keywords.DialectPostgreSQL,
    "mysql":      keywords.DialectMySQL,
    "sqlite":     keywords.DialectSQLite,
    "sqlserver":  keywords.DialectSQLServer,
    "oracle":     keywords.DialectOracle,
    "snowflake":  keywords.DialectSnowflake,
}
```

- [ ] **Step 2: Add dialect parameter to existing functions**

Modify each registered function to accept `(sql, dialect)` instead of `(sql)`. When dialect is provided and non-empty, use `gosqlx.ParseWithDialect()` instead of `gosqlx.Parse()`.

- [ ] **Step 3: Add gosqlxAnalyze function**

```go
import (
    "github.com/ajitpratap0/GoSQLX/pkg/advisor"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/security"
)

// Register: js.Global().Set("gosqlxAnalyze", js.FuncOf(analyze))
func analyze(this js.Value, args []js.Value) interface{} {
    sql := args[0].String()
    // Run security scan
    scanner := security.NewScanner()
    scanResult := scanner.ScanSQL(sql)
    // Run optimization analysis
    opt := advisor.NewOptimizer()
    optResult, _ := opt.AnalyzeSQL(sql)
    // Return combined JSON
    result := map[string]interface{}{
        "security": map[string]interface{}{
            "findings": scanResult.Findings,
            "total_count": scanResult.TotalCount,
            "critical_count": scanResult.CriticalCount,
            "high_count": scanResult.HighCount,
            "medium_count": scanResult.MediumCount,
            "low_count": scanResult.LowCount,
        },
        "optimization": map[string]interface{}{
            "score": optResult.Score,
            "query_complexity": optResult.QueryComplexity,
            "suggestions": optResult.Suggestions,
        },
    }
    jsonBytes, _ := json.Marshal(result)
    return string(jsonBytes)
}
```

- [ ] **Step 4: Build and test WASM**

```bash
cd wasm && make build
```
Expected: Builds successfully with new function.

- [ ] **Step 5: Test in existing playground**

```bash
cd wasm && make serve
```
Open `http://localhost:8080`, verify `gosqlxAnalyze("SELECT * FROM users")` works in browser console.

- [ ] **Step 6: Commit**

```bash
git add wasm/main.go
git commit -m "feat(wasm): add gosqlxAnalyze and dialect support to all functions"
```

---

### Task 4: Copy WASM Artifacts to Website

**Files:**
- Create: `website/public/wasm/.gitkeep`

- [ ] **Step 1: Build WASM and copy artifacts to website**

```bash
cd wasm && make build
cp playground/gosqlx.wasm ../website/public/wasm/gosqlx.wasm
cp playground/wasm_exec.js ../website/public/wasm/wasm_exec.js
```

- [ ] **Step 2: Verify WASM artifacts exist**

```bash
ls -la website/public/wasm/
```
Expected: `gosqlx.wasm` (10-20MB) and `wasm_exec.js` present.

- [ ] **Step 3: Add wasm binary to gitignore**

Add to `website/.gitignore`:
```
public/wasm/gosqlx.wasm
```
(The WASM binary is built in CI, not committed.)

- [ ] **Step 4: Commit**

```bash
git add wasm/ website/
git commit -m "feat(website): WASM build pipeline for playground"
```

---

### Task 5: WASM Loader React Component

**Files:**
- Create: `website/src/components/WasmLoader.tsx`

- [ ] **Step 1: Create WasmLoader**

Create `website/src/components/WasmLoader.tsx`:
- Async function `initWasm()` that loads `wasm_exec.js` and instantiates `gosqlx.wasm`
- Returns an API object with `parse(sql, dialect)`, `format(sql, dialect)`, `lint(sql, dialect)`, `analyze(sql, dialect)` methods
- Each method calls the corresponding `window.gosqlxParse()` etc. and parses the JSON response
- Checks for `error` field in response and surfaces it to caller
- Loading state management: `loading`, `ready`, `error`
- Uses `fetch()` with progress tracking for the WASM binary download

- [ ] **Step 2: Test manually in browser**

```bash
cd website && npm run dev
```
Open browser console, verify `window.gosqlxParse` is available after WASM loads.

- [ ] **Step 3: Commit**

```bash
git add website/src/components/WasmLoader.tsx
git commit -m "feat(website): WASM loader with progress tracking"
```

---

### Task 6: SQL Editor Component

**Files:**
- Create: `website/src/components/SqlEditor.tsx`
- Install: `codemirror`, `@codemirror/lang-sql`, `@codemirror/theme-one-dark`

- [ ] **Step 1: Install CodeMirror**

```bash
cd website && npm install codemirror @codemirror/lang-sql @codemirror/theme-one-dark @codemirror/view @codemirror/state
```

- [ ] **Step 2: Create SqlEditor component**

Create `website/src/components/SqlEditor.tsx`:
- CodeMirror 6 editor with SQL syntax highlighting
- One Dark theme (matches site dark aesthetic)
- Props: `value`, `onChange`, `placeholder`
- Debounced onChange (200ms) to avoid excessive re-renders
- Auto-height with min-height

- [ ] **Step 3: Commit**

```bash
git add website/
git commit -m "feat(website): CodeMirror SQL editor component"
```

---

### Task 7: Playground Component (4 Tabs)

**Files:**
- Create: `website/src/components/Playground.tsx`
- Create: `website/src/components/playground/AstTab.tsx`
- Create: `website/src/components/playground/FormatTab.tsx`
- Create: `website/src/components/playground/LintTab.tsx`
- Create: `website/src/components/playground/AnalyzeTab.tsx`

- [ ] **Step 1: Create AstTab**

Renders parsed AST as a collapsible tree view. Each node shows type, and children are indented and collapsible. Syntax-colored by node type (statements = blue, expressions = green, identifiers = orange).

- [ ] **Step 2: Create FormatTab**

Shows formatted SQL output in a read-only CodeMirror instance. If formatting fails, shows error message inline.

- [ ] **Step 3: Create LintTab**

Renders lint violations as a list. Each violation shows: severity badge (error=red, warning=yellow, info=blue), rule code (e.g., L007), line:column, message, and suggestion. Empty state: green checkmark "No violations found".

- [ ] **Step 4: Create AnalyzeTab**

Three score cards side by side:
- Security: score derived from findings (`100 - critical*25 - high*10 - medium*5 - low*1`, clamped to 0)
- Optimization: score from `pkg/advisor` (0-100)
- Complexity: level from `query_complexity` (simple/moderate/complex)

Below the cards: recommendations list from optimization suggestions.

- [ ] **Step 5: Create main Playground component**

Create `website/src/components/Playground.tsx`:
- Left panel: SqlEditor with default example SQL
- Right panel: Tab bar (AST | Format | Lint | Analyze) + active tab content
- Top bar: Dialect selector dropdown
- Calls WASM functions on SQL change, updates all tabs
- Loading state: spinner while WASM initializes
- Error state: inline error display if WASM fails to load

- [ ] **Step 6: Create playground page**

Create `website/src/pages/playground.astro`:
```astro
---
import BaseLayout from '../layouts/BaseLayout.astro';
import Playground from '../components/Playground.tsx';
---
<BaseLayout title="SQL Playground - GoSQLX">
  <div class="h-[calc(100vh-64px)]">
    <Playground client:load />
  </div>
</BaseLayout>
```

- [ ] **Step 7: Test playground end-to-end**

```bash
cd website && npm run dev
```
Navigate to `/playground`. Paste SQL, verify all 4 tabs produce output.

- [ ] **Step 8: Commit**

```bash
git add website/
git commit -m "feat(website): interactive SQL playground with 4 tabs"
```

---

## Chunk 3: Homepage

### Task 8: Homepage Hero (Mini Playground)

**Files:**
- Create: `website/src/components/HeroPlayground.tsx`
- Modify: `website/src/pages/index.astro`

- [ ] **Step 1: Create HeroPlayground**

A compact version of the Playground for the homepage hero:
- Smaller editor (6-8 lines visible)
- Only shows one output tab at a time (tabs still switchable)
- Pre-loaded with an impressive example query
- "Open Full Playground →" link
- Subtle grid background pattern behind it
- Headline above: "Parse SQL at the speed of Go"
- Subtitle: "Try it now — paste SQL and see the AST in real time"

- [ ] **Step 2: Commit**

```bash
git add website/
git commit -m "feat(website): hero section with mini playground"
```

---

### Task 9: Stats Bar + Feature Cards + Code Examples

**Files:**
- Create: `website/src/components/StatsBar.astro`
- Create: `website/src/components/FeatureCards.astro`
- Create: `website/src/components/CodeExamples.astro`
- Create: `website/src/components/VscodeSection.astro`
- Create: `website/src/components/SocialProof.astro`
- Modify: `website/src/pages/index.astro`

- [ ] **Step 1: Create StatsBar**

Four metrics in a row: 1.25M+ ops/sec, <1μs latency, 85% SQL-99, 6 Dialects.
Each metric: large colored number + small label below. Use Intersection Observer for animated count-up on scroll.

- [ ] **Step 2: Create FeatureCards**

Six cards in a 3x2 grid:
1. Multi-Dialect (6 SQL dialects)
2. Thread-Safe (zero race conditions)
3. Zero-Copy (direct byte slice ops)
4. Object Pooling (60-80% memory reduction)
5. Security Scanner (injection detection)
6. MCP Server (AI-ready tools)

Each card: icon, title, short description. Dark surface background with subtle hover glow.

- [ ] **Step 3: Create CodeExamples**

Tabbed code block with 4 tabs: Parse, Format, Validate, Lint.
Each tab shows a Go code snippet with syntax highlighting (Shiki via Astro).

- [ ] **Step 4: Create VscodeSection**

Split layout: left = VS Code extension screenshot/mockup, right = description + "Install in VS Code" button linking to Marketplace.

- [ ] **Step 5: Create SocialProof**

Row of badges: GitHub stars, Go Report Card A+, Tests passing, GoDoc reference.

- [ ] **Step 6: Assemble homepage**

Wire all components into `website/src/pages/index.astro` in scroll order:
HeroPlayground → StatsBar → FeatureCards → CodeExamples → VscodeSection → SocialProof

- [ ] **Step 7: Verify full homepage**

```bash
cd website && npm run dev
```
Scroll through entire page, verify all sections render.

- [ ] **Step 8: Commit**

```bash
git add website/
git commit -m "feat(website): complete homepage with all sections"
```

---

## Chunk 4: Documentation + Blog

### Task 10: Docs Content Collection + Layout

**Files:**
- Create: `website/src/content/config.ts`
- Create: `website/src/layouts/DocsLayout.astro`
- Create: `website/src/components/DocsSidebar.astro`
- Create: `website/src/pages/docs/[...slug].astro`
- Create: `website/src/plugins/remark-auto-title.mjs`

- [ ] **Step 1: Create remark plugin for auto-title**

Create `website/src/plugins/remark-auto-title.mjs`:
Extracts the first `# heading` from markdown and injects it as `title` in frontmatter. This handles existing docs that lack Astro-compatible frontmatter.

- [ ] **Step 2: Create symlink to docs directory**

```bash
mkdir -p website/src/content
ln -s ../../../docs website/src/content/docs
```
This makes the existing `docs/` directory available as an Astro Content Collection.

- [ ] **Step 3: Create content config**

Create `website/src/content/config.ts`:
Define `docs` collection. Schema makes `title` optional (auto-generated by remark plugin). Uses the symlinked `docs/` directory.

- [ ] **Step 3: Create DocsSidebar**

Sidebar with categorized navigation:
- Getting Started: GETTING_STARTED.md, CLI_GUIDE.md
- Core: USAGE_GUIDE.md, API_REFERENCE.md, ARCHITECTURE.md
- Reference: ERROR_CODES.md, SQL_COMPATIBILITY.md, LINTING_RULES.md
- Advanced: LSP_GUIDE.md, MCP_GUIDE.md, SECURITY.md
- Tutorials: tutorials/*.md
- Migration: migration/*.md
- Editors: editors/*.md

Hardcoded sidebar config (more reliable than auto-generation for categorization).

- [ ] **Step 4: Create DocsLayout**

Two-column layout: sidebar (left, sticky) + content (right, scrollable). Includes table of contents on the right for large screens. Uses `@tailwindcss/typography` for prose styling.

- [ ] **Step 5: Create dynamic docs page**

Create `website/src/pages/docs/[...slug].astro`:
Fetches content from `docs` collection, renders in DocsLayout.

- [ ] **Step 6: Test docs pages**

```bash
cd website && npm run dev
```
Navigate to `/docs/GETTING_STARTED`. Verify sidebar, content rendering, code highlighting.

- [ ] **Step 7: Commit**

```bash
git add website/
git commit -m "feat(website): docs pages with sidebar and content collections"
```

---

### Task 11: Blog/Changelog + Search

**Files:**
- Create: `website/scripts/split-changelog.js`
- Create: `website/src/pages/blog/index.astro`
- Create: `website/src/pages/blog/[slug].astro`
- Create: `website/src/content/config.ts` (add blog collection)

- [ ] **Step 1: Create changelog splitter script**

Create `website/scripts/split-changelog.js`:
- Reads `CHANGELOG.md` from project root
- Splits on `## [X.Y.Z]` headers
- Writes each version to `website/src/content/blog/vX-Y-Z.md` with frontmatter (`title`, `date`, `version`)
- Add to package.json scripts: `"prebuild": "node scripts/split-changelog.js"`

- [ ] **Step 2: Create blog listing page**

Create `website/src/pages/blog/index.astro`:
Lists all changelog entries reverse-chronologically. Each entry: version badge, date, title, excerpt.

- [ ] **Step 3: Create blog entry page**

Create `website/src/pages/blog/[slug].astro`:
Renders individual changelog entry with full content.

- [ ] **Step 4: Add Pagefind search**

```bash
cd website && npm install pagefind
```

Add to `astro.config.mjs` build script or post-build hook. Add search component to Navbar.

- [ ] **Step 5: Commit**

```bash
git add website/
git commit -m "feat(website): blog from changelog + Pagefind search"
```

---

## Chunk 5: Remaining Pages + CI/CD

### Task 12: VS Code Extension + Benchmarks Pages

**Files:**
- Create: `website/src/pages/vscode.astro`
- Create: `website/src/pages/benchmarks.astro`

- [ ] **Step 1: Create VS Code extension page**

Features list, installation instructions, Marketplace link, "Install in VS Code" button.
Show key capabilities: LSP, formatting, linting, analysis, multi-dialect.

- [ ] **Step 2: Create Benchmarks page**

Performance data tables:
- Parse throughput: ops/sec across SQL sizes
- Memory usage: allocs/op, B/op
- Comparison table vs other Go SQL parsers (if data available)
- Data sourced from `performance_baselines.json`

- [ ] **Step 3: Commit**

```bash
git add website/
git commit -m "feat(website): VS Code extension and benchmarks pages"
```

---

### Task 13: GitHub Actions Deployment

**Files:**
- Create: `.github/workflows/website.yml`

- [ ] **Step 1: Create deployment workflow**

Create `.github/workflows/website.yml`:
```yaml
name: Deploy Website
on:
  push:
    branches: [main]
    paths:
      - 'website/**'
      - 'docs/**'
      - 'wasm/**'
      - 'CHANGELOG.md'
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages
  cancel-in-progress: true

jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.23'

      - name: Build WASM
        run: |
          cd wasm && make build
          mkdir -p ../website/public/wasm
          cp playground/gosqlx.wasm ../website/public/wasm/
          cp playground/wasm_exec.js ../website/public/wasm/

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '22'
          cache: 'npm'
          cache-dependency-path: website/package-lock.json

      - name: Install and build website
        run: |
          cd website
          npm ci
          npm run build

      - name: Upload Pages artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: website/dist

  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
```

- [ ] **Step 2: Verify workflow YAML is valid**

```bash
cat .github/workflows/website.yml | python3 -c "import yaml,sys; yaml.safe_load(sys.stdin); print('Valid YAML')"
```

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/website.yml
git commit -m "ci: add GitHub Actions workflow for website deployment"
```

---

### Task 14: Final Polish + PR

- [ ] **Step 1: Build full site locally**

```bash
cd wasm && make build
cp playground/gosqlx.wasm ../website/public/wasm/
cp playground/wasm_exec.js ../website/public/wasm/
cd ../website && npm run build
```
Expected: Clean build with no errors.

- [ ] **Step 2: Preview locally**

```bash
cd website && npm run preview
```
Navigate through all pages: Home, Playground, Docs, Blog, VS Code, Benchmarks.

- [ ] **Step 3: Add `.superpowers/` to .gitignore**

```bash
echo '.superpowers/' >> .gitignore
```

- [ ] **Step 4: Create PR**

```bash
git push origin feat/website
gh pr create --title "feat: GoSQLX product website with WASM playground" --body "..."
```

---

## Task Dependencies & Parallelization

```
Chunk 1 (Tasks 1-2): Sequential — scaffold then layout
Chunk 2 (Tasks 3-7): Task 3 (extend WASM) first, then 4 (copy artifacts), then 5+6 in parallel, then 7
Chunk 3 (Tasks 8-9): Sequential — hero then remaining sections
Chunk 4 (Tasks 10-11): Can run in parallel (docs and blog are independent)
Chunk 5 (Tasks 12-13): Can run in parallel (pages and CI are independent)
Task 14: Sequential — after all chunks complete
```

**Parallel opportunities:**
- Tasks 5 + 6 (WasmLoader + SqlEditor) — no dependencies between them
- Tasks 10 + 11 (Docs + Blog) — independent content systems
- Tasks 12 + 13 (Pages + CI) — independent concerns
