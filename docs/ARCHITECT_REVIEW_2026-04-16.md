# GoSQLX Architect Review — 2026-04-16

Cross-component review of the entire project via 5 parallel architect agents. Scope: parsing pipeline, foundation layer, public APIs, advanced features (linter/LSP/security), and cross-cutting concerns (repo/build/CI).

---

## Executive Summary

The architecture is **good, not great**. The pipeline shape, pool strategy, concurrency model, DoS hardening, and security workflow are sensible and well above average for an OSS Go SDK. Three classes of issues hold it back:

1. **Correctness landmines** in pool cleanup and metrics that quietly undermine the 1.38M ops/sec headline claim.
2. **DX friction** at the public API boundary that likely explains the 0 imports on pkg.go.dev despite 88 stars.
3. **Extensibility debt** — dialect branching, linter rules, and security detection are all hardcoded; there is no published extension API.

None of this is a rewrite. It's **2–3 sprints** of focused work to turn a respectable SDK into a credible category leader.

---

## Critical Issues (Fix Before v1.15)

### C1. Pool leak in `PutSelectStatement`
**File**: `pkg/sql/ast/pool.go:671-726`
Only `Columns`, `OrderBy`, `Where` are released. Missing: `GroupBy`, `Having`, `Qualify`, `StartWith`, `ConnectBy`, `Joins`, `Windows`, `PrewhereClause`, `Sample`, `ArrayJoin`, `Pivot`, `Unpivot`, `MatchRecognize`, `Top`, `DistinctOnColumns`, `From`, `Limit`, `Offset`, `Fetch`, `For`. Every production-shaped SELECT leaks pooled expressions. `UpdateStatement` has the same defect at line 593+.

### C2. `PutExpression` silently drops past `MaxWorkQueueSize`
**File**: `pkg/sql/ast/pool.go:880`
The work-queue cap of 1000 causes remaining entries to not return to pools. Large IN-lists (an advertised use case — 1000 values = ~3000-4000 tokens) leak hundreds of nodes per parse.

### C3. Unbounded metrics map keyed by `err.Error()`
**File**: `pkg/metrics/metrics.go:372-376, 458-462`
`errorsByType` uses full formatted error strings as keys under a write lock. Pathological or fuzz-generated inputs with unique error strings create a memory DoS vector. Plus the map is deep-copied on every `GetStats()` call (line 739-744).
**Fix**: key by `ErrorCode` (bounded ~20 buckets), use `atomic.Int64` per bucket, drop the mutex.

### C4. Release workflow CGO mismatch
**File**: `.github/workflows/release.yml:27`
Runs `go test -race ./...` with implicit `CGO_ENABLED=0`, but `pkg/cbinding` requires CGO. Either passes silently (skipping cbinding tests) or fails on tag push. Replace with `task test:race`.

### C5. Linter rules don't traverse nested AST
All 22 linter rules use flat `for _, stmt := range ctx.AST.Statements` — zero use of `ast.Walk`. `SelectStarRule` won't detect `SELECT * FROM (SELECT id FROM t)`. `DeleteWithoutWhereRule` misses CTE-modifying statements. Rules silently regress every time a new AST node type lands.
**Fix**: route all rules through `ast.Walk`/`ast.Inspector` in `pkg/sql/ast/visitor.go:161,218`.

### C6. AST `Children()` coverage is incomplete
15+ node types return `nil` despite having children: `DropStatement`, `TruncateStatement`, `PragmaStatement`, `ShowStatement`, `DescribeStatement`, `UnsupportedStatement`, `WindowFrame`, `FetchClause`, `ForClause`, `UnpivotClause`, `SampleClause`, `ReferenceDefinition`, `TableOption`, `IndexColumn`. Anyone building a semantic analyzer on `Walk` gets silent truncation. Add a `go vet`-style test: any Node/Expression/Statement-typed field must appear in `Children()`.

---

## High-Severity Issues (Target v1.15–v1.16)

### H1. Public API leaks `*ast.AST` — forces users into `pkg/sql/ast`
**File**: `pkg/gosqlx/gosqlx.go:102`
`Parse()` returns `*ast.AST`. Users must import `pkg/sql/ast` to do anything non-trivial (type-switch, walk). This defeats the two-tier abstraction promise.
**Fix**: wrap in an opaque `gosqlx.Tree` with methods `Statements()`, `Walk(fn)`, `Format(opts)`, `Tables()`, `Release()`, `Raw()`.

### H2. `FormatAST` not exposed at top tier — every Parse→Modify→Format re-parses
**File**: `pkg/gosqlx/gosqlx.go:564-587`
`Format(sql string, opts)` re-tokenizes. `formatter.FormatAST` exists internally but isn't surfaced. Self-inflicted perf wound for a library marketed on throughput.

### H3. Functional options anti-pattern: `ParseWithContext`, `ParseWithDialect`, `ParseWithTimeout`, `ParseWithRecovery`…
Combinatorial explosion (`ParseWithContextWithDialectWithStrict`?). Collapse to `gosqlx.Parse(ctx, sql, WithDialect(d), WithTimeout(t), WithRecovery(), WithStrict())` using functional options.

### H4. No `io.Reader` / `io.Writer` support
Zero `io.Reader` references in `pkg/gosqlx`. Users parsing files/HTTP bodies `io.ReadAll` first. `ParseReader(ctx, io.Reader, ...Option)` is table stakes for a Go SDK.

### H5. Dialect is `string` with 72 scattered `p.dialect ==` comparisons
**Fix**: switch `Parser.dialect` to the typed `keywords.SQLDialect`, add helper predicates (`isClickHouse`, `isSnowflake`, etc.), and consider a `DialectCapabilities` struct (`SupportsQualify bool`, `SupportsArrayJoin bool`, …) to centralize feature gates. This is the #1 extensibility drag. Adding a 9th dialect today is a multi-file scavenger hunt.

### H6. `*errors.Error` claims immutability but `WithContext`/`WithHint`/`WithCause` mutate
**File**: `pkg/errors/errors.go:367, 399, 429`
Docstrings lie. External consumers holding a shared `*Error` get observer effects. Either return shallow copies or unexport fields behind accessors.

### H7. 38 call sites use `fmt.Errorf` instead of structured errors
Errors without position info, without error codes, without `errors.Is`-compatibility. Violates the LSP integration that already ships. Grep for `fmt.Errorf(` inside `func (p *Parser)` methods and rewrite via `goerrors.InvalidSyntaxError(msg, p.currentLocation(), hint)`.

### H8. No linter rule configuration (`.gosqlx.yml` referenced but unimplemented)
`cmd/gosqlx/doc.go:52, 294` and `docs/CONFIGURATION.md:11` advertise `.gosqlx.yml`; `pkg/linter/` contains **zero** YAML/config code. Rule severity is baked in at construction, no per-rule disable, no inline `-- gosqlx:disable L016` suppression. Major adoption blocker vs. sqlfluff.

### H9. LSP uses reflection-via-strings for statement dispatch
**File**: `pkg/lsp/handler.go:1230-1271`
`fmt.Sprintf("%T", stmt)` then `strings.Contains(typeName, "SelectStatement")`. Forbidden by the project's own style guide; breaks on rename/vendor; unnecessary when a two-value type switch is 3 lines away.

### H10. LSP `documentSymbol` returns fake ranges
**File**: `pkg/lsp/handler.go:1278-1288`
"A more sophisticated implementation would track actual positions" — today every outline entry points at line 0. Primary value of documentSymbol is degraded.

### H11. Keyword registration is order-dependent
**File**: `pkg/sql/keywords/keywords.go:293-309`
`addKeywordsWithCategory` silently skips duplicates via `containsKeyword`. `REPLACE` appears in both `ADDITIONAL_KEYWORDS` and `SQLITE_SPECIFIC`; whichever runs first wins. Position-dependent semantics masquerading as a dispatch table. Log/panic on conflicts in tests.

---

## Medium-Severity (Strategic / Multi-Sprint)

- **M1. God-files need splitting**: `pkg/sql/ast/ast.go` (2,327L), `pkg/sql/ast/sql.go` (1,853L), `pkg/sql/tokenizer/tokenizer.go` (1,842L), `pkg/sql/parser/parser.go` (1,186L). All exceed the 800-line ceiling in the project's own `coding-style.md`. Mechanical split by domain (`ast_select.go`, `ast_dml.go`, etc.) is cheap and materially improves contributor onboarding.
- **M2. Two parallel token types** — `pkg/models/Token` and `pkg/sql/token/Token` coexist. Pick one. `pkg/sql/ast` already only uses `pkg/models`; `pkg/sql/token` is effectively dead outside `pkg/sql/parser`.
- **M3. `Token` struct carries a `*Word` pointer** — heap alloc per keyword/identifier. Flatten in a v2 token type.
- **M4. No Prometheus collector** — `pkg/metrics` exposes `Stats` but no `prometheus.Collector`. Given the repo's stated observability stack, `pkg/metrics/prometheus/` is a natural sub-package.
- **M5. Compatibility package is reflect-snapshots, not a contract** — `pkg/compatibility/compatibility_test.go` golden files stop at v1.5.1 (we're on v1.14). High-level `pkg/gosqlx` has zero stability tests. Wire `gorelease`/`apidiff` into CI.
- **M6. `preprocessTokens` allocates a slice on every Parse** (`pkg/sql/parser/preprocess.go:50`). At 1.38M ops/sec × 50 tokens, that's ~70M allocs/sec. Pool the preprocess buffer.
- **M7. Perf regression gate is `continue-on-error: true`** with 60–65% tolerance. Regressions up to 1.65× slip through silently. Tighten to <25% on a self-hosted runner and make the job required.
- **M8. No benchstat comparison in CI** — benchmarks run but output is discarded. Add `benchmark-action/github-action-benchmark` or upload/compare artifacts.
- **M9. Error severity missing** — all `ErrorCode`s are flat; no `Severity` (warning/error/fatal). LSP diagnostic severity mapping is thus heuristic. Add `Severity` to the `Error` type.
- **M10. Module graph documentation drift** — `CLAUDE.md:44-52` claims dependencies that don't match the code. `tokenizer→keywords` is false; `ast→token` is false; `transform`, `fingerprint`, `lsp`, `linter`, `formatter`, `cbinding` aren't in the graph at all.

---

## Repo Hygiene (Quick Wins)

1. Clean up the 100+ `.png` audit screenshots and `.claude/worktrees/` from the working tree (route to `docs/audits/YYYY-MM/` or a separate repo).
2. Add `tools/tools.go` with pinned dev tools — local `task deps:tools` installs `@latest`, CI pins `golangci-lint v2.11.3`, they already drift.
3. Fix the module graph in `CLAUDE.md` lines 44-52 to match reality.
4. Replace `.github/workflows/release.yml:27` `go test -race` with `task test:race` — single source of truth.
5. Delete the committed `examples/cmd/cmd` binary.
6. Consider moving `pkg/metrics`, `pkg/config`, infrastructure packages to `internal/` to reduce SemVer commitment burden.

---

## Pre-v2.0 Tech Debt Punch List

| # | Item | Why v2.0 gate |
|---|------|---------------|
| 1 | Split god-files (ast.go, sql.go, tokenizer.go, parser.go) | SemVer break lets you reorganize safely |
| 2 | Remove `ConversionResult.PositionMapping` (marked deprecated at `parser.go:41-42`) | Removal window |
| 3 | Merge/delete `pkg/sql/token` — parallel token types are confusing | Pick one |
| 4 | Move non-API packages behind `internal/` | Reduces public API surface |
| 5 | `DialectRegistry` replacing `switch` in `keywords.New()` | Clean extension boundary |
| 6 | `gosqlx.Tree` opaque wrapper replacing raw `*ast.AST` return | Lets AST internals evolve without user breakage |
| 7 | Functional options on `Parse` | Collapse `ParseWith*` family |
| 8 | Structured errors everywhere (no `fmt.Errorf` in parser) | LSP/IDE integration quality |
| 9 | Logger interface injection (203 `fmt.Println` calls across 38 files) | Embedders cannot silence output today |

---

## Competitive Framing

| Capability | GoSQLX | vitess | sqlparser-rs | sqlfluff |
|---|---|---|---|---|
| One-line Parse | ✅ | ✅ | ✅ | N/A |
| Typed AST walk at top level | ❌ | ✅ | ✅ | N/A |
| AST → SQL no-reparse | ❌ | ✅ | ✅ | N/A |
| io.Reader / streaming | ❌ | partial | ✅ | N/A |
| Functional options | ❌ | N/A | ✅ | N/A |
| Sentinel errors (errors.Is) | ❌ | ✅ | ✅ | N/A |
| API stability tooling | reflect-snapshot | apidiff | cargo semver-checks | N/A |
| Rule config / suppressions | ❌ | N/A | N/A | ✅ |
| Auto-fix rules | ❌ (all stubs) | N/A | N/A | ✅ (~30) |

The **three** highest-leverage gaps vs competitors: (1) AST walk ergonomics, (2) FormatAST at top tier, (3) functional options. These are 1–2 weeks each. Fixing them would make the 5-minute DX experience competitive with sqlparser-rs.

---

## Recommended Sprint Plan

**Sprint 1 — "Correctness" (1 week)**
- Fix C1, C2 (pool leaks)
- Fix C3 (metrics DoS)
- Fix C4 (release workflow)
- Complete AST `Children()` coverage (C6)
- Add leak-detection benchmark for production-shaped SELECT

**Sprint 2 — "DX" (2 weeks)**
- H1: `gosqlx.Tree` opaque wrapper
- H2: `FormatTree`/`FormatAST` at top tier
- H3: Functional options
- H4: `ParseReader`
- README first-impression fix

**Sprint 3 — "Extensibility" (2 weeks)**
- C5: Rules through `ast.Walk`
- H8: `.gosqlx.yml` loader + per-rule config + inline suppression
- Rule-Authoring SDK (`pkg/linter/sdk/`)
- H5: Typed dialect + `DialectCapabilities` struct

**Sprint 4 — "Quality polish" (1 week)**
- H7: `fmt.Errorf` → structured errors sweep
- H9, H10: LSP dispatch + document symbol ranges
- H11: Keyword conflict detection
- M1: Split god-files
- Repo hygiene quick wins

That's 6 weeks of real work. Ship v1.15 after Sprint 2, v1.16 after Sprint 3, v1.17 (or v2.0 cut) after Sprint 4.

---

## Net Assessment

**What's unusually good**: security workflow, Taskfile DX, pool discipline philosophy, DoS hardening, LSP capability breadth, error-code taxonomy design, dependency graph discipline, context.Context propagation.

**What will block adoption at 1000+ stars**: the public API forcing users into `pkg/sql/ast`, no functional options, no `FormatAST`, no rule config, no `io.Reader`. These are not academic — they're the exact frictions a Go dev hits in the first 5 minutes and closes the tab over.

**What threatens the performance claim**: C1 + C2 (pool leaks) are real and likely hidden by simple benchmarks. Add a production-shaped benchmark before anyone publishes "1.5M ops/sec" again.

**Timeline to category credibility**: 6 weeks of focused work. Not a rewrite. The bones are good.
