# GoSQLX Architect Review (Round 2) — 2026-04-21

Second-round review after PR #517 (merged 2026-04-21). Five parallel architect agents did a fresh pass across core parsing, foundation, public API, advanced features, and cross-cutting infra. This is a **delta document**: what landed cleanly, what slipped through, what's newly surfaced.

Previous review: `docs/ARCHITECT_REVIEW_2026-04-16.md`.

---

## Executive Summary

PR #517 **delivered all 11 claimed fixes** to a solid baseline. But:

1. **One class-C1 defect was missed**: subquery leaks in `PutExpression` (see §1).
2. **The new infrastructure is unused**: `pkg/sql/dialect.Capabilities` has zero production callers; legacy `Parse` doesn't wrap errors in the new sentinels; README still shows the old Parse pattern. You built the engine but left the signage.
3. **Structural debt grew**: `ast.go` is +136 lines, `pool.go` +500 lines, `gosqlx.go` is now a 694-line candidate for the next god-file. 6 of 9 pre-v2.0 items are still open.
4. **CI health is operationally fragile**: two follow-up commits (timeout bump, staticcheck fix) after #517 are symptoms of an un-sharded race suite.

Net assessment: **PR #517 was additive, not transformative**. The "strangler fig" pattern needs actual strangling to follow through.

---

## 1. Critical Miss: Subquery Leaks in `PutExpression`

**Defect**: `pkg/sql/ast/pool.go` lines 1344-1455 — every expression type that embeds a `*SelectStatement` subquery sets `e.Subquery = nil` without releasing the statement first.

Affected paths:
- `InExpression` (line 1344-1358)
- `SubqueryExpression` (line 1360-1362)
- `ExistsExpression` (line 1404-1406)
- `AnyExpression` (line 1408-1415)
- `AllExpression` (line 1417-1424)
- `ArrayConstructorExpression.Subquery` (line 1446-1455)

Every `WHERE id IN (SELECT ...)`, `EXISTS (SELECT ...)`, `col = ANY(SELECT ...)` leaks the full inner SelectStatement including Columns, From, Where, Joins, Windows. Same defect class C1/C2 fixed, just at expression level. `pool_leak_test.go` doesn't cover these constructs — that's why round-1 tests didn't catch it.

**Fix**: call `releaseStatement(e.Subquery)` before `e.Subquery = nil` in all six sites. Add test: parse `SELECT x FROM t WHERE id IN (SELECT y FROM u WHERE z = 1)` 1000 times, assert stable heap.

**Severity**: CRITICAL — same production perf claim at stake.

---

## 2. Fix Quality — What Landed Well

| Item | Status | Notes |
|------|--------|-------|
| C1/C2 statement-level leaks | Solid | `releaseTableReference` helper factoring is right; no double-release risk |
| C3 metrics DoS | Solid | Lock-free atomic buckets; 4 allocs/op `GetStats` proven |
| C5 linter `ast.Walk` migration | Solid | Consistent pattern; L029 latent bug found & fixed in flight |
| C6 Children() coverage | Partial | Test has structural gap (see §3) |
| H6 errors immutability | Solid | All callers audited; return-value pattern universal |
| H7 structured parser errors | Solid | Zero `fmt.Errorf` remaining in parser |
| H8 config loader | Solid | Schema complete; walk-up safe; `**` glob properly implemented |
| H9 LSP type switch | Solid | 15 statement kinds; default fallback correct |
| H10 LSP real ranges | Solid | Semicolon fallback only hits rare DDL-no-Pos case |
| H11 keyword conflicts | Solid | `keywordsEquivalent` is the right semantic gate; resolutions preserve runtime |

Eight of eleven fixes are production-quality. Three have material issues addressed below.

---

## 3. Issues in the Fixes Themselves

### 3.1 `children_coverage_test.go` has a structural gap

`pkg/sql/ast/children_coverage_test.go:286-288` explicitly admits: "concrete-typed fields like `*CommonTableExpr` cannot accept a bare sentinel." But the AST references concrete pointer types throughout (`*WithClause`, `*TopClause`, `*MergeWhenClause`, `*OnConflict`, `*ConnectByClause`, `*SampleClause`). **The test only exercises interface-typed fields.** Plus `childrenCoverageAllowlist` (line 233) is declared but **never consulted** — it's misleading documentation.

**Fix**: (a) generate zero-value concrete mocks via reflection for each concrete pointer type, or (b) register a per-type fixture table. And either wire the allowlist into the test skip logic or delete it.

### 3.2 `releaseStatement` dispatch missing cases

`pkg/sql/ast/pool.go:541` — no case for statement types defined in `dml.go` (`*Select`, `*Insert`, `*Update`, `*Delete` — the legacy duplicates), nor for `*PragmaStatement` wrapper variants. If the parser ever stores these in `AST.Statements`, `ReleaseAST` silently drops without returning to pool. Low severity because they may never be pooled today, but the dispatch should mirror pool declarations.

### 3.3 `putExpressionImpl` allocates its work queue

`pool.go:1257` — `workQueue := make([]Expression, 0, 32)` runs **on every call**. In the hot path, that's one heap alloc per `PutExpression`, called transitively 10-100× per parse. Pool the work queue itself via `sync.Pool`, or use a fixed-size stack array with spillover.

### 3.4 `metrics.errorsMutex` is vestigial

`pkg/metrics/metrics.go:408` — retained "to serialize rare reset paths" but `reset()` uses atomic stores that already race-safe against concurrent increments. The mutex protects nothing. Delete.

### 3.5 `ErrorsByType` wire format change is undocumented breaking change

Round-1 fix changed map keys from `err.Error()` strings to `ErrorCode` strings. Grafana/dashboard users bound to the old keys are silently broken. Needs a CHANGELOG note and ideally a deprecation window with dual-emission.

---

## 4. "Two Models Colliding" — The Core Observation

Round 1 introduced new infrastructure that hasn't been adopted:

### 4.1 `dialect.Capabilities` has **zero production callers**

Grep confirms: `p.Capabilities()` / `p.DialectTyped()` / `p.IsSnowflake()` etc. used nowhere in parser production code. Meanwhile `p.dialect` string is referenced **88 times** (up from 72 at round 1) across 17 files. The old pattern is growing; the new one is read-only.

Parser now has three representations coexisting:
1. `p.dialect string` — actual storage, 88 reads
2. `keywords.DialectXxx` string constants — cast as `string(keywords.DialectOracle)` in 60+ places
3. `dialect.Dialect` typed — zero production usage

**Recommendation**: Stop doing big-bang migrations. Cache `p.dialectTyped dialect.Dialect` in the Parser struct populated by `WithDialect`. Migrate 3-5 pure-capability sites per release (QUALIFY, PREWHERE, ARRAY JOIN, ILIKE, BRACKET_QUOTING). Add a CI grep gate: new production code may not introduce `p.dialect ==`; must use `p.Is<Dialect>()` or `p.Capabilities()`. Without this gate, v2.0 arrives with more, not fewer, string comparisons.

### 4.2 Sentinel errors only work on new API

`gosqlx.ErrSyntax`, `ErrTokenize`, `ErrTimeout`, `ErrUnsupportedDialect` work for `ParseTree` / `ParseReader`. Legacy `Parse` / `ParseWithContext` / `ParseWithDialect` still return `fmt.Errorf("tokenization failed: %w", err)` without the sentinel. So:

```go
ast, err := gosqlx.Parse(sql)
if errors.Is(err, gosqlx.ErrSyntax) { ... }  // NEVER MATCHES
```

**Fix**: 4-line retrofit per legacy function, purely additive to the error chain. Unifies the story.

### 4.3 README & package doc still promote legacy

`README.md` lines 63-90: canonical example is still the old Parse + type-assertion pattern. Zero mentions of `ParseTree`, `Tree`, `WithDialect`, `ErrSyntax`, `FormatTree`. Package `doc.go` lists legacy functions as "primary entry points" — Tree isn't mentioned at all.

This is the **single largest DX leak remaining**. Round-1's criticism ("new users reach for Parse and type-assert") is still architecturally true on the surface.

### 4.4 No compat tests for new Tree API

`pkg/compatibility/api_stability_test.go` covers only legacy surface (ast.Node, pools, token types). The Tree API is unprotected. If someone refactors `ParseTree` to drop `ctx` or change `Option` to a struct, compat suite won't flag it.

---

## 5. Tree API Completeness Gaps

Round-1 added Tree; usability audit surfaces what's missing for real workflows:

1. **No typed walkers** — `WalkSelects(func(*ast.SelectStatement) bool)`, `WalkExpressions(...)`. Users still write `if stmt, ok := n.(*ast.SelectStatement); ok` dance. sqlparser-rs and vitess both ship typed visitors.
2. **No `Rewrite(pre, post)`** — closes parity gap with vitess.
3. **No `Tree.Clone()`** for copy-on-write experiments.
4. **No `Tree.Subqueries() []*Tree` / `Tree.CTEs()`** — common SQL analysis need.
5. **`Release()` is a documented no-op** — aspirational for future pooling, but creates a training hazard today.
6. **Tree carries full source string** — 1MB SQL doubles memory.

Fixing (1) and (2) takes the Tree from "viable" to "competitive."

---

## 6. `ParseReader` Pitfalls

### 6.1 No bounded read
`pkg/gosqlx/reader.go:67` — `io.ReadAll(r)` unconditionally. A 100MB SQL dump allocates 200MB (ReadAll + string conversion). Real-world exposures: migration files, data dumps, HTTP POST bodies. Add `WithMaxBytes(n)` + `ErrTooLarge` sentinel.

### 6.2 `ParseReaderMultiple` splitter is not dialect-aware
Correctly handles: single quotes, double-quoted identifiers, line comments, block comments.
Misses:
- PostgreSQL dollar-quoted strings (`$$...;...$$`) — will split on inner `;`, producing garbage
- MySQL/ClickHouse backtick identifiers containing `;`
- SQL Server bracketed identifiers containing `;`
- PostgreSQL E-string backslash escapes (`E'\''`)
- PostgreSQL nested block comments (`/* /* nested */ */`)

For a library advertising 8 dialects this is a shipping hole. Expose `SplitStatements(sql, dialect)` with dialect-aware handling.

---

## 7. Structural Debt — Getting Worse

Line counts after PR #517:

| File | Before | After | Δ |
|------|--------|-------|---|
| pkg/sql/ast/ast.go | 2327 | **2463** | +136 |
| pkg/sql/ast/pool.go | ~1500 | **2030** | +500 |
| pkg/sql/ast/sql.go | 1853 | 1853 | 0 |
| pkg/sql/tokenizer/tokenizer.go | 1842 | 1842 | 0 |
| pkg/sql/parser/parser.go | 1186 | 1195 | +9 |
| pkg/gosqlx/gosqlx.go | — | **694** | new |

Every core file exceeds the 400-line ceiling in the project's own `coding-style.md` by 3-6×. PR #517 **added** to ast.go and pool.go rather than splitting. `gosqlx.go` is trending toward god-file status.

**Natural split seams**:
- `ast.go` → `ast_statements.go` + `ast_expressions.go` + `ast_literals.go` + `ast_clauses.go`
- `pool.go` → `pool.go` (declarations) + `pool_statement_release.go` + `pool_expression_release.go`
- `sql.go` (String()/SQL() serializer) along the same node-category axis

Do this before v2.0 breaking changes — refactoring 4KLOC while also breaking APIs is a merge-conflict nightmare.

---

## 8. CI Health Symptoms

PR #517 follow-ups (e0f0992 `increase race detector timeout to 120s`, c01edeb `resolve staticcheck and race detector failures`) are patches on a bigger problem:

- `task test:race` runs the entire tree under `-race` with 3-5× overhead. No sharding.
- `pool_leak_test.go` uses `runtime.GC()` + heap measurement — will be flaky on shared runners. Gate behind `-short` or build tag.
- Task install not cached across jobs — each of 4 race/cbinding jobs reinstalls it.
- `perf-regression` still `continue-on-error: true` with 60-65% tolerance — decorative.

Expect another timeout bump within 1-2 sprints unless split into `test:race:fast` + `test:race:integration`.

---

## 9. Pre-v2.0 Punch-List Status

| # | Item | Round 1 | Round 2 |
|---|------|---------|---------|
| 1 | God-file splits | Open | **Worse** (+136L) |
| 2 | ConversionResult.PositionMapping removal | Open | Open (still `Deprecated`) |
| 3 | Merge/delete pkg/sql/token | Open | Open (still imported 18× ) |
| 4 | Move non-API packages to internal/ | Open | Open (no `internal/` at root) |
| 5 | DialectRegistry replacing keywords switch | Open | Open |
| 6 | gosqlx.Tree opaque wrapper | Open | **Done** |
| 7 | Functional options | Open | **Done** |
| 8 | Structured errors in parser | Open | **Done (H7)** |
| 9 | Logger interface injection | Open | Open (fmt.Println in 41 files) |

**Progress: 3 of 9 complete. 1 worse. 5 unchanged.**

---

## 10. Recommended v1.16 Sprint Plan

Ordered by leverage:

**Sprint A — "Fix the misses" (3-4 days)**
1. Subquery leak in `PutExpression` (§1) — critical
2. `Children()` coverage test gap (§3.1)
3. `releaseStatement` dispatch completeness (§3.2)
4. Retrofit legacy error wrappers with sentinels (§4.2)
5. Delete vestigial `metrics.errorsMutex` (§3.4)

**Sprint B — "Close the narrative" (3-4 days)**
6. README rewrite leading with `ParseTree` example
7. `doc.go` rewrite promoting Tree as primary entry
8. `docs/MIGRATION.md` Tree migration section + deprecation timeline
9. Add Tree API to `pkg/compatibility/api_stability_test.go`

**Sprint C — "Tree competitive" (1 week)**
10. Typed walkers (`WalkSelects`, `WalkExpressions`, generics-based)
11. `Tree.Rewrite(pre, post)` for transformation
12. `Tree.Clone()` for COW workflows
13. Dialect-aware `SplitStatements` (dollar-quoting, backticks, brackets)
14. `WithMaxBytes` + `ErrTooLarge` on ParseReader

**Sprint D — "Begin the strangling" (1 week)**
15. Cache `p.dialectTyped` field in Parser
16. Migrate 5 pure-capability sites to `p.Capabilities()` (QUALIFY, PREWHERE, ARRAY JOIN, ILIKE, BRACKET_QUOTING)
17. Add CI grep gate forbidding new `p.dialect ==` in production code
18. Allocate `workQueue` from pool in `putExpressionImpl` (§3.3)

**Sprint E — "Structural debt" (1-2 weeks)**
19. Split `ast.go` by node category
20. Split `pool.go` by responsibility
21. Shard `task test:race` into fast + integration
22. `tools/tools.go` for dev-tool pinning
23. Delete `examples/cmd/cmd` committed binary

Sprints A+B are 1 week. Add C and you have v1.16 with a credible adoption story. D+E belong in v1.17 or a dedicated structural PR.

---

## 11. Net Assessment

**Trend**: net-better on DX surface (Tree, options, sentinels), net-worse on structure (god files grew, 2-model coexistence).

**What PR #517 really was**: a correctness & API-expansion PR. It wasn't a refactor. Treating it as if it closed the architectural debt would be wrong — every structural punch-list item except three is still open, and the new code compounds some of it.

**The "adoption still stuck in round 1" observation** from the public API agent is the single most important line in this review. The Tree API exists but the library's outer layer (README, doc.go, compat tests) still treats legacy Parse as canonical. Until that flips, the adoption story hasn't moved.

**For HN launch / v1.15 release**: do Sprint A + B minimum. That's one week of work, and it turns "we added Tree" into "Tree is how you use this library."
