# GoSQLX Roadmap — Q2 2026

**Date:** 2026-03-29 | **Current Version:** v1.13.0 | **Stars:** 73 | **Status:** Production-Ready

> This spec is the output of a full-project audit using 5 parallel analytical personas:
> Performance/Internals, SQL Compatibility, API/DX, Competitive/Ecosystem, Community/Growth.
> Each roadmap item maps to findings from one or more personas.

---

## Executive Summary

GoSQLX is the **only actively maintained, pure-Go, multi-dialect SQL parsing SDK** — technically superior to all Go alternatives but dramatically under-discovered. The codebase is production-grade with excellent architecture, 1.38M ops/sec, 8 dialects, and a full-stack SDK (parser + formatter + linter + security + LSP + MCP + CLI + WASM). The gaps are:

1. **Discovery**: 73 stars; the dev.to article and MCP story have never been distributed to HN/r/golang
2. **Feature breadth**: Query fingerprinting, SQL transpilation, and live DB schema introspection are market gaps no Go library fills
3. **Linter depth**: 10 rules vs. 200+ in Bytebase; this is the enterprise adoption gap
4. **Integration bridges**: No ORM hooks, no OpenTelemetry, no GORM/sqlc integration examples
5. **Internal hardening**: C binding at 18% coverage, transform missing DML rewrites, advisor at 8 rules

---

## Roadmap Priorities

### P0 — Must Do (Immediate, Unblocking)

| ID | Title | Source | Rationale |
|----|-------|--------|-----------|
| P0-1 | HN + r/golang launch — submit dev.to article | Community | 595 unique cloners but only 113 viewers → top-of-funnel problem. Article exists, never distributed. Single highest-ROI action. |
| P0-2 | golangweekly.com newsletter submission | Community | ~50K Go devs, zero current GoSQLX presence. 15 minutes of effort. |
| P0-3 | OpenSSF Scorecard badge + assessment | Community | Security tooling (SQL injection scanner) without security posture badge is a trust gap for enterprise evaluators. |
| P0-4 | Fix Sentry issues #437 and #434 | Bugs | Two open Sentry-auto-generated bugs on the website: hydration error (replay) + pushState TypeError. These are visible to all users. |

### P1 — High Impact (Next 2–4 Weeks)

| ID | Title | Source | Rationale |
|----|-------|--------|-----------|
| P1-1 | Query Fingerprinting & Normalization API | Competitive | `pg_query_go` owns this use case today. Text-to-SQL/LLM SQL validation pipelines need `Fingerprint()` + `Normalize()` (replace literals with `?`). This is the #1 feature gap vs pg_query_go and positions GoSQLX for the exploding NL2SQL market. |
| P1-2 | Expand Linter to 30 Rules (from 10) | Competitive/DX | Bytebase has 200+; SQLFluff is popular primarily because of linting. 30 rules is the threshold for CI pipeline adoption. Target: naming conventions, dangerous operations (DROP without WHERE, DELETE without WHERE), missing indexes, SELECT *, N+1 patterns. |
| P1-3 | DML Transform API — UPDATE/DELETE rewrites | Internals | Transform package only handles SELECT. `UpdateSetClause`, `ReplaceSetClause`, `RemoveWhere` for DELETE, `AddWhere` for UPDATE/DELETE are needed to complete programmatic SQL generation. 30% of typical app SQL is DML mutations. |
| P1-4 | Harden C Binding to 90%+ coverage | Internals | 18% coverage blocks production deployment for Python/Ruby/Node consumers. Need stress tests, error path coverage, Python ctypes concurrency tests. |
| P1-5 | Live Database Schema Introspection | DX | `pkg/schema/loader/postgres.go` + `mysql.go` — introspect running DB for schema-aware validation. This is the #1 DX gap; users currently must manually maintain YAML schema. |

### P2 — Medium Impact (4–8 Weeks)

| ID | Title | Source | Rationale |
|----|-------|--------|-----------|
| P2-1 | SQL Transpilation API — `gosqlx.Transpile()` | Competitive | MySQL→PostgreSQL, PostgreSQL→Snowflake dialect conversion. Zero Go competitors. Python sqlglot (14k stars) owns this. Would be the biggest unique capability addition. Start with 2–3 high-demand pairs. |
| P2-2 | Oracle CONNECT BY / Hierarchical Queries | SQL Compat | Keywords reserved since v1.9.0. Oracle and MariaDB compatibility blocks. Planned for v1.14.0. AST structure designed. |
| P2-3 | OpenTelemetry Integration | DX | `pkg/integration/otel/tracer.go` — trace parse duration, statement count, dialect. Required for production observability in microservices. |
| P2-4 | GORM Hooks + database/sql Integration | DX | Pre-query validation middleware for the dominant Go ORM. Tutorial + package. Captures the GORM user base (~39k stars). |
| P2-5 | Advisor Rules Expansion (8 → 20 rules) | Internals | Add: implicit type conversions, N+1 detection, join order hints, unused aliases, OR-to-IN conversion, NOT IN with NULLs, missing indexes analysis. |
| P2-6 | "Who's Using GoSQLX" + Discussions | Community | Social proof section in README + pinned Discussion thread. Even 5 entries change how enterprise evaluators perceive the project. |
| P2-7 | ClickHouse SAMPLE Clause | SQL Compat | Marked TODO in tests. Completes ClickHouse dialect support. 3–5 days effort. |
| P2-8 | Formatter: Sequence DDL + SHOW/DESCRIBE | Internals | Missing render handlers for `CreateSequenceStatement`, `AlterSequenceStatement`, `DropSequenceStatement`, `ShowStatement`, `DescribeStatement`. Blocks round-trip formatting for these constructs. |
| P2-9 | SQL Server PIVOT/UNPIVOT | SQL Compat | Keywords reserved, no parsing. Needed for analytics-heavy SQL Server migration use cases. |

### P3 — Nice to Have (Backlog)

| ID | Title | Source | Rationale |
|----|-------|--------|-----------|
| P3-1 | Stored Procedures / Procedural Blocks | SQL Compat | 0% support. Very high enterprise demand but very high effort (dialect-specific PL/SQL, T-SQL, PL/pgSQL parsers). Deferred until core SQL coverage exceeds 90%. |
| P3-2 | CLI Watch Mode | DX | `gosqlx watch *.sql` — file system watcher for continuous validation in development. Low effort (fsnotify already in deps), nice ergonomics. |
| P3-3 | JSON Functions (SQL:2016) | SQL Compat | JSON_EXTRACT, JSON_TABLE, JSON_ARRAY_AGG. 20–50% support today. PostgreSQL JSON operators work; MySQL/SQL Server syntax varies significantly. |
| P3-4 | Streaming Parser | DX | Token-by-token progressive parsing for large files (10MB+). Low ROI — mitigated by LSP incremental sync and batch processing. High effort (significant parser refactoring). |
| P3-5 | SQL Server CROSS APPLY / OUTER APPLY | SQL Compat | Keywords reserved, no parsing. Needed for SQL Server lateral correlation. |
| P3-6 | Go Time Podcast Pitch | Community | "Building a production SQL parser in Go" — war stories about sync.Pool discipline and CGo tradeoffs. Medium effort, high-quality audience. |
| P3-7 | Pool Statistics/Monitoring API | Internals | Expose pool hit rates and memory savings metrics. Currently internal only. Nice for production observability. |

---

## Version Milestones

### v1.14.0 — "Hierarchical & Hardened" (2-3 weeks)
- Oracle CONNECT BY / START WITH / PRIOR / NOCYCLE (P2-2)
- MariaDB dialect fully integrated into playground + config (carry-forward)
- C binding hardened to 90%+ coverage (P1-4)
- ClickHouse SAMPLE clause (P2-7)
- Formatter: Sequence DDL + SHOW/DESCRIBE (P2-8)

### v1.15.0 — "Fingerprint & Lint" (3-4 weeks)
- Query Fingerprinting & Normalization API (P1-1)
- Linter expanded to 30 rules (P1-2)
- DML Transform API (P1-3)
- Advisor rules 8 → 20 (P2-5)

### v1.16.0 — "Integrate & Scale" (4-6 weeks)
- Live Database Schema Introspection (P1-5)
- OpenTelemetry Integration (P2-3)
- GORM Hooks + database/sql examples (P2-4)
- SQL Server PIVOT/UNPIVOT (P2-9)

### v2.0.0 — "Transpile" (6-10 weeks)
- SQL Transpilation API — `gosqlx.Transpile(sql, from, to)` (P2-1)
- Breaking: remove deprecated `parser.Parse()` shim, `ParseFromModelTokensWithPositions`, `ConversionResult.PositionMapping`
- Semantic validation layer (column resolution, type checking against schema)

---

## Competitive Moat Analysis

| Dimension | GoSQLX | Best Competitor | Gap |
|-----------|--------|-----------------|-----|
| Pure-Go multi-dialect | 8 dialects, zero CGo | pg_query_go (1 dialect, CGo) | GoSQLX leads |
| Formatter | ✅ | None | GoSQLX leads |
| Linter | 10 rules | Bytebase 200+ (different product) | GoSQLX gap — must expand |
| Security scanner | ✅ | None | GoSQLX leads |
| LSP | ✅ | None | GoSQLX leads |
| MCP server | ✅ | None | GoSQLX leads (first mover) |
| WASM playground | ✅ | None | GoSQLX leads |
| Query fingerprinting | ❌ | pg_query_go | Gap — P1 action |
| SQL transpilation | ❌ | sqlglot (Python) | Market gap — P2 action |
| ORM integration | ❌ | None | Gap — P2 action |
| Stars | 73 | ~1,578 (xwb1989, abandoned) | Perception gap, not quality gap |

---

## Success Metrics

| Metric | Current | 30-Day Target | 90-Day Target |
|--------|---------|---------------|---------------|
| GitHub Stars | 73 | 200+ | 500+ |
| pkg.go.dev importers | unknown | 50+ | 200+ |
| Linter rules | 10 | 30 | 50 |
| C binding coverage | 18% | 90% | 95%+ |
| Advisor rules | 8 | 20 | 30 |
| MCP tool count | 7 | 9 | 12 |

---

## Non-Goals (What We Are Not Building)

- **Query Builder** — Out of scope by design. sqlc, squirrel, and goqu fill this. GoSQLX is parse-first.
- **Query Execution** — GoSQLX parses; it does not run queries. Use database/sql for that.
- **Full ORM** — Not building a GORM competitor. Building an analysis/validation layer that integrates with ORMs.
- **Stored Procedure Runtime** — P3 at best. Parsing PL/SQL/T-SQL procedural blocks is dialect-specific and very high effort with limited incremental value for a parsing SDK.
