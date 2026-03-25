# I benchmarked every Go SQL parser in 2026 and built my own

> *A comparison of xwb1989/sqlparser, pganalyze/pg_query_go, TiDB's parser, and GoSQLX — with real benchmark numbers, trade-off analysis, and code. Disclosure: I'm the author of GoSQLX, so weight this comparison accordingly.*

---

## Why I needed a SQL parser

I was building a query analysis system in Go. The requirements were straightforward:

- Parse SQL from multiple databases: PostgreSQL, MySQL, SQLite, SQL Server
- Handle 1M+ queries per day without becoming a bottleneck
- Produce a structured AST I could walk programmatically
- No cgo — we deploy to environments where cross-compilation matters
- Actively maintained — I didn't want to maintain a fork

I expected to find a mature ecosystem. What I found was more fragmented than I expected.

Here's my experience evaluating each option, and how I ended up writing [GoSQLX](https://github.com/ajitpratap0/GoSQLX).

---

## The landscape: what actually exists

Before benchmarking anything, I catalogued every option.

### xwb1989/sqlparser (~1,580 stars)

The most-starred pure Go SQL parser. It's a port of Vitess's MySQL parser, which is itself a hand-modified yacc grammar. If you search "golang sql parser" today, this is what comes up first.

**The reality**: The last meaningful code commit was in 2018; the last push was in 2022 for a minor infrastructure change. It parses MySQL syntax only — no DDL support beyond basic CREATE TABLE, no CTEs, no window functions, no SET operations beyond UNION. Several forks exist (ClearBlade, others) but none cover the feature gaps.

For simple MySQL SELECT/INSERT/UPDATE/DELETE with no CTEs or window functions, it still works. For anything beyond that, you're on your own. The upstream Vitess sqlparser (which this was forked from) has continued to develop, so the feature gap grows with time.

### pingcap/parser → now tidb/pkg/parser (~1,443 stars on the old repo)

PingCAP built a MySQL-compatible parser in Go for TiDB. It was genuinely good — fully compatible with MySQL 8.0 syntax, goyacc-based, actively developed. The Bytebase team [lists it](https://www.bytebase.com/blog/top-open-source-sql-parsers/) as the most widely adopted MySQL parser in Go, and it has excellent coverage: CTEs, window functions, DDL, JSON operators.

**The problem**: The standalone `pingcap/parser` repo is deprecated. The parser was absorbed into the TiDB monorepo at `pingcap/tidb/pkg/parser` starting at v5.3.0. The parser package has its own `go.mod`, so the dependency footprint depends significantly on which import path and version you use — but in my experience pulling in the full monorepo added substantial dependency weight. If you import carefully via the parser sub-module, the footprint is manageable; if you pull top-level TiDB, you're importing a database engine.

If you're deploying TiDB anyway, the parser is excellent and battle-tested at scale. If you're not, the import path requires care.

### blastrain/vitess-sqlparser (~491 stars)

Another Vitess port, more complete than xwb1989's — it combines the Vitess parser with TiDB's DDL support to address gaps that xwb1989 leaves open (OFFSET, bulk INSERT). There's ongoing community usage and issues being filed in 2025.

**The problem**: Feature development appears stalled since 2020. It's MySQL-only, and actively maintained alternatives now exist. It's a reasonable option if you need a pure-Go MySQL parser today and can accept the maintenance risk — but I wanted something with a clear release history and ongoing development.

### pganalyze/pg_query_go (~826 stars)

This one is different. It's not a reimplementation — it's a CGo binding around libpg_query, which ships the actual PostgreSQL server's parser as a C library. If you need a parse tree that exactly matches what PostgreSQL produces, this is the most accurate option.

**The trade-offs are real**:

1. **CGo is required** — no cross-compilation without a C toolchain, no building for `GOOS=js`, no use in environments with `CGO_ENABLED=0`. *Caveat: [wasilibs/go-pgquery](https://github.com/wasilibs/go-pgquery) is a drop-in replacement that compiles libpg_query to WASM and runs it via wazero — no CGo, full cross-compilation support. The sqlc project migrated to it in early 2025. If cross-compilation is your blocker, evaluate this before ruling pg_query_go out.*
2. **First build takes 3+ minutes** — it compiles PostgreSQL source code. This happens once per clean environment.
3. **PostgreSQL only.** No MySQL, no SQLite, no SQL Server.
4. **Cgo call overhead per parse.** pg_query_go crosses the C↔Go boundary and deserializes a protobuf binary payload on every parse call. This adds cgo call cost and allocation overhead — not JSON (that was the v1/v2 behavior; v2+ uses protobuf), but still a real cost.

pg_query_go is actively maintained on v6 (January 2026), backed by the pganalyze team. It's a solid library for its exact use case, and for PostgreSQL-specific tooling it remains the most accurate option available.

### vitessio/vitess (~21k stars)

Vitess is a database clustering solution for MySQL that powers deployments at PlanetScale and YouTube scale. It contains a production-hardened SQL parser, but it's not designed to be imported as a standalone library. The top-level go.mod includes Kubernetes client libraries, gRPC infrastructure, and more — though Go's lazy module loading means you don't necessarily compile all of it. For teams who want a focused, minimal-dependency parser, the import tax is high.

### dolthub/go-mysql-server (~2.6k stars)

go-mysql-server is a full MySQL-compatible relational database engine in Go, built on a maintained fork of the Vitess sqlparser. It's worth knowing about for two use cases: as a MySQL test-double (standing in for MySQL in Go tests, which is its primary documented use case), or as an SQL execution layer over arbitrary data backends — Grafana adopted it for exactly this purpose. For pure AST analysis with no execution needed, importing the engine is more than you need. But "not just a parser" is a feature, not a bug, for certain workloads.

### The conclusion before I started coding

| Library | Stars | Last Active | Dialects | CGo? | Standalone? |
|---|---|---|---|---|---|
| xwb1989/sqlparser | ~1,580 | 2018 (push 2022) | MySQL | No | Yes |
| pingcap/parser | ~1,443 | Deprecated | MySQL | No | Via sub-module |
| blastrain/vitess-sqlparser | ~491 | Stalled | MySQL | No | Yes |
| pganalyze/pg_query_go | ~826 | Active | PostgreSQL | **Yes** | Yes |
| GoSQLX | 60 | Active (v1.13.0) | 8 dialects | No | Yes |

The available pure-Go options were either MySQL-only, require a large import footprint, or PostgreSQL-only with a CGo dependency. My specific requirement — multi-dialect support, no CGo, actively maintained as a standalone library — didn't have a clear answer. So I built one.

---

## Benchmark methodology

All benchmarks run on Apple Silicon (M-series ARM64) with `GOMAXPROCS=1` for single-threaded comparisons. Parallel benchmarks use `b.RunParallel`.

**Test queries:**

Simple SELECT:
```sql
SELECT id, name FROM users
```

Complex SELECT (JOIN + WHERE + GROUP BY + HAVING + ORDER BY + LIMIT):
```sql
SELECT u.id, u.name, COUNT(o.id) AS order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
WHERE u.active = true
GROUP BY u.id, u.name
HAVING COUNT(o.id) > 5
ORDER BY order_count DESC
LIMIT 10
```

**Important caveat**: pg_query_go benchmarks are taken from their repository's own `benchmark_test.go` on ARM64 darwin; GoSQLX numbers are from `pkg/sql/parser/bench_test.go` on the same machine. These are not head-to-head on identical harnesses — pg_query_go's `Parse()` returns a richer, more complete AST (it IS the PostgreSQL parser) while GoSQLX's ~85% SQL-99 coverage means it is doing less work per parse. Faster ≠ equally complete. I did not benchmark xwb1989 or TiDB's parser fresh for this post.

---

## The numbers

### Single-threaded throughput

| Operation | GoSQLX (ns/op) | pg_query_go (ns/op) |
|---|---|---|
| Simple SELECT | 712 | 4,186 |
| Simple SELECT (parallel) | ~180 | 1,320 |
| Complex SELECT | 2,660 | 14,572 |
| Complex SELECT (parallel) | ~700 | ~4,500 |

*pg_query_go numbers from their v6 benchmark_test.go, ARM64 darwin. GoSQLX from performance_baselines.json, Apple Silicon, Go 1.26.*

GoSQLX's sustained throughput across mixed workloads in my benchmarks: **1.38M ops/sec**.

The performance gap is structural. pg_query_go crosses the C↔Go cgo boundary and deserializes a protobuf payload for every parse call. That cgo overhead plus protobuf allocation adds up, and their v6 README benchmark numbers reflect it. For workloads where PostgreSQL parse accuracy is not required, a pure-Go parser avoids this overhead entirely.

### Memory allocations

GoSQLX uses **layered object pooling with `sync.Pool`** at every level of the pipeline:

```go
// 5 separate sync.Pool layers:
// 1. tokenizer instances        — pkg/sql/tokenizer/pool.go
// 2. internal byte buffers      — pkg/sql/tokenizer/buffer.go
// 3. token slices               — pkg/sql/token/pool.go
// 4. AST nodes (15+ node types) — pkg/sql/ast/pool.go
// 5. parser instances           — pkg/sql/parser/parser.go

tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)  // MANDATORY — returns to pool

ast, err := ast.NewAST()
defer ast.ReleaseAST(ast)
```

Under sustained high-throughput load with a warm pool, this significantly reduces per-parse allocation pressure. The `lineStarts` slice illustrates the approach:

```go
func (t *Tokenizer) Reset() {
    t.input = nil  // Clear reference, allow GC of input
    t.pos = NewPosition(1, 0)
    if cap(t.lineStarts) > 0 {
        t.lineStarts = t.lineStarts[:0]
        t.lineStarts = append(t.lineStarts, 0)
    }
    t.line = 0
    t.logger = nil
    if cap(t.Comments) > 0 {
        t.Comments = t.Comments[:0]
    }
}
```

Every pool return preserves slice capacity. Subsequent calls reuse allocated memory. Note: `sync.Pool` objects can be collected by the GC between cycles (Go 1.13+ has a two-cycle victim cache that helps significantly under sustained load). Pool hit rates depend heavily on workload — sustained high-throughput is the best case.

---

## How GoSQLX's parser works

Understanding the performance requires understanding the architecture.

### Recursive descent

xwb1989 and TiDB use **goyacc** — a Go port of yacc generating an LALR(1) parser. LALR parsers use generated state machine tables and shift-reduce operations. They're correct and well-understood, but the algorithm is fixed.

GoSQLX uses **hand-written recursive descent** with **one-token lookahead**. Each SQL construct maps to a Go function: `parseSelect()` calls `parseProjection()`, which calls `parseExpression()`, etc. Direct function calls that the Go compiler can inline and optimize per-construct.

The practical advantage isn't primarily speed — the compiler engineering literature is genuinely mixed on recursive descent vs. LALR for raw throughput. The real advantages are **extensibility** (adding a new SQL construct is one function, not a grammar file change + regeneration) and **error quality** (you control exactly what context you have when producing error messages). These are the same reasons Clang, GCC, Go's own parser, and Roslyn all use recursive descent.

```go
// The parse pipeline: raw bytes → tokens → AST
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)
tokens, err := tkz.Tokenize([]byte(sql))

// Parser dispatches on pre-classified integer token types for core SQL keywords
stmt, err := parser.ParseFromModelTokens(tokens, dialect)
```

Core SQL keywords (SELECT, FROM, WHERE, etc.) are pre-classified as integer token types during tokenization, enabling O(1) dispatch in the parser's main switch. Dialect-specific and context-dependent tokens are handled with additional string disambiguation — this is a common pattern in production parsers that need to handle reserved/non-reserved keyword ambiguity.

### Zero-copy tokenization

The tokenizer holds a `[]byte` reference to the input SQL and records tokens as offset spans into that buffer rather than copying bytes into new strings for each token. Identifiers and keywords are represented as `(start, end)` positions in the original input. String allocation happens for tokens that need escaping (e.g., quoted strings with escape sequences) via a pooled buffer.

```go
type Tokenizer struct {
    input []byte  // reference to original input — no copy
    pos   Position
    // ...
}
```

On `PutTokenizer`, `t.input = nil` releases the reference so the original SQL can be GC'd. The tokenizer itself returns to the pool.

---

## Feature comparison

### Multi-dialect support

| Feature | GoSQLX | xwb1989 | pg_query_go | TiDB parser |
|---|---|---|---|---|
| PostgreSQL | ✅ | ❌ | ✅ (native) | ❌ |
| MySQL | ✅ | ✅ | ❌ | ✅ |
| SQLite | ✅ | ❌ | ❌ | ❌ |
| SQL Server | ✅ | ❌ | ❌ | ❌ |
| Oracle | ✅ | ❌ | ❌ | ❌ |
| ClickHouse | ✅ | ❌ | ❌ | ❌ |

### SQL features

| Feature | GoSQLX | xwb1989 | pg_query_go | TiDB parser |
|---|---|---|---|---|
| CTEs (WITH) | ✅ | ❌ | ✅ | ✅ |
| Recursive CTEs | ✅ | ❌ | ✅ | ✅ |
| Window functions | ✅ | ❌ | ✅ | ✅ |
| MERGE statement | ✅ | ❌ | ✅ | ❌ |
| SET operations (UNION/INTERSECT/EXCEPT) | ✅ | UNION only | ✅ | ✅ |
| All JOIN types | ✅ | Partial | ✅ | ✅ |
| JSON operators (->, ->>) | ✅ | ❌ | ✅ | ❌ |
| DDL (CREATE/ALTER/DROP) | ✅ | Partial | ✅ | ✅ |
| SQL-99 compliance (approx.) | ~85% | ~40% | ~95%+ | ~90% |

pg_query_go is the accuracy leader for PostgreSQL — it uses the actual PostgreSQL parser. For PostgreSQL-only workloads where parse accuracy is the primary concern, that's a meaningful advantage.

GoSQLX's ~85% SQL-99 compliance figure is measured against a self-written test suite of 700+ cases — not an external conformance corpus. Take it as directional. Stored procedures, some advanced DDL, and dialect-specific edge cases are not yet fully covered.

### The toolkit

Beyond parsing, GoSQLX ships a SQL development toolkit in a single Go module:

**Linter (10 built-in rules):** L001-L010 covering trailing whitespace, mixed indentation, blank lines, indentation depth, line length, column alignment, keyword case (auto-fix), comma placement, aliasing consistency, redundant whitespace.

**Security scanner:** Detects SQL injection patterns, tautologies, UNION-based injection, comment-based injection. Classifies by severity (CRITICAL / HIGH / MEDIUM / LOW).

**Formatter:** Configurable indentation, keyword casing, comma placement.

**LSP server:** Language Server Protocol with semantic token highlighting, real-time diagnostics, hover documentation. Works with any LSP-compatible editor.

**VS Code extension:** Published on the marketplace.

**WASM playground:** [gosqlx.dev/playground](https://gosqlx.dev/playground) — parse, format, lint, and analyze SQL in the browser without a backend.

**MCP server:** Model Context Protocol integration for AI/LLM workflows.

**CLI:**
```bash
gosqlx validate "SELECT * FROM users"
gosqlx format -i query.sql
gosqlx lint query.sql
gosqlx analyze "SELECT COUNT(*) FROM orders GROUP BY status"
gosqlx lsp
```

These are features that the other parsers don't ship — though to be clear, for someone who just needs an AST, these are extras, not the core value proposition.

---

## When to use each

**Use pg_query_go if:**
- You're PostgreSQL-only and need 100% parse accuracy (schema migrations, query planners, anything that must handle every PostgreSQL edge case)
- You can accept CGo or are willing to use [wasilibs/go-pgquery](https://github.com/wasilibs/go-pgquery) as a drop-in no-CGo alternative
- Parse accuracy > parse throughput for your use case

**Use xwb1989/sqlparser if:**
- You need a quick MySQL parser for simple DML (SELECT/INSERT/UPDATE/DELETE) right now
- Your queries don't use CTEs, window functions, or DDL beyond basic CREATE TABLE
- You understand it's unmaintained and are prepared to fork if needed

**Use TiDB's parser (via tidb/pkg/parser) if:**
- You need high MySQL/TiDB compatibility with excellent SQL coverage
- You can work with the monorepo import path (use the parser sub-module's own go.mod to minimize footprint)
- You're already in the TiDB ecosystem

**Use GoSQLX if:**
- You need multi-dialect support (PostgreSQL + MySQL in the same codebase, or SQL Server, Oracle, SQLite, ClickHouse)
- You want zero CGo and pure-Go cross-compilation
- You want the extended toolkit: linter, formatter, security scanner, LSP, WASM, MCP
- You're validating AI-generated SQL in an LLM pipeline
- You can accept "actively developed but not yet battle-hardened across thousands of codebases"

---

## GoSQLX's honest limitations

Before you adopt it:

1. **~85% SQL-99 compliance.** The 700+ test cases are self-written, not validated against an external conformance suite. Stored procedures, some advanced DDL, and dialect-specific edge cases have gaps. If you hit the 15%, the parser will return an error — not a partial AST.

2. **PostgreSQL parse accuracy.** pg_query_go IS the PostgreSQL parser. GoSQLX's PostgreSQL dialect is solid for DML but for complex DDL introspection or tooling that must match exactly what PostgreSQL accepts, pg_query_go wins.

3. **60 GitHub stars.** The social proof problem is real. This library has not been vetted by thousands of production codebases. v1.13.0 has a 700+ test suite and passes the race detector, but that is different from years of production exposure.

4. **New codebase.** The production-ready declaration dates to v1.6.0. That's recent. There is no public list of production deployments. If that matters to your evaluation, it should.

---

## Running the benchmarks yourself

```bash
# GoSQLX
git clone https://github.com/ajitpratap0/GoSQLX
cd GoSQLX
go test -bench=BenchmarkParserSimpleSelect -benchmem ./pkg/sql/parser/
go test -bench=BenchmarkParserComplexSelect -benchmem ./pkg/sql/parser/
go test -bench=BenchmarkParserSustainedLoad -benchmem ./pkg/sql/parser/

# pg_query_go (requires CGo + C toolchain)
git clone https://github.com/pganalyze/pg_query_go
cd pg_query_go
go test -bench=BenchmarkParseSelect1 -benchmem .
go test -bench=BenchmarkParseSelect2 -benchmem .
```

---

## The install is one line

```bash
go get github.com/ajitpratap0/GoSQLX
```

No CGo. No build flags. No vendored C libraries.

```go
import "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"

// High-level API — no pool management required
ast, err := gosqlx.Parse("SELECT * FROM users WHERE active = true")
if err != nil {
    log.Fatal(err)
}

// With dialect
result, err := gosqlx.ParseWithDialect(sql, "postgresql")

// Validate
if err := gosqlx.Validate(sql); err != nil {
    fmt.Println("Invalid SQL:", err)
}

// Format
formatted, err := gosqlx.Format(sql)

// Lint
violations, err := gosqlx.Lint(sql)
for _, v := range violations {
    fmt.Printf("[%s] %s at line %d\n", v.Rule, v.Message, v.Line)
}

// Low-level API — explicit pool management for maximum performance
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)
tokens, err := tkz.Tokenize([]byte(sql))
// ...
```

---

## What I learned writing a SQL parser

**Recursive descent is underrated for SQL.** Not necessarily for raw throughput (the literature is mixed on that), but for maintainability and error quality. Adding a new SQL construct is one function. Error messages can use full parse context. GCC, Clang, and Go's own parser all use recursive descent for the same reasons.

**sync.Pool is a meaningful win for parsers under sustained load.** Pooling tokenizers, byte buffers, token slices, AST nodes, and parser instances significantly reduces per-parse allocation pressure. The gains are real under high-throughput sustained workloads; GC behavior limits this under bursty or low-throughput conditions.

**The ecosystem is more fragmented than I expected.** The actively maintained options — pg_query_go, TiDB's parser, Vitess — are all excellent at their specific use cases. What's missing is a maintained pure-Go parser that handles multiple dialects without CGo. Whether GoSQLX fills that gap adequately is something only production usage will determine.

---

## Links

- [GoSQLX on GitHub](https://github.com/ajitpratap0/GoSQLX)
- [Interactive WASM playground](https://gosqlx.dev/playground)
- [VS Code extension](https://marketplace.visualstudio.com/items?itemName=ajitpratap0.gosqlx)
- [Documentation](https://gosqlx.dev/docs/getting-started)
- [pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX)

Issues, feedback, and contributions welcome. If GoSQLX is missing a SQL feature you need, [open an issue](https://github.com/ajitpratap0/GoSQLX/issues).

---

*Benchmark methodology: pg_query_go numbers from their v6 benchmark_test.go (ARM64 darwin). GoSQLX numbers from performance_baselines.json (Apple Silicon, Go 1.26). All ns/op figures are single-threaded unless marked parallel. Running on your hardware will produce different absolute numbers. pg_query_go parses a richer AST than GoSQLX — faster is not the same as equally complete.*
