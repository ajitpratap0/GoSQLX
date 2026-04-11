# Migration Guide

## v1.13.0 → v1.14.0 (2026-04-12)

**Drop-in upgrade** — no breaking API changes. Anything that compiled against v1.13.0 will still compile and run identically against v1.14.0.

### Why upgrade

v1.14.0 is the largest dialect-coverage release in the project's history. Headline reasons to upgrade:

- **Dialect-aware formatting** — `transform.FormatSQLWithDialect()` renders SQL in the target dialect's row-limiting syntax (TOP for SQL Server, FETCH FIRST for Oracle, LIMIT everywhere else). Closes #479.
- **Snowflake at 100%** of the QA corpus (87/87) — MATCH_RECOGNIZE, @stage, SAMPLE, QUALIFY, VARIANT paths, time-travel, MINUS, LATERAL FLATTEN, TRY_CAST, IGNORE/RESPECT NULLS, LIKE ANY/ALL, CREATE STAGE/STREAM/TASK/PIPE stubs
- **ClickHouse dialect significantly expanded** (69/83 of the QA corpus, up from 53% in v1.13.0) — nested column types, parametric aggregates, bare-bracket arrays, ORDER BY WITH FILL, CODEC, WITH TOTALS, LIMIT BY, ANY/ALL JOIN, SETTINGS/TTL, INSERT FORMAT, `table`/`partition` as identifiers (#480). Known gaps tracked for v1.15: ARRAY JOIN, named windows, scalar CTE subqueries, materialized views
- **MariaDB dialect** — SEQUENCE DDL, temporal tables, CONNECT BY
- **Live schema introspection** — `gosqlx.LoadSchema()` queries Postgres, MySQL, and SQLite at runtime
- **SQL transpilation** — `gosqlx.Transpile()` converts between MySQL, PostgreSQL, and SQLite
- **30 linter rules** (up from 10) covering safety, performance, and naming
- **CVE-2026-39883** (OpenTelemetry SDK) fixed

### New APIs to adopt

#### Dialect-aware formatting

```go
import (
    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
    "github.com/ajitpratap0/GoSQLX/pkg/transform"
)

tree, _ := gosqlx.ParseWithDialect("SELECT * FROM users u", keywords.DialectPostgreSQL)
stmt := tree.Statements[0]
transform.Apply(stmt, transform.SetLimit(100))

// Dialect-specific output
sqlserver := transform.FormatSQLWithDialect(stmt, keywords.DialectSQLServer)
// -> SELECT TOP 100 * FROM users u

oracle := transform.FormatSQLWithDialect(stmt, keywords.DialectOracle)
// -> SELECT * FROM users u FETCH FIRST 100 ROWS ONLY

postgres := transform.FormatSQLWithDialect(stmt, keywords.DialectPostgreSQL)
// -> SELECT * FROM users u LIMIT 100
```

`transform.FormatSQL(stmt)` (generic, no dialect) continues to work unchanged.

#### SQL transpilation

```go
import (
    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

result, err := gosqlx.Transpile(
    "CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY)",
    keywords.DialectMySQL,
    keywords.DialectPostgreSQL,
)
// result: "CREATE TABLE t (id SERIAL PRIMARY KEY)"
```

Or from the CLI:

```bash
gosqlx transpile --from postgresql --to sqlite "SELECT * FROM users WHERE id = ANY(ARRAY[1,2,3])"
```

#### Live schema introspection

```go
import (
    "context"
    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
    "github.com/ajitpratap0/GoSQLX/pkg/schema/postgres"
)

loader, _ := postgres.New("postgres://user:pw@host/db")
defer loader.Close()

schema, _ := gosqlx.LoadSchema(context.Background(), loader)
for _, table := range schema.Tables {
    fmt.Printf("%s.%s (%d columns)\n", table.Schema, table.Name, len(table.Columns))
}
```

Also available: `pkg/schema/mysql` and `pkg/schema/sqlite`.

#### Query fingerprinting

```go
import "github.com/ajitpratap0/GoSQLX/pkg/fingerprint"

norm := fingerprint.Normalize("SELECT * FROM users WHERE id = 123")
// norm: "SELECT * FROM users WHERE id = ?"

hash := fingerprint.Fingerprint("SELECT * FROM users WHERE id = 123")
// hash: deterministic SHA-256 of the normalized form
```

Use for query deduplication, caching, or aggregating metrics by query shape.

### New CLI subcommands

```bash
gosqlx transpile --from <dialect> --to <dialect> "<sql>"   # Cross-dialect conversion
gosqlx optimize query.sql                                  # Run OPT-001 through OPT-020 advisor
gosqlx stats                                               # Object pool utilization
gosqlx watch queries/*.sql                                 # Continuous validation on file change
gosqlx action --fail-on warn queries/                      # GitHub Actions integration
```

### Behavioral change worth noting

**SQL Server TOP clauses now render.** If you were parsing `SELECT TOP 10 * FROM users` and round-tripping through `formatter.FormatStatement()` (or `transform.FormatSQL()`), the `TOP 10` was being silently dropped from the output. This was a bug. In v1.14.0, parsed `TopClause` values correctly render.

If your code relied on the broken behavior (unlikely — it would have produced queries that returned the wrong row count), you'll now see `TOP N` in formatted output. For dialect-specific control, use `FormatSQLWithDialect()` and it will normalize based on the target.

### Deprecations (carried over from v1.13.0 — no new deprecations)

- `parser.Parse([]token.Token)` — use `ParseFromModelTokens` instead
- `ParseFromModelTokensWithPositions` — consolidated into `ParseFromModelTokens`
- `ConversionResult.PositionMapping` — always nil, will be removed in v2

### Security

- **CVE-2026-39883** (HIGH severity, `go.opentelemetry.io/otel/sdk`): fixed by upgrading to v1.43.0. No action required for consumers — `go get github.com/ajitpratap0/GoSQLX@v1.14.0 && go mod tidy` picks up the fix transitively.

### Companion release versions

| Component | v1.13.0 | v1.14.0 |
|-----------|---------|---------|
| Library (`github.com/ajitpratap0/GoSQLX`) | 1.13.0 | **1.14.0** |
| CLI (`cmd/gosqlx`) | 1.13.0 | **1.14.0** |
| MCP server (`cmd/gosqlx-mcp`) | 1.13.0 | **1.14.0** |
| VS Code extension (`ajitpratap0.gosqlx`) | 1.13.0 | **1.14.0** |
| OpenTelemetry integration (`integrations/opentelemetry`) | v1.13.0 | **v1.14.0** |
| GORM integration (`integrations/gorm`) | v1.13.0 | **v1.14.0** |
| Python bindings (`pygosqlx`) | 0.1.0 (alpha) | **0.2.0 (alpha)** — independent semver track |

---

## v1.9.x → v1.10.0 (2026-03-13)

**Go version requirement changed**: Go 1.23+ is now required (was 1.21+). This is due to the `mark3labs/mcp-go` dependency used by the new MCP server. If you only use the parsing SDK (not the MCP server), Go 1.21+ still works, but `go.mod` declares 1.23.

No breaking API changes. Drop-in upgrade for existing code.

### New: MCP Server
- `pkg/mcp/` - MCP server package with 7 SQL tools
- `cmd/gosqlx-mcp/` - Standalone MCP server binary
- See `docs/MCP_GUIDE.md` for usage

---

## v1.8.0 → v1.9.0 (2026-02-28)

No breaking changes. No API changes. Drop-in upgrade.

### Behavioral changes to be aware of

**`lint` exit codes** (CLI-7):
Previously: exits 0 unless errors present or `--fail-on-warn` set
Now: exits 1 whenever any violation (error, warning, or info) is found
Impact: CI pipelines using `gosqlx lint` as a gate will now correctly fail on warnings

**`E1009` for unterminated block comments** (ERR-1):
Previously: unterminated `/* ... */` emitted `E1002` (generic string error code)
Now: emits `E1009 ErrCodeUnterminatedBlockComment`
Impact: code catching specific error codes for `/*` handling should update to `E1009`

---

## v1.7.0 → v1.8.0

**Last Updated**: 2026-02-24

This guide covers breaking changes in GoSQLX v1.8.0 and how to update your code. The primary breaking change is the token type system overhaul (#215) completed across PRs #252, #254, #255, #257, #258, #281, #267, #282, and #283.

## Who Is Affected?

| Usage Pattern | Breaking? | Action Required |
|--------------|-----------|-----------------|
| `gosqlx.Parse()`, `gosqlx.Validate()`, `gosqlx.Format()` | No | None |
| `gosqlx.ParseWithTimeout()`, `gosqlx.ParseBytes()` | No | None |
| CLI tool (`gosqlx validate`, `gosqlx format`, etc.) | No | None |
| `pkg/sql/parser` with `parser.Parse()` | No | None |
| Direct `token.Token` struct field access | **Yes** | See below |
| String-based token constants (`token.SELECT`, etc.) | **Yes** | See below |
| `token.Token.ModelType` field | **Yes** | Renamed to `Type` |
| `ConvertTokensForParser()` function | **Yes** | Removed - use `ParseFromModelTokens()` |

**If you only use the high-level `gosqlx` package or the CLI tool, v1.8.0 is fully backward compatible and no changes are needed.**

## Breaking Change: Token Type System (#215)

### Summary

The legacy string-based `token.Type` system has been completely removed. All token type comparisons now use `models.TokenType` (an integer type) for O(1) performance.

### What Was Removed

1. **`type Type string`** from `pkg/sql/token` - the string-based type definition
2. **`Type` (string) field** from `token.Token` struct - replaced by the renamed `ModelType` → `Type`
3. **All string-based token constants** - `token.SELECT`, `token.FROM`, `token.WHERE`, etc.
4. **`stringTypeToModelType` map** - the bridge between old and new type systems
5. **`normalizeTokens()` function** - no longer needed with unified types
6. **`ConvertTokensForParser()` function** - replaced by `ParseFromModelTokens()`

### Migration Steps

#### Step 1: Update Token Creation

```go
// BEFORE (v1.7.0)
import "github.com/ajitpratap0/GoSQLX/pkg/sql/token"

tok := token.Token{
    Type:      token.SELECT,              // string-based
    ModelType: models.TokenTypeSelect,    // int-based (was secondary)
    Literal:   "SELECT",
}

// AFTER (v1.8.0)
import "github.com/ajitpratap0/GoSQLX/pkg/sql/token"
import "github.com/ajitpratap0/GoSQLX/pkg/models"

tok := token.Token{
    Type:    models.TokenTypeSelect,      // int-based (now primary)
    Literal: "SELECT",
}
```

#### Step 2: Update Token Type Comparisons

```go
// BEFORE (v1.7.0) - string comparison
if tok.Type == token.SELECT {
    // handle SELECT
}

if tok.Type == "SELECT" {
    // also worked
}

// AFTER (v1.8.0) - integer comparison (faster)
if tok.Type == models.TokenTypeSelect {
    // handle SELECT
}
```

#### Step 3: Replace String Constants with models.TokenType

| Old (string) | New (int) |
|-------------|-----------|
| `token.SELECT` | `models.TokenTypeSelect` |
| `token.FROM` | `models.TokenTypeFrom` |
| `token.WHERE` | `models.TokenTypeWhere` |
| `token.INSERT` | `models.TokenTypeInsert` |
| `token.UPDATE` | `models.TokenTypeUpdate` |
| `token.DELETE` | `models.TokenTypeDelete` |
| `token.CREATE` | `models.TokenTypeCreate` |
| `token.ALTER` | `models.TokenTypeAlter` |
| `token.DROP` | `models.TokenTypeDrop` |
| `token.JOIN` | `models.TokenTypeJoin` |
| `token.ON` | `models.TokenTypeOn` |
| `token.AND` | `models.TokenTypeAnd` |
| `token.OR` | `models.TokenTypeOr` |
| `token.NOT` | `models.TokenTypeNot` |
| `token.NULL` | `models.TokenTypeNull` |
| `token.TRUE` | `models.TokenTypeTrue` |
| `token.FALSE` | `models.TokenTypeFalse` |
| `token.AS` | `models.TokenTypeAs` |
| `token.IN` | `models.TokenTypeIn` |
| `token.LIKE` | `models.TokenTypeLike` |
| `token.BETWEEN` | `models.TokenTypeBetween` |
| `token.EXISTS` | `models.TokenTypeExists` |
| `token.CASE` | `models.TokenTypeCase` |
| `token.WHEN` | `models.TokenTypeWhen` |
| `token.THEN` | `models.TokenTypeThen` |
| `token.ELSE` | `models.TokenTypeElse` |
| `token.END` | `models.TokenTypeEnd` |
| `token.ORDER` | `models.TokenTypeOrder` |
| `token.GROUP` | `models.TokenTypeGroup` |
| `token.HAVING` | `models.TokenTypeHaving` |
| `token.LIMIT` | `models.TokenTypeLimit` |
| `token.OFFSET` | `models.TokenTypeOffset` |
| `token.UNION` | `models.TokenTypeUnion` |
| `token.EXCEPT` | `models.TokenTypeExcept` |
| `token.INTERSECT` | `models.TokenTypeIntersect` |

For a complete mapping, see the `models.TokenType` constants in `pkg/models/token.go`.

#### Step 4: Replace ModelType with Type

```go
// BEFORE (v1.7.0)
tokenType := tok.ModelType  // was the int-based secondary field

// AFTER (v1.8.0)
tokenType := tok.Type       // ModelType renamed to Type
```

#### Step 5: Replace ConvertTokensForParser

```go
// BEFORE (v1.7.0)
tokens, _ := tkz.Tokenize([]byte(sql))
converted, _ := parser.ConvertTokensForParser(tokens)
ast, _ := p.Parse(converted)

// AFTER (v1.8.0)
tokens, _ := tkz.Tokenize([]byte(sql))
ast, _ := p.ParseFromModelTokens(tokens)
```

### Using TokenType.String() for Display

The `TokenType.String()` method provides human-readable names for all token types:

```go
tok := token.Token{Type: models.TokenTypeSelect, Literal: "SELECT"}
fmt.Println(tok.Type.String()) // "SELECT"
```

## Other Changes (Non-Breaking)

### New Dialect API

v1.8.0 adds dialect-aware parsing. No migration needed - existing code defaults to PostgreSQL:

```go
// New (optional) - parse with explicit dialect
ast, err := parser.ParseWithDialect(sql, "mysql")
err = parser.ValidateWithDialect(sql, "mysql")
```

### New Transform API

The new `pkg/transform/` package is purely additive:

```go
import "github.com/ajitpratap0/GoSQLX/pkg/transform"

stmt, _ := transform.ParseSQL("SELECT * FROM orders")
transform.AddWhere(stmt, "tenant_id = 42")
```

### New ParseWithRecovery API

For multi-error parsing (useful for IDE integration):

```go
ast, errors := gosqlx.ParseWithRecovery(sql)
// ast may be partial, errors contains all parse errors
```

### Renamed Packages

| Old | New | PR |
|-----|-----|-----|
| `pkg/optimizer/` | `pkg/advisor/` | #261 |

### slog Replaces DebugLogger

```go
// BEFORE (v1.7.0)
tkz.SetDebugLogger(myLogger)

// AFTER (v1.8.0)
import "log/slog"
tkz.SetLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
```

## Performance Impact

The token type overhaul delivers ~50% faster parsing with no API changes needed for high-level users:

| Benchmark | v1.7.0 | v1.8.0 | Improvement |
|-----------|--------|--------|-------------|
| SimpleSelect 10 cols | 1542 ns/op | 783 ns/op | **49% faster** |
| SimpleSelect 100 cols | 9736 ns/op | 4843 ns/op | **50% faster** |
| SimpleSelect 1000 cols | 83612 ns/op | 39487 ns/op | **53% faster** |
| SingleJoin | 1425 ns/op | 621 ns/op | **56% faster** |
| SimpleWhere | 736 ns/op | 373 ns/op | **49% faster** |

## License Change

GoSQLX was relicensed from AGPL-3.0 to **Apache License 2.0** in this release cycle (PR #227). This is a more permissive license that allows commercial use without copyleft obligations.

## Quick Checklist

- [ ] Search your code for `token.SELECT`, `token.FROM`, etc. - replace with `models.TokenType*`
- [ ] Search for `tok.ModelType` - rename to `tok.Type`
- [ ] Search for `tok.Type == "..."` (string comparison) - replace with `tok.Type == models.TokenType*`
- [ ] Search for `ConvertTokensForParser` - replace with `ParseFromModelTokens`
- [ ] Search for `SetDebugLogger` - replace with `SetLogger`
- [ ] Search for `pkg/optimizer` imports - replace with `pkg/advisor`
- [ ] Run `go build ./...` to verify
- [ ] Run `go test -race ./...` to validate

## Getting Help

If you encounter issues migrating:
- Open an issue: https://github.com/ajitpratap0/GoSQLX/issues
- Join discussions: https://github.com/ajitpratap0/GoSQLX/discussions
