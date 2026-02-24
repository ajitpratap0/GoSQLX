# Migration Guide: v1.7.0 to v1.8.0

**Last Updated**: February 2026

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
| `ConvertTokensForParser()` function | **Yes** | Removed — use `ParseFromModelTokens()` |

**If you only use the high-level `gosqlx` package or the CLI tool, v1.8.0 is fully backward compatible and no changes are needed.**

## Breaking Change: Token Type System (#215)

### Summary

The legacy string-based `token.Type` system has been completely removed. All token type comparisons now use `models.TokenType` (an integer type) for O(1) performance.

### What Was Removed

1. **`type Type string`** from `pkg/sql/token` — the string-based type definition
2. **`Type` (string) field** from `token.Token` struct — replaced by the renamed `ModelType` → `Type`
3. **All string-based token constants** — `token.SELECT`, `token.FROM`, `token.WHERE`, etc.
4. **`stringTypeToModelType` map** — the bridge between old and new type systems
5. **`normalizeTokens()` function** — no longer needed with unified types
6. **`ConvertTokensForParser()` function** — replaced by `ParseFromModelTokens()`

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
// BEFORE (v1.7.0) — string comparison
if tok.Type == token.SELECT {
    // handle SELECT
}

if tok.Type == "SELECT" {
    // also worked
}

// AFTER (v1.8.0) — integer comparison (faster)
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

v1.8.0 adds dialect-aware parsing. No migration needed — existing code defaults to PostgreSQL:

```go
// New (optional) — parse with explicit dialect
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

- [ ] Search your code for `token.SELECT`, `token.FROM`, etc. — replace with `models.TokenType*`
- [ ] Search for `tok.ModelType` — rename to `tok.Type`
- [ ] Search for `tok.Type == "..."` (string comparison) — replace with `tok.Type == models.TokenType*`
- [ ] Search for `ConvertTokensForParser` — replace with `ParseFromModelTokens`
- [ ] Search for `SetDebugLogger` — replace with `SetLogger`
- [ ] Search for `pkg/optimizer` imports — replace with `pkg/advisor`
- [ ] Run `go build ./...` to verify
- [ ] Run `go test -race ./...` to validate

## Getting Help

If you encounter issues migrating:
- Open an issue: https://github.com/ajitpratap0/GoSQLX/issues
- Join discussions: https://github.com/ajitpratap0/GoSQLX/discussions
