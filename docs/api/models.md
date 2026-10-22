# models package

Core data structures shared by every stage: tokens, spans and locations.

Import path: `github.com/ajitpratap0/GoSQLX/pkg/models` ([pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/models))

Part of the [GoSQLX API reference](../API_REFERENCE.md).

## Core Types

### `TokenType` (Type)
```go
type TokenType int
```

Constants: `TokenTypeSelect`, `TokenTypeFrom`, `TokenTypeWhere`, `TokenTypeIdentifier`, etc.

**Enhancements:**
- **120+ new SQL token types** with proper categorization
- `ModelType` field for O(1) int-based comparisons
- Helper methods: `IsKeyword()`, `IsOperator()`, `IsLiteral()`, `IsDMLKeyword()`, `IsDDLKeyword()`, etc.

### `TokenWithSpan`
```go
type TokenWithSpan struct {
    Type  TokenType
    Value string
    Span  Span
}
```

### `Span`
```go
type Span struct {
    Start Location
    End   Location
}
```

### `Location`
```go
type Location struct {
    Line   int // 1-based line number
    Column int // 1-based byte column within the line
}
```

`Column` counts bytes, not runes or UTF-16 units: a multi-byte character counts its bytes, and a tab is one column. A token's `Start` is the token itself, after any leading whitespace and comments. Convert to UTF-16 before sending positions to an LSP client.

## Functions

### `NewTokenWithSpan(tokenType TokenType, value string, span Span) TokenWithSpan`
Create token with span.

### `(t TokenType) String() string`
Get string representation.

**Enhancement:**
- Complete hash map implementation covering all 90+ token types (optimized for performance)
