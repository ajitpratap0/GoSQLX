# SQL Tokenizer Package

## Overview

The `tokenizer` package provides a high-performance, zero-copy SQL lexical analyzer that converts SQL text into tokens. It supports multiple SQL dialects with full Unicode support and comprehensive operator recognition.

## Key Features

- **Zero-Copy Operation**: Works directly on input bytes without string allocation
- **Unicode Support**: Full UTF-8 support for international SQL (8+ languages tested)
- **Multi-Dialect**: PostgreSQL, MySQL, SQL Server, Oracle, SQLite operators and syntax
- **Object Pooling**: 60-80% memory reduction through instance reuse
- **Position Tracking**: Precise line/column information for error reporting
- **DOS Protection**: Token limits and input size validation
- **Thread-Safe**: All pool operations are race-free

## Performance

- **Throughput**: 8M tokens/second sustained
- **Latency**: Sub-microsecond tokenization for typical queries
- **Memory**: Minimal allocations with zero-copy design
- **Concurrency**: Validated race-free with 20,000+ concurrent operations

## Usage

### Basic Tokenization

```go
package main

import (
    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func main() {
    // Get tokenizer from pool
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)  // ALWAYS return to pool

    // Tokenize SQL
    sql := []byte("SELECT * FROM users WHERE active = true")
    tokens, err := tkz.Tokenize(sql)
    if err != nil {
        // Handle tokenization error
    }

    // Process tokens
    for _, tok := range tokens {
        fmt.Printf("%s at line %d, col %d\n",
            tok.Token.Value,
            tok.Start.Line,
            tok.Start.Column)
    }
}
```

### Batch Processing

```go
func ProcessMultipleQueries(queries []string) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    for _, query := range queries {
        tokens, err := tkz.Tokenize([]byte(query))
        if err != nil {
            continue
        }

        // Process tokens
        // ...

        tkz.Reset()  // Reset between uses
    }
}
```

### Concurrent Tokenization

```go
func ConcurrentTokenization(queries []string) {
    var wg sync.WaitGroup

    for _, query := range queries {
        wg.Add(1)
        go func(sql string) {
            defer wg.Done()

            // Each goroutine gets its own tokenizer
            tkz := tokenizer.GetTokenizer()
            defer tokenizer.PutTokenizer(tkz)

            tokens, _ := tkz.Tokenize([]byte(sql))
            // Process tokens...
        }(query)
    }

    wg.Wait()
}
```

## Token Types

### Keywords

```
SELECT, FROM, WHERE, JOIN, GROUP BY, ORDER BY, HAVING, LIMIT, OFFSET,
INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, WITH, UNION, EXCEPT, INTERSECT, etc.
```

### Identifiers

- **Standard**: `user_id`, `TableName`, `column123`
- **Quoted**: `"column name"` (SQL standard)
- **Backtick**: `` `column` `` (MySQL)
- **Bracket**: `[column]` (SQL Server)
- **Unicode**: `"名前"`, `"имя"`, `"الاسم"` (international)

### Literals

- **Numbers**: `42`, `3.14`, `1.5e10`, `0xFF`
- **Strings**: `'hello'`, `'it''s'` (escaped quotes)
- **Booleans**: `TRUE`, `FALSE`
- **NULL**: `NULL`

### Operators

- **Comparison**: `=`, `<>`, `!=`, `<`, `>`, `<=`, `>=`
- **Arithmetic**: `+`, `-`, `*`, `/`, `%`
- **Logical**: `AND`, `OR`, `NOT`
- **PostgreSQL**: `@>`, `<@`, `->`, `->>`, `#>`, `?`, `||`
- **Pattern**: `LIKE`, `ILIKE`, `SIMILAR TO`

## Dialect-Specific Features

### PostgreSQL

```sql
-- Array operators
SELECT * FROM users WHERE tags @> ARRAY['admin']

-- JSON operators
SELECT data->>'email' FROM users

-- String concatenation
SELECT first_name || ' ' || last_name FROM users
```

### MySQL

```sql
-- Backtick identifiers
SELECT `user_id` FROM `users`

-- Double pipe as OR
SELECT * FROM users WHERE status = 1 || status = 2
```

### SQL Server

```sql
-- Bracket identifiers
SELECT [User ID] FROM [User Table]

-- String concatenation with +
SELECT FirstName + ' ' + LastName FROM Users
```

## Architecture

### Core Files

- **tokenizer.go**: Main tokenizer logic
- **string_literal.go**: String parsing with escape sequence handling
- **unicode.go**: Unicode identifier and quote normalization
- **position.go**: Position tracking (line, column, byte offset)
- **pool.go**: Object pool management
- **buffer.go**: Internal buffer pool for performance
- **error.go**: Structured error types

### Tokenization Pipeline

```
Input bytes → Position tracking → Character scanning → Token recognition → Output tokens
```

## Error Handling

### Detailed Error Information

```go
tokens, err := tkz.Tokenize(sqlBytes)
if err != nil {
    if tokErr, ok := err.(*tokenizer.Error); ok {
        fmt.Printf("Error at line %d, column %d: %s\n",
            tokErr.Location.Line,
            tokErr.Location.Column,
            tokErr.Message)
    }
}
```

### Common Error Types

- **Unterminated String**: Missing closing quote
- **Invalid Number**: Malformed numeric literal
- **Invalid Character**: Unexpected character in input
- **Invalid Escape**: Unknown escape sequence in string

## DOS Protection

### Token Limit

```go
// Default: 100,000 tokens per query
// Prevents memory exhaustion from malicious input
```

### Input Size Validation

```go
// Configurable maximum input size
// Default: 10MB per query
```

## Unicode Support

### Supported Scripts

- **Latin**: English, Spanish, French, German, etc.
- **Cyrillic**: Russian, Ukrainian, Bulgarian, etc.
- **CJK**: Chinese, Japanese, Korean
- **Arabic**: Arabic, Persian, Urdu
- **Devanagari**: Hindi, Sanskrit
- **Greek**, **Hebrew**, **Thai**, and more

### Example

```go
sql := `
    SELECT "名前" AS name,
           "возраст" AS age,
           "البريد_الإلكتروني" AS email
    FROM "المستخدمون"
    WHERE "نشط" = true
`
tokens, _ := tkz.Tokenize([]byte(sql))
```

## Testing

Run tokenizer tests:

```bash
# All tests
go test -v ./pkg/sql/tokenizer/

# With race detection (MANDATORY during development)
go test -race ./pkg/sql/tokenizer/

# Specific features
go test -v -run TestTokenizer_Unicode ./pkg/sql/tokenizer/
go test -v -run TestTokenizer_PostgreSQL ./pkg/sql/tokenizer/

# Performance benchmarks
go test -bench=BenchmarkTokenizer -benchmem ./pkg/sql/tokenizer/

# Fuzz testing
go test -fuzz=FuzzTokenizer -fuzztime=30s ./pkg/sql/tokenizer/
```

## Best Practices

### 1. Always Use Object Pool

```go
// GOOD: Use pool
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)

// BAD: Direct instantiation
tkz := &Tokenizer{}  // Misses pool benefits
```

### 2. Reset Between Uses

```go
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)

for _, query := range queries {
    tokens, _ := tkz.Tokenize([]byte(query))
    // ... process tokens
    tkz.Reset()  // Reset state for next query
}
```

### 3. Use Byte Slices

```go
// GOOD: Zero-copy with byte slice
tokens, _ := tkz.Tokenize([]byte(sql))

// LESS EFFICIENT: String conversion
tokens, _ := tkz.Tokenize([]byte(sqlString))
```

## Common Pitfalls

### ❌ Forgetting to Return to Pool

```go
// BAD: Memory leak
tkz := tokenizer.GetTokenizer()
tokens, _ := tkz.Tokenize(sql)
// tkz never returned to pool
```

### ✅ Correct Pattern

```go
// GOOD: Automatic cleanup
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)
tokens, err := tkz.Tokenize(sql)
```

### ❌ Reusing Without Reset

```go
// BAD: State contamination
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)

tkz.Tokenize(sql1)  // First use
tkz.Tokenize(sql2)  // State from sql1 still present!
```

### ✅ Correct Pattern

```go
// GOOD: Reset between uses
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)

tkz.Tokenize(sql1)
tkz.Reset()  // Clear state
tkz.Tokenize(sql2)
```

## Performance Tips

### 1. Minimize Allocations

The tokenizer is designed for zero-copy operation. To maximize performance:
- Pass `[]byte` directly (avoid string conversions)
- Reuse tokenizer instances via the pool
- Process tokens immediately (avoid copying token slices)

### 2. Batch Processing

For multiple queries, reuse a single tokenizer:

```go
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)

for _, query := range queries {
    tokens, _ := tkz.Tokenize([]byte(query))
    // Process immediately
    tkz.Reset()
}
```

### 3. Concurrent Processing

Each goroutine should get its own tokenizer:

```go
// Each goroutine gets its own instance from pool
go func() {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    // ... tokenize and process
}()
```

## Related Packages

- **parser**: Consumes tokens to build AST
- **keywords**: Keyword recognition and categorization
- **models**: Token type definitions
- **metrics**: Performance monitoring integration

## Documentation

- [Main API Reference](../../../docs/API_REFERENCE.md)
- [Architecture Guide](../../../docs/ARCHITECTURE.md)
- [Unicode Support](../../../docs/UNICODE_SUPPORT.md)
- [Examples](../../../examples/)

## Version History

- **v1.5.0**: Enhanced Unicode support, DOS protection hardening
- **v1.4.0**: Production validation, 8M tokens/sec sustained
- **v1.3.0**: PostgreSQL operator support expanded
- **v1.2.0**: Multi-dialect operator recognition
- **v1.0.0**: Initial release with zero-copy design
