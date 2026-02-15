# SQL Parser Package

## Overview

The `parser` package provides a production-ready, recursive descent SQL parser that converts tokenized SQL into an Abstract Syntax Tree (AST). It supports comprehensive SQL features across multiple dialects with ~80-85% SQL-99 compliance.

## Key Features

- **DML Operations**: SELECT, INSERT, UPDATE, DELETE with full clause support
- **DDL Operations**: CREATE TABLE, ALTER TABLE, DROP TABLE, CREATE INDEX
- **Advanced SQL**: CTEs (WITH), set operations (UNION/EXCEPT/INTERSECT), window functions
- **JOINs**: All types (INNER, LEFT, RIGHT, FULL, CROSS, NATURAL) with proper left-associative parsing
- **Window Functions**: PARTITION BY, ORDER BY, frame clauses (ROWS/RANGE)
- **SQL-99 F851**: NULLS FIRST/LAST support in ORDER BY clauses
- **Object Pooling**: Memory-efficient parser instance reuse
- **Context Support**: Cancellation and timeout handling

## Usage

### Basic Parsing

```go
package main

import (
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

func main() {
    // Create parser from pool
    p := parser.NewParser()
    defer p.Release()  // ALWAYS release back to pool

    // Parse tokens into AST
    tokens := []token.Token{ /* your tokens */ }
    astNode, err := p.Parse(tokens)
    if err != nil {
        // Handle parsing error
    }

    // Work with AST
    // ...
}
```

### Context-Aware Parsing

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

p := parser.NewParser()
defer p.Release()

astNode, err := p.ParseContext(ctx, tokens)
if err != nil {
    if ctx.Err() != nil {
        // Handle timeout/cancellation
    }
    // Handle parse error
}
```

## Architecture

### Core Components

- **parser.go** (1,628 lines): Main parser with all parsing logic
- **alter.go** (368 lines): DDL ALTER statement parsing
- **token_conversion.go** (~200 lines): Internal token conversion (unexported)

### Parsing Flow

```
Tokens → Parse() → parseStatement() → Specific statement parser → AST Node
```

### Recursion Protection

Maximum recursion depth: **100 levels**

Protects against:
- Deeply nested CTEs
- Excessive subquery nesting
- Stack overflow attacks

## Supported SQL Features

### Phase 1 (v1.0.0) - Core DML

- SELECT with FROM, WHERE, GROUP BY, HAVING, ORDER BY, LIMIT, OFFSET
- All JOIN types with proper precedence
- INSERT (single/multi-row)
- UPDATE with SET and WHERE
- DELETE with WHERE

### Phase 2 (v1.2.0) - Advanced Features

- Common Table Expressions (WITH clause)
- Recursive CTEs with depth protection
- Set operations: UNION [ALL], EXCEPT, INTERSECT
- CTE column specifications

### Phase 2.5 (v1.3.0) - Window Functions

- Ranking: ROW_NUMBER(), RANK(), DENSE_RANK(), NTILE()
- Analytic: LAG(), LEAD(), FIRST_VALUE(), LAST_VALUE()
- PARTITION BY and ORDER BY
- Frame clauses: ROWS/RANGE with bounds

### Phase 2.6 (v1.5.0) - NULL Ordering

- NULLS FIRST/LAST in ORDER BY
- NULLS FIRST/LAST in window ORDER BY
- Database portability for NULL ordering

## Performance Characteristics

- **Throughput**: 1.5M operations/second (peak), 1.38M sustained
- **Memory**: Object pooling provides 60-80% reduction vs. new instances
- **Latency**: <1μs for complex queries with window functions
- **Thread Safety**: All pool operations are race-free

## Error Handling

```go
astNode, err := p.Parse(tokens)
if err != nil {
    if parseErr, ok := err.(*parser.ParseError); ok {
        fmt.Printf("Parse error at token '%s': %s\n",
            parseErr.Token.Literal, parseErr.Message)
    }
}
```

## Testing

Run parser tests:

```bash
# All tests
go test -v ./pkg/sql/parser/

# With race detection
go test -race ./pkg/sql/parser/

# Specific features
go test -v -run TestParser_.*Window ./pkg/sql/parser/
go test -v -run TestParser_.*CTE ./pkg/sql/parser/
go test -v -run TestParser_.*Join ./pkg/sql/parser/

# Performance benchmarks
go test -bench=BenchmarkParser -benchmem ./pkg/sql/parser/
```

## Best Practices

### 1. Always Use Defer

```go
p := parser.NewParser()
defer p.Release()  // Ensures cleanup even on panic
```

### 2. Don't Store Pooled Instances

```go
// BAD: Storing pooled object
type MyStruct struct {
    parser *Parser  // DON'T DO THIS
}

// GOOD: Get from pool when needed
func ParseSQL(tokens []token.Token) (*ast.AST, error) {
    p := parser.NewParser()
    defer p.Release()
    return p.Parse(tokens)
}
```

### 3. Use Context for Long Operations

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

p := parser.NewParser()
defer p.Release()

astNode, err := p.ParseContext(ctx, tokens)
```

## Common Pitfalls

### ❌ Forgetting to Release

```go
// BAD: Memory leak
p := parser.NewParser()
astNode, _ := p.Parse(tokens)
// p never returned to pool
```

### ✅ Correct Pattern

```go
// GOOD: Automatic cleanup
p := parser.NewParser()
defer p.Release()
astNode, err := p.Parse(tokens)
```

## Related Packages

- **tokenizer**: Converts SQL text to tokens (input to parser)
- **ast**: AST node definitions (output from parser)
- **token**: Token type definitions
- **keywords**: SQL keyword classification

## Documentation

- [Main API Reference](../../../docs/API_REFERENCE.md)
- [Architecture Guide](../../../docs/ARCHITECTURE.md)
- [Examples](../../../examples/)

## Version History

- **v1.5.0**: NULLS FIRST/LAST support (SQL-99 F851)
- **v1.4.0**: Production validation complete
- **v1.3.0**: Window functions (Phase 2.5)
- **v1.2.0**: CTEs and set operations (Phase 2)
- **v1.0.0**: Core DML and JOINs (Phase 1)
