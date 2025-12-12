# GoSQLX Examples

**Version**: v1.6.0

This directory contains various examples demonstrating how to use the GoSQLX SQL parsing SDK.

## Examples Structure

### `/cmd` - Basic Command Line Example
Simple command-line tool showing basic tokenization and parsing:
```bash
cd cmd/
go run example.go
go test -v example_test.go
```

### `/postgresql` - PostgreSQL Feature Examples (v1.6.0)

GoSQLX v1.6.0 adds comprehensive PostgreSQL-specific feature support. Run these examples to see the new capabilities:

#### `postgresql/lateral-join/` - LATERAL JOIN Support
Demonstrates PostgreSQL LATERAL subquery parsing:
```bash
cd postgresql/lateral-join/
go run main.go
```
- Basic LATERAL subqueries
- LATERAL with LEFT/CROSS JOIN
- Multiple LATERAL joins
- LATERAL with generate_series
- LATERAL with window functions

#### `postgresql/jsonb-operators/` - JSON/JSONB Operators
Demonstrates all PostgreSQL JSON/JSONB operators:
```bash
cd postgresql/jsonb-operators/
go run main.go
```
- Arrow operators: `->`, `->>`
- Path operators: `#>`, `#>>`
- Containment: `@>`, `<@`
- Key existence: `?`, `?|`, `?&`
- Delete path: `#-`

#### `postgresql/filter-clause/` - FILTER Clause
Demonstrates SQL:2003 FILTER clause for conditional aggregation:
```bash
cd postgresql/filter-clause/
go run main.go
```
- COUNT/SUM/AVG with FILTER
- Window functions with FILTER
- Pivot-like queries with FILTER
- FILTER with GROUPING SETS

#### `postgresql/returning-clause/` - RETURNING Clause
Demonstrates PostgreSQL RETURNING clause parsing:
```bash
cd postgresql/returning-clause/
go run main.go
```
- INSERT RETURNING
- UPDATE RETURNING
- DELETE RETURNING
- UPSERT (ON CONFLICT) with RETURNING
- CTEs with RETURNING for data archival

#### `distinct_on_example.go` - DISTINCT ON
Demonstrates PostgreSQL DISTINCT ON clause:
```bash
go run distinct_on_example.go
```
- Single column DISTINCT ON
- Multiple column DISTINCT ON
- DISTINCT ON with ORDER BY

### `/cli-linter` - SQL Linting Tools
Command-line SQL validation and analysis tools:
- `simple.go` - Basic SQL syntax validation
- `advanced.go` - Advanced SQL analysis with detailed feedback

### `/linter-example` - Linting Integration
Example of using GoSQLX linter programmatically:
```bash
cd linter-example/
go run main.go
```

### `/sql-formatter` - SQL Formatting
Example of SQL formatting capabilities:
```bash
cd sql-formatter/
go run main.go
```

### `/sql-validator` - SQL Validation
Example of SQL validation with error reporting:
```bash
cd sql-validator/
go run main.go
```

### `/error-demo` - Error Handling
Demonstrates structured error handling:
```bash
cd error-demo/
go run main.go
```

### `/getting-started` - Tutorial Examples
Step-by-step examples for beginners:
```bash
cd getting-started/01-hello-world/
go run main.go
```

### `/tutorials` - Advanced Tutorials
In-depth tutorials covering specific features:
- `01-sql-validator/` - Building a SQL validator
- `02-sql-formatter/` - Building a SQL formatter

### `/web-services` - Web Service Integration
Examples of integrating GoSQLX into web applications.

### `/grpc-service` - gRPC Service
Example gRPC service exposing SQL parsing capabilities over RPC.

### `/rest-api-server` - REST API Server
REST API server for SQL parsing operations with JSON input/output.

## Quick Start

All examples follow the same pattern:

```go
package main

import (
    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func main() {
    // 1. Get tokenizer from pool
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)  // Always return to pool
    
    // 2. Get AST from pool
    astObj := ast.NewAST()
    defer ast.ReleaseAST(astObj)  // Always release AST
    
    // 3. Tokenize SQL
    sql := []byte("SELECT * FROM users WHERE id = 1")
    tokens, err := tkz.Tokenize(sql)
    if err != nil {
        // Handle error
    }
    
    // 4. Parse tokens
    result, err := parser.Parse(tokens)
    if err != nil {
        // Handle error
    }
    
    // 5. Use the AST
    // ... process result ...
}
```

## Running Tests

```bash
# Run all example tests
go test -v ./examples/...

# Run with race detection (recommended)
go test -race ./examples/...

# Run benchmarks
go test -bench=. ./examples/...
```

## Key Features Demonstrated

- **Object Pooling**: Efficient memory management with tokenizer and AST pools
- **Unicode Support**: Full international SQL support (see cmd/example_test.go)
- **Multi-dialect**: PostgreSQL, MySQL, SQL Server, Oracle, SQLite compatibility
- **Error Handling**: Graceful error recovery and reporting
- **Performance**: High-throughput parsing with minimal allocations