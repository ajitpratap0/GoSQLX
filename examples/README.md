# GoSQLX Examples

This directory contains various examples demonstrating how to use the GoSQLX SQL parsing SDK.

## Examples Structure

### `/cmd` - Basic Command Line Example
Simple command-line tool showing basic tokenization and parsing:
```bash
cd cmd/
go run example.go
go test -v example_test.go
```

### `/cli-linter` - SQL Linting Tools
Command-line SQL validation and analysis tools:
- `simple.go` - Basic SQL syntax validation
- `advanced.go` - Advanced SQL analysis with detailed feedback

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