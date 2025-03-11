# GoSQLX

A high-performance, efficient, production-grade SQL parsing SDK for Go. GoSQLX provides a robust implementation of SQL lexing, parsing, and Abstract Syntax Tree (AST) generation, following ANSI SQL standards while maintaining zero-copy optimizations for maximum performance.

## Features

- Fast and efficient SQL lexer and parser
- Zero-copy implementation for optimal performance
- ANSI SQL standard compliance
- Comprehensive AST generation
- Extensive keyword support across different SQL dialects
- Built-in support for various SQL operations (DDL, DML, etc.)
- Thread-safe implementation
- Memory-efficient object pooling

## Installation

```bash
go get github.com/ajitpratap0/GoSQLX
```

## Usage

Below is an example of how to use GoSQLX in your Go application. This demonstrates the basic workflow of tokenizing SQL, parsing it into an AST, and properly managing resources with the object pools.

```go
// Example usage of GoSQLX
package main

import (
    "fmt"
    
    // Import the required GoSQLX packages
    "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/token"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/models"
)

func main() {
    // 1. Get a tokenizer from the pool
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz) // Return to pool when done
    
    // 2. Tokenize the SQL query
    sql := []byte("SELECT id, name FROM users WHERE age > 18")
    tokens, err := tkz.Tokenize(sql)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Tokenized SQL into %d tokens\n", len(tokens))
    
    // 3. Convert TokenWithSpan to token.Token for the parser
    tokenSlice := make([]token.Token, len(tokens))
    for i, t := range tokens {
        tokenSlice[i] = t.Token
    }
    
    // 4. Create a parser
    p := parser.NewParser()
    defer p.Release() // Clean up resources
    
    // 5. Parse tokens into an AST
    result, err := p.Parse(tokenSlice)
    if err != nil {
        panic(err)
    }
    
    // 6. Work with the AST
    fmt.Printf("Parsed %d statements\n", len(result.Statements))
    
    // 7. Return AST to the pool when done
    ast.ReleaseAST(result)
}
```

For more detailed examples, see the [examples directory](examples/).

## Project Structure

```
pkg/
├── models/      - Core data models and types
└── sql/         - SQL processing components
    ├── ast/      - Abstract Syntax Tree implementation
    ├── keywords/  - SQL keyword definitions
    ├── models/    - SQL-specific data models
    ├── parser/    - SQL parser implementation
    ├── token/     - Token type definitions
    └── tokenizer/ - SQL tokenization implementation
```

## Performance Benchmarks

### Tokenizer Performance

```
| Benchmark                                | Operations | Speed (ns/op) | Memory (B/op) | Allocations |
|------------------------------------------|------------|---------------|---------------|-------------|
| BenchmarkTokenizer/SimpleSQL-16         |    860,258 |         1,233 |           N/A |         N/A |
| BenchmarkTokenizer/ComplexSQL-16        |     98,812 |        12,008 |           N/A |         N/A |
| BenchmarkTokenizerAllocations/SimpleSQL |  1,000,000 |         1,228 |         1,617 |          24 |
```

### Parser Performance

```
| Benchmark                        | Operations | Speed (ns/op) | Memory (B/op) | Allocations |
|----------------------------------|------------|---------------|---------------|-------------|
| BenchmarkParserSimpleSelect-16   |  6,419,961 |         169.9 |           536 |           9 |
| BenchmarkParserComplexSelect-16  |  1,639,564 |         721.4 |         1,433 |          36 |
| BenchmarkParserInsert-16         |  5,387,626 |         221.3 |           536 |          14 |
| BenchmarkParserUpdate-16         |  5,944,860 |         199.4 |           584 |          12 |
| BenchmarkParserDelete-16         |  8,192,491 |         144.4 |           424 |           8 |
```

### AST Pool Performance

```
| Benchmark                                        | Operations  | Speed (ns/op) | Memory (B/op) | Allocations |
|--------------------------------------------------|-------------|---------------|---------------|-------------|
| BenchmarkASTPool/GetReleaseAST-16               | 169,205,184 |          6.65 |             0 |           0 |
| BenchmarkSelectStatementPool/GetPutSelectStmt-16 |  11,730,066 |        100.2  |           274 |           4 |
| BenchmarkIdentifierPool/GetPutIdentifier-16      | 170,082,399 |          7.05 |             0 |           0 |
```

## Examples

For detailed examples, please check the [examples directory](examples/).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
