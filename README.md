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

```go
package main

import (
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func main() {
    // Get a tokenizer from the pool
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz) // Return to pool when done
    
    // Tokenize the SQL query
    sql := []byte("SELECT id, name FROM users WHERE age > 18")
    tokens, err := tkz.Tokenize(sql)
    if err != nil {
        panic(err)
    }
    
    // Create a parser
    p := parser.New()
    defer p.Release() // Clean up resources
    
    // Parse tokens into an AST
    ast, err := p.Parse(tokens)
    if err != nil {
        panic(err)
    }
    
    // Work with the AST
    // ...
    
    // Return AST to the pool when done
    ast.ReleaseAST(ast)
}
```

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
BenchmarkTokenizer/SimpleSQL-16         	  860258	      1233 ns/op
BenchmarkTokenizer/ComplexSQL-16        	   98812	     12008 ns/op
BenchmarkTokenizerAllocations/SimpleSQL-16	 1000000	      1228 ns/op	    1617 B/op	      24 allocs/op
```

### Parser Performance

```
BenchmarkParserSimpleSelect-16          	 6419961	       169.9 ns/op	     536 B/op	       9 allocs/op
BenchmarkParserComplexSelect-16         	 1639564	       721.4 ns/op	    1433 B/op	      36 allocs/op
BenchmarkParserInsert-16                	 5387626	       221.3 ns/op	     536 B/op	      14 allocs/op
BenchmarkParserUpdate-16                	 5944860	       199.4 ns/op	     584 B/op	      12 allocs/op
BenchmarkParserDelete-16                	 8192491	       144.4 ns/op	     424 B/op	       8 allocs/op
```

### AST Pool Performance

```
BenchmarkASTPool/GetReleaseAST-16      	169205184	         6.650 ns/op	       0 B/op	       0 allocs/op
BenchmarkSelectStatementPool/GetPutSelectStatement-16	11730066	       100.2 ns/op	     274 B/op	       4 allocs/op
BenchmarkIdentifierPool/GetPutIdentifier-16	170082399	         7.050 ns/op	       0 B/op	       0 allocs/op
```

## Examples

For detailed examples, please check the [examples directory](examples/).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
