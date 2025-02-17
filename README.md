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

## Installation

```bash
go get github.com/ajitpratap0/GoSQLX
```

## Usage

```go
package main

import (
    "github.com/ajitpratap0/GoSQLX/pkg"
)

func main() {
    // Create a new parser
    parser := pkg.NewParser()
    
    // Parse a SQL query
    sql := "SELECT id, name FROM users WHERE age > 18"
    ast, err := parser.Parse(sql)
    if err != nil {
        panic(err)
    }
    
    // Work with the AST
    // ...
}
```

## Documentation

For detailed documentation and examples, please visit the [pkg directory](pkg/) which contains various components:

- `pkg/tokenizer`: SQL tokenization implementation
- `pkg/keywords`: Comprehensive SQL keyword definitions
- `pkg/models`: Core data models and types
- `pkg/ast.go`: Abstract Syntax Tree implementation
- `pkg/parser.go`: SQL parser implementation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
}
```
