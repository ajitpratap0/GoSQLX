# gosqlx - High-Level SQL Parsing API

[![Go Reference](https://pkg.go.dev/badge/github.com/ajitpratap0/GoSQLX/pkg/gosqlx.svg)](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/gosqlx)

The `gosqlx` package provides a convenient, high-level API for SQL parsing in GoSQLX. It wraps the lower-level tokenizer and parser APIs to provide a simple, ergonomic interface for common operations with automatic object pool management.

## Quick Start

```go
import "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"

// Parse SQL in one line
ast, err := gosqlx.Parse("SELECT * FROM users WHERE active = true")
if err != nil {
    log.Fatal(err)
}

// Or just validate
if err := gosqlx.Validate("SELECT * FROM users"); err != nil {
    log.Fatal("Invalid SQL:", err)
}
```

## Features

- **Simple API**: Parse SQL with a single function call
- **Automatic Resource Management**: Object pools handled internally
- **Batch Processing**: Efficient parsing of multiple queries
- **Validation**: Quick syntax validation without full AST construction
- **Format Support**: Basic SQL formatting (with plans for advanced formatting)
- **Production Ready**: Built on top of GoSQLX's production-tested parser

## Installation

```bash
go get github.com/ajitpratap0/GoSQLX
```

## API Reference

### Core Functions

#### Parse

Parse SQL string into an Abstract Syntax Tree (AST):

```go
func Parse(sql string) (*ast.AST, error)
```

**Example:**
```go
ast, err := gosqlx.Parse("SELECT * FROM users")
if err != nil {
    return err
}

// Access parsed statements
for _, stmt := range ast.Statements {
    // Process each statement
}
```

#### ParseBytes

Parse SQL from a byte slice (useful for file I/O):

```go
func ParseBytes(sql []byte) (*ast.AST, error)
```

**Example:**
```go
sqlBytes := []byte("SELECT * FROM users")
ast, err := gosqlx.ParseBytes(sqlBytes)
```

#### Validate

Validate SQL syntax without building the full AST:

```go
func Validate(sql string) error
```

**Example:**
```go
if err := gosqlx.Validate(userInput); err != nil {
    return fmt.Errorf("invalid SQL: %w", err)
}
```

#### MustParse

Parse SQL or panic (useful for testing and initialization):

```go
func MustParse(sql string) *ast.AST
```

**Example:**
```go
// In tests or init functions
ast := gosqlx.MustParse("SELECT 1")
```

### Batch Processing Functions

#### ParseMultiple

Parse multiple SQL statements efficiently by reusing parser resources:

```go
func ParseMultiple(queries []string) ([]*ast.AST, error)
```

**Example:**
```go
queries := []string{
    "SELECT * FROM users",
    "SELECT * FROM orders",
    "SELECT * FROM products",
}

asts, err := gosqlx.ParseMultiple(queries)
if err != nil {
    return err
}

for i, ast := range asts {
    fmt.Printf("Query %d: %d statements\n", i, len(ast.Statements))
}
```

#### ValidateMultiple

Validate multiple SQL statements:

```go
func ValidateMultiple(queries []string) error
```

**Example:**
```go
queries := []string{
    "SELECT * FROM users",
    "INSERT INTO logs (msg) VALUES ('test')",
}

if err := gosqlx.ValidateMultiple(queries); err != nil {
    return fmt.Errorf("validation failed: %w", err)
}
```

### Formatting Functions

#### Format

Format SQL according to specified options:

```go
func Format(sql string, options FormatOptions) (string, error)
```

**Example:**
```go
opts := gosqlx.DefaultFormatOptions()
opts.AddSemicolon = true
opts.UppercaseKeywords = true

formatted, err := gosqlx.Format("select * from users", opts)
// Returns validated SQL with semicolon added
```

#### FormatOptions

Control formatting behavior:

```go
type FormatOptions struct {
    IndentSize        int  // Number of spaces for indentation (default: 2)
    UppercaseKeywords bool // Uppercase SQL keywords (default: false)
    AddSemicolon      bool // Add semicolon if missing (default: false)
    SingleLineLimit   int  // Max line length before breaking (default: 80)
}
```

**Note:** Full AST-based formatting is planned for a future release. Current implementation validates SQL and applies basic formatting options.

## Use Cases

### 1. Input Validation

```go
func validateUserQuery(userSQL string) error {
    // Quick validation before executing
    if err := gosqlx.Validate(userSQL); err != nil {
        return fmt.Errorf("invalid SQL: %w", err)
    }
    return nil
}
```

### 2. SQL Analysis Tool

```go
func analyzeSQL(sql string) error {
    ast, err := gosqlx.Parse(sql)
    if err != nil {
        return err
    }

    // Analyze the AST
    for _, stmt := range ast.Statements {
        switch s := stmt.(type) {
        case *ast.SelectStatement:
            fmt.Println("Found SELECT statement")
        case *ast.InsertStatement:
            fmt.Println("Found INSERT statement")
        // Handle other statement types
        }
    }

    return nil
}
```

### 3. Batch Query Processing

```go
func processMigrationFiles(files []string) error {
    var queries []string

    // Read all SQL files
    for _, file := range files {
        content, err := os.ReadFile(file)
        if err != nil {
            return err
        }
        queries = append(queries, string(content))
    }

    // Validate all at once
    if err := gosqlx.ValidateMultiple(queries); err != nil {
        return fmt.Errorf("migration validation failed: %w", err)
    }

    // Parse all efficiently
    asts, err := gosqlx.ParseMultiple(queries)
    if err != nil {
        return err
    }

    // Process each migration
    for i, ast := range asts {
        fmt.Printf("Migration %s: %d statements\n", files[i], len(ast.Statements))
    }

    return nil
}
```

### 4. SQL Formatting Service

```go
func formatSQLEndpoint(w http.ResponseWriter, r *http.Request) {
    sql := r.FormValue("sql")

    opts := gosqlx.DefaultFormatOptions()
    opts.AddSemicolon = true
    opts.IndentSize = 4

    formatted, err := gosqlx.Format(sql, opts)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    w.Write([]byte(formatted))
}
```

## Migration from Low-Level API

If you're currently using the low-level tokenizer and parser APIs directly, migrating to `gosqlx` is simple:

### Before (Low-Level API)

```go
import (
    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

func parseSQL(sql string) (*ast.AST, error) {
    // Get tokenizer from pool
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    // Tokenize
    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        return nil, err
    }

    // Convert tokens
    converter := parser.NewTokenConverter()
    result, err := converter.Convert(tokens)
    if err != nil {
        return nil, err
    }

    // Parse
    p := parser.NewParser()
    defer p.Release()

    return p.Parse(result.Tokens)
}
```

### After (High-Level API)

```go
import "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"

func parseSQL(sql string) (*ast.AST, error) {
    return gosqlx.Parse(sql)
}
```

**Benefits:**
- Less boilerplate code
- Automatic resource management
- Simpler error handling
- Same performance characteristics

## Best Practices

### 1. Use Validate for Quick Checks

If you only need to check syntax validity, use `Validate` instead of `Parse`:

```go
// Good - faster for validation only
if err := gosqlx.Validate(sql); err != nil {
    return err
}

// Less efficient - builds full AST
if _, err := gosqlx.Parse(sql); err != nil {
    return err
}
```

### 2. Batch Processing

For multiple queries, use batch functions to reuse parser resources:

```go
// Good - reuses resources
asts, err := gosqlx.ParseMultiple(queries)

// Less efficient - recreates resources for each query
for _, sql := range queries {
    ast, err := gosqlx.Parse(sql)
    // ...
}
```

### 3. Use MustParse Only for Literals

Use `MustParse` only with SQL you control (tests, constants):

```go
// Good - SQL literal in code
var testQuery = gosqlx.MustParse("SELECT 1")

// Bad - user input could panic
ast := gosqlx.MustParse(userInput) // Don't do this!
```

### 4. Performance-Critical Code

For performance-critical applications, consider using the low-level API directly:

```go
// High-level API - simpler but slight overhead
ast, err := gosqlx.Parse(sql)

// Low-level API - more control, slightly faster
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)
// ... manual token/parse operations
```

## Error Handling

All functions return descriptive errors with context:

```go
ast, err := gosqlx.Parse("SELECT * FROM")
if err != nil {
    // Error includes position and context
    fmt.Printf("Parse error: %v\n", err)
    // Output: Parse error: parsing failed: unexpected EOF at line 1, column 14
}
```

Batch functions include query index in error messages:

```go
err := gosqlx.ValidateMultiple(queries)
if err != nil {
    // Error includes query number
    fmt.Printf("Error: %v\n", err)
    // Output: Error: query 2: invalid SQL: unexpected token 'FROM'
}
```

## Supported SQL Features

The `gosqlx` package supports all SQL features provided by GoSQLX:

- **DML**: SELECT, INSERT, UPDATE, DELETE
- **DDL**: CREATE, ALTER, DROP
- **JOINs**: INNER, LEFT, RIGHT, FULL OUTER, CROSS, NATURAL
- **Subqueries**: Scalar, row, table subqueries
- **Window Functions**: All SQL-99 window functions with OVER clause
- **CTEs**: WITH clause, recursive CTEs
- **Set Operations**: UNION, INTERSECT, EXCEPT
- **Advanced Clauses**: GROUP BY, HAVING, ORDER BY, LIMIT, OFFSET
- **Multiple Dialects**: PostgreSQL, MySQL, SQL Server, Oracle, SQLite

## Performance

The high-level API has minimal overhead compared to the low-level API:

```
BenchmarkParse-8              50000    ~30-50 μs/op    ~15 KB/op
BenchmarkParseMultiple-8      10000   ~150-200 μs/op   ~75 KB/op (5 queries)
BenchmarkValidate-8           50000    ~30-50 μs/op    ~15 KB/op
BenchmarkFormat-8             45000    ~35-55 μs/op    ~16 KB/op
```

Object pooling keeps allocations low and performance high.

## Examples

See comprehensive examples in:
- [example_test.go](./example_test.go) - Runnable examples with expected output
- [gosqlx_test.go](./gosqlx_test.go) - Unit tests showing various usage patterns

## Advanced Usage

For advanced use cases requiring fine-grained control:
- Use the low-level APIs in `pkg/sql/tokenizer` and `pkg/sql/parser`
- Access AST visitor pattern in `pkg/sql/ast/visitor.go`
- Implement custom AST traversal and analysis

## Contributing

Contributions are welcome! Please see the main [GoSQLX repository](https://github.com/ajitpratap0/GoSQLX) for contribution guidelines.

## License

This package is part of GoSQLX. See the main repository for license information.

## Related Documentation

- [GoSQLX Main Documentation](../../README.md)
- [Tokenizer Package](../sql/tokenizer/)
- [Parser Package](../sql/parser/)
- [AST Package](../sql/ast/)
