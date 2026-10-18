# gosqlx package (high-level API)

The recommended entry point: parse, validate, format, lint and extract metadata with pooling handled for you.

Import path: `github.com/ajitpratap0/GoSQLX/pkg/gosqlx` ([pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/gosqlx))

Part of the [GoSQLX API reference](../API_REFERENCE.md).

The high-level API provides convenient functions with automatic object pool management.

## Parsing Functions

### `Parse(sql string) (*ast.AST, error)`
Parse SQL in a single call.

```go
astNode, err := gosqlx.Parse("SELECT * FROM users WHERE active = true")
if err != nil {
    log.Fatal(err)
}
defer ast.ReleaseAST(astNode)
```

### `ParseWithContext(ctx context.Context, sql string) (*ast.AST, error)`
Parse with context support for cancellation and timeouts.

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

astNode, err := gosqlx.ParseWithContext(ctx, sql)
if err == context.DeadlineExceeded {
    log.Println("Parsing timed out")
}
defer ast.ReleaseAST(astNode)
```

### `ParseWithTimeout(sql string, timeout time.Duration) (*ast.AST, error)`
Convenience wrapper with automatic timeout.

```go
astNode, err := gosqlx.ParseWithTimeout(sql, 10*time.Second)
defer ast.ReleaseAST(astNode)
```

### `ParseBytes(sql []byte) (*ast.AST, error)`
Parse from byte slice (zero-copy when already in bytes).

```go
sqlBytes, _ := os.ReadFile("query.sql")
astNode, err := gosqlx.ParseBytes(sqlBytes)
defer ast.ReleaseAST(astNode)
```

### `MustParse(sql string) *ast.AST`
Parse SQL, panicking on error (for tests and initialization).

```go
ast := gosqlx.MustParse("SELECT 1")
defer ast.ReleaseAST(ast)
```

### `ParseMultiple(queries []string) ([]*ast.AST, error)`
Parse multiple SQL statements in one call (see [benchmarks](/benchmarks/) for measured numbers).

```go
queries := []string{
    "SELECT * FROM users",
    "SELECT * FROM orders",
}
asts, err := gosqlx.ParseMultiple(queries)
for _, ast := range asts {
    defer ast.ReleaseAST(ast)
}
```

## Validation Functions

### `Validate(sql string) error`
Check if SQL is syntactically valid.

```go
if err := gosqlx.Validate("SELECT * FROM users"); err != nil {
    fmt.Printf("Invalid SQL: %v\n", err)
}
```

### `ValidateMultiple(queries []string) error`
Validate multiple queries efficiently.

```go
queries := []string{"SELECT * FROM users", "INSERT INTO logs (msg) VALUES ('test')"}
if err := gosqlx.ValidateMultiple(queries); err != nil {
    log.Fatal("Validation failed:", err)
}
```
