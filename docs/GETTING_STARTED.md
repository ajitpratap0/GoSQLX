# Getting Started with GoSQLX in 5 Minutes

Welcome! This guide will get you parsing SQL in under 5 minutes. No prior experience with GoSQLX required.

---

## Step 1: Install GoSQLX (30 seconds)

**Requirements**: Go 1.24+ (toolchain go1.25.0)

### Option A: Install CLI Tool (Recommended)
```bash
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
```

### Option B: Library Only
```bash
go get github.com/ajitpratap0/GoSQLX
```

**Verify installation:**
```bash
# Check Go version
go version  # Should show Go 1.24+

# If you installed CLI:
gosqlx --version
```

---

## Step 2: Validate Your First Query (1 minute)

The fastest way to get started is with the CLI:

```bash
# Validate SQL syntax (from stdin)
echo "SELECT * FROM users WHERE active = true" | gosqlx validate
# Output: ✅ Valid SQL

# Or validate SQL files
gosqlx validate query.sql

# Format SQL with intelligent indentation (from stdin)
echo "select * from users where age>18" | gosqlx format
# Output:
# SELECT *
# FROM users
# WHERE age > 18

# Analyze SQL structure (from stdin)
echo "SELECT COUNT(*) FROM orders GROUP BY status" | gosqlx analyze
```

**Available CLI Commands:**
- `validate` - Ultra-fast SQL validation
- `format` - High-performance SQL formatting
- `analyze` - Advanced SQL analysis
- `parse` - AST structure inspection
- `lint` - Check SQL code for style issues
- `lsp` - Start Language Server Protocol server
- `config` - Manage configuration
- `completion` - Shell autocompletion

See [CLI Guide](CLI_GUIDE.md) for complete documentation.

---

## Step 3: Parse Your First Query in Go (2 minutes)

Use GoSQLX in your Go application with the simple API:

### Create `main.go`:

```go
package main

import (
    "fmt"
    "log"

    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func main() {
    // Parse SQL in one line - that's it!
    ast, err := gosqlx.Parse("SELECT * FROM users WHERE active = true")
    if err != nil {
        log.Fatal(err)
    }

    // Success!
    fmt.Printf("✓ Successfully parsed SQL!\n")
    fmt.Printf("  Type: %T\n", ast)
    fmt.Printf("  Statements: %d\n", len(ast.Statements))
}
```

**Run it:**
```bash
go mod init myproject
go get github.com/ajitpratap0/GoSQLX
go run main.go
```

**Expected output:**
```
✓ Successfully parsed SQL!
  Type: *ast.AST
  Statements: 1
```

**That's it!** Just 3 lines of code. No pool management, no manual cleanup - everything is handled automatically.

---

## Step 4: More Quick Examples (1 minute)

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func main() {
    // Validate SQL without parsing
    if err := gosqlx.Validate("SELECT * FROM users"); err != nil {
        fmt.Println("Invalid SQL:", err)
    } else {
        fmt.Println("Valid SQL!")
    }

    // Parse multiple queries efficiently (reuses internal resources)
    queries := []string{
        "SELECT * FROM users",
        "SELECT * FROM orders",
        "SELECT * FROM products",
    }
    asts, err := gosqlx.ParseMultiple(queries)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Parsed %d queries\n", len(asts))

    // Parse with timeout for long queries
    sql := "SELECT * FROM large_table"
    ast, err := gosqlx.ParseWithTimeout(sql, 5*time.Second)
    if err == context.DeadlineExceeded {
        fmt.Println("Query took too long to parse")
    }

    // Parse from byte slice (zero-copy optimization)
    sqlBytes := []byte("SELECT * FROM users")
    ast, err = gosqlx.ParseBytes(sqlBytes)
}
```

> **Performance Note:** The simple API has < 1% overhead compared to the low-level API. Use it everywhere unless you need fine-grained control over resource management.

---

## Step 5: Common Use Cases (30 seconds)

### Validate SQL in Your Application:
```go
func ValidateUserQuery(sql string) error {
    return gosqlx.Validate(sql)
}
```

### Process Multiple Queries:
```go
func ProcessBatch(queries []string) error {
    asts, err := gosqlx.ParseMultiple(queries)
    if err != nil {
        return err
    }

    for i, ast := range asts {
        fmt.Printf("Query %d: %d statement(s)\n", i+1, len(ast.Statements))
    }
    return nil
}
```

### Use in CI/CD:
```bash
# In your .github/workflows/test.yml
- name: Validate SQL
  run: |
    gosqlx validate migrations/*.sql
    gosqlx lint --check queries/*.sql
```

---

## What's Next?

### Learn More:
- **[Usage Guide](USAGE_GUIDE.md)** - Comprehensive patterns and examples
- **[CLI Guide](CLI_GUIDE.md)** - Full CLI documentation and all commands
- **[API Reference](API_REFERENCE.md)** - Complete API documentation
- **[Examples](../examples/)** - Real-world code examples

### Advanced Topics:
- **Low-Level API** - For performance-critical applications (>100K queries/sec)
- **Object Pooling** - Manual resource management for fine-grained control
- **SQL Injection Detection** - Built-in security scanning
- **Multi-Dialect Support** - PostgreSQL, MySQL, SQL Server, Oracle, SQLite
- **Unicode Support** - Full international character support

See [Usage Guide](USAGE_GUIDE.md) for advanced patterns.

---

## Troubleshooting

### "command not found: gosqlx"
**Solution:** Make sure `$GOPATH/bin` is in your `PATH`:
```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

### "cannot find package"
**Solution:** Run `go mod tidy` to download dependencies:
```bash
go mod init myproject
go get github.com/ajitpratap0/GoSQLX
go mod tidy
```

### "tokenization failed: unexpected character"
**Solution:** Check for invalid SQL syntax. Use CLI to debug:
```bash
gosqlx validate "your SQL here"
```

### Need Help?
- **[Troubleshooting Guide](TROUBLESHOOTING.md)** - Common issues and solutions
- **[GitHub Issues](https://github.com/ajitpratap0/GoSQLX/issues)** - Report bugs or ask questions
- **[Discussions](https://github.com/ajitpratap0/GoSQLX/discussions)** - Community Q&A

---

## What You've Learned

- ✓ Installing GoSQLX (library and CLI)
- ✓ Validating and formatting SQL with CLI
- ✓ Parsing SQL in Go applications with simple API
- ✓ Common use cases and patterns
- ✓ Where to find more help

---

**Time to first success:** < 5 minutes

**Questions?** Open an issue or start a discussion on GitHub!

---

*Built by the GoSQLX community*
