# Getting Started with GoSQLX in 5 Minutes

Welcome! This guide will get you parsing SQL in under 5 minutes. No prior experience with GoSQLX required.

**What's New in v1.6.0:**
- PostgreSQL extensions (LATERAL JOIN, JSON operators, DISTINCT ON, FILTER clause)
- LSP server for IDE integration with real-time diagnostics
- Built-in SQL security scanner for injection detection
- 10 comprehensive linter rules (L001-L010) for style enforcement
- Advanced aggregate features (ORDER BY in aggregates, FILTER clauses)
- Enhanced SQL-99 compliance with NULLS FIRST/LAST ordering

---

## Step 1: Install GoSQLX (30 seconds)

**Requirements**: Go 1.24+ (toolchain go1.25.0 for CLI builds)

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

**Available CLI Commands (v1.6.0):**
- `validate` - Ultra-fast SQL validation with security scanning
- `format` - High-performance SQL formatting with style options
- `analyze` - Advanced SQL analysis with complexity metrics
- `parse` - AST structure inspection (JSON/text output)
- `lint` - Check SQL code for style issues (10 built-in rules)
- `lsp` - Start Language Server Protocol server for IDE integration
- `config` - Manage configuration files (.gosqlx.yml)
- `completion` - Shell autocompletion for bash/zsh/fish

**New in v1.6.0:**
```bash
# Security scanning for SQL injection
gosqlx validate --security query.sql

# Lint SQL files with auto-fix
gosqlx lint --fix queries/*.sql

# Start LSP server for VSCode/Neovim
gosqlx lsp --log /tmp/lsp.log

# Format with configuration
gosqlx format --config .gosqlx.yml query.sql
```

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

## Step 4: v1.6.0 Feature Examples (2 minutes)

### PostgreSQL Extensions

```go
package main

import (
    "fmt"
    "log"

    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func main() {
    // Parse PostgreSQL JSON operators
    jsonQuery := `
        SELECT data->>'name' AS name,
               data->'address'->>'city' AS city
        FROM users
        WHERE profile @> '{"role": "admin"}'
    `
    ast, err := gosqlx.Parse(jsonQuery)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Parsed JSON operator query successfully!")

    // Parse LATERAL JOIN (correlated subquery in FROM clause)
    lateralQuery := `
        SELECT u.name, r.order_date
        FROM users u,
        LATERAL (
            SELECT * FROM orders
            WHERE user_id = u.id
            ORDER BY order_date DESC
            LIMIT 3
        ) r
    `
    ast, err = gosqlx.Parse(lateralQuery)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Parsed LATERAL JOIN successfully!")

    // Parse DISTINCT ON (PostgreSQL-specific)
    distinctOnQuery := `
        SELECT DISTINCT ON (dept_id) dept_id, name, salary
        FROM employees
        ORDER BY dept_id, salary DESC
    `
    ast, err = gosqlx.Parse(distinctOnQuery)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Parsed DISTINCT ON successfully!")

    // Parse FILTER clause (SQL:2003 conditional aggregation)
    filterQuery := `
        SELECT
            COUNT(*) FILTER (WHERE status = 'active') AS active_count,
            SUM(amount) FILTER (WHERE type = 'credit') AS total_credits
        FROM transactions
    `
    ast, err = gosqlx.Parse(filterQuery)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Parsed FILTER clause successfully!")
}
```

### Security Scanning

```go
package main

import (
    "fmt"
    "log"

    "github.com/ajitpratap0/GoSQLX/pkg/sql/security"
)

func main() {
    // Scan SQL for injection vulnerabilities
    suspiciousSQL := "SELECT * FROM users WHERE id = '" + userInput + "'"

    scanner := security.NewScanner()
    result := scanner.Scan(suspiciousSQL)

    if len(result.Threats) > 0 {
        fmt.Printf("Found %d security threats:\n", len(result.Threats))
        for _, threat := range result.Threats {
            fmt.Printf("  [%s] %s at line %d\n",
                threat.Severity, threat.Description, threat.Location.Line)
        }
    } else {
        fmt.Println("No security threats detected!")
    }
}
```

### Linting SQL

```go
package main

import (
    "fmt"
    "log"

    "github.com/ajitpratap0/GoSQLX/pkg/linter"
)

func main() {
    // Create linter with default rules (L001-L010)
    l := linter.New()

    sql := "select * from users where name='john'"

    // Run linting
    violations, err := l.Lint(sql)
    if err != nil {
        log.Fatal(err)
    }

    if len(violations) > 0 {
        fmt.Printf("Found %d style violations:\n", len(violations))
        for _, v := range violations {
            fmt.Printf("  [%s] %s at line %d\n", v.Rule, v.Message, v.Line)
        }
    } else {
        fmt.Println("No style violations found!")
    }
}
```

### More Quick Examples

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

## Step 5: Common Use Cases (1 minute)

### Validate SQL in Your Application:
```go
func ValidateUserQuery(sql string) error {
    // Simple validation
    if err := gosqlx.Validate(sql); err != nil {
        return err
    }

    // With security scanning
    scanner := security.NewScanner()
    result := scanner.Scan(sql)
    if len(result.Threats) > 0 {
        return fmt.Errorf("security threats detected: %v", result.Threats)
    }

    return nil
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

### Lint SQL Before Deployment:
```go
func ValidateCodeStyle(sql string) error {
    l := linter.New()
    violations, err := l.Lint(sql)
    if err != nil {
        return err
    }

    if len(violations) > 0 {
        return fmt.Errorf("found %d style violations", len(violations))
    }

    return nil
}
```

### Use in CI/CD:
```bash
# In your .github/workflows/test.yml
- name: Validate SQL
  run: |
    # Validate syntax
    gosqlx validate migrations/*.sql

    # Check security
    gosqlx validate --security queries/*.sql

    # Enforce style
    gosqlx lint --check migrations/*.sql queries/*.sql

    # Format check
    gosqlx format --check --diff queries/*.sql
```

### IDE Integration with LSP:
```bash
# Start LSP server for VSCode/Neovim
gosqlx lsp --log /tmp/lsp.log

# Or in VSCode settings.json:
{
  "sql.lsp.command": "gosqlx",
  "sql.lsp.args": ["lsp"]
}
```

---

## What's Next?

### Essential Guides:
- **[Usage Guide](USAGE_GUIDE.md)** - Comprehensive patterns and examples
- **[CLI Guide](CLI_GUIDE.md)** - Full CLI documentation and all commands
- **[LSP Guide](LSP_GUIDE.md)** - Complete LSP server documentation for IDE integration
- **[Linting Rules](LINTING_RULES.md)** - All 10 linting rules (L001-L010) reference
- **[Configuration](CONFIGURATION.md)** - Configuration file (.gosqlx.yml) guide
- **[API Reference](API_REFERENCE.md)** - Complete API documentation
- **[Examples](../examples/)** - Real-world code examples

### v1.6.0 Feature Guides:
- **PostgreSQL Extensions:**
  - LATERAL JOIN for correlated subqueries
  - JSON/JSONB operators (->/->>/#>/@>/?/etc.)
  - DISTINCT ON for row selection
  - FILTER clause for conditional aggregation
  - RETURNING clause for DML operations

- **IDE Integration:**
  - LSP server with real-time diagnostics
  - Hover information and documentation
  - Code completion for SQL keywords
  - Auto-formatting on save
  - See [LSP Guide](LSP_GUIDE.md) for setup instructions

- **Security Features:**
  - SQL injection pattern detection
  - Severity classification (HIGH/MEDIUM/LOW)
  - Integration with validation pipeline
  - See [Usage Guide](USAGE_GUIDE.md) for security scanning patterns

- **Code Quality:**
  - 10 built-in linter rules for style enforcement
  - Auto-fix capabilities for common issues
  - Configurable rule severity and exclusions
  - See [Linting Rules](LINTING_RULES.md) for complete reference

### Advanced Topics:
- **Low-Level API** - For performance-critical applications (>100K queries/sec)
- **Object Pooling** - Manual resource management for fine-grained control
- **Multi-Dialect Support** - PostgreSQL, MySQL, SQL Server, Oracle, SQLite
- **Unicode Support** - Full international character support
- **SQL Compatibility** - See [SQL_COMPATIBILITY.md](SQL_COMPATIBILITY.md) for dialect matrix

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

## v1.6.0 Feature Highlights

### Production-Ready Performance
- **1.38M+ operations/second** sustained throughput
- **1.5M peak** operations with memory-efficient pooling
- **<1μs latency** for complex queries with window functions
- **Zero race conditions** - validated with comprehensive concurrent testing

### SQL Compliance
- **~80-85% SQL-99 compliance** including window functions, CTEs, set operations
- **95%+ success rate** on real-world SQL queries
- **Multi-dialect support** - PostgreSQL, MySQL, SQL Server, Oracle, SQLite
- **Full Unicode support** for international SQL processing

### Enterprise Features
- **Thread-safe** - Race-free codebase confirmed through extensive testing
- **Memory efficient** - 60-80% memory reduction with object pooling
- **Security scanning** - Built-in SQL injection detection
- **IDE integration** - LSP server for VSCode, Neovim, and other editors
- **Code quality** - 10 linter rules for consistent SQL style

---

## What You've Learned

- ✓ Installing GoSQLX (library and CLI)
- ✓ Validating and formatting SQL with CLI
- ✓ Parsing SQL in Go applications with simple API
- ✓ Using v1.6.0 features (PostgreSQL extensions, security, linting, LSP)
- ✓ Common use cases and patterns
- ✓ Where to find more help

---

**Time to first success:** < 5 minutes

**Questions?** Open an issue or start a discussion on GitHub!

---

*Built by the GoSQLX community - Production-ready since v1.6.0*
