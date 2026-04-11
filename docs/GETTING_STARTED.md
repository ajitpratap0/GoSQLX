# Getting Started with GoSQLX in 5 Minutes

Welcome! This guide will get you parsing SQL in under 5 minutes. No prior experience with GoSQLX required.

**What's New in v1.14.0:**
- **Dialect-Aware Formatting**: `transform.FormatSQLWithDialect(stmt, dialect)` renders TOP / FETCH FIRST / LIMIT per dialect (closes #479)
- **Snowflake Dialect at 100%** (87/87 QA corpus): MATCH_RECOGNIZE, @stage references, SAMPLE/TABLESAMPLE, QUALIFY, VARIANT colon-paths, time-travel (AT/BEFORE), MINUS, LATERAL FLATTEN, TRY_CAST, IGNORE/RESPECT NULLS, LIKE ANY/ALL, CREATE STAGE/STREAM/TASK/PIPE stubs
- **ClickHouse Dialect 83%** (69/83 QA corpus, up from 53%): nested column types (Nullable, Array, Map, LowCardinality), parametric aggregates, bare-bracket arrays, ORDER BY WITH FILL, CODEC, WITH TOTALS, LIMIT BY, ANY/ALL JOIN, SETTINGS/TTL, INSERT FORMAT, `table`/`partition` as identifiers (closes #480)
- **MariaDB Dialect**: SEQUENCE DDL, temporal tables, CONNECT BY hierarchical queries
- **SQL Transpilation**: MySQL↔PostgreSQL and PostgreSQL→SQLite dialect conversion + `gosqlx transpile` CLI subcommand
- **Live Schema Introspection**: `pkg/schema/db` with PostgreSQL, MySQL, and SQLite loaders
- **30 Linter Rules**: expanded from 10 to 30 (safety, performance, naming categories)
- **Integrations**: `integrations/opentelemetry` (OTel spans) and `integrations/gorm` (query metadata plugin)
- **New CLI Subcommands**: `transpile`, `optimize`, `stats`, `watch`, `action`

---

## Step 1: Install GoSQLX (30 seconds)

**Requirements**: Go 1.26+

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
go version  # Should show Go 1.26+

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

**Available CLI Commands (v1.14.0):**
- `validate` - Ultra-fast SQL validation with security scanning
- `format` - High-performance SQL formatting with style options
- `analyze` - Advanced SQL analysis with complexity metrics
- `parse` - AST structure inspection (JSON/text output)
- `lint` - Check SQL code for style issues (30 built-in rules)
- `transpile` - Convert SQL between dialects (MySQL ↔ PostgreSQL, PostgreSQL → SQLite)
- `optimize` - Run optimization advisor (OPT-001 through OPT-020)
- `action` - GitHub Actions integration with annotations
- `stats` - Object pool utilization metrics
- `watch` - Watch mode for continuous validation
- `lsp` - Start Language Server Protocol server for IDE integration
- `config` - Manage configuration files (.gosqlx.yml)
- `completion` - Shell autocompletion for bash/zsh/fish

**New in v1.14.0:**
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

See [CLI Guide](/docs/cli-guide) for complete documentation.

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

## Step 4: v1.14.0 Feature Examples (2 minutes)

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
- **[Usage Guide](/docs/usage-guide)** - Comprehensive patterns and examples
- **[CLI Guide](/docs/cli-guide)** - Full CLI documentation and all commands
- **[LSP Guide](/docs/lsp-guide)** - Complete LSP server documentation for IDE integration
- **[MCP Server Guide](/docs/mcp-guide)** - Use GoSQLX as MCP tools inside Claude, Cursor, and other AI assistants
- **[Linting Rules](/docs/linting-rules)** - All 30 linting rules reference
- **[Configuration](/docs/configuration)** - Configuration file (.gosqlx.yml) guide
- **[API Reference](/docs/api-reference)** - Complete API documentation
- **[Examples](https://github.com/ajitpratap0/GoSQLX/tree/main/examples)** - Real-world code examples

### v1.14.0 Feature Guides:
- **Dialect-Aware Transforms:**
  - `transform.FormatSQLWithDialect(stmt, dialect)` for dialect-specific SQL output
  - `transform.ParseSQLWithDialect(sql, dialect)` for dialect-aware parsing
  - TOP (SQL Server) / FETCH FIRST (Oracle) / LIMIT (PostgreSQL, MySQL, SQLite, Snowflake, ClickHouse)

- **SQL Transpilation:**
  - MySQL ↔ PostgreSQL (AUTO_INCREMENT ↔ SERIAL, TINYINT(1) ↔ BOOLEAN)
  - PostgreSQL → SQLite (SERIAL → INTEGER, arrays → TEXT)
  - `gosqlx transpile --from <dialect> --to <dialect>` CLI subcommand

- **Live Schema Introspection:**
  - `gosqlx.LoadSchema(ctx, loader)` for dialect-agnostic metadata querying
  - PostgreSQL, MySQL, and SQLite loaders in `pkg/schema/db`
  - Tables, columns, indexes, foreign keys

- **Expanded Dialects:**
  - Snowflake at 100% QA pass (87/87: MATCH_RECOGNIZE, @stage, SAMPLE, QUALIFY, VARIANT, time-travel)
  - ClickHouse 83% QA pass (69/83, up from 53%: nested types, parametric aggregates, WITH FILL, CODEC)
  - MariaDB with SEQUENCE, temporal tables, CONNECT BY

- **IDE Integration:**
  - LSP server with real-time diagnostics
  - Semantic tokens + diagnostic debouncing
  - Code completion for SQL keywords
  - Auto-formatting on save
  - See [LSP Guide](/docs/lsp-guide) for setup instructions

- **Security Features:**
  - SQL injection pattern detection
  - Severity classification (HIGH/MEDIUM/LOW)
  - OpenSSF Scorecard workflow
  - See [Usage Guide](/docs/usage-guide) for security scanning patterns

- **Code Quality:**
  - 30 built-in linter rules (safety, performance, naming, style)
  - Auto-fix capabilities for common issues
  - OPT-001 through OPT-020 optimization advisor
  - Query fingerprinting + normalization
  - See [Linting Rules](/docs/linting-rules) for complete reference

### Advanced Topics:
- **Low-Level API** - For performance-critical applications (>100K queries/sec)
- **Object Pooling** - Manual resource management for fine-grained control
- **Multi-Dialect Support** - PostgreSQL, MySQL, MariaDB, SQL Server, Oracle, SQLite, Snowflake, ClickHouse
- **Unicode Support** - Full international character support
- **SQL Compatibility** - See [SQL Compatibility](/docs/sql-compatibility) for dialect matrix

See [Usage Guide](/docs/usage-guide) for advanced patterns.

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
- **[Troubleshooting Guide](/docs/troubleshooting)** - Common issues and solutions
- **[GitHub Issues](https://github.com/ajitpratap0/GoSQLX/issues)** - Report bugs or ask questions
- **[Discussions](https://github.com/ajitpratap0/GoSQLX/discussions)** - Community Q&A

---

## v1.14.0 Feature Highlights

### Production-Ready Performance
- **1.38M+ operations/second** sustained throughput
- **1.5M peak** operations with memory-efficient pooling
- **<1μs latency** for complex queries with window functions
- **Zero race conditions** - validated with comprehensive concurrent testing

### SQL Compliance
- **~80-85% SQL-99 compliance** including window functions, CTEs, set operations
- **Snowflake at 100%** of the QA corpus (87/87); **ClickHouse at 83%** (69/83, up from 53%)
- **Multi-dialect support** - PostgreSQL, MySQL, MariaDB, SQL Server, Oracle, SQLite, Snowflake, ClickHouse
- **Full Unicode support** for international SQL processing

### Enterprise Features
- **Thread-safe** - Race-free codebase confirmed through extensive testing
- **Memory efficient** - 60-80% memory reduction with object pooling
- **Security scanning** - Built-in SQL injection detection
- **IDE integration** - LSP server for VSCode, Neovim, and other editors
- **Code quality** - 30 linter rules for consistent SQL style
- **Dialect-aware transforms** - Round-trip SQL with dialect-specific syntax
- **Live schema introspection** - Query Postgres/MySQL/SQLite metadata at runtime
- **SQL transpilation** - Convert between MySQL, PostgreSQL, and SQLite

---

## What You've Learned

- ✓ Installing GoSQLX (library and CLI)
- ✓ Validating and formatting SQL with CLI
- ✓ Parsing SQL in Go applications with simple API
- ✓ Using v1.14.0 features (dialect-aware transforms, transpilation, schema introspection, 30 linter rules)
- ✓ Common use cases and patterns
- ✓ Where to find more help

---

**Time to first success:** < 5 minutes

**Questions?** Open an issue or start a discussion on GitHub!

---

*Built by the GoSQLX community - Production-ready since v1.12.0, ClickHouse dialect since v1.13.0, dialect-aware transforms since v1.14.0*
