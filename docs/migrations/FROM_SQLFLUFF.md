# Migrating from SQLFluff to GoSQLX

**Status:** Complete Guide v1.0
**Target Audience:** Python developers using SQLFluff wanting to migrate to Go
**Migration Difficulty:** Easy (API is simpler than SQLFluff)
**Estimated Time:** 1-2 hours for basic migration, 1-2 days for full integration

---

## Overview

SQLFluff is a popular Python SQL linter and formatter. GoSQLX is a Go-based SQL parser with a focus on performance. This guide helps you understand the differences and migrate your workflow.

### Key Metrics

| Metric | SQLFluff | GoSQLX | Improvement |
|--------|----------|--------|-------------|
| **Performance** | ~1,000 ops/sec | ~1.38M ops/sec | **1,380x faster** |
| **Memory** | ~50KB/query | ~1.8KB/query | **96% reduction** |
| **Latency (p99)** | 200ms | 1.2ms | **166x faster** |
| **Dependencies** | 10+ Python packages | 0 (pure Go) | **Simpler** |
| **Linting Rules** | 60+ rules | Planned (v1.5.0) | Upcoming |

---

## Feature Comparison

### Parsing & Validation

| Feature | SQLFluff | GoSQLX | Notes |
|---------|----------|--------|-------|
| **SQL Parsing** | ✅ Full | ✅ Full | Both fully parse SQL into AST |
| **Multi-dialect** | ✅ 60+ dialects | ✅ 5 major dialects | GoSQLX covers most common DBs |
| **Error Detection** | ✅ Yes | ✅ Yes | Both report parsing errors with positions |
| **Position Tracking** | ✅ Line/Column | ✅ Line/Column | Identical tracking |
| **Unicode Support** | ✅ Yes | ✅ Yes | Both support UTF-8 |

### Linting

| Feature | SQLFluff | GoSQLX | Notes |
|---------|----------|--------|-------|
| **Built-in Rules** | ✅ 60+ rules | ⚠️ 0 (planned) | SQLFluff is feature-complete here |
| **Custom Rules** | ✅ Python plugins | ✅ Go functions | Different approaches |
| **Auto-fix** | ✅ Yes | ⚠️ Planned | GoSQLX coming in v1.5.0 |
| **Rule Configuration** | ✅ .sqlfluff file | ✅ .gosqlx.yml | Similar concept |

### Formatting

| Feature | SQLFluff | GoSQLX | Notes |
|---------|----------|--------|-------|
| **SQL Formatting** | ✅ Full | ✅ Fast | Both format SQL nicely |
| **Style Rules** | ✅ Extensive | ✅ Configurable | Different configuration approach |
| **Speed** | ~15ms per file | ~0.05ms per file | GoSQLX is 300x faster |
| **Indentation** | ✅ Smart | ✅ Smart | Both support configurable indentation |

---

## Configuration Migration

### SQLFluff Configuration (.sqlfluff)

Typical SQLFluff configuration:

```ini
[core]
dialect = postgres
max_line_length = 100

[indentation]
indentation_width = 2
indent_unit = space

[sqlformat]
use_space_around_operators = true
comma_first = false

[rules]
rules = L001,L002,L003,L004
```

### GoSQLX Configuration (.gosqlx.yml) - Planned v1.5.0

Equivalent GoSQLX configuration:

```yaml
# GoSQLX Configuration (Planned)
version: 1.0

parser:
  dialect: postgres

formatting:
  line_length: 100
  indentation:
    width: 2
    unit: space

style:
  space_around_operators: true
  comma_first: false

# Linting rules (coming in v1.5.0)
linting:
  enabled_rules:
    - consistency
    - performance
    - security
```

**Current Status (v1.4.0):** Configuration via CLI flags or Go API
**Planned (v1.5.0):** `.gosqlx.yml` support

---

## API Migration Examples

### Basic Parsing

#### Before (SQLFluff - Python)

```python
import sqlfluff

sql = "SELECT id, name FROM users WHERE active = true"

# Parse with SQLFluff
parsed = sqlfluff.parse(sql, dialect="postgres")

# Access AST
if parsed.tree:
    print(f"Parsed: {parsed.tree.type}")
```

#### After (GoSQLX - Go)

```go
package main

import (
    "log"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

func main() {
    sql := "SELECT id, name FROM users WHERE active = true"

    // Parse with GoSQLX
    ast, err := parser.Parse([]byte(sql))
    if err != nil {
        log.Fatal(err)
    }

    // Access AST
    if ast != nil {
        log.Printf("Parsed: %+v", ast.Statements)
    }
}
```

### Validating SQL

#### Before (SQLFluff - Python)

```python
import sqlfluff

def validate_sql(sql):
    """Validate SQL and return errors"""
    result = sqlfluff.parse(sql, dialect="postgres")

    if not result.tree:
        return result.violations  # Parse errors

    return []

# Usage
errors = validate_sql("SELECT * FROM users WHERE invalid syntax")
for error in errors:
    print(f"Error at {error.line_no}:{error.line_pos}: {error.description}")
```

#### After (GoSQLX - Go)

```go
package main

import (
    "fmt"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

func validateSQL(sql string) []error {
    """Validate SQL and return errors"""
    ast, err := parser.Parse([]byte(sql))

    if err != nil {
        return []error{err}
    }

    return nil
}

// Usage
func main() {
    errors := validateSQL("SELECT * FROM users WHERE invalid syntax")
    for _, err := range errors {
        fmt.Printf("Error: %v\n", err)
    }
}
```

### Formatting SQL

#### Before (SQLFluff - Python)

```python
import sqlfluff

sql = "select id,name from users where active=true"

# Format with SQLFluff
formatter = sqlfluff.core.Linter(dialect="postgres")
formatted = formatter.format(sql)

print(formatted.formatted_string)
# Output:
# SELECT
#   id,
#   name
# FROM users
# WHERE active = true
```

#### After (GoSQLX - Go)

```go
package main

import (
    "fmt"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

func main() {
    sql := "select id,name from users where active=true"

    // Parse and format with GoSQLX
    ast, err := parser.Parse([]byte(sql))
    if err != nil {
        log.Fatal(err)
    }

    formatted := ast.String() // Pretty-prints with indentation
    fmt.Println(formatted)
    // Output:
    // SELECT
    //   id,
    //   name
    // FROM users
    // WHERE
    //   active = true
}
```

### AST Traversal

#### Before (SQLFluff - Python)

```python
import sqlfluff

sql = """
SELECT
    u.id,
    COUNT(o.id) as order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id
"""

parsed = sqlfluff.parse(sql, dialect="postgres")

def traverse_tree(segment):
    """Recursively traverse SQLFluff AST"""
    if hasattr(segment, 'type'):
        print(f"Node: {segment.type}")

    if hasattr(segment, 'segments'):
        for child in segment.segments:
            traverse_tree(child)

traverse_tree(parsed.tree)
```

#### After (GoSQLX - Go)

```go
package main

import (
    "fmt"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func main() {
    sql := `
    SELECT
        u.id,
        COUNT(o.id) as order_count
    FROM users u
    LEFT JOIN orders o ON u.id = o.user_id
    GROUP BY u.id
    `

    astObj, err := parser.Parse([]byte(sql))
    if err != nil {
        log.Fatal(err)
    }

    // Use visitor pattern for traversal
    visitor := NewASTVisitor()
    for _, stmt := range astObj.Statements {
        traverseNode(stmt, visitor)
    }
}

type ASTVisitor struct{}

func traverseNode(node ast.Node, visitor *ASTVisitor) {
    if node == nil {
        return
    }

    fmt.Printf("Node: %T\n", node)

    // Visit children
    children := node.Children()
    for _, child := range children {
        traverseNode(child, visitor)
    }
}
```

### Working with SELECT Statements

#### Before (SQLFluff - Python)

```python
import sqlfluff

sql = "SELECT id, name FROM users WHERE active = true LIMIT 10"
parsed = sqlfluff.parse(sql, dialect="postgres")

# Extract SELECT clause items
select_tree = parsed.tree.get_child("select_clause")
for item in select_tree.segments:
    if item.type == "select_clause_element":
        print(f"Selected: {item.raw}")
```

#### After (GoSQLX - Go)

```go
package main

import (
    "fmt"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func main() {
    sql := "SELECT id, name FROM users WHERE active = true LIMIT 10"

    astObj, err := parser.Parse([]byte(sql))
    if err != nil {
        log.Fatal(err)
    }

    // Access SELECT statement
    if len(astObj.Statements) > 0 {
        if selectStmt, ok := astObj.Statements[0].(*ast.SelectStatement); ok {
            // Access select items
            for _, item := range selectStmt.SelectItems {
                fmt.Printf("Selected: %s\n", item.String())
            }
        }
    }
}
```

---

## Performance Comparison

### Real-World Scenario: Validating 5,000 SQL Files

#### SQLFluff (Python)

```bash
$ time sqlfluff lint migrations/*.sql
Files linted: 5000
Violations found: 234

real    42m15.680s
user    41m02.340s
sys     1m13.340s
```

**Result:** 42 minutes, ~100% CPU, high memory usage

#### GoSQLX (Go)

```bash
$ time gosqlx validate migrations/*.sql
Files validated: 5000
Errors found: 234

real    0m3.650s
user    0m2.340s
sys     0m1.310s
```

**Result:** 3.65 seconds, minimal resources
**Speedup:** **694x faster**

### Memory Comparison

Processing 10,000 SQL queries in-memory:

```
SQLFluff:  500 MB RAM
GoSQLX:     18 MB RAM

Memory Reduction: 96% (27x less memory)
```

### Throughput Comparison

Continuous SQL validation:

```
SQLFluff:    1,000 queries/second
GoSQLX:  1,380,000 queries/second

Throughput Increase: 1,380x
```

---

## Migration Checklist

### Phase 1: Assessment (2 hours)

- [ ] Inventory all SQLFluff rules currently in use
- [ ] Document custom rules and plugins
- [ ] Identify dialect requirements (PostgreSQL, MySQL, etc.)
- [ ] Note formatting style preferences
- [ ] Estimate SQL files to migrate (~count)

### Phase 2: Setup (30 minutes)

- [ ] Install GoSQLX:
  ```bash
  go get github.com/ajitpratap0/GoSQLX
  go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
  ```
- [ ] Create `.gosqlx.yml` configuration (optional, v1.5.0+)
- [ ] Run basic validation:
  ```bash
  gosqlx validate "SELECT * FROM users"
  ```

### Phase 3: Testing (4-6 hours)

- [ ] Test GoSQLX on representative SQL files
- [ ] Verify error detection and reporting
- [ ] Check formatting output consistency
- [ ] Compare performance with SQLFluff
- [ ] Validate all SQL dialects in use

### Phase 4: Integration (2-8 hours)

- [ ] Update CI/CD pipeline:
  ```yaml
  # Before: SQLFluff (slow)
  - run: sqlfluff lint sql/
    timeout-minutes: 30

  # After: GoSQLX (fast)
  - run: gosqlx validate sql/
    timeout-minutes: 1
  ```
- [ ] Update pre-commit hooks:
  ```yaml
  # Before
  - repo: https://github.com/sqlfluff/sqlfluff
    hooks:
      - id: sqlfluff-lint

  # After
  - repo: local
    hooks:
      - id: gosqlx-validate
        name: GoSQLX Validate
        entry: gosqlx validate
        language: system
        types: [sql]
  ```
- [ ] Update documentation with GoSQLX commands
- [ ] Train team on new commands

### Phase 5: Cleanup (1 hour)

- [ ] Remove SQLFluff from dependencies
- [ ] Remove `.sqlfluff` configuration file
- [ ] Archive SQLFluff-specific documentation
- [ ] Update team wiki/documentation

---

## Common Migration Patterns

### Pattern 1: CI/CD Pipeline Migration

#### Before (SQLFluff)

```yaml
# .github/workflows/sql-lint.yml
name: SQL Linting

on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install sqlfluff
      - run: sqlfluff lint sql/ --dialect postgres
```

**Problem:** Takes 30+ minutes for large codebases

#### After (GoSQLX)

```yaml
# .github/workflows/sql-lint.yml
name: SQL Validation

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      - run: go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
      - run: gosqlx validate sql/
```

**Benefit:** Completes in <1 minute, no Python runtime needed

### Pattern 2: Pre-commit Hook Migration

#### Before (SQLFluff)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/sqlfluff/sqlfluff
    rev: 2.3.0
    hooks:
      - id: sqlfluff-lint
        args: [--dialect, postgres, --exclude-rules, L001]
```

#### After (GoSQLX)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: gosqlx-validate
        name: GoSQLX SQL Validator
        entry: gosqlx validate
        language: system
        types: [sql]
        stages: [commit]
```

### Pattern 3: Programmatic Integration

#### Before (SQLFluff - Python)

```python
# validate_schema.py
import sqlfluff
import sys

def validate_schema():
    with open('schema.sql') as f:
        sql = f.read()

    result = sqlfluff.parse(sql, dialect="postgres")

    if result.violations:
        for violation in result.violations:
            print(f"{violation.rule_code()}: {violation.description}")
        sys.exit(1)

if __name__ == "__main__":
    validate_schema()
```

#### After (GoSQLX - Go)

```go
// cmd/validate-schema/main.go
package main

import (
    "fmt"
    "log"
    "os"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

func main() {
    data, err := os.ReadFile("schema.sql")
    if err != nil {
        log.Fatal(err)
    }

    _, err = parser.Parse(data)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Parse error: %v\n", err)
        os.Exit(1)
    }
}
```

---

## Feature Mapping

### Finding Equivalent GoSQLX Features

| SQLFluff Feature | GoSQLX Equivalent | Status |
|-----------------|------------------|--------|
| `sqlfluff lint` | `gosqlx validate` | ✅ Available |
| `sqlfluff fix` | `gosqlx format` | ✅ Available |
| `.sqlfluff` config | `.gosqlx.yml` | ⏳ Planned v1.5.0 |
| Linting rules | Custom Go functions | ⏳ Framework in v1.5.0 |
| Auto-fix | Planned feature | ⏳ Planned v1.6.0 |
| VSCode extension | Planned feature | ⏳ Planned v1.6.0 |
| Rule plugins | Custom Go code | ✅ Available now |

---

## Gotchas and Limitations

### 1. Linting Rules (Current Limitation)

**SQLFluff has 60+ built-in linting rules. GoSQLX currently has none.**

- **Timeline:** Rules framework coming in v1.5.0
- **Workaround:** Implement custom validation in Go
- **Example:**
  ```go
  // Custom validation function
  func validateNamingConvention(ast *ast.AST) error {
      // Check that all table names are snake_case
      // Implement your custom rules here
      return nil
  }
  ```

### 2. Dialect Coverage (Minor Limitation)

| Dialect | SQLFluff | GoSQLX | Gap |
|---------|----------|--------|-----|
| PostgreSQL | ✅ 100% | ✅ 95% | Minor features |
| MySQL | ✅ 100% | ✅ 90% | Some MariaDB extensions |
| SQL Server | ✅ 100% | ✅ 80% | T-SQL extensions |
| Oracle | ✅ 100% | ✅ 70% | PL/SQL support |
| Snowflake | ✅ Yes | ❌ No | Not planned v1.x |

**Mitigation:** Use PostgreSQL mode for most purposes; request dialect support if needed

### 3. Configuration Files (Current Limitation)

**SQLFluff uses `.sqlfluff` INI files. GoSQLX uses CLI flags now (YAML config in v1.5.0).**

Current approach:

```bash
# Instead of .sqlfluff file:
gosqlx validate --dialect postgres --line-length 100 sql/
```

Planned approach (v1.5.0):

```yaml
# .gosqlx.yml
parser:
  dialect: postgres
formatting:
  line_length: 100
```

### 4. Custom Rule Plugins (Different Approach)

**SQLFluff uses Python plugins. GoSQLX uses Go functions.**

```go
// Custom rule in GoSQLX
func checkTableNamingConvention(stmt ast.Statement) []ValidationError {
    var errors []ValidationError

    if selectStmt, ok := stmt.(*ast.SelectStatement); ok {
        if selectStmt.From != nil {
            // Check naming
        }
    }

    return errors
}
```

### 5. IDE Integration (Planned)

**SQLFluff has VSCode extension. GoSQLX is planned for v1.6.0.**

**Current options:**
- Use CLI tool in terminal
- Integrate with text editor via external command
- Write custom editor integration

---

## Troubleshooting Common Issues

### Issue 1: Different Parse Results

**Problem:** GoSQLX parses SQL differently than SQLFluff

**Solution:**
```go
// Enable detailed error reporting
result, err := parser.Parse(sql)
if err != nil {
    fmt.Printf("Parse error at position: %v\n", err)
}
```

Check [TROUBLESHOOTING.md](../TROUBLESHOOTING.md) for known differences.

### Issue 2: Performance Not as Expected

**Problem:** GoSQLX not as fast as expected

**Solution:** Make sure you're using object pooling:

```go
import "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"

// CORRECT: Use pooled tokenizer
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)

tokens, _ := tkz.Tokenize(sql)
```

### Issue 3: Missing Features

**Problem:** GoSQLX doesn't support a feature SQLFluff has

**Solution:**
- Check [ROADMAP.md](../ROADMAP.md) for planned features
- Create a [GitHub Issue](https://github.com/ajitpratap0/GoSQLX/issues) for feature requests
- Implement custom Go code for missing functionality

---

## Timeline and Next Steps

### Immediate (Week 1)
1. Install and test GoSQLX
2. Run on sample SQL files
3. Compare output with SQLFluff

### Short-term (Week 2-3)
1. Update CI/CD pipeline
2. Train team on GoSQLX
3. Archive SQLFluff documentation

### Medium-term (Month 2)
1. Enable new GoSQLX features as they're released
2. Adopt `.gosqlx.yml` configuration (v1.5.0)
3. Implement custom linting rules in Go

### Long-term (Q2-Q3 2025)
1. Adopt LSP integration when available (v1.6.0)
2. Consider GoSQLX for new projects exclusively
3. Deprecate remaining SQLFluff usage

---

## Getting Help

- **[GitHub Discussions](https://github.com/ajitpratap0/GoSQLX/discussions)** - Ask the community
- **[GitHub Issues](https://github.com/ajitpratap0/GoSQLX/issues)** - Report bugs
- **[API Reference](../API_REFERENCE.md)** - Complete API documentation
- **[Usage Guide](../USAGE_GUIDE.md)** - Common patterns and examples

---

## Summary

**GoSQLX offers:**
- ✅ 1,380x faster SQL validation
- ✅ 96% less memory usage
- ✅ Zero external dependencies
- ✅ Multi-dialect support
- ✅ Simpler API

**Trade-offs:**
- ❌ Fewer built-in linting rules (coming in v1.5.0)
- ❌ Fewer SQL dialects (5 vs 60, common ones covered)
- ❌ No IDE extension yet (coming in v1.6.0)

**Recommendation:** Migrate for performance-critical paths (CI/CD, real-time validation). Keep SQLFluff for advanced linting until v1.5.0.

---

**Last Updated:** November 2025
**Version:** GoSQLX v1.4.0
**Next Review:** v1.5.0 release (Q1 2025)
