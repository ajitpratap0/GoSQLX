# SQL Linter Package

## Overview

The `linter` package provides a comprehensive SQL linting rules engine similar to SQLFluff. It offers code style checking, auto-fix capabilities, and extensible rule system for SQL quality enforcement.

**Status**: Phase 1a Complete (3/10 rules implemented)
**Test Coverage**: 98.1% (exceeded 70% target by +28%)

## Key Features

- **Extensible Rule System**: Plugin-based architecture for custom rules
- **Auto-Fix Capability**: Automatic correction for applicable violations
- **Multi-Input Support**: Files, directories (recursive), stdin
- **Severity Levels**: Error, Warning, Info
- **CLI Integration**: `gosqlx lint` command
- **Context-Aware**: Access to SQL text, tokens, and AST
- **Thread-Safe**: Safe for concurrent linting operations

## Implemented Rules (Phase 1a)

| Rule | Name | Severity | Auto-Fix | Status |
|------|------|----------|----------|--------|
| L001 | Trailing Whitespace | Warning | ✅ Yes | ✅ Complete |
| L002 | Mixed Indentation | Error | ✅ Yes | ✅ Complete |
| L005 | Long Lines | Info | ❌ No | ✅ Complete |

## Planned Rules (Phase 1)

| Rule | Name | Status |
|------|------|--------|
| L003 | Consecutive Blank Lines | 📋 Planned |
| L004 | Indentation Depth | 📋 Planned |
| L006 | SELECT Column Alignment | 📋 Planned |
| L007 | Keyword Case Consistency | 📋 Planned |
| L008 | Comma Placement | 📋 Planned |
| L009 | Aliasing Consistency | 📋 Planned |
| L010 | Redundant Whitespace | 📋 Planned |

## Usage

### CLI Usage

```bash
# Lint a single file
gosqlx lint query.sql

# Auto-fix violations
gosqlx lint --auto-fix query.sql

# Lint directory recursively
gosqlx lint -r ./sql-queries/

# Custom max line length
gosqlx lint --max-length 120 query.sql

# Lint from stdin
cat query.sql | gosqlx lint
echo "SELECT * FROM users" | gosqlx lint
```

### Programmatic Usage

```go
package main

import (
    "github.com/ajitpratap0/GoSQLX/pkg/linter"
    "github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
)

func main() {
    // Create linter with rules
    l := linter.New(
        whitespace.NewTrailingWhitespaceRule(),
        whitespace.NewMixedIndentationRule(),
        whitespace.NewLongLinesRule(100), // Max 100 chars
    )

    // Lint SQL string
    sql := `SELECT * FROM users WHERE active = true  `  // Trailing space
    results, err := l.LintString(sql, "query.sql")
    if err != nil {
        // Handle error
    }

    // Check violations
    for _, result := range results {
        for _, violation := range result.Violations {
            fmt.Printf("[%s] Line %d: %s\n",
                violation.RuleID,
                violation.Line,
                violation.Message)
        }
    }
}
```

### Auto-Fix Example

```go
l := linter.New(
    whitespace.NewTrailingWhitespaceRule(),
    whitespace.NewMixedIndentationRule(),
)

sql := `SELECT *
FROM users	WHERE active = true`  // Mixed tabs/spaces, trailing space

// Lint and get violations
results, _ := l.LintString(sql, "query.sql")

// Auto-fix violations
for _, result := range results {
    for _, violation := range result.Violations {
        if violation.CanAutoFix {
            fixedSQL, err := violation.Fix(sql)
            if err == nil {
                sql = fixedSQL
            }
        }
    }
}

fmt.Println(sql)  // Cleaned SQL
```

## Architecture

### Core Components

#### Rule Interface

```go
type Rule interface {
    ID() string           // L001, L002, etc.
    Name() string         // Human-readable name
    Description() string  // Detailed description
    Severity() Severity   // Error, Warning, Info
    Check(ctx *Context) ([]Violation, error)
    CanAutoFix() bool
    Fix(content string, violations []Violation) (string, error)
}
```

#### Context

Provides access to SQL analysis results:

```go
type Context struct {
    SQL      string                     // Raw SQL
    Filename string                     // Source file name
    Lines    []string                   // Split by line
    Tokens   []models.TokenWithSpan     // Tokenization result
    AST      *ast.AST                   // Parsed AST (if available)
    Errors   []error                    // Parse errors
}
```

#### Violation

Represents a rule violation:

```go
type Violation struct {
    RuleID      string
    Message     string
    Line        int
    Column      int
    Severity    Severity
    CanAutoFix  bool
}
```

### Package Structure

```
pkg/linter/
├── rule.go           # Rule interface, BaseRule, Violation
├── context.go        # Linting context
├── linter.go         # Main linter engine
└── rules/
    └── whitespace/
        ├── trailing_whitespace.go
        ├── mixed_indentation.go
        └── long_lines.go
```

## Creating Custom Rules

### Simple Rule Example

```go
package myrules

import "github.com/ajitpratap0/GoSQLX/pkg/linter"

type MyCustomRule struct {
    linter.BaseRule
}

func NewMyCustomRule() *MyCustomRule {
    return &MyCustomRule{
        BaseRule: linter.NewBaseRule(
            "C001",                  // Rule ID
            "My Custom Rule",        // Name
            "Checks custom pattern", // Description
            linter.SeverityWarning,  // Severity
            false,                   // CanAutoFix
        ),
    }
}

func (r *MyCustomRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
    violations := []linter.Violation{}

    // Iterate through lines
    for lineNum, line := range ctx.Lines {
        // Check for your pattern
        if /* violation found */ {
            violations = append(violations, linter.Violation{
                RuleID:     r.ID(),
                Message:    "Custom violation message",
                Line:       lineNum + 1,  // 1-based
                Column:     0,
                Severity:   r.Severity(),
                CanAutoFix: false,
            })
        }
    }

    return violations, nil
}
```

### Rule with Auto-Fix

```go
func (r *MyCustomRule) CanAutoFix() bool {
    return true
}

func (r *MyCustomRule) Fix(content string, violations []linter.Violation) (string, error) {
    // Apply fixes to content
    fixed := content

    for _, violation := range violations {
        // Apply fix for this violation
        // ...
    }

    return fixed, nil
}
```

## Testing

Run linter tests:

```bash
# All linter tests (98.1% coverage)
go test -v ./pkg/linter/...

# With race detection
go test -race ./pkg/linter/...

# Specific rules
go test -v ./pkg/linter/rules/whitespace/

# Coverage report
go test -cover -coverprofile=coverage.out ./pkg/linter/...
go tool cover -html=coverage.out
```

## Performance

### Benchmarks

```bash
go test -bench=. -benchmem ./pkg/linter/...
```

### Characteristics

- **Speed**: Designed for batch processing of large SQL codebases
- **Memory**: Leverages existing tokenizer/parser infrastructure
- **Graceful Degradation**: Works even if parsing fails (text-only rules)
- **Concurrent-Safe**: Thread-safe for parallel file processing

## Best Practices

### 1. Use Appropriate Severity

```go
// Critical violations (prevents execution)
linter.SeverityError

// Style violations (should fix)
linter.SeverityWarning

// Informational (nice to have)
linter.SeverityInfo
```

### 2. Provide Clear Messages

```go
// GOOD: Specific, actionable message
"Line exceeds maximum length of 100 characters (current: 125 chars)"

// BAD: Vague message
"Line too long"
```

### 3. Implement Auto-Fix When Possible

```go
// Auto-fix for deterministic corrections
rule.CanAutoFix() == true

// Manual review for complex/ambiguous cases
rule.CanAutoFix() == false
```

## CLI Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| 0 | No violations found |
| 1 | Violations found (errors or warnings) |
| 2 | Linter execution error |

## Configuration (Future)

Configuration file support planned:

```yaml
# .gosqlx.yml
linter:
  rules:
    L001: enabled   # Trailing whitespace
    L002: enabled   # Mixed indentation
    L005:
      enabled: true
      max-length: 120  # Custom max line length
```

## Examples

### Example 1: Trailing Whitespace (L001)

```sql
-- VIOLATION
SELECT * FROM users
-- Trailing spaces ^^

-- FIXED
SELECT * FROM users
```

### Example 2: Mixed Indentation (L002)

```sql
-- VIOLATION
SELECT *
    FROM users  -- 4 spaces
	WHERE id = 1  -- Tab character

-- FIXED (converted to spaces)
SELECT *
    FROM users
    WHERE id = 1
```

### Example 3: Long Lines (L005)

```sql
-- VIOLATION (assuming max-length=80)
SELECT very_long_column_name, another_long_column, yet_another_column, and_more FROM users;

-- SUGGESTION: Break into multiple lines
SELECT
    very_long_column_name,
    another_long_column,
    yet_another_column,
    and_more
FROM users;
```

## Related Packages

- **tokenizer**: Provides tokens for token-based rules
- **parser**: Provides AST for semantic rules
- **ast**: AST node types for tree traversal

## Documentation

- [Main API Reference](../../docs/API_REFERENCE.md)
- [CLI Guide](../../docs/CLI_GUIDE.md)
- [Examples](../../examples/linter-example/)

## Roadmap

### Phase 1 (10 basic rules)
- [x] L001: Trailing Whitespace
- [x] L002: Mixed Indentation
- [x] L005: Long Lines
- [ ] L003: Consecutive Blank Lines
- [ ] L004: Indentation Depth
- [ ] L006: SELECT Column Alignment
- [ ] L007: Keyword Case Consistency
- [ ] L008: Comma Placement
- [ ] L009: Aliasing Consistency
- [ ] L010: Redundant Whitespace

### Phase 2 (10 more rules)
- Naming conventions
- Style consistency
- Custom rule API

### Phase 3 (20 advanced rules)
- Complexity analysis
- Performance anti-patterns
- Rule packs (postgres, mysql, style)

## Version History

- **v1.5.0**: Phase 1b - 98.1% test coverage, bug fixes
- **v1.5.0**: Phase 1a - Initial release with 3 whitespace rules
