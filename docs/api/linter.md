# linter package

The SQL linting engine, its rule interface and the built-in rules.

Import path: `github.com/ajitpratap0/GoSQLX/pkg/linter` ([pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/linter))

Part of the [GoSQLX API reference](../API_REFERENCE.md).

The linter package provides SQL linting with 10 built-in rules (L001-L010) and auto-fix capabilities.

## Types

### `Linter`
```go
type Linter struct {
    rules []Rule
}
```

### `Rule` (Interface)
```go
type Rule interface {
    ID() string                                 // Rule ID (e.g., "L001")
    Name() string                               // Human-readable name
    Description() string                        // What the rule checks
    Severity() Severity                         // Default severity
    Check(ctx *Context) ([]Violation, error)   // Perform check
    CanAutoFix() bool                           // Whether auto-fix is supported
    Fix(content string, violations []Violation) (string, error) // Apply fixes
}
```

### `Severity`
```go
type Severity string

const (
    SeverityError   Severity = "error"
    SeverityWarning Severity = "warning"
    SeverityInfo    Severity = "info"
)
```

### `Violation`
```go
type Violation struct {
    Rule       string          // Rule ID (e.g., "L001")
    RuleName   string          // Human-readable rule name
    Severity   Severity        // Severity level
    Message    string          // Violation description
    Location   models.Location // Position in source (1-based)
    Line       string          // The actual line content
    Suggestion string          // How to fix the violation
    CanAutoFix bool            // Whether this violation can be auto-fixed
}
```

### `Result`
```go
type Result struct {
    Files           []FileResult
    TotalFiles      int
    TotalViolations int
}
```

### `FileResult`
```go
type FileResult struct {
    Filename   string
    Violations []Violation
    Error      error
}
```

## Functions

### `New(rules ...Rule) *Linter`
Create linter with specified rules.

```go
linter := linter.New(
    rules.NewTrailingWhitespaceRule(),
    rules.NewMixedTabsSpacesRule(),
    rules.NewKeywordCaseRule(),
)
```

### `(l *Linter) LintFile(filename string) FileResult`
Lint a single SQL file.

```go
linter := linter.New(rules.AllRules()...)
result := linter.LintFile("query.sql")

for _, violation := range result.Violations {
    fmt.Println(linter.FormatViolation(violation))
}
```

### `(l *Linter) LintString(sql string, filename string) FileResult`
Lint SQL content provided as a string.

```go
result := linter.LintString("SELECT * from users", "inline.sql")
```

### `(l *Linter) LintFiles(filenames []string) Result`
Lint multiple files.

```go
result := linter.LintFiles([]string{"query1.sql", "query2.sql"})
fmt.Printf("Total violations: %d\n", result.TotalViolations)
```

### `(l *Linter) LintDirectory(dir string, pattern string) Result`
Recursively lint all SQL files matching pattern in directory.

```go
result := linter.LintDirectory("./sql", "*.sql")
```

### `FormatViolation(v Violation) string`
Format violation for display.

### `FormatResult(result Result) string`
Format linting results for display.

## Built-in Rules (v1.6.0)

| Rule | Name | Description | Auto-Fix | Severity |
|------|------|-------------|----------|----------|
| **L001** | Trailing Whitespace | Detects trailing whitespace at end of lines | ✅ Yes | warning |
| **L002** | Mixed Tabs/Spaces | Detects mixed tab and space indentation | ❌ No | error |
| **L003** | Consecutive Blank Lines | Detects multiple consecutive blank lines | ✅ Yes | warning |
| **L004** | Indentation Depth | Warns on excessive nesting (>4 levels) | ❌ No | warning |
| **L005** | Line Length | Warns on long lines (configurable, default 120 chars) | ❌ No | warning |
| **L006** | Column Alignment | Checks SELECT column alignment consistency | ❌ No | info |
| **L007** | Keyword Case | Enforces uppercase/lowercase keywords (configurable) | ✅ Yes | warning |
| **L008** | Comma Placement | Checks trailing vs leading comma style | ❌ No | info |
| **L009** | Aliasing Consistency | Detects mixed table aliasing (AS vs no AS) | ❌ No | warning |
| **L010** | Redundant Whitespace | Finds multiple consecutive spaces | ✅ Yes | warning |

**Example:**
```go
import (
    "github.com/ajitpratap0/GoSQLX/pkg/linter"
    "github.com/ajitpratap0/GoSQLX/pkg/linter/rules"
)

// Create linter with all rules
l := linter.New(rules.AllRules()...)

// Lint SQL
sql := `SELECT  *  from   users
WHERE  id=1`

result := l.LintString(sql, "test.sql")

// Output violations
for _, v := range result.Violations {
    fmt.Println(linter.FormatViolation(v))
}
// [L010] Redundant Whitespace at line 1, column 7
//   Severity: warning
//   Multiple consecutive spaces found
//
// [L007] Keyword Case at line 1, column 16
//   Severity: warning
//   Keyword 'from' should be uppercase
//
// [L001] Trailing Whitespace at line 1, column 26
//   Severity: warning
//   Trailing whitespace found
```

**Auto-Fix Example:**
```go
// Get violations that can be auto-fixed
autoFixableRules := []linter.Rule{
    rules.NewTrailingWhitespaceRule(),
    rules.NewKeywordCaseRule(),
    rules.NewRedundantWhitespaceRule(),
}

l := linter.New(autoFixableRules...)
result := l.LintString(sql, "test.sql")

// Apply auto-fixes
fixed := sql
for _, rule := range autoFixableRules {
    if rule.CanAutoFix() {
        violations := filterByRule(result.Violations, rule.ID())
        fixed, _ = rule.Fix(fixed, violations)
    }
}

fmt.Println(fixed)
// Output: SELECT * FROM users
// WHERE id=1
```
