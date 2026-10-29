# linter package

The SQL linting engine, its rule interface and the built-in rules.

Import path: `github.com/ajitpratap0/GoSQLX/pkg/linter` ([pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/linter))

Part of the [GoSQLX API reference](../API_REFERENCE.md).

The linter package provides SQL linting with 30 built-in rules (L001-L030) and auto-fix for the rules that support it. The rules live in sub-packages of `pkg/linter/rules/`. For a one-call API that runs all 30 rules, use `gosqlx.Lint`.

## Types

### `Linter`
```go
type Linter struct {
    // unexported fields: rules, ignore matcher, dialect
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
    Filename      string
    Violations    []Violation
    Error         error // File read or rule execution failure
    TokenizeError error // SQL could not be tokenized
    ParseError    error // Tokenized SQL could not be parsed
}
```

## Functions

### `(r FileResult) SyntaxError() error`
Returns `TokenizeError` when present, otherwise `ParseError`; returns nil when
the input tokenized and parsed. Empty, whitespace-only and comment-only input
is not a syntax error.

`Error` reports a failed lint operation and may accompany partial violations.
Syntax errors are recorded separately: applicable text and token rules still
run and report violations. Check both operation and syntax errors when using
linting as a validation gate.

```go
result := l.LintString(sql, "query.sql")
if result.Error != nil {
    log.Fatal(result.Error)
}
if err := result.SyntaxError(); err != nil {
    log.Fatal(err)
}
```

### `New(rules ...Rule) *Linter`
Create linter with specified rules.

```go
linter := linter.New(
    whitespace.NewTrailingWhitespaceRule(),
    whitespace.NewMixedIndentationRule(),
    keywords.NewKeywordCaseRule(keywords.CaseUpper),
)
```

### `(l *Linter) SetDialect(dialect keywords.SQLDialect)`
Select the SQL dialect used when tokenizing and parsing SQL for the rules that inspect tokens or the AST. An empty string or `keywords.DialectUnknown` restores the default dialect (PostgreSQL). Call it before linting; it is not synchronised with concurrent `Lint*` calls on the same `Linter`.

This affects dialect-specific syntax such as SQL Server `TOP` and `[bracketed]` identifiers, the MySQL/SQLite `?` placeholder or MySQL `LIMIT offset, count`.

```go
import sqlkeywords "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"

l := linter.New(rules...)
l.SetDialect(sqlkeywords.DialectSQLServer)
result := l.LintString("SELECT TOP 10 [id] FROM orders", "query.sql")
```

The CLI sets it from `gosqlx lint --dialect`.

### `(l *Linter) LintFile(filename string) FileResult`
Lint a single SQL file.

```go
// Pass the rules to run; use gosqlx.Lint to run all 30 built-in rules.
linter := linter.New(
    whitespace.NewTrailingWhitespaceRule(),
    whitespace.NewMixedIndentationRule(),
)
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

## Linting With a Dialect From gosqlx

### `gosqlx.LintWithDialect(sql string, dialect keywords.SQLDialect) (*gosqlx.LintResult, error)`
Like `gosqlx.Lint`, which runs all 30 built-in rules, but tokenizes and parses the SQL with the given dialect, so the AST-based rules (L011-L030) also run on dialect-specific syntax such as SQL Server's `TOP` or `[bracketed]` identifiers. An empty dialect behaves exactly like `gosqlx.Lint`. An unknown dialect returns an error wrapping `gosqlx.ErrUnsupportedDialect`, as `gosqlx.ParseWithDialect` does. Safe for concurrent use.

```go
result, err := gosqlx.LintWithDialect("SELECT TOP 10 [id] FROM orders", sqlkeywords.DialectSQLServer)
if err != nil {
    log.Fatal(err)
}
for _, v := range result.Violations {
    fmt.Println(linter.FormatViolation(v))
}
```

## Built-in Rules

All 30 rules are listed below. The [Linting Rules reference](../LINTING_RULES.md) documents each one with examples.

| Rule | Name | Package | Auto-Fix | Severity |
|------|------|---------|----------|----------|
| **L001** | Trailing Whitespace | `whitespace` | Yes | warning |
| **L002** | Mixed Indentation | `whitespace` | Yes | error |
| **L003** | Consecutive Blank Lines | `whitespace` | Yes | warning |
| **L004** | Indentation Depth | `whitespace` | No | warning |
| **L005** | Long Lines | `whitespace` | No | info |
| **L006** | Column Alignment | `style` | No | info |
| **L007** | Keyword Case Consistency | `keywords` | Yes | warning |
| **L008** | Comma Placement | `style` | No | info |
| **L009** | Aliasing Consistency | `style` | No | warning |
| **L010** | Redundant Whitespace | `whitespace` | Yes | info |
| **L011** | Delete Without WHERE | `safety` | No | error |
| **L012** | Update Without WHERE | `safety` | No | error |
| **L013** | Drop Without IF EXISTS | `safety` | No | warning |
| **L014** | Truncate Table | `safety` | No | warning |
| **L015** | Select Into Outfile | `safety` | No | error |
| **L016** | Select Star | `performance` | No | warning |
| **L017** | Missing WHERE on Full Scan | `performance` | No | warning |
| **L018** | Leading Wildcard LIKE | `performance` | No | warning |
| **L019** | NOT IN With NULL Risk | `performance` | No | warning |
| **L020** | Correlated Subquery in SELECT | `performance` | No | warning |
| **L021** | OR Instead of IN | `performance` | No | warning |
| **L022** | Function on Indexed Column | `performance` | No | warning |
| **L023** | Implicit Cross Join | `performance` | No | warning |
| **L024** | Table Alias Required | `naming` | No | warning |
| **L025** | Reserved Keyword Identifier | `naming` | No | warning |
| **L026** | Implicit Column List in INSERT | `naming` | No | warning |
| **L027** | UNION Instead of UNION ALL | `naming` | No | warning |
| **L028** | Missing ORDER BY with LIMIT | `naming` | No | warning |
| **L029** | Subquery Can Be JOIN | `naming` | No | warning |
| **L030** | Distinct on Many Columns | `naming` | No | warning |

**Example:**
```go
import (
    "fmt"

    "github.com/ajitpratap0/GoSQLX/pkg/linter"
    "github.com/ajitpratap0/GoSQLX/pkg/linter/rules/keywords"
    "github.com/ajitpratap0/GoSQLX/pkg/linter/rules/safety"
    "github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
)

// Create a linter from the rules you want
l := linter.New(
    whitespace.NewTrailingWhitespaceRule(),
    whitespace.NewRedundantWhitespaceRule(),
    keywords.NewKeywordCaseRule(keywords.CaseUpper),
    safety.NewDeleteWithoutWhereRule(),
)

// Lint SQL
result := l.LintString("select  *  from users", "test.sql")

// Output violations
for _, v := range result.Violations {
    fmt.Println(linter.FormatViolation(v))
}
```

**Auto-Fix Example:**
```go
// Get violations that can be auto-fixed
autoFixableRules := []linter.Rule{
    whitespace.NewTrailingWhitespaceRule(),
    keywords.NewKeywordCaseRule(keywords.CaseUpper),
    whitespace.NewRedundantWhitespaceRule(),
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
