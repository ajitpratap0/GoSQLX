# GoSQLX API Reference

GoSQLX is split into small packages with a one-way dependency chain. Most programs only need the high-level `gosqlx` package; the lower-level packages are there when you need control over pooling, tokens or individual AST nodes.

Each package has its own reference page. Signatures on [pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX) are generated from the source and are authoritative when the two disagree.

New to GoSQLX? Start with [Getting Started](GETTING_STARTED.md), then pick a task guide such as [Parse PostgreSQL in Go](guides/parse-postgresql-in-go.md) or [Extract table names from SQL in Go](guides/extract-table-names-from-sql-in-go.md).

## Packages

| Package | Import path | Use it for |
|---|---|---|
| [gosqlx](api/gosqlx.md) | `pkg/gosqlx` | Parsing, validation, formatting, linting and metadata extraction with pooling handled for you |
| [tokenizer](api/tokenizer.md) | `pkg/sql/tokenizer` | Zero-copy lexing of SQL bytes into tokens |
| [parser](api/parser.md) | `pkg/sql/parser` | Building an AST from tokens |
| [ast](api/ast.md) | `pkg/sql/ast` | Statement and expression node types, pools and visitors |
| [keywords](api/keywords.md) | `pkg/sql/keywords` | Keyword tables and dialect identifiers |
| [models](api/models.md) | `pkg/models` | Tokens, spans and source locations |
| [errors](api/errors.md) | `pkg/errors` | Structured errors with codes, positions and hints |
| [metrics](api/metrics.md) | `pkg/metrics` | Production counters and timings |
| [security](api/security.md) | `pkg/sql/security` | SQL injection pattern detection |
| [highlight](#highlight-package) | `pkg/highlight` | Dialect-aware SQL syntax highlighting as spans, ANSI, HTML and CSS |
| [linter](api/linter.md) | `pkg/linter` | The lint engine and its rules |
| [lsp](api/lsp.md) | `pkg/lsp` | The Language Server Protocol server |
| [mcp](api/mcp.md) | `pkg/mcp` | The Model Context Protocol server |
| [config](api/config.md) | `pkg/config` | Configuration loading for the CLI, LSP and library |

All import paths are relative to `github.com/ajitpratap0/GoSQLX/`.

## High-Level API

Moved to the [gosqlx package reference](api/gosqlx.md).

## Tokenizer API

Moved to the [tokenizer package reference](api/tokenizer.md).

## Parser API

Moved to the [parser package reference](api/parser.md).

## AST API

Moved to the [ast package reference](api/ast.md).

## Keywords Package

Moved to the [keywords package reference](api/keywords.md).

## Models

Moved to the [models package reference](api/models.md).

## Error Handling

Moved to the [errors package reference](api/errors.md). Every error code is listed in [Error Codes](ERROR_CODES.md).

## Metrics Package

Moved to the [metrics package reference](api/metrics.md).

## Security Package

Moved to the [security package reference](api/security.md).

## Highlight Package

`github.com/ajitpratap0/GoSQLX/pkg/highlight` classifies SQL into byte-offset spans for terminals, HTML and editors. The guide with examples is [Syntax Highlighting](HIGHLIGHTING.md).

### Spans

```go
func Spans(sql string, opts ...Option) []Span
func WithDialect(d keywords.SQLDialect) Option // type Option func(*config)

type Span struct {
    Start    int      `json:"start"`    // byte offset, inclusive
    End      int      `json:"end"`      // byte offset, exclusive
    Category Category `json:"category"`
}
func (s Span) Text(src string) string
```

`Spans` returns spans sorted by `Start` that never overlap and never carry `Plain`; uncovered bytes are plain text. It never returns an error: after the first lexical error the rest of the input is one `Error` span. Input the tokenizer refuses outright (beyond its size or token limits) yields no spans. `Spans` is safe for concurrent use. `WithDialect` accepts the dialect identifiers listed below; an empty or unknown dialect uses the generic keyword set.

### Categories

```go
type Category uint8

const (
    Plain Category = iota // never on a Span; implicit category of gaps
    Keyword
    Function
    DataType
    Identifier
    QuotedIdentifier
    String
    Number
    Constant
    Operator
    Punctuation
    Comment
    Placeholder
    Error
)

func Categories() []Category          // every category except Plain, in declaration order
func ParseCategory(name string) (Category, bool)
func (c Category) String() string     // stable name, e.g. "quoted-identifier"
```

Stable names, used as JSON values, HTML class suffixes and theme keys: `keyword`, `function`, `type` (`DataType`), `identifier`, `quoted-identifier`, `string`, `number`, `constant`, `operator`, `punctuation`, `comment`, `placeholder`, `error`. `Category` marshals to and from these names in JSON.

### Terminal Output

```go
func ANSI(src string, spans []Span, opts ANSIOptions) string
func WriteANSI(w io.Writer, src string, spans []Span, opts ANSIOptions) error

type ANSIOptions struct {
    Theme Theme     // zero Theme means DarkTheme
    Mode  ColorMode // zero value is Color256
}

type ColorMode int // Color256 (default), TrueColor, NoColor
```

`NoColor` emits only bold, italic and underline. Styles are reset before each newline and re-applied after it, so output stays correct through `head`, `grep` or a pager.

### HTML and CSS

```go
func HTML(src string, spans []Span, opts HTMLOptions) string
func WriteHTML(w io.Writer, src string, spans []Span, opts HTMLOptions) error
func CSS(theme Theme, classPrefix string) string

type HTMLOptions struct {
    ClassPrefix  string // empty means DefaultClassPrefix ("gsx-")
    InlineStyles bool   // emit style="..." from Theme instead of classes
    Theme        Theme  // used with InlineStyles; zero means DarkTheme
    Wrap         bool   // wrap in <pre class="{prefix}highlight"><code>
}

const DefaultClassPrefix = "gsx-"
```

All source text is HTML-escaped. Spans become `<span class="gsx-<category>">`. `CSS` returns one rule per category for the same class names; it styles the token classes only.

### Themes

```go
type Theme struct {
    Name   string
    Styles map[Category]Style
}

type Style struct {
    Color     string // "#RRGGBB" or "#RGB"; other values are ignored
    Bold      bool
    Italic    bool
    Underline bool
}

func DarkTheme() Theme
func LightTheme() Theme
func MonoTheme() Theme
func ThemeByName(name string) (Theme, bool) // case-insensitive
func ThemeNames() []string                  // "dark", "light", "mono"
func (t Theme) Style(c Category) Style
```

Each constructor returns a fresh copy that the caller may modify.

### High-Level Helpers (gosqlx)

```go
func gosqlx.Highlight(sql string, opts ...highlight.Option) []highlight.Span
func gosqlx.HighlightANSI(sql string, opts ...highlight.Option) string // dark theme, 256 colors
func gosqlx.HighlightHTML(sql string, opts ...highlight.Option) string // wrapped in <pre class="gsx-highlight">
```

### Dialects

`highlight.WithDialect` and the CLI `--dialect` flag accept `generic`, `postgresql`, `mysql`, `mariadb`, `sqlserver`, `oracle`, `sqlite`, `snowflake`, `bigquery`, `redshift` and `clickhouse` (the values of `keywords.AllDialects()`). With no dialect, the generic keyword set is used.

## Linter Package

Moved to the [linter package reference](api/linter.md). Every rule is listed in [Linting Rules](LINTING_RULES.md).

## LSP Package

Moved to the [lsp package reference](api/lsp.md).

## MCP Package

Moved to the [mcp package reference](api/mcp.md).

## Configuration Package

Moved to the [config package reference](api/config.md).

## Performance Considerations

### Object Pooling

**Always use `defer` with pool return functions:**

```go
// Tokenizer
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)

// Parser
p := parser.NewParser()
defer p.Release()

// AST
astObj := ast.NewAST()
defer ast.ReleaseAST(astObj)

// Statements
stmt := ast.NewSelectStatement()
defer ast.ReleaseSelectStatement(stmt)
```

### Batch Processing

Use batch functions for multiple queries:

```go
// Reuses pooled objects across the batch
asts, err := gosqlx.ParseMultiple(queries)

// More efficient validation
err := gosqlx.ValidateMultiple(queries)
```

### Context and Timeouts

Use context for long-running operations:

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

astNode, err := gosqlx.ParseWithContext(ctx, complexSQL)
```

For measured throughput and latency, see the [benchmarks page](https://gosqlx.dev/benchmarks/), which labels every number with its stage, hardware and Go version.

## Complete Example

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/security"
    "github.com/ajitpratap0/GoSQLX/pkg/metrics"
    "github.com/ajitpratap0/GoSQLX/pkg/config"
)

func main() {
    // Load configuration
    cfg, _ := config.Load(".gosqlx.yml")

    // Enable metrics
    metrics.Enable()
    defer func() {
        snapshot := metrics.GetSnapshot()
        fmt.Printf("Processed %d queries with %.2f%% success rate\n",
            snapshot.TotalQueries, snapshot.SuccessRate)
    }()

    sql := `
        -- PostgreSQL features demonstration
        WITH RECURSIVE active_users AS (
            SELECT id, name, manager_id, 1 as level
            FROM employees
            WHERE active = true AND manager_id IS NULL

            UNION ALL

            SELECT e.id, e.name, e.manager_id, au.level + 1
            FROM employees e
            INNER JOIN active_users au ON e.manager_id = au.id
            WHERE au.level < 10
        )
        SELECT DISTINCT ON (dept_id)
               u.id,
               u.name,
               COUNT(o.id) FILTER (WHERE o.status = 'completed') as completed_orders,
               STRING_AGG(o.product, ', ' ORDER BY o.date DESC NULLS LAST) as recent_products,
               ROW_NUMBER() OVER (PARTITION BY u.dept_id ORDER BY COUNT(o.id) DESC) as dept_rank,
               u.metadata->>'email' as email,
               u.metadata->'address'->>'city' as city
        FROM active_users u
        LEFT JOIN LATERAL (
            SELECT * FROM orders
            WHERE user_id = u.id
            ORDER BY order_date DESC
            LIMIT 5
        ) o ON true
        WHERE u.created_at >= '2024-01-01'
        GROUP BY u.id, u.name, u.dept_id, u.metadata
        HAVING COUNT(o.id) > 5
        ORDER BY dept_id, completed_orders DESC NULLS LAST
        FETCH FIRST 10 ROWS WITH TIES
        RETURNING u.id, u.name, completed_orders
    `

    // Parse SQL with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    astNode, err := gosqlx.ParseWithContext(ctx, sql)
    if err != nil {
        log.Fatal("Parse error:", err)
    }
    defer ast.ReleaseAST(astNode)

    // Security scan
    scanner := security.NewScanner()
    secResults := scanner.Scan(astNode)
    if secResults.HasCritical() {
        fmt.Println("CRITICAL SECURITY ISSUES FOUND:")
        for _, f := range secResults.Findings {
            if f.Severity == security.SeverityCritical {
                fmt.Printf("  - [%s] %s: %s\n", f.Severity, f.Pattern, f.Description)
            }
        }
    } else {
        fmt.Println("Security scan: CLEAN")
    }

    // Lint SQL
    lintResult, err := gosqlx.Lint(sql)
    if err != nil {
        log.Fatal(err)
    }

    if len(lintResult.Violations) > 0 {
        fmt.Printf("\nLinting violations: %d\n", len(lintResult.Violations))
        for _, v := range lintResult.Violations {
            fmt.Printf("  [%s] %s at line %d\n", v.Rule, v.Message, v.Location.Line)
        }
    } else {
        fmt.Println("Linting: PASSED")
    }

    // Analyze AST structure
    if len(astNode.Statements) > 0 {
        if stmt, ok := astNode.Statements[0].(*ast.SelectStatement); ok {
            fmt.Printf("\nQuery Analysis:\n")
            fmt.Printf("  Columns: %d\n", len(stmt.Columns))
            fmt.Printf("  DISTINCT ON: %v\n", len(stmt.DistinctOn) > 0)

            if stmt.With != nil {
                fmt.Printf("  CTEs: %d (Recursive: %v)\n",
                    len(stmt.With.CTEs), stmt.With.Recursive)
            }

            if len(stmt.Windows) > 0 {
                fmt.Printf("  Window Functions: %d\n", len(stmt.Windows))
            }

            // Check for PostgreSQL features
            hasLateral := false
            for _, from := range stmt.From {
                if from.Lateral {
                    hasLateral = true
                    break
                }
            }
            fmt.Printf("  LATERAL JOIN: %v\n", hasLateral)

            // Check for FILTER clause
            hasFilter := false
            for _, col := range stmt.Columns {
                if fc, ok := col.(*ast.FunctionCall); ok && fc.Filter != nil {
                    hasFilter = true
                    break
                }
            }
            fmt.Printf("  FILTER Clause: %v\n", hasFilter)

            if stmt.FetchClause != nil {
                fmt.Printf("  FETCH FIRST: %v rows (WITH TIES: %v)\n",
                    *stmt.FetchClause.Count, stmt.FetchClause.WithTies)
            }

            if len(stmt.Returning) > 0 {
                fmt.Printf("  RETURNING: %d columns\n", len(stmt.Returning))
            }
        }
    }

    fmt.Println("\nSQL parsed, validated, and analyzed successfully!")
}
```

**Output:**
```
Security scan: CLEAN

Linting violations: 2
  [L003] Multiple consecutive blank lines at line 11
  [L005] Line length exceeds 120 characters at line 17

Query Analysis:
  Columns: 7
  DISTINCT ON: true
  CTEs: 1 (Recursive: true)
  Window Functions: 1
  LATERAL JOIN: true
  FILTER Clause: true
  FETCH FIRST: 10 rows (WITH TIES: true)
  RETURNING: 3 columns

SQL parsed, validated, and analyzed successfully!
Processed 1 queries with 100.00% success rate
```

## Additional Resources

- [Getting Started](GETTING_STARTED.md): install and parse your first query
- [Usage Guide](USAGE_GUIDE.md): patterns for services and batch jobs
- [SQL Compatibility](SQL_COMPATIBILITY.md): dialect and feature coverage
- [Error Codes](ERROR_CODES.md): every error code with causes and fixes
- [Linting Rules](LINTING_RULES.md): all built-in lint rules
- [Configuration](CONFIGURATION.md): the `.gosqlx.yml` file
- [Benchmarks](https://gosqlx.dev/benchmarks/): measured performance with stage, hardware and Go version
- [Examples](https://github.com/ajitpratap0/GoSQLX/tree/main/examples): runnable programs
