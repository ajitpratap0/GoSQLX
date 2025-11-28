# GoSQLX API Reference

## Table of Contents

- [Package Overview](#package-overview)
- [High-Level API (pkg/gosqlx)](#high-level-api)
- [Tokenizer API](#tokenizer-api)
- [Parser API](#parser-api)
- [AST API](#ast-api)
- [Keywords Package](#keywords-package)
- [Models](#models)
- [Error Handling](#error-handling)
- [Metrics Package](#metrics-package)
- [Security Package](#security-package)
- [Linter Package](#linter-package)

## Package Overview

GoSQLX is organized into the following packages:

```
github.com/ajitpratap0/GoSQLX/
├── pkg/
│   ├── gosqlx/          # High-level convenience API
│   ├── models/          # Core data structures (100% coverage)
│   ├── sql/
│   │   ├── tokenizer/   # SQL lexical analysis (75.3% coverage)
│   │   ├── parser/      # SQL syntax parsing (76.1% coverage)
│   │   ├── ast/         # Abstract syntax tree (80.3% coverage)
│   │   ├── keywords/    # SQL keyword definitions (100% coverage)
│   │   ├── token/       # Token types and utilities (68.8% coverage)
│   │   ├── security/    # SQL injection detection (90.2% coverage)
│   │   └── monitor/     # Parser monitoring (98.6% coverage)
│   ├── errors/          # Structured error handling (91.9% coverage)
│   ├── metrics/         # Performance monitoring (73.9% coverage)
│   ├── linter/          # SQL linting rules engine (96.7% coverage)
│   ├── lsp/             # Language Server Protocol (70.2% coverage)
│   ├── config/          # Configuration management (81.8% coverage)
│   └── gosqlx/testing/  # Testing utilities (95.0% coverage)
```

---

## High-Level API

### Package: `github.com/ajitpratap0/GoSQLX/pkg/gosqlx`

The high-level API provides convenient functions with automatic object pool management.

### Parsing Functions

#### `Parse(sql string) (*ast.AST, error)`
Parse SQL in a single call.

```go
astNode, err := gosqlx.Parse("SELECT * FROM users WHERE active = true")
if err != nil {
    log.Fatal(err)
}
defer ast.ReleaseAST(astNode)
```

#### `ParseWithContext(ctx context.Context, sql string) (*ast.AST, error)`
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

#### `ParseWithTimeout(sql string, timeout time.Duration) (*ast.AST, error)`
Convenience wrapper with automatic timeout.

```go
astNode, err := gosqlx.ParseWithTimeout(sql, 10*time.Second)
defer ast.ReleaseAST(astNode)
```

#### `ParseBytes(sql []byte) (*ast.AST, error)`
Parse from byte slice (zero-copy when already in bytes).

```go
sqlBytes, _ := os.ReadFile("query.sql")
astNode, err := gosqlx.ParseBytes(sqlBytes)
defer ast.ReleaseAST(astNode)
```

#### `MustParse(sql string) *ast.AST`
Parse SQL, panicking on error (for tests and initialization).

```go
ast := gosqlx.MustParse("SELECT 1")
defer ast.ReleaseAST(ast)
```

#### `ParseMultiple(queries []string) ([]*ast.AST, error)`
Parse multiple SQL statements efficiently (40-60% faster than individual Parse calls).

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

### Validation Functions

#### `Validate(sql string) error`
Check if SQL is syntactically valid.

```go
if err := gosqlx.Validate("SELECT * FROM users"); err != nil {
    fmt.Printf("Invalid SQL: %v\n", err)
}
```

#### `ValidateMultiple(queries []string) error`
Validate multiple queries efficiently.

```go
queries := []string{"SELECT * FROM users", "INSERT INTO logs (msg) VALUES ('test')"}
if err := gosqlx.ValidateMultiple(queries); err != nil {
    log.Fatal("Validation failed:", err)
}
```

---

## Tokenizer API

### Package: `github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer`

### Functions

#### `GetTokenizer() *Tokenizer`
Retrieve tokenizer from pool.

```go
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz) // ALWAYS defer
```

#### `PutTokenizer(t *Tokenizer)`
Return tokenizer to pool.

### Type: `Tokenizer`

#### `Tokenize(input []byte) ([]models.TokenWithSpan, error)`
Tokenize SQL with zero-copy operation and position tracking.

```go
tokens, err := tkz.Tokenize([]byte("SELECT * FROM users"))
```

#### `TokenizeContext(ctx context.Context, input []byte) ([]models.TokenWithSpan, error)`
Tokenize with context support.

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
tokens, err := tkz.TokenizeContext(ctx, []byte("SELECT * FROM users"))
```

### Supported Token Types

| Token Type | Example |
|------------|---------|
| `TokenTypeSelect` | `SELECT` |
| `TokenTypeFrom` | `FROM` |
| `TokenTypeWhere` | `WHERE` |
| `TokenTypeIdentifier` | `users`, `id` |
| `TokenTypeNumber` | `42`, `3.14` |
| `TokenTypeSingleQuotedString` | `'hello'` |
| `TokenTypeDoubleQuotedString` | `"column name"` |
| `TokenTypeBacktickIdentifier` | `` `column` `` |

**Features:**
- Unicode support (UTF-8)
- Dialect-specific tokens (PostgreSQL `@>`, MySQL backticks, etc.)
- Zero-copy operations
- Position tracking (line, column)

---

## Parser API

### Package: `github.com/ajitpratap0/GoSQLX/pkg/sql/parser`

### Functions

#### `NewParser() *Parser`
Create parser from pool.

```go
p := parser.NewParser()
defer p.Release() // ALWAYS defer
```

### Type: `Parser`

#### `Parse(tokens []token.Token) (*ast.AST, error)`
Parse tokens into AST.

```go
astNode, err := p.Parse(tokens)
```

**Supported Statements:**
- DML: SELECT, INSERT, UPDATE, DELETE, MERGE
- DDL: CREATE TABLE/INDEX/VIEW/MATERIALIZED VIEW, ALTER TABLE, DROP
- Advanced: CTEs, window functions, set operations (UNION/EXCEPT/INTERSECT)
- Grouping: ROLLUP, CUBE, GROUPING SETS

#### `ParseContext(ctx context.Context, tokens []token.Token) (*ast.AST, error)`
Parse with context support.

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
astNode, err := p.ParseContext(ctx, tokens)
```

#### `Reset()`
Reset parser state for reuse.

---

## AST API

### Package: `github.com/ajitpratap0/GoSQLX/pkg/sql/ast`

### Core Interfaces

#### Interface: `Node`
Base interface for all AST nodes.

```go
type Node interface {
    TokenLiteral() string
    Children() []Node
}
```

#### Interface: `Statement`
Executable SQL statements.

```go
type Statement interface {
    Node
    statementNode()
}
```

#### Interface: `Expression`
SQL expressions (values, conditions, computations).

```go
type Expression interface {
    Node
    expressionNode()
}
```

### DML Statement Types

#### `SelectStatement`
```go
type SelectStatement struct {
    With      *WithClause
    Distinct  bool
    Columns   []Expression
    From      []TableReference
    Joins     []JoinClause
    Where     Expression
    GroupBy   []Expression        // Supports ROLLUP, CUBE, GROUPING SETS
    Having    Expression
    Windows   []WindowSpec
    OrderBy   []OrderByExpression // Supports NULLS FIRST/LAST
    Limit     *int
    Offset    *int
}
```

**Example:**
```go
if stmt, ok := astNode.(*ast.SelectStatement); ok {
    for _, col := range stmt.Columns {
        fmt.Println("Column:", col.TokenLiteral())
    }
}
```

#### `InsertStatement`
```go
type InsertStatement struct {
    With       *WithClause
    TableName  string
    Columns    []Expression
    Values     []Expression
    Query      *SelectStatement
    Returning  []Expression
    OnConflict *OnConflict
}
```

#### `UpdateStatement`
```go
type UpdateStatement struct {
    With      *WithClause
    TableName string
    Updates   []UpdateExpression
    From      []TableReference
    Where     Expression
    Returning []Expression
}
```

#### `DeleteStatement`
```go
type DeleteStatement struct {
    With      *WithClause
    TableName string
    Using     []TableReference
    Where     Expression
    Returning []Expression
}
```

#### `MergeStatement`
```go
type MergeStatement struct {
    TargetTable TableReference
    TargetAlias string
    SourceTable TableReference
    SourceAlias string
    OnCondition Expression
    WhenClauses []*MergeWhenClause
}
```

### DDL Statement Types

#### `CreateTableStatement`
```go
type CreateTableStatement struct {
    IfNotExists bool
    Temporary   bool
    Name        string
    Columns     []ColumnDef
    Constraints []TableConstraint
    PartitionBy *PartitionBy
    Options     []TableOption
}
```

#### `CreateIndexStatement`
```go
type CreateIndexStatement struct {
    Name        string
    Unique      bool
    TableName   string
    Columns     []IndexColumn
    Where       Expression
    Using       string
    Concurrently bool
}
```

#### `CreateViewStatement`
```go
type CreateViewStatement struct {
    Name          string
    Columns       []string
    Query         *SelectStatement
    OrReplace     bool
    Temporary     bool
    Recursive     bool
    CheckOption   string
}
```

#### `CreateMaterializedViewStatement`
```go
type CreateMaterializedViewStatement struct {
    Name     string
    Columns  []string
    Query    *SelectStatement
    WithData bool
}
```

#### `AlterTableStatement`
```go
type AlterTableStatement struct {
    TableName string
    Actions   []AlterAction
}
```

#### `DropStatement`
```go
type DropStatement struct {
    ObjectType string // TABLE, INDEX, VIEW, etc.
    ObjectName string
    IfExists   bool
    Cascade    bool
}
```

### CTE and Set Operations

#### `WithClause`
```go
type WithClause struct {
    Recursive bool
    CTEs      []CommonTableExpr
}
```

#### `CommonTableExpr`
```go
type CommonTableExpr struct {
    Name    string
    Columns []string
    Query   *SelectStatement
}
```

#### `SetOperation`
```go
type SetOperation struct {
    Left      *SelectStatement
    Operator  string // UNION, EXCEPT, INTERSECT
    All       bool
    Right     *SelectStatement
}
```

### Grouping Set Types

#### `RollupExpression`
```go
type RollupExpression struct {
    Expressions []Expression
}
```

#### `CubeExpression`
```go
type CubeExpression struct {
    Expressions []Expression
}
```

#### `GroupingSetsExpression`
```go
type GroupingSetsExpression struct {
    Sets [][]Expression
}
```

### Window Function Types

#### `WindowSpec`
```go
type WindowSpec struct {
    Name        string
    PartitionBy []Expression
    OrderBy     []OrderByExpression
    Frame       *WindowFrame
}
```

#### `WindowFrame`
```go
type WindowFrame struct {
    Type  string // ROWS or RANGE
    Start *FrameBound
    End   *FrameBound
}
```

#### `FrameBound`
```go
type FrameBound struct {
    Type       string // UNBOUNDED, CURRENT, PRECEDING, FOLLOWING
    Expression Expression
}
```

### Expression Types

#### `Identifier`
```go
type Identifier struct {
    Value string
}
```

#### `LiteralValue`
```go
type LiteralValue struct {
    Type  string // STRING, NUMBER, BOOLEAN, NULL
    Value string
}
```

#### `BinaryExpression`
```go
type BinaryExpression struct {
    Left     Expression
    Operator string
    Right    Expression
}
```

#### `FunctionCall`
```go
type FunctionCall struct {
    Name     string
    Args     []Expression
    Distinct bool
    Filter   Expression
    Over     *WindowSpec
}
```

#### `CaseExpression`
```go
type CaseExpression struct {
    CaseExpr  Expression
    WhenPairs []WhenPair
    ElseExpr  Expression
}
```

#### `InExpression`
```go
type InExpression struct {
    Expr   Expression
    Not    bool
    Values []Expression
    Query  *SelectStatement
}
```

#### `BetweenExpression`
```go
type BetweenExpression struct {
    Expr  Expression
    Not   bool
    Lower Expression
    Upper Expression
}
```

#### `SubqueryExpression`
```go
type SubqueryExpression struct {
    Query *SelectStatement
}
```

### Supporting Types

#### `JoinClause`
```go
type JoinClause struct {
    Type      string // INNER, LEFT, RIGHT, FULL, CROSS, NATURAL
    Table     TableReference
    Condition Expression
    Using     []string
}
```

#### `OrderByExpression`
```go
type OrderByExpression struct {
    Expression Expression
    Descending bool
    NullsFirst bool
    NullsLast  bool
}
```

#### `TableReference`
```go
type TableReference struct {
    Name    string
    Alias   string
    Lateral bool
    Query   *SelectStatement
}
```

### Object Pool Functions

#### `NewAST() *AST`
Get AST from pool.

```go
astObj := ast.NewAST()
defer ast.ReleaseAST(astObj)
```

#### `ReleaseAST(a *AST)`
Return AST to pool.

#### `NewSelectStatement() *SelectStatement`
Get SELECT statement from pool.

```go
stmt := ast.NewSelectStatement()
defer ast.ReleaseSelectStatement(stmt)
```

**Pool Functions Available For:**
- `SelectStatement`, `InsertStatement`, `UpdateStatement`, `DeleteStatement`
- `Identifier`, `BinaryExpression`, `LiteralValue`

### Visitor Pattern

#### Interface: `Visitor`
```go
type Visitor interface {
    Visit(node Node) Visitor
}
```

**Example:**
```go
type TableCollector struct {
    Tables []string
}

func (tc *TableCollector) Visit(node ast.Node) ast.Visitor {
    if sel, ok := node.(*ast.SelectStatement); ok {
        tc.Tables = append(tc.Tables, sel.TableName)
    }
    return tc
}

collector := &TableCollector{}
ast.Walk(collector, astNode)
```

---

## Keywords Package

### Package: `github.com/ajitpratap0/GoSQLX/pkg/sql/keywords`

### Core Types

#### `Category` (Type)
```go
const (
    CategoryReserved Category = iota
    CategoryDML
    CategoryDDL
    CategoryDataType
    CategoryFunction
    CategoryOperator
    CategoryJoin
    CategoryWindow
    CategoryAggregate
)
```

### Functions

#### `IsKeyword(word string) bool`
Check if string is a SQL keyword.

```go
keywords.IsKeyword("SELECT") // true
```

#### `GetCategory(word string) (Category, bool)`
Get keyword category.

```go
cat, ok := keywords.GetCategory("SELECT")
```

#### `IsDMLKeyword(word string) bool`
Check if DML keyword.

#### `IsDDLKeyword(word string) bool`
Check if DDL keyword.

#### `IsReserved(word string) bool`
Check if reserved keyword.

#### `IsFunction(word string) bool`
Check if function name.

#### `IsAggregate(word string) bool`
Check if aggregate function.

#### `IsWindowFunction(word string) bool`
Check if window function.

#### `IsDataType(word string) bool`
Check if data type.

#### `GetAllKeywords() []string`
Get all keywords.

#### `GetKeywordsByCategory(cat Category) []string`
Get keywords by category.

### Dialect-Specific Functions

#### `IsPostgreSQLKeyword(word string) bool`
#### `IsMySQLKeyword(word string) bool`
#### `IsSQLServerKeyword(word string) bool`
#### `IsOracleKeyword(word string) bool`
#### `IsSQLiteKeyword(word string) bool`

#### `GetSuggestions(prefix string, maxResults int) []string`
Get keyword suggestions for autocomplete.

```go
suggestions := keywords.GetSuggestions("SEL", 5)
// Returns: ["SELECT"]
```

---

## Models

### Package: `github.com/ajitpratap0/GoSQLX/pkg/models`

### Core Types

#### `TokenType` (Type)
```go
type TokenType int
```

Constants: `TokenTypeSelect`, `TokenTypeFrom`, `TokenTypeWhere`, `TokenTypeIdentifier`, etc.

#### `TokenWithSpan`
```go
type TokenWithSpan struct {
    Type  TokenType
    Value string
    Span  Span
}
```

#### `Span`
```go
type Span struct {
    Start Location
    End   Location
}
```

#### `Location`
```go
type Location struct {
    Line   int
    Column int
    Offset int
}
```

### Functions

#### `NewTokenWithSpan(tokenType TokenType, value string, span Span) TokenWithSpan`
Create token with span.

#### `(t TokenType) String() string`
Get string representation.

---

## Error Handling

### Package: `github.com/ajitpratap0/GoSQLX/pkg/errors`

### Types

#### `Error`
```go
type Error struct {
    Code     ErrorCode
    Message  string
    Location *models.Location
    Context  string
}
```

#### `ErrorCode` (Type)
```go
const (
    ErrCodeSyntax ErrorCode = iota
    ErrCodeUnexpectedToken
    ErrCodeUnexpectedEOF
    ErrCodeInvalidIdentifier
    ErrCodeUnsupportedFeature
    ErrCodeInvalidExpression
)
```

### Functions

#### `NewSyntaxError(msg string, loc *models.Location) *Error`
Create syntax error.

```go
err := errors.NewSyntaxError("Expected FROM", &location)
```

#### `NewUnexpectedTokenError(expected, got string, loc *models.Location) *Error`
Create unexpected token error.

#### `NewUnexpectedEOFError(loc *models.Location) *Error`
Create unexpected EOF error.

#### `(e *Error) Error() string`
Get error message.

#### `(e *Error) WithContext(ctx string) *Error`
Add context to error.

---

## Metrics Package

### Package: `github.com/ajitpratap0/GoSQLX/pkg/metrics`

### Configuration

#### `Enable()`
Enable metrics collection.

```go
metrics.Enable()
```

#### `Disable()`
Disable metrics collection.

#### `IsEnabled() bool`
Check if enabled.

#### `Reset()`
Reset all metrics.

### Recording Functions

#### `RecordTokenization(querySize int, tokenCount int)`
Record tokenization metrics.

#### `RecordParsing(success bool, duration time.Duration)`
Record parsing metrics.

#### `RecordPoolGet(poolName string)`
Record pool get operation.

#### `RecordPoolPut(poolName string)`
Record pool put operation.

#### `RecordPoolHit(poolName string)`
Record pool cache hit.

#### `RecordPoolMiss(poolName string)`
Record pool cache miss.

#### `RecordError(errType string)`
Record error occurrence.

### Query Functions

#### `GetSnapshot() MetricsSnapshot`
Get current metrics snapshot.

```go
snapshot := metrics.GetSnapshot()
fmt.Printf("Total queries: %d\n", snapshot.TotalQueries)
fmt.Printf("Success rate: %.2f%%\n", snapshot.SuccessRate)
```

#### `MetricsSnapshot`
```go
type MetricsSnapshot struct {
    TotalQueries      int64
    SuccessfulQueries int64
    FailedQueries     int64
    SuccessRate       float64
    TotalTokens       int64
    AvgTokensPerQuery float64
    PoolStats         map[string]PoolStats
    ErrorCounts       map[string]int64
}
```

#### `PoolStats`
```go
type PoolStats struct {
    Gets     int64
    Puts     int64
    Hits     int64
    Misses   int64
    HitRate  float64
}
```

---

## Security Package

### Package: `github.com/ajitpratap0/GoSQLX/pkg/sql/security`

### Types

#### `Scanner`
```go
type Scanner struct {
    Patterns []Pattern
}
```

#### `Pattern`
```go
type Pattern struct {
    Name        string
    Pattern     *regexp.Regexp
    Severity    Severity
    Description string
}
```

#### `Severity`
```go
type Severity int

const (
    SeverityLow Severity = iota
    SeverityMedium
    SeverityHigh
    SeverityCritical
)
```

#### `Finding`
```go
type Finding struct {
    Pattern     string
    Severity    Severity
    Location    string
    Description string
    Match       string
}
```

### Functions

#### `NewScanner() *Scanner`
Create security scanner.

```go
scanner := security.NewScanner()
```

#### `(s *Scanner) Scan(sql string) []Finding`
Scan SQL for security issues.

```go
findings := scanner.Scan("SELECT * FROM users WHERE id = '" + userInput + "'")
for _, f := range findings {
    fmt.Printf("Security issue: %s (Severity: %v)\n", f.Description, f.Severity)
}
```

#### `(s *Scanner) AddPattern(pattern Pattern)`
Add custom detection pattern.

#### `DefaultPatterns() []Pattern`
Get default security patterns.

**Detected Patterns:**
- SQL injection attempts (UNION-based, comment-based)
- Dangerous functions (xp_cmdshell, LOAD_FILE)
- Tautologies (1=1, OR 1=1)
- Stacked queries (;DROP, ;DELETE)

---

## Linter Package

### Package: `github.com/ajitpratap0/GoSQLX/pkg/linter`

### Types

#### `Linter`
```go
type Linter struct {
    Rules []Rule
}
```

#### `Rule`
```go
type Rule interface {
    Name() string
    Check(node ast.Node) []Violation
}
```

#### `Violation`
```go
type Violation struct {
    Rule        string
    Severity    Severity
    Message     string
    Location    *models.Location
    Suggestion  string
}
```

#### `Severity`
```go
const (
    SeverityInfo Severity = iota
    SeverityWarning
    SeverityError
)
```

### Functions

#### `NewLinter() *Linter`
Create linter.

```go
linter := linter.NewLinter()
```

#### `(l *Linter) AddRule(rule Rule)`
Add linting rule.

#### `(l *Linter) Lint(astNode *ast.AST) []Violation`
Lint SQL AST.

```go
violations := linter.Lint(astNode)
for _, v := range violations {
    fmt.Printf("%s: %s\n", v.Rule, v.Message)
}
```

#### `DefaultRules() []Rule`
Get default rules.

**Default Rules:**
- SELECT * usage detection
- Missing WHERE in UPDATE/DELETE
- Inconsistent naming conventions
- Inefficient query patterns

---

## Performance Considerations

### Object Pooling

**Always use defer with pool returns:**

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
// 40-60% faster than individual calls
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

### Performance Metrics

- **Tokenization**: 8M+ tokens/second
- **Parsing**: 1.38M+ operations/second sustained, 1.5M peak
- **Memory**: 60-80% reduction with object pooling
- **Pool Hit Rate**: 95%+ in production workloads
- **Latency**: <1μs for complex queries

---

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
    "github.com/ajitpratap0/GoSQLX/pkg/linter"
    "github.com/ajitpratap0/GoSQLX/pkg/metrics"
)

func main() {
    // Enable metrics
    metrics.Enable()
    defer func() {
        snapshot := metrics.GetSnapshot()
        fmt.Printf("Processed %d queries with %.2f%% success rate\n",
            snapshot.TotalQueries, snapshot.SuccessRate)
    }()

    sql := `
        WITH active_users AS (
            SELECT id, name FROM users WHERE active = true
        )
        SELECT u.id, u.name, COUNT(o.id) as order_count,
               ROW_NUMBER() OVER (ORDER BY COUNT(o.id) DESC) as rank
        FROM active_users u
        LEFT JOIN orders o ON u.id = o.user_id
        WHERE u.created_at >= '2024-01-01'
        GROUP BY u.id, u.name
        HAVING COUNT(o.id) > 5
        ORDER BY order_count DESC NULLS LAST
        LIMIT 10
    `

    // Parse SQL
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    astNode, err := gosqlx.ParseWithContext(ctx, sql)
    if err != nil {
        log.Fatal("Parse error:", err)
    }
    defer ast.ReleaseAST(astNode)

    // Security scan
    scanner := security.NewScanner()
    findings := scanner.Scan(sql)
    if len(findings) > 0 {
        fmt.Println("Security issues found:")
        for _, f := range findings {
            fmt.Printf("  - %s (Severity: %v)\n", f.Description, f.Severity)
        }
    }

    // Lint SQL
    linter := linter.NewLinter()
    violations := linter.Lint(astNode)
    if len(violations) > 0 {
        fmt.Println("Linting violations:")
        for _, v := range violations {
            fmt.Printf("  - %s: %s\n", v.Rule, v.Message)
        }
    }

    // Analyze AST
    if len(astNode.Statements) > 0 {
        if stmt, ok := astNode.Statements[0].(*ast.SelectStatement); ok {
            fmt.Printf("Query has %d columns\n", len(stmt.Columns))
            if stmt.With != nil {
                fmt.Printf("Uses %d CTEs\n", len(stmt.With.CTEs))
            }
            if len(stmt.Windows) > 0 {
                fmt.Println("Uses window functions")
            }
        }
    }

    fmt.Println("SQL parsed, validated, and analyzed successfully!")
}
```

---

## Test Coverage Summary

| Package | Coverage | Status |
|---------|----------|--------|
| models | 100.0% | ⭐⭐⭐⭐⭐ |
| keywords | 100.0% | ⭐⭐⭐⭐⭐ |
| linter/rules/whitespace | 100.0% | ⭐⭐⭐⭐⭐ |
| monitor | 98.6% | ⭐⭐⭐⭐⭐ |
| linter | 96.7% | ⭐⭐⭐⭐⭐ |
| gosqlx/testing | 95.0% | ⭐⭐⭐⭐⭐ |
| errors | 91.9% | ⭐⭐⭐⭐ |
| security | 90.2% | ⭐⭐⭐⭐ |
| config | 81.8% | ⭐⭐⭐⭐ |
| ast | 80.3% | ⭐⭐⭐⭐ |
| parser | 76.1% | ⭐⭐⭐⭐ |
| tokenizer | 75.3% | ⭐⭐⭐⭐ |
| metrics | 73.9% | ⭐⭐⭐ |
| lsp | 70.2% | ⭐⭐⭐ |
| token | 68.8% | ⭐⭐⭐ |
| gosqlx | 65.6% | ⭐⭐⭐ |

---

## Additional Resources

- **GitHub Repository**: https://github.com/ajitpratap0/GoSQLX
- **Documentation**: See `/docs` directory
- **Examples**: See `/examples` directory
- **Issue Tracker**: GitHub Issues
- **License**: MIT
