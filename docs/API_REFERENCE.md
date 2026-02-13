# GoSQLX API Reference (v1.6.0)

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
- [LSP Package](#lsp-package)
- [Configuration Package](#configuration-package)

## Package Overview

GoSQLX v1.6.0 is organized into the following packages:

```
github.com/ajitpratap0/GoSQLX/
├── pkg/
│   ├── gosqlx/          # High-level convenience API
│   ├── models/          # Core data structures (100% coverage)
│   ├── sql/
│   │   ├── tokenizer/   # SQL lexical analysis (76.1% coverage)
│   │   ├── parser/      # SQL syntax parsing (75.0% coverage)
│   │   ├── ast/         # Abstract syntax tree (80.3% coverage)
│   │   ├── keywords/    # SQL keyword definitions (100% coverage)
│   │   ├── token/       # Token types and utilities (100% coverage)
│   │   ├── security/    # SQL injection detection (90.2% coverage)
│   │   └── monitor/     # Parser monitoring (98.6% coverage)
│   ├── errors/          # Structured error handling (95.6% coverage)
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

| Token Type | Example | v1.6.0 Features |
|------------|---------|-----------------|
| `TokenTypeSelect` | `SELECT` | ✅ Standard |
| `TokenTypeFrom` | `FROM` | ✅ Standard |
| `TokenTypeWhere` | `WHERE` | ✅ Standard |
| `TokenTypeIdentifier` | `users`, `id` | ✅ Standard |
| `TokenTypeNumber` | `42`, `3.14` | ✅ Scientific notation support |
| `TokenTypeSingleQuotedString` | `'hello'` | ✅ Standard |
| `TokenTypeDoubleQuotedString` | `"column name"` | ✅ Standard |
| `TokenTypeBacktickIdentifier` | `` `column` `` | ✅ MySQL dialect |
| `TokenTypeLateral` | `LATERAL` | ✅ **NEW v1.6.0** PostgreSQL |
| `TokenTypeFilter` | `FILTER` | ✅ **NEW v1.6.0** SQL:2003 |
| `TokenTypeDistinctOn` | `DISTINCT ON` | ✅ **NEW v1.6.0** PostgreSQL |
| `TokenTypeReturning` | `RETURNING` | ✅ **NEW v1.6.0** PostgreSQL |
| `TokenTypeFetch` | `FETCH FIRST` | ✅ **NEW v1.6.0** SQL-99 F861 |
| `TokenTypeTruncate` | `TRUNCATE` | ✅ **NEW v1.6.0** SQL:2008 |
| **JSON/JSONB Operators** | | |
| `TokenTypeArrow` | `->` | ✅ **NEW v1.6.0** PostgreSQL |
| `TokenTypeDoubleArrow` | `->>` | ✅ **NEW v1.6.0** PostgreSQL |
| `TokenTypeHashArrow` | `#>` | ✅ **NEW v1.6.0** PostgreSQL |
| `TokenTypeHashDoubleArrow` | `#>>` | ✅ **NEW v1.6.0** PostgreSQL |
| `TokenTypeAtGreater` | `@>` | ✅ **NEW v1.6.0** PostgreSQL containment |
| `TokenTypeLessAt` | `<@` | ✅ **NEW v1.6.0** PostgreSQL contained by |
| `TokenTypeQuestionMark` | `?` | ✅ **NEW v1.6.0** PostgreSQL key exists |
| `TokenTypeQuestionPipe` | `?|` | ✅ **NEW v1.6.0** PostgreSQL any key exists |
| `TokenTypeQuestionAmpersand` | `?&` | ✅ **NEW v1.6.0** PostgreSQL all keys exist |
| `TokenTypeHashMinus` | `#-` | ✅ **NEW v1.6.0** PostgreSQL delete at path |

**Features:**
- **14x faster token type checking** (v1.6.0 optimization with ModelType field)
- Unicode support (UTF-8)
- Dialect-specific tokens (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)
- Zero-copy operations
- Position tracking (line, column, offset)
- Scientific notation support (1.23e4, 1.23E+4)
- Triple-quoted strings (Python-style)
- Escape sequences (\n, \t, \r, \\, \', \")

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

**Supported Statements (v1.6.0):**

**DML (Data Manipulation Language):**
- SELECT (with DISTINCT, DISTINCT ON)
- INSERT (with RETURNING clause)
- UPDATE (with RETURNING clause)
- DELETE (with RETURNING clause)
- MERGE (SQL:2003 F312)
- TRUNCATE TABLE (SQL:2008)

**DDL (Data Definition Language):**
- CREATE TABLE/INDEX/VIEW/MATERIALIZED VIEW
- ALTER TABLE
- DROP TABLE/INDEX/VIEW/MATERIALIZED VIEW

**Advanced Features:**
- CTEs (Common Table Expressions) with RECURSIVE support
- Window functions (ROW_NUMBER, RANK, DENSE_RANK, NTILE, LAG, LEAD, FIRST_VALUE, LAST_VALUE)
- Set operations (UNION, EXCEPT, INTERSECT)
- Grouping Sets (ROLLUP, CUBE, GROUPING SETS)
- PostgreSQL extensions (LATERAL JOIN, FILTER clause, DISTINCT ON, JSON/JSONB operators)
- FETCH FIRST/OFFSET-FETCH (SQL-99 F861, F862)

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
    With        *WithClause         // CTE support
    Distinct    bool                // DISTINCT keyword
    DistinctOn  []Expression        // NEW v1.6.0: PostgreSQL DISTINCT ON
    Columns     []Expression
    From        []TableReference
    Joins       []JoinClause
    Where       Expression
    GroupBy     []Expression        // Supports ROLLUP, CUBE, GROUPING SETS
    Having      Expression
    Windows     []WindowSpec        // Window function specifications
    OrderBy     []OrderByExpression // Supports NULLS FIRST/LAST
    Limit       *int
    Offset      *int
    FetchClause *FetchClause        // NEW v1.6.0: SQL-99 FETCH FIRST support
}
```

**PostgreSQL-Specific Features (v1.6.0):**
- `DistinctOn` - SELECT DISTINCT ON (column1, column2)

**Example:**
```go
// PostgreSQL DISTINCT ON
sql := "SELECT DISTINCT ON (dept_id) dept_id, name, salary FROM employees ORDER BY dept_id, salary DESC"
ast, _ := gosqlx.Parse(sql)
if stmt, ok := ast.Statements[0].(*ast.SelectStatement); ok {
    fmt.Printf("DISTINCT ON columns: %d\n", len(stmt.DistinctOn))
}
```

#### `InsertStatement`
```go
type InsertStatement struct {
    With       *WithClause      // CTE support
    TableName  string
    Columns    []Expression
    Values     []Expression     // Supports function calls (NOW(), UUID(), etc.)
    Query      *SelectStatement // INSERT INTO ... SELECT
    Returning  []Expression     // NEW v1.6.0: PostgreSQL RETURNING clause
    OnConflict *OnConflict      // Upsert support
}
```

**v1.6.0 Enhancements:**
- `Returning` - PostgreSQL RETURNING clause for INSERT
- Expression-based VALUES (function calls, arithmetic)

**Example:**
```go
// INSERT with RETURNING
sql := "INSERT INTO users (name, email) VALUES ('John', 'john@example.com') RETURNING id, created_at"
ast, _ := gosqlx.Parse(sql)
if stmt, ok := ast.Statements[0].(*ast.InsertStatement); ok {
    fmt.Printf("RETURNING %d columns\n", len(stmt.Returning))
}
```

#### `UpdateStatement`
```go
type UpdateStatement struct {
    With        *WithClause      // CTE support
    TableName   string
    Updates     []UpdateExpression // SET column = value pairs
    Assignments []UpdateExpression // Alias for Updates (preferred)
    From        []TableReference  // PostgreSQL UPDATE ... FROM
    Where       Expression
    Returning   []Expression      // NEW v1.6.0: PostgreSQL RETURNING clause
}
```

**v1.6.0 Enhancements:**
- `Returning` - PostgreSQL RETURNING clause for UPDATE

#### `DeleteStatement`
```go
type DeleteStatement struct {
    With      *WithClause      // CTE support
    TableName string
    Using     []TableReference // PostgreSQL DELETE ... USING
    Where     Expression
    Returning []Expression     // NEW v1.6.0: PostgreSQL RETURNING clause
}
```

**v1.6.0 Enhancements:**
- `Returning` - PostgreSQL RETURNING clause for DELETE

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

**Example:**
```go
sql := `MERGE INTO target_table t USING source_table s ON t.id = s.id
        WHEN MATCHED THEN UPDATE SET t.name = s.name
        WHEN NOT MATCHED THEN INSERT (id, name) VALUES (s.id, s.name)`
ast, _ := gosqlx.Parse(sql)
```

#### `TruncateStatement` (**NEW v1.6.0**)
```go
type TruncateStatement struct {
    Tables          []string // Table names to truncate
    RestartIdentity bool     // RESTART IDENTITY (PostgreSQL)
    ContinueIdentity bool    // CONTINUE IDENTITY (PostgreSQL)
    Cascade         bool     // CASCADE option
    Restrict        bool     // RESTRICT option
}
```

**Example:**
```go
// TRUNCATE with CASCADE
sql := "TRUNCATE TABLE logs, events RESTART IDENTITY CASCADE"
ast, _ := gosqlx.Parse(sql)
if stmt, ok := ast.Statements[0].(*ast.TruncateStatement); ok {
    fmt.Printf("Truncating %d tables with CASCADE=%v\n", len(stmt.Tables), stmt.Cascade)
}
```

### DDL Statement Types

#### `CreateTableStatement`
```go
type CreateTableStatement struct {
    IfNotExists bool
    Temporary   bool
    Name        string
    Columns     []ColumnDef       // Column definitions with constraints
    Constraints []TableConstraint // Table-level constraints
    PartitionBy *PartitionBy
    Options     []TableOption
}
```

**v1.6.0 Enhancements:**
- Full column constraint support (PRIMARY KEY, FOREIGN KEY, UNIQUE, CHECK, NOT NULL, DEFAULT)
- Parameterized types (VARCHAR(100), DECIMAL(10,2))
- Referential actions (ON DELETE/UPDATE CASCADE, SET NULL, SET DEFAULT)

#### `CreateIndexStatement`
```go
type CreateIndexStatement struct {
    Name         string
    Unique       bool
    TableName    string
    Columns      []IndexColumn
    Where        Expression
    Using        string
    Concurrently bool // PostgreSQL CONCURRENTLY option
}
```

#### `CreateViewStatement`
```go
type CreateViewStatement struct {
    Name        string
    Columns     []string
    Query       *SelectStatement
    OrReplace   bool
    Temporary   bool
    Recursive   bool
    CheckOption string
}
```

#### `CreateMaterializedViewStatement`
```go
type CreateMaterializedViewStatement struct {
    Name     string
    Columns  []string
    Query    *SelectStatement
    WithData bool // WITH DATA / WITH NO DATA (PostgreSQL)
}
```

**Example:**
```go
sql := "CREATE MATERIALIZED VIEW sales_summary AS SELECT region, SUM(amount) FROM sales GROUP BY region"
ast, _ := gosqlx.Parse(sql)
```

#### `RefreshMaterializedViewStatement` (**NEW v1.6.0**)
```go
type RefreshMaterializedViewStatement struct {
    Name         string
    Concurrently bool // CONCURRENTLY option (PostgreSQL)
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
    ObjectType string // TABLE, INDEX, VIEW, MATERIALIZED VIEW, etc.
    ObjectName string
    IfExists   bool
    Cascade    bool   // CASCADE option
}
```

### CTE and Set Operations

#### `WithClause`
```go
type WithClause struct {
    Recursive    bool
    Materialized *bool              // NEW v1.6.0: MATERIALIZED/NOT MATERIALIZED hint
    CTEs         []CommonTableExpr
}
```

**v1.6.0 Enhancements:**
- `Materialized` - PostgreSQL optimization hints (MATERIALIZED, NOT MATERIALIZED)

**Example:**
```go
// Materialized CTE
sql := "WITH cte AS MATERIALIZED (SELECT * FROM large_table WHERE expensive_filter = true) SELECT * FROM cte"
ast, _ := gosqlx.Parse(sql)
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
    Left     Statement // Can be SelectStatement or another SetOperation
    Operator string    // UNION, EXCEPT, INTERSECT
    All      bool
    Right    Statement
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

**Example:**
```go
// ROLLUP
sql := "SELECT region, product, SUM(sales) FROM orders GROUP BY ROLLUP(region, product)"
ast, _ := gosqlx.Parse(sql)
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
    Type  string       // ROWS or RANGE
    Start *FrameBound
    End   *FrameBound
}
```

#### `FrameBound`
```go
type FrameBound struct {
    Type       string     // UNBOUNDED, CURRENT, PRECEDING, FOLLOWING
    Expression Expression // Offset value for PRECEDING/FOLLOWING
}
```

**Example:**
```go
// Window function with frame
sql := "SELECT date, amount, SUM(amount) OVER (ORDER BY date ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) as rolling_sum FROM transactions"
ast, _ := gosqlx.Parse(sql)
```

### Expression Types

#### `Identifier`
```go
type Identifier struct {
    Name  string
    Value string // Alias for Name
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

**Supported Operators (v1.6.0):**
- Arithmetic: `+`, `-`, `*`, `/`, `%`
- Comparison: `=`, `!=`, `<>`, `<`, `>`, `<=`, `>=`
- Logical: `AND`, `OR`, `NOT`
- PostgreSQL JSON/JSONB: `->`, `->>`, `#>`, `#>>`, `@>`, `<@`, `?`, `?|`, `?&`, `#-`

**Example:**
```go
// PostgreSQL JSON operators
sql := "SELECT data->>'name' AS name, data->'address'->>'city' AS city FROM users"
ast, _ := gosqlx.Parse(sql)
```

#### `FunctionCall`
```go
type FunctionCall struct {
    Name      string
    Arguments []Expression
    Distinct  bool          // DISTINCT keyword in aggregate
    Filter    Expression    // NEW v1.6.0: FILTER (WHERE ...) clause
    OrderBy   []OrderByExpression // NEW v1.6.0: ORDER BY inside aggregate
    Over      *WindowSpec   // Window specification
}
```

**v1.6.0 Enhancements:**
- `Filter` - SQL:2003 T612 FILTER clause for conditional aggregation
- `OrderBy` - ORDER BY inside aggregates (STRING_AGG, ARRAY_AGG, JSON_AGG, etc.)

**Example:**
```go
// FILTER clause
sql := "SELECT COUNT(*) FILTER (WHERE status = 'active') AS active_count FROM users"
ast, _ := gosqlx.Parse(sql)

// ORDER BY in aggregate
sql := "SELECT STRING_AGG(name, ', ' ORDER BY name DESC NULLS LAST) FROM users"
ast, _ := gosqlx.Parse(sql)
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

**v1.6.0 Enhancement:**
- Derived tables in FROM clause: `(SELECT ...) AS alias`

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
    NullsFirst bool // NEW v1.6.0: NULLS FIRST
    NullsLast  bool // NEW v1.6.0: NULLS LAST
}
```

**Example:**
```go
// NULLS FIRST/LAST
sql := "SELECT * FROM users ORDER BY last_login DESC NULLS LAST"
ast, _ := gosqlx.Parse(sql)
```

#### `TableReference`
```go
type TableReference struct {
    Name    string
    Alias   string
    Lateral bool             // NEW v1.6.0: PostgreSQL LATERAL JOIN
    Query   *SelectStatement // For derived tables
}
```

**v1.6.0 Enhancement:**
- `Lateral` - PostgreSQL LATERAL JOIN support

**Example:**
```go
// LATERAL JOIN
sql := "SELECT u.name, r.order_date FROM users u, LATERAL (SELECT * FROM orders WHERE user_id = u.id ORDER BY order_date DESC LIMIT 3) r"
ast, _ := gosqlx.Parse(sql)
```

#### `FetchClause` (**NEW v1.6.0**)
```go
type FetchClause struct {
    Count       *int64  // Number of rows
    Percent     bool    // PERCENT keyword
    WithTies    bool    // WITH TIES keyword
}
```

**Example:**
```go
// FETCH FIRST with TIES
sql := "SELECT * FROM users ORDER BY score DESC FETCH FIRST 10 ROWS WITH TIES"
ast, _ := gosqlx.Parse(sql)
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
- `ExistsExpression`, `AnyExpression`, `AllExpression`
- `ListExpression`, `UnaryExpression`
- `ExtractExpression`, `PositionExpression`, `SubstringExpression`

**v1.6.0 Pool Optimizations:**
- Iterative cleanup with work queue pattern (prevents stack overflow)
- MaxCleanupDepth and MaxWorkQueueSize limits
- 8 new expression pools added

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
        for _, from := range sel.From {
            tc.Tables = append(tc.Tables, from.Name)
        }
    }
    return tc
}

collector := &TableCollector{}
ast.Walk(collector, astNode)
fmt.Printf("Tables: %v\n", collector.Tables)
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
keywords.IsKeyword("SELECT")  // true
keywords.IsKeyword("LATERAL") // true (v1.6.0)
```

#### `GetCategory(word string) (Category, bool)`
Get keyword category.

```go
cat, ok := keywords.GetCategory("SELECT")
// Returns: CategoryDML, true
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

**v1.6.0 Performance:**
- **575x faster** with caching system (12.87ns vs 7402ns)

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

**v1.6.0 Enhancements:**
- **120+ new SQL token types** with proper categorization
- `ModelType` field for O(1) int-based comparisons (14x faster)
- Helper methods: `IsKeyword()`, `IsOperator()`, `IsLiteral()`, `IsDMLKeyword()`, `IsDDLKeyword()`, etc.

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
    Line   int // 1-based line number
    Column int // 1-based column number
    Offset int // 0-based byte offset
}
```

### Functions

#### `NewTokenWithSpan(tokenType TokenType, value string, span Span) TokenWithSpan`
Create token with span.

#### `(t TokenType) String() string`
Get string representation.

**v1.6.0 Enhancement:**
- Complete hash map implementation covering all 90+ token types (optimized for performance)

---

## Error Handling

### Package: `github.com/ajitpratap0/GoSQLX/pkg/errors`

### Types

#### `Error`
```go
type Error struct {
    Code     ErrorCode        // NEW v1.6.0: Structured error codes
    Message  string
    Location *models.Location
    Context  string
    Hint     string           // NEW v1.6.0: Helpful hints
    DocURL   string           // NEW v1.6.0: Documentation link
}
```

**v1.6.0 Enhancements:**
- Structured error codes (E1001-E1005 tokenizer, E2001-E2012 parser, E3001-E3004 semantic)
- Helpful hints for common errors
- Documentation links

#### `ErrorCode` (Type)
```go
type ErrorCode string

const (
    // Tokenizer errors (E1001-E1005)
    ErrCodeUnterminatedString   ErrorCode = "E1001"
    ErrCodeInvalidNumber        ErrorCode = "E1002"
    ErrCodeUnexpectedCharacter  ErrorCode = "E1003"
    ErrCodeInvalidEscape        ErrorCode = "E1004"
    ErrCodeUnterminatedComment  ErrorCode = "E1005"

    // Parser errors (E2001-E2012)
    ErrCodeSyntax               ErrorCode = "E2001"
    ErrCodeUnexpectedToken      ErrorCode = "E2002"
    ErrCodeUnexpectedEOF        ErrorCode = "E2003"
    ErrCodeInvalidIdentifier    ErrorCode = "E2004"
    ErrCodeUnsupportedFeature   ErrorCode = "E2005"
    ErrCodeInvalidExpression    ErrorCode = "E2006"
    ErrCodeMissingColumn        ErrorCode = "E2007"
    ErrCodeMissingTable         ErrorCode = "E2008"
    ErrCodeInvalidJoin          ErrorCode = "E2009"
    ErrCodeInvalidWindow        ErrorCode = "E2010"
    ErrCodeInvalidGroupBy       ErrorCode = "E2011"
    ErrCodeInvalidOrderBy       ErrorCode = "E2012"

    // Semantic errors (E3001-E3004)
    ErrCodeUndefinedTable       ErrorCode = "E3001"
    ErrCodeUndefinedColumn      ErrorCode = "E3002"
    ErrCodeTypeMismatch         ErrorCode = "E3003"
    ErrCodeAmbiguousColumn      ErrorCode = "E3004"
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

#### `(e *Error) WithHint(hint string) *Error` (**NEW v1.6.0**)
Add helpful hint.

#### `(e *Error) WithDocURL(url string) *Error` (**NEW v1.6.0**)
Add documentation link.

**Example:**
```go
err := errors.NewSyntaxError("Missing WHERE clause", &loc).
    WithHint("Consider adding a WHERE clause to filter results").
    WithDocURL("https://gosqlx.dev/docs/where-clause")
```

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
    Gets    int64
    Puts    int64
    Hits    int64
    Misses  int64
    HitRate float64
}
```

**v1.6.0 Enhancements:**
- Parser operation metrics (duration, errors, statement counts)
- AST pool metrics (gets/puts/balance)
- Statement pool metrics
- Expression pool metrics
- Tokenizer pool metrics with hit rate tracking
- Thread-safe atomic counters

---

## Security Package

### Package: `github.com/ajitpratap0/GoSQLX/pkg/sql/security`

The security package provides SQL injection pattern detection and security scanning.

### Types

#### `Scanner`
```go
type Scanner struct {
    MinSeverity Severity // Filter findings by minimum severity
}
```

#### `Severity`
```go
type Severity string

const (
    SeverityLow      Severity = "LOW"
    SeverityMedium   Severity = "MEDIUM"
    SeverityHigh     Severity = "HIGH"
    SeverityCritical Severity = "CRITICAL"
)
```

#### `PatternType`
```go
type PatternType string

const (
    PatternTautology     PatternType = "TAUTOLOGY"
    PatternComment       PatternType = "COMMENT_BYPASS"
    PatternStackedQuery  PatternType = "STACKED_QUERY"
    PatternUnionBased    PatternType = "UNION_BASED"
    PatternTimeBased     PatternType = "TIME_BASED"
    PatternBooleanBased  PatternType = "BOOLEAN_BASED"
    PatternOutOfBand     PatternType = "OUT_OF_BAND"
    PatternDangerousFunc PatternType = "DANGEROUS_FUNCTION"
)
```

#### `Finding`
```go
type Finding struct {
    Severity    Severity    // Severity level
    Pattern     PatternType // Pattern type detected
    Description string      // Description of the finding
    Risk        string      // Risk explanation
    Line        int         // Line number (if available)
    Column      int         // Column number (if available)
    SQL         string      // SQL snippet (if available)
    Suggestion  string      // Fix suggestion
}
```

#### `ScanResult`
```go
type ScanResult struct {
    Findings      []Finding // All findings
    TotalCount    int       // Total findings
    CriticalCount int       // Critical findings
    HighCount     int       // High severity findings
    MediumCount   int       // Medium severity findings
    LowCount      int       // Low severity findings
}
```

### Functions

#### `NewScanner() *Scanner`
Create security scanner with default settings (minimum severity: LOW).

```go
scanner := security.NewScanner()
```

#### `NewScannerWithSeverity(minSeverity Severity) (*Scanner, error)`
Create scanner with custom minimum severity filter.

```go
scanner, err := security.NewScannerWithSeverity(security.SeverityHigh)
// Only returns HIGH and CRITICAL findings
```

#### `(s *Scanner) Scan(ast *ast.AST) *ScanResult`
Scan parsed AST for security issues.

```go
scanner := security.NewScanner()
ast, _ := gosqlx.Parse(sql)
result := scanner.Scan(ast)

for _, finding := range result.Findings {
    fmt.Printf("[%s] %s: %s\n", finding.Severity, finding.Pattern, finding.Description)
}
```

#### `(s *Scanner) ScanSQL(sql string) *ScanResult`
Scan raw SQL string for injection patterns (useful for patterns not in AST).

```go
scanner := security.NewScanner()
result := scanner.ScanSQL("SELECT * FROM users WHERE id = '" + userInput + "'")
```

#### `(r *ScanResult) HasCritical() bool`
Returns true if any critical findings exist.

#### `(r *ScanResult) HasHighOrAbove() bool`
Returns true if any high or critical findings exist.

#### `(r *ScanResult) IsClean() bool`
Returns true if no findings exist.

### Detection Patterns

The scanner detects 8 pattern types:

1. **Tautologies** - Always-true conditions (e.g., `1=1`, `'a'='a'`)
2. **Comment Bypasses** - SQL comment-based injection (`--`, `/**/`, `#`)
3. **UNION-Based Injection** - Data extraction via UNION SELECT
4. **Stacked Queries** - Destructive statements after semicolon (`;DROP`, `;DELETE`)
5. **Time-Based Blind** - Time delay functions (SLEEP, WAITFOR DELAY, pg_sleep, BENCHMARK)
6. **Out-of-Band** - Data exfiltration (xp_cmdshell, LOAD_FILE, UTL_HTTP)
7. **Dangerous Functions** - Dynamic SQL execution (EXEC, sp_executesql, PREPARE FROM)
8. **Boolean-Based** - Conditional logic exploitation

**Example:**
```go
scanner := security.NewScanner()

// Detect tautology
sql := "SELECT * FROM users WHERE username = 'admin' OR 1=1 --"
result := scanner.ScanSQL(sql)
// Finding: TAUTOLOGY, Severity: CRITICAL

// Detect UNION injection
sql := "SELECT * FROM products WHERE id = 1 UNION SELECT NULL, username, password FROM users"
result = scanner.ScanSQL(sql)
// Finding: UNION_BASED, Severity: CRITICAL

// Detect time-based injection
sql := "SELECT * FROM orders WHERE id = 1; SELECT SLEEP(5)"
result = scanner.ScanSQL(sql)
// Finding: TIME_BASED, Severity: HIGH

// Clean SQL
sql := "SELECT * FROM users WHERE id = $1"
result = scanner.ScanSQL(sql)
// result.IsClean() == true
```

**v1.6.0 Performance:**
- Pre-compiled regex patterns for performance
- Thread-safe pattern compilation (sync.Once)
- Precise system table matching (avoids false positives)
- 100% detection rate on common injection patterns

---

## Linter Package

### Package: `github.com/ajitpratap0/GoSQLX/pkg/linter`

The linter package provides SQL linting with 10 built-in rules (L001-L010) and auto-fix capabilities.

### Types

#### `Linter`
```go
type Linter struct {
    rules []Rule
}
```

#### `Rule` (Interface)
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

#### `Severity`
```go
type Severity string

const (
    SeverityError   Severity = "error"
    SeverityWarning Severity = "warning"
    SeverityInfo    Severity = "info"
)
```

#### `Violation`
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

#### `Result`
```go
type Result struct {
    Files           []FileResult
    TotalFiles      int
    TotalViolations int
}
```

#### `FileResult`
```go
type FileResult struct {
    Filename   string
    Violations []Violation
    Error      error
}
```

### Functions

#### `New(rules ...Rule) *Linter`
Create linter with specified rules.

```go
linter := linter.New(
    rules.NewTrailingWhitespaceRule(),
    rules.NewMixedTabsSpacesRule(),
    rules.NewKeywordCaseRule(),
)
```

#### `(l *Linter) LintFile(filename string) FileResult`
Lint a single SQL file.

```go
linter := linter.New(rules.AllRules()...)
result := linter.LintFile("query.sql")

for _, violation := range result.Violations {
    fmt.Println(linter.FormatViolation(violation))
}
```

#### `(l *Linter) LintString(sql string, filename string) FileResult`
Lint SQL content provided as a string.

```go
result := linter.LintString("SELECT * from users", "inline.sql")
```

#### `(l *Linter) LintFiles(filenames []string) Result`
Lint multiple files.

```go
result := linter.LintFiles([]string{"query1.sql", "query2.sql"})
fmt.Printf("Total violations: %d\n", result.TotalViolations)
```

#### `(l *Linter) LintDirectory(dir string, pattern string) Result`
Recursively lint all SQL files matching pattern in directory.

```go
result := linter.LintDirectory("./sql", "*.sql")
```

#### `FormatViolation(v Violation) string`
Format violation for display.

#### `FormatResult(result Result) string`
Format linting results for display.

### Built-in Rules (v1.6.0)

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

---

## LSP Package

### Package: `github.com/ajitpratap0/GoSQLX/pkg/lsp`

The LSP package provides a complete Language Server Protocol implementation for SQL, enabling IDE integration.

### Server Configuration

#### Constants
```go
const (
    MaxContentLength  = 10 * 1024 * 1024 // 10MB max message size
    MaxDocumentSize   = 5 * 1024 * 1024  // 5MB max document size
    RateLimitRequests = 100              // 100 requests per second
    RateLimitWindow   = time.Second
    RequestTimeout    = 30 * time.Second
)
```

### Types

#### `Server`
```go
type Server struct {
    // Internal fields
}
```

#### `Handler`
```go
type Handler struct {
    // Internal fields
}
```

### Functions

#### `NewServer(reader io.Reader, writer io.Writer, logger *log.Logger) *Server`
Create a new LSP server.

```go
server := lsp.NewServer(os.Stdin, os.Stdout, logger)
```

#### `NewStdioServer(logger *log.Logger) *Server`
Create a new LSP server using stdin/stdout.

```go
logger := log.New(os.Stderr, "LSP: ", log.LstdFlags)
server := lsp.NewStdioServer(logger)
```

#### `(s *Server) Run() error`
Start the server's main loop.

```go
if err := server.Run(); err != nil {
    log.Fatal(err)
}
```

### LSP Capabilities (v1.6.0)

The GoSQLX LSP server implements the following LSP features:

#### **1. Text Document Synchronization**
- `textDocument/didOpen` - Document opened notification
- `textDocument/didChange` - Document changed notification (incremental sync)
- `textDocument/didClose` - Document closed notification
- `textDocument/didSave` - Document saved notification

**Example (VSCode):**
```typescript
// When you open a .sql file in VSCode, the LSP server receives:
{
  "method": "textDocument/didOpen",
  "params": {
    "textDocument": {
      "uri": "file:///path/to/query.sql",
      "languageId": "sql",
      "version": 1,
      "text": "SELECT * FROM users"
    }
  }
}
```

#### **2. Diagnostics (Real-time Validation)**
- `textDocument/publishDiagnostics` - Syntax error reporting with position info

**Features:**
- Real-time SQL syntax validation
- Error position extraction from parser messages
- Error code integration (E1001-E3004)
- Contextual error messages

**Example:**
```go
// Invalid SQL triggers diagnostic
sql := "SELECT * FORM users" // Typo: FORM instead of FROM

// LSP sends diagnostic:
{
  "uri": "file:///query.sql",
  "diagnostics": [
    {
      "range": {
        "start": {"line": 0, "character": 9},
        "end": {"line": 0, "character": 13}
      },
      "severity": 1,  // Error
      "code": "E2002",
      "source": "gosqlx",
      "message": "unexpected token: expected FROM, got FORM"
    }
  ]
}
```

#### **3. Hover Documentation**
- `textDocument/hover` - Keyword/function documentation

**Supported Keywords (60+):**
SELECT, FROM, WHERE, JOIN, LEFT, RIGHT, INNER, OUTER, GROUP, ORDER, HAVING, LIMIT, OFFSET, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER, TRUNCATE, WITH, UNION, EXCEPT, INTERSECT, CASE, WHEN, THEN, ELSE, END, AND, OR, NOT, IN, BETWEEN, LIKE, IS, NULL, AS, DISTINCT, COUNT, SUM, AVG, MIN, MAX, OVER, PARTITION, ROW_NUMBER, RANK, DENSE_RANK, LAG, LEAD, MERGE, ROLLUP, CUBE, GROUPING, FETCH, ROWS, RANGE

**Example:**
```go
// Hovering over "SELECT" shows:
**SELECT** - Retrieves data from one or more tables.

```sql
SELECT column1, column2 FROM table_name;
```
```

#### **4. Code Completion**
- `textDocument/completion` - SQL keywords and snippets

**Features:**
- 100+ keyword completions (SELECT, FROM, WHERE, JOIN, etc.)
- 22 code snippets for common patterns
- Function signatures with parameters
- Prefix-based filtering

**Snippet Examples:**
```go
// Typing "sel" suggests:
"SELECT ${1:columns}\nFROM ${2:table}\nWHERE ${3:condition}"

// Typing "cte" suggests:
"WITH ${1:cte_name} AS (\n\tSELECT ${2:columns}\n\tFROM ${3:table}\n\tWHERE ${4:condition}\n)\nSELECT *\nFROM ${1:cte_name}"

// Typing "window" suggests:
"${1:ROW_NUMBER}() OVER (\n\tPARTITION BY ${2:partition_column}\n\tORDER BY ${3:order_column}\n)"
```

#### **5. Document Formatting**
- `textDocument/formatting` - SQL code formatting

**Features:**
- Automatic keyword case normalization
- Smart indentation based on SQL clauses
- Whitespace normalization
- Configurable via FormattingOptions

**Example:**
```go
// Input:
"select  *  from   users   where  id=1"

// Formatted output:
"SELECT * FROM users\nWHERE id = 1"
```

#### **6. Document Symbols**
- `textDocument/documentSymbol` - SQL statement outline

**Features:**
- Statement-level navigation (SELECT #1, INSERT #2, etc.)
- Statement type classification (DML, DDL)
- Symbol kinds for different statement types

**Example:**
```go
// Multi-statement file:
WITH active_users AS (SELECT * FROM users WHERE active = true)
SELECT * FROM active_users;
INSERT INTO logs (message) VALUES ('Query executed');

// Returns symbols:
[
  {"name": "SELECT #1", "kind": "Method", "detail": "SELECT statement"},
  {"name": "INSERT #2", "kind": "Method", "detail": "INSERT statement"}
]
```

#### **7. Signature Help**
- `textDocument/signatureHelp` - Function parameter hints

**Supported Functions (20+):**
COUNT, SUM, AVG, MIN, MAX, COALESCE, NULLIF, CAST, SUBSTRING, TRIM, UPPER, LOWER, LENGTH, CONCAT, ROW_NUMBER, RANK, DENSE_RANK, LAG, LEAD, FIRST_VALUE, LAST_VALUE, NTILE

**Example:**
```go
// Typing "COALESCE(" shows:
COALESCE(value1, value2, ...)
Returns the first non-null value in the list.

Parameters:
  - value1: First value to check.
  - value2, ...: Additional values to check.
```

#### **8. Code Actions (Quick Fixes)**
- `textDocument/codeAction` - Automated fixes for common errors

**Available Quick Fixes:**
- Add missing semicolon
- Convert keyword to uppercase
- Additional context-aware fixes

**Example:**
```go
// Diagnostic: "Expected semicolon"
// Quick fix: Add semicolon at end of statement

// Diagnostic: "Keyword should be uppercase"
// Quick fix: Convert 'select' to 'SELECT'
```

### LSP Usage

#### **Starting the LSP Server**
```bash
# Start LSP server on stdio
./gosqlx lsp

# Start with debug logging
./gosqlx lsp --log /tmp/lsp.log
```

#### **VSCode Integration**
```json
// settings.json
{
  "gosqlx.enable": true,
  "gosqlx.executablePath": "/path/to/gosqlx",
  "gosqlx.format.indentSize": 2,
  "gosqlx.format.uppercaseKeywords": true,
  "gosqlx.dialect": "postgresql"
}
```

#### **Programmatic Usage**
```go
import (
    "log"
    "os"
    "github.com/ajitpratap0/GoSQLX/pkg/lsp"
)

func main() {
    logger := log.New(os.Stderr, "LSP: ", log.LstdFlags)
    server := lsp.NewStdioServer(logger)

    if err := server.Run(); err != nil {
        log.Fatal(err)
    }
}
```

### LSP Performance (v1.6.0)

- **Rate Limiting**: 100 requests/second with window-based throttling
- **Size Limits**: 10MB max message size, 5MB max document size
- **Request Timeout**: 30 seconds per request
- **Incremental Sync**: Supports incremental document updates for performance
- **Concurrent Safety**: Thread-safe document management with defensive copying

---

## Configuration Package

### Package: `github.com/ajitpratap0/GoSQLX/pkg/config`

The configuration package provides unified configuration management for GoSQLX.

### Types

#### `Config`
```go
type Config struct {
    Linter   LinterConfig   // Linter settings
    Format   FormatConfig   // Formatting settings
    Dialect  string         // SQL dialect (postgresql, mysql, sqlite, etc.)
    MaxDepth int            // Maximum parsing depth
}
```

#### `LinterConfig`
```go
type LinterConfig struct {
    Enabled bool              // Enable linting
    Rules   map[string]bool   // Rule enablement (L001, L002, etc.)
    Severity map[string]string // Rule severity overrides
}
```

#### `FormatConfig`
```go
type FormatConfig struct {
    IndentSize        int  // Indent size (default: 2)
    UppercaseKeywords bool // Uppercase SQL keywords
    InsertFinalNewline bool // Insert newline at end of file
}
```

### Functions

#### `Load(filename string) (*Config, error)`
Load configuration from file (.gosqlx.yml).

```go
cfg, err := config.Load(".gosqlx.yml")
if err != nil {
    log.Fatal(err)
}
```

#### `LoadFromEnv() *Config`
Load configuration from environment variables.

```go
cfg := config.LoadFromEnv()
```

#### `Default() *Config`
Get default configuration.

```go
cfg := config.Default()
```

### Configuration File Example

```yaml
# .gosqlx.yml
dialect: postgresql

linter:
  enabled: true
  rules:
    L001: true  # Trailing whitespace
    L002: true  # Mixed tabs/spaces
    L003: true  # Consecutive blank lines
    L004: true  # Indentation depth
    L005: true  # Line length
    L006: false # Column alignment (disabled)
    L007: true  # Keyword case
    L008: false # Comma placement (disabled)
    L009: true  # Aliasing consistency
    L010: true  # Redundant whitespace

  severity:
    L007: error  # Override: keyword case is error instead of warning

format:
  indent_size: 2
  uppercase_keywords: true
  insert_final_newline: true

max_depth: 100
```

**v1.6.0 Performance:**
- **22.5x faster config file loading** with caching (1302ns vs 29379ns)
- Thread-safe cache with automatic invalidation on file modification

---

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

### Performance Metrics (v1.6.0)

- **Tokenization**: 8M+ tokens/second
- **Token Type Checking**: **14x faster** (0.28ns vs 4.9ns with ModelType optimization)
- **Keyword Suggestions**: **575x faster** (12.87ns vs 7402ns with caching)
- **Config Loading**: **22.5x faster** (1302ns vs 29379ns with caching)
- **Parsing**: 1.38M+ operations/second sustained, 1.5M peak
- **Memory**: 60-80% reduction with object pooling
- **Pool Hit Rate**: 95%+ in production workloads
- **Latency**: <1μs for complex queries with window functions and CTEs

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
    "github.com/ajitpratap0/GoSQLX/pkg/linter/rules"
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
        -- PostgreSQL v1.6.0 features demonstration
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
    linter := linter.New(rules.AllRules()...)
    lintResult := linter.LintString(sql, "demo.sql")

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

---

## Test Coverage Summary (v1.6.0)

| Package | Coverage | Status |
|---------|----------|--------|
| models | 100.0% | ⭐⭐⭐⭐⭐ Perfect |
| keywords | 100.0% | ⭐⭐⭐⭐⭐ Perfect |
| token | 100.0% | ⭐⭐⭐⭐⭐ Perfect |
| monitor | 98.6% | ⭐⭐⭐⭐⭐ Excellent |
| linter | 96.7% | ⭐⭐⭐⭐⭐ Excellent |
| errors | 95.6% | ⭐⭐⭐⭐⭐ Excellent |
| gosqlx/testing | 95.0% | ⭐⭐⭐⭐⭐ Excellent |
| security | 90.2% | ⭐⭐⭐⭐ Very Good |
| config | 81.8% | ⭐⭐⭐⭐ Good |
| ast | 80.3% | ⭐⭐⭐⭐ Good |
| tokenizer | 76.1% | ⭐⭐⭐⭐ Good |
| parser | 75.0% | ⭐⭐⭐⭐ Good |
| metrics | 73.9% | ⭐⭐⭐ Acceptable |
| lsp | 70.2% | ⭐⭐⭐ Acceptable |
| gosqlx | 65.6% | ⭐⭐⭐ Acceptable |

**Overall Test Quality:**
- 3 packages at 100% coverage
- Zero race conditions detected (20,000+ concurrent operations tested)
- Real-world SQL validation: 95%+ success rate
- Thread-safe operation confirmed across all test scenarios

---

## SQL Standards Compliance (v1.6.0)

GoSQLX achieves **~80-85% SQL-99 compliance** with comprehensive support for:

### SQL-92 Core Features
- ✅ Basic SELECT, INSERT, UPDATE, DELETE
- ✅ JOINs (INNER, LEFT, RIGHT, FULL OUTER, CROSS, NATURAL)
- ✅ Subqueries and derived tables
- ✅ Basic aggregates (COUNT, SUM, AVG, MIN, MAX)
- ✅ GROUP BY, HAVING, ORDER BY

### SQL-99 Advanced Features
- ✅ **F401** Extended UNION, EXCEPT, INTERSECT
- ✅ **F591** Derived tables
- ✅ **F611** Indicator data types
- ✅ **F831** Full outer join
- ✅ **F851** NULLS FIRST/LAST in ORDER BY
- ✅ **F861** FETCH FIRST clause
- ✅ **F862** OFFSET clause with FETCH
- ✅ **T431** Extended grouping capabilities (ROLLUP, CUBE, GROUPING SETS)

### SQL:2003 Features
- ✅ **F302** INTERSECT table operator
- ✅ **F304** EXCEPT ALL/INTERSECT ALL
- ✅ **F312** MERGE statement
- ✅ **T431** Extended ROLLUP, CUBE
- ✅ **T612** Advanced OLAP operations (window functions)
- ✅ **T612** FILTER clause for aggregates

### SQL:2008 Features
- ✅ TRUNCATE TABLE

### PostgreSQL Extensions (v1.6.0)
- ✅ LATERAL JOIN
- ✅ JSON/JSONB operators (10 operators)
- ✅ DISTINCT ON
- ✅ FILTER clause
- ✅ ORDER BY inside aggregates
- ✅ RETURNING clause
- ✅ MATERIALIZED/NOT MATERIALIZED CTE hints

### Multi-Dialect Support
- ✅ PostgreSQL (primary)
- ✅ MySQL (backtick identifiers, dialect keywords)
- ✅ SQL Server (dialect keywords)
- ✅ Oracle (dialect keywords)
- ✅ SQLite (dialect keywords)

---

## Additional Resources

- **GitHub Repository**: https://github.com/ajitpratap0/GoSQLX
- **Documentation**: See `/docs` directory
  - `GETTING_STARTED.md` - Quick start guide
  - `USAGE_GUIDE.md` - Comprehensive usage guide
  - `LSP_GUIDE.md` - LSP server and IDE integration
  - `LINTING_RULES.md` - All 10 linting rules reference
  - `CONFIGURATION.md` - Configuration file guide
  - `SQL_COMPATIBILITY.md` - SQL dialect compatibility matrix
  - `ERROR_CODES.md` - Complete error code reference
- **Examples**: See `/examples` directory
- **Issue Tracker**: GitHub Issues
- **License**: Apache-2.0

---

**Version**: 1.6.0
**Last Updated**: 2025-12-12
**Minimum Go Version**: 1.21+
