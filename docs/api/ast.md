# ast package

Statement and expression node types, object pools and the visitor pattern.

Import path: `github.com/ajitpratap0/GoSQLX/pkg/sql/ast` ([pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/sql/ast))

Part of the [GoSQLX API reference](../API_REFERENCE.md).

## Core Interfaces

### Interface: `Node`
Base interface for all AST nodes.

```go
type Node interface {
    TokenLiteral() string
    Children() []Node
}
```

### Interface: `Statement`
Executable SQL statements.

```go
type Statement interface {
    Node
    statementNode()
}
```

### Interface: `Expression`
SQL expressions (values, conditions, computations).

```go
type Expression interface {
    Node
    expressionNode()
}
```

## DML Statement Types

### `SelectStatement`
```go
type SelectStatement struct {
    With        *WithClause         // CTE support
    Distinct    bool                // DISTINCT keyword
    DistinctOn  []Expression        // PostgreSQL DISTINCT ON
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
    FetchClause *FetchClause        // SQL-99 FETCH FIRST support
}
```

**PostgreSQL-Specific Features:**
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

### `InsertStatement`
```go
type InsertStatement struct {
    With       *WithClause      // CTE support
    TableName  string
    Columns    []Expression
    Values     []Expression     // Supports function calls (NOW(), UUID(), etc.)
    Query      *SelectStatement // INSERT INTO ... SELECT
    Returning  []Expression     // PostgreSQL RETURNING clause
    OnConflict *OnConflict      // Upsert support
}
```

**Enhancements:**
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

### `UpdateStatement`
```go
type UpdateStatement struct {
    With        *WithClause      // CTE support
    TableName   string
    Updates     []UpdateExpression // SET column = value pairs
    Assignments []UpdateExpression // Alias for Updates (preferred)
    From        []TableReference  // PostgreSQL UPDATE ... FROM
    Where       Expression
    Returning   []Expression      // PostgreSQL RETURNING clause
}
```

**Enhancements:**
- `Returning` - PostgreSQL RETURNING clause for UPDATE

### `DeleteStatement`
```go
type DeleteStatement struct {
    With      *WithClause      // CTE support
    TableName string
    Using     []TableReference // PostgreSQL DELETE ... USING
    Where     Expression
    Returning []Expression     // PostgreSQL RETURNING clause
}
```

**Enhancements:**
- `Returning` - PostgreSQL RETURNING clause for DELETE

### `MergeStatement`
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

### `TruncateStatement`
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

## DDL Statement Types

### `CreateTableStatement`
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

**Enhancements:**
- Full column constraint support (PRIMARY KEY, FOREIGN KEY, UNIQUE, CHECK, NOT NULL, DEFAULT)
- Parameterized types (VARCHAR(100), DECIMAL(10,2))
- Referential actions (ON DELETE/UPDATE CASCADE, SET NULL, SET DEFAULT)

### `CreateIndexStatement`
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

### `CreateViewStatement`
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

### `CreateMaterializedViewStatement`
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

### `RefreshMaterializedViewStatement`
```go
type RefreshMaterializedViewStatement struct {
    Name         string
    Concurrently bool // CONCURRENTLY option (PostgreSQL)
}
```

### `AlterTableStatement`
```go
type AlterTableStatement struct {
    TableName string
    Actions   []AlterAction
}
```

### `DropStatement`
```go
type DropStatement struct {
    ObjectType string // TABLE, INDEX, VIEW, MATERIALIZED VIEW, etc.
    ObjectName string
    IfExists   bool
    Cascade    bool   // CASCADE option
}
```

## CTE and Set Operations

### `WithClause`
```go
type WithClause struct {
    Recursive    bool
    Materialized *bool              // MATERIALIZED/NOT MATERIALIZED hint
    CTEs         []CommonTableExpr
}
```

**Enhancements:**
- `Materialized` - PostgreSQL optimization hints (MATERIALIZED, NOT MATERIALIZED)

**Example:**
```go
// Materialized CTE
sql := "WITH cte AS MATERIALIZED (SELECT * FROM large_table WHERE expensive_filter = true) SELECT * FROM cte"
ast, _ := gosqlx.Parse(sql)
```

### `CommonTableExpr`
```go
type CommonTableExpr struct {
    Name    string
    Columns []string
    Query   *SelectStatement
}
```

### `SetOperation`
```go
type SetOperation struct {
    Left     Statement // Can be SelectStatement or another SetOperation
    Operator string    // UNION, EXCEPT, INTERSECT
    All      bool
    Right    Statement // SelectStatement, or a SetOperation for "A EXCEPT (B UNION C)"

    LeftParenthesized  bool // Left was written as "(query)"
    RightParenthesized bool // Right was written as "(query)"
}
```

`LeftParenthesized` / `RightParenthesized` record operand parentheses, as in
`(SELECT 1) UNION (SELECT 2)`. `SQL()` and the formatters emit them, and always
parenthesize a `Right` operand that is itself a `SetOperation`.

## Grouping Set Types

### `RollupExpression`
```go
type RollupExpression struct {
    Expressions []Expression
}
```

### `CubeExpression`
```go
type CubeExpression struct {
    Expressions []Expression
}
```

### `GroupingSetsExpression`
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

## Window Function Types

### `WindowSpec`
```go
type WindowSpec struct {
    Name        string
    PartitionBy []Expression
    OrderBy     []OrderByExpression
    Frame       *WindowFrame
}
```

### `WindowFrame`
```go
type WindowFrame struct {
    Type  string       // ROWS or RANGE
    Start *FrameBound
    End   *FrameBound
}
```

### `FrameBound`
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

## Expression Types

### `Identifier`
```go
type Identifier struct {
    Name  string
    Value string // Alias for Name
}
```

### `LiteralValue`
```go
type LiteralValue struct {
    Type  string // STRING, NUMBER, BOOLEAN, NULL
    Value string
}
```

### `BinaryExpression`
```go
type BinaryExpression struct {
    Left     Expression
    Operator string
    Right    Expression
}
```

**Supported Operators:**
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

### `FunctionCall`
```go
type FunctionCall struct {
    Name      string
    Arguments []Expression
    Distinct  bool          // DISTINCT keyword in aggregate
    Filter    Expression    // FILTER (WHERE ...) clause
    OrderBy   []OrderByExpression // ORDER BY inside aggregate
    Over      *WindowSpec   // Window specification
}
```

**Enhancements:**
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

### `CaseExpression`
```go
type CaseExpression struct {
    CaseExpr  Expression
    WhenPairs []WhenPair
    ElseExpr  Expression
}
```

### `InExpression`
```go
type InExpression struct {
    Expr   Expression
    Not    bool
    Values []Expression
    Query  *SelectStatement
}
```

### `BetweenExpression`
```go
type BetweenExpression struct {
    Expr  Expression
    Not   bool
    Lower Expression
    Upper Expression
}
```

### `SubqueryExpression`
```go
type SubqueryExpression struct {
    Query *SelectStatement
}
```

**Enhancement:**
- Derived tables in FROM clause: `(SELECT ...) AS alias`

## Supporting Types

### `JoinClause`
```go
type JoinClause struct {
    Type      string // INNER, LEFT, RIGHT, FULL, CROSS, NATURAL
    Table     TableReference
    Condition Expression   // ON condition (nil for USING / CROSS / NATURAL)
    Using     []Expression // USING (col, ...) columns
}
```

### `OrderByExpression`
```go
type OrderByExpression struct {
    Expression Expression
    Descending bool
    NullsFirst bool // NULLS FIRST
    NullsLast  bool // NULLS LAST
}
```

**Example:**
```go
// NULLS FIRST/LAST
sql := "SELECT * FROM users ORDER BY last_login DESC NULLS LAST"
ast, _ := gosqlx.Parse(sql)
```

### `TableReference`
```go
type TableReference struct {
    Name        string
    Alias       string
    Lateral     bool             // PostgreSQL LATERAL JOIN
    Subquery    *SelectStatement // Derived table: (SELECT ...) alias
    SetSubquery *SetOperation    // Derived table whose body is a set operation
}
```

**Enhancement:**
- `Lateral` - PostgreSQL LATERAL JOIN support

At most one of `Subquery` and `SetSubquery` is set. A derived table whose body is a
single `SELECT` (including one with a `WITH` clause or extra parentheses, as in
`FROM ((SELECT 1)) t`) is held in `Subquery`; one whose body is a set operation, as in
`FROM (SELECT a FROM t1 UNION SELECT a FROM t2) u`, is held in `SetSubquery`.

**Example:**
```go
// LATERAL JOIN
sql := "SELECT u.name, r.order_date FROM users u, LATERAL (SELECT * FROM orders WHERE user_id = u.id ORDER BY order_date DESC LIMIT 3) r"
ast, _ := gosqlx.Parse(sql)
```

### `FetchClause`
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

## Object Pool Functions

### `NewAST() *AST`
Get AST from pool.

```go
astObj := ast.NewAST()
defer ast.ReleaseAST(astObj)
```

### `ReleaseAST(a *AST)`
Return AST to pool.

### `NewSelectStatement() *SelectStatement`
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

**Pool Optimizations:**
- Iterative cleanup with work queue pattern (prevents stack overflow)
- MaxCleanupDepth and MaxWorkQueueSize limits
- 8 new expression pools added

## Visitor Pattern

### Interface: `Visitor`
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
