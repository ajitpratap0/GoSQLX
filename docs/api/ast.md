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
    With              *WithClause         // CTE support
    Distinct          bool                // DISTINCT keyword
    DistinctOnColumns []Expression        // PostgreSQL DISTINCT ON
    Top               *TopClause          // SQL Server TOP N [PERCENT]
    Columns           []Expression
    From              []TableReference
    Joins             []JoinClause
    Where             Expression
    GroupBy           []Expression        // Supports ROLLUP, CUBE, GROUPING SETS
    Having            Expression
    Windows           []WindowSpec        // Window function specifications
    OrderBy           []OrderByExpression // Supports NULLS FIRST/LAST
    Limit             *int
    Offset            *int
    Fetch             *FetchClause        // SQL-99 FETCH FIRST/NEXT
    Extras            *SelectExtras       // Rarer dialect clauses; nil when absent
    // ... dialect clauses such as ArrayJoin, Sample, Qualify, For, Settings
}
```

**PostgreSQL-Specific Features:**
- `DistinctOnColumns` - SELECT DISTINCT ON (column1, column2)

`Extras` is described under [Dialect extension fields](#dialect-extension-fields).

**Example:**
```go
// PostgreSQL DISTINCT ON
sql := "SELECT DISTINCT ON (dept_id) dept_id, name, salary FROM employees ORDER BY dept_id, salary DESC"
ast, _ := gosqlx.Parse(sql)
if stmt, ok := ast.Statements[0].(*ast.SelectStatement); ok {
    fmt.Printf("DISTINCT ON columns: %d\n", len(stmt.DistinctOnColumns))
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

## Utility Statements

### `ExplainStatement`
`EXPLAIN`, `DESCRIBE` or `DESC` applied to a statement, such as `EXPLAIN ANALYZE SELECT ...`, `EXPLAIN (FORMAT JSON) ...` or SQLite `EXPLAIN QUERY PLAN ...`. `DESCRIBE` of a table name is still a `DescribeStatement`.

```go
type ExplainStatement struct {
    Keyword   string    // EXPLAIN, DESCRIBE or DESC, upper-cased
    Options   string    // text between the keyword and the statement, e.g. "ANALYZE VERBOSE"
    Statement Statement // the explained statement
}
```

On the main branch (unreleased, next release), `EXPLAIN SELECT 1` parses into an `*ast.ExplainStatement` whose `Statement` is the `*ast.SelectStatement`, and `SQL()` writes it back as `EXPLAIN SELECT 1`. In earlier releases it became a `DescribeStatement`, so code that matched `EXPLAIN` through `*ast.DescribeStatement` must handle `*ast.ExplainStatement` instead. `Children()` returns the explained statement, so `ast.Inspect` and `ast.Walk` reach it.

```go
tree, _ := gosqlx.ParseWithDialect("EXPLAIN SELECT 1", keywords.DialectPostgreSQL)
if e, ok := tree.Statements[0].(*ast.ExplainStatement); ok {
    fmt.Printf("%s %T\n", e.Keyword, e.Statement) // EXPLAIN *ast.SelectStatement
}
```

### `BatchSeparator`
A SQL Server `GO` line. It sits in `AST.Statements` between the statements of a T-SQL script.

```go
type BatchSeparator struct {
    RepeatCount int             // n in "GO n"; 0 when no count was written
    Pos         models.Location // source position of the GO keyword
}
```

On the main branch (unreleased, next release), scripts that use `GO` and `GO <count>` parse with the SQL Server dialect, also without semicolons. Repeated batches are not expanded, and `SQL()` and `FormatAST` keep each `GO` on its own line. Code that enumerates `AST.Statements` must skip `*ast.BatchSeparator` nodes when it counts statements:

```go
tree, _ := gosqlx.ParseWithDialect("SELECT 1\nGO\nSELECT 2\nGO 3", keywords.DialectSQLServer)
for _, stmt := range tree.Statements {
    if sep, ok := stmt.(*ast.BatchSeparator); ok {
        fmt.Println("GO", sep.RepeatCount) // GO 0, then GO 3
        continue
    }
    fmt.Printf("%T\n", stmt) // *ast.SelectStatement
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
    Name       string
    Table      string          // optional qualifier; "db.t" for db.t.col
    Pos        models.Location
    Quoted     bool            // Name was an ANSI double-quoted identifier
    Quotes     NameQuote       // which parts were delimited and must stay delimited
    QuoteStyle rune            // '"', '`' or '[' as written; 0 when nothing was delimited
}
```

`QuoteStyle` records the opening delimiter the source used: `"` (ANSI), `` ` `` (MySQL, MariaDB, ClickHouse) or `[` (SQL Server). On the main branch (unreleased, next release), `SQL()`, the formatter and fingerprints write quoted identifiers back with the same delimiters, so a MySQL `` `select` `` stays a name. Statement, table and column names carry the same information in `NameQuote` fields, such as `TableReference.NameQuote` and `TableReference.AliasQuote`.

### `LiteralValue`
```go
type LiteralValue struct {
    Value interface{}
    Type  string // INTEGER, FLOAT, STRING, BOOLEAN, NULL, ...
    // unexported extras: introducer and escape metadata
}
```

String literals keep their introducer and escape rules (unreleased, on the main branch). Read them with `DialectExtras()`, which returns a `LiteralExtras` value, and change them through `EnsureExtras()` or `SetRawBackslash()`:

```go
type LiteralExtras struct {
    Prefix       string // N, X, B or a MySQL introducer such as _utf8mb4; "" for a plain string
    RawBackslash bool   // backslash is an ordinary character in the source dialect
}
```

```go
tree, _ := gosqlx.ParseWithDialect("SELECT N'abc', X'0F', _utf8mb4'hi' FROM t", keywords.DialectMySQL)
sel := tree.Statements[0].(*ast.SelectStatement)
lit := sel.Columns[2].(*ast.LiteralValue)
fmt.Println(lit.DialectExtras().Prefix) // _utf8mb4
fmt.Println(tree.SQL())                 // SELECT N'abc', X'0F', _utf8mb4'hi' FROM t
```

### `BinaryExpression`
```go
type BinaryExpression struct {
    Left       Expression
    Operator   string
    Right      Expression
    Not        bool
    PipesOr    bool                  // MySQL || meaning OR
    BitwiseXor bool                  // ^ is bitwise XOR (MySQL, MariaDB, SQL Server), not exponentiation
    CustomOp   *CustomBinaryOperator // PostgreSQL custom operators
    Extras     *BinaryExtras         // LIKE ... ESCAPE; nil when absent
    Pos        models.Location
}
```

`^` is exponentiation in PostgreSQL and bitwise XOR in MySQL, MariaDB and SQL Server. The parser records the XOR meaning in `BitwiseXor` (unreleased, on the main branch), and `gosqlx.Transpile` uses it to write `POWER()`, `#`, `BITXOR()` or `bitXor()` for the target dialect.

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
    Subquery    *SelectStatement // Derived table: (SELECT ...) alias
    Lateral     bool             // PostgreSQL LATERAL JOIN
    NameQuote   NameQuote        // delimited parts of Name
    AliasQuote  NameQuote        // delimited parts of Alias
    Pivot       *PivotClause     // PIVOT (...)
    Unpivot     *UnpivotClause   // UNPIVOT (...)
    SetSubquery *SetOperation    // Derived table whose body is a set operation
    Modifiers   *TableModifiers  // Rarer table modifiers; nil when absent
    // ... Final, Only, TableHints, TableFunc, TimeTravel and other dialect fields
}
```

`Modifiers` holds TABLESAMPLE / SAMPLE, Oracle flashback and `@dblink`, MySQL `PARTITION` selection and index hints, SQLite `INDEXED BY`, the SQL Server `OPENJSON ... WITH` schema and a derived `VALUES` table. Read it with `DialectModifiers()` and write it after `EnsureModifiers()`; see [Dialect extension fields](#dialect-extension-fields).

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
    OffsetValue *int64     // OFFSET n ROWS
    FetchValue  *int64     // FETCH n ROWS
    FetchType   string     // "FIRST" or "NEXT"
    IsPercent   bool       // PERCENT keyword
    WithTies    bool       // WITH TIES keyword
    FetchExpr   Expression // row count that is not a plain integer
}
```

**Example:**
```go
// FETCH FIRST with TIES
sql := "SELECT * FROM users ORDER BY score DESC FETCH FIRST 10 ROWS WITH TIES"
ast, _ := gosqlx.Parse(sql)
```

### `PivotClause` and `UnpivotClause`
```go
type PivotClause struct {
    AggregateFunction Expression       // e.g. SUM(sales)
    AggregateAlias    string           // alias of AggregateFunction
    ExtraAggregates   []PivotAggregate // second and later aggregates (Oracle, BigQuery)
    PivotColumn       string
    InValues          []string
    Pos               models.Location
    PivotExtensions                    // XML, dynamic IN lists, source aliases
}

type PivotAggregate struct {
    Function Expression
    Alias    string
}

type UnpivotClause struct {
    NullHandling     string   // "", "INCLUDE NULLS" or "EXCLUDE NULLS"
    ValueColumn      string
    ValueColumns     []string // multi-column UNPIVOT
    NameColumn       string
    InColumns        []string
    Pos              models.Location
    SourceAlias      string
    SourceAliasQuote NameQuote
}
```

`AggregateAlias`, `ExtraAggregates`, `NullHandling` and `ValueColumns` are unreleased additions on the main branch. `ast.UnpivotNullHandling(s)` normalizes a `NullHandling` value. Quoted aliases and value columns keep their source delimiters when rendered.

## Dialect Extension Fields

Dialect-specific clauses that most statements never use live behind optional pointers, so common statements do not carry them. On the main branch (unreleased, next release) these are:

| Field | Type | Holds |
|---|---|---|
| `SelectStatement.Extras` | `*SelectExtras` | SELECT modifiers, INTO, LIMIT BY, ROWS EXAMINED, INTERPOLATE, query hints, output formats |
| `InsertStatement.Extras` | `*InsertDialectFields` | INSERT modifiers (MySQL `IGNORE`, SQLite `OR REPLACE`, Snowflake `OVERWRITE`), PostgreSQL `OVERRIDING`, the MySQL row alias and other INSERT clauses |
| `UpdateStatement.Extras`, `DeleteStatement.Extras` | `*DMLTargetFields` | modifiers, TOP, ONLY, extra targets, joins, OUTPUT, ORDER BY / LIMIT, RETURNING INTO |
| `FunctionCall.Extras` | `*FunctionExtras` | `GROUP_CONCAT ... SEPARATOR`, Oracle KEEP |
| `BinaryExpression.Extras` | `*BinaryExtras` | `LIKE ... ESCAPE` |
| `TableReference.Modifiers` | `*TableModifiers` | sampling, partitions, index hints, derived `VALUES` |

Read them through `DialectExtras()` (or `DialectModifiers()` for a table reference). It returns a copy of the struct by value (the zero value when the pointer is nil), so callers need no nil check, and assigning to a field of the copy does not change the node. The copy is shallow: slices and pointers inside it still refer to the node's data, so treat them as read-only. To change a node, call `EnsureExtras()` (or `EnsureModifiers()`); it allocates the struct when needed and returns a pointer to it:

```go
sel := tree.Statements[0].(*ast.SelectStatement)
if sel.DialectExtras().Into != nil { // safe when sel.Extras is nil
    // SELECT ... INTO
}
sel.EnsureExtras().OutputFormat = "JSON" // allocates sel.Extras if needed
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
