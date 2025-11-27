# GoSQLX API Reference

## Table of Contents

- [Package Overview](#package-overview)
- [High-Level API (pkg/gosqlx)](#high-level-api)
  - [Parsing Functions](#parsing-functions)
  - [Validation Functions](#validation-functions)
  - [Future Enhancements](#future-enhancements)
- [Tokenizer API](#tokenizer-api)
  - [Functions](#functions)
  - [Supported Token Types](#supported-token-types)
- [Parser API](#parser-api)
  - [Type: Parser](#type-parser)
- [AST API](#ast-api)
  - [Core Interfaces](#core-interfaces)
  - [DML Statement Types](#dml-statement-types) (SELECT, INSERT, UPDATE, DELETE, MERGE)
  - [DDL Statement Types](#ddl-statement-types) (CREATE, ALTER, DROP)
  - [CTE and Set Operation Types](#cte-and-set-operation-types)
  - [Expression Types](#expression-types)
  - [Grouping Set Types](#grouping-set-types) (ROLLUP, CUBE, GROUPING SETS)
  - [Window Function Types](#window-function-types)
  - [Supporting Types](#supporting-types)
  - [Object Pool Functions](#object-pool-functions)
  - [Visitor Pattern](#visitor-pattern)
- [Keywords Package](#keywords-package)
  - [Core Types](#core-types)
  - [Dialect-Specific Keywords](#dialect-specific-keywords)
- [Models](#models)
- [Error Handling](#error-handling)
  - [Error Codes](#error-codes)
  - [Error Builder Functions](#error-builder-functions)
- [Metrics Package](#metrics-package)
  - [Configuration Functions](#configuration-functions)
  - [Recording Functions](#recording-functions)
  - [Query Functions](#query-functions)
- [Security Package](#security-package)
  - [Scanner Types](#scanner-types)
  - [Pattern Detection](#pattern-detection)
  - [Severity Levels](#severity-levels)
- [Performance Considerations](#performance-considerations)

## Package Overview

GoSQLX is organized into the following packages:

```
github.com/ajitpratap0/GoSQLX/
├── pkg/
│   ├── gosqlx/          # High-level convenience API
│   ├── models/          # Core data structures
│   ├── sql/
│   │   ├── tokenizer/   # SQL lexical analysis
│   │   ├── parser/      # SQL syntax parsing
│   │   ├── ast/         # Abstract syntax tree
│   │   ├── keywords/    # SQL keyword definitions
│   │   ├── token/       # Token types and utilities
│   │   └── security/    # SQL injection detection
│   ├── errors/          # Structured error handling
│   ├── metrics/         # Performance monitoring
│   └── linter/          # SQL linting rules engine
```

## High-Level API

### Package: `github.com/ajitpratap0/GoSQLX/pkg/gosqlx`

The high-level API provides convenient functions for common SQL parsing operations with automatic object pool management. This is the recommended API for most use cases.

### Parsing Functions

#### `Parse(sql string) (*ast.AST, error)`

Parse SQL in a single convenient call.

```go
sql := "SELECT * FROM users WHERE active = true"
astNode, err := gosqlx.Parse(sql)
if err != nil {
    log.Fatal(err)
}
```

**Returns:**
- `*ast.AST`: Parsed abstract syntax tree
- `error`: Parse error if any

**Use Case:** Simple parsing without timeout requirements

---

#### `ParseWithContext(ctx context.Context, sql string) (*ast.AST, error)`

Parse SQL with context support for cancellation and timeouts.

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

astNode, err := gosqlx.ParseWithContext(ctx, sql)
if err == context.DeadlineExceeded {
    log.Println("Parsing timed out")
}
```

**Parameters:**
- `ctx`: Context for cancellation/timeout
- `sql`: SQL string to parse

**Returns:**
- `*ast.AST`: Parsed AST
- `error`: `context.Canceled`, `context.DeadlineExceeded`, or parse error

**Use Case:** Long-running parsing operations that need cancellation

---

#### `ParseWithTimeout(sql string, timeout time.Duration) (*ast.AST, error)`

Convenience wrapper for parsing with automatic timeout.

```go
astNode, err := gosqlx.ParseWithTimeout(sql, 10*time.Second)
if err == context.DeadlineExceeded {
    log.Println("Timeout after 10 seconds")
}
```

**Use Case:** Quick timeout-based parsing without manual context management

---

#### `ParseBytes(sql []byte) (*ast.AST, error)`

Parse SQL from byte slice (zero-copy when already in bytes).

```go
sqlBytes, _ := os.ReadFile("query.sql")
astNode, err := gosqlx.ParseBytes(sqlBytes)
```

**Use Case:** Parsing SQL from file I/O or byte sources

---

#### `MustParse(sql string) *ast.AST`

Parse SQL, panicking on error (for tests and initialization).

```go
// In test or init()
ast := gosqlx.MustParse("SELECT 1")
```

**Use Case:** Parsing SQL literals where errors indicate bugs

---

#### `ParseMultiple(queries []string) ([]*ast.AST, error)`

Parse multiple SQL statements efficiently.

```go
queries := []string{
    "SELECT * FROM users",
    "SELECT * FROM orders",
    "SELECT * FROM products",
}
asts, err := gosqlx.ParseMultiple(queries)
```

**Benefits:**
- Reuses tokenizer and parser objects
- 40-60% faster than individual Parse() calls
- Lower memory allocation

**Use Case:** Batch processing SQL queries

---

### Validation Functions

#### `Validate(sql string) error`

Check if SQL is syntactically valid.

```go
if err := gosqlx.Validate("SELECT * FROM users"); err != nil {
    fmt.Printf("Invalid SQL: %v\n", err)
}
```

**Returns:** `nil` if valid, error describing the problem

**Use Case:** Syntax validation without building full AST

---

#### `ValidateMultiple(queries []string) error`

Validates multiple SQL queries in a batch operation.

```go
queries := []string{
    "SELECT * FROM users",
    "INSERT INTO logs (msg) VALUES ('test')",
    "UPDATE users SET name = 'John' WHERE id = 1",
}
if err := gosqlx.ValidateMultiple(queries); err != nil {
    log.Fatal("Validation failed:", err)
}
```

**Parameters:**
- `queries`: A slice of SQL query strings to validate

**Returns:**
- `error`: First validation error encountered, or nil if all queries are valid

**Benefits:**
- Reuses tokenizer and parser objects across queries
- More efficient than calling `Validate()` individually
- Ideal for batch validation scenarios

**Use Case:** Validating multiple SQL queries efficiently

---

### Future Enhancements

**Note:** The following metadata extraction functions are planned for future releases but not yet implemented:

- `ExtractTables(astNode *ast.AST) []string` - Extract table names from parsed SQL
- `ExtractColumns(astNode *ast.AST) []string` - Extract column references
- `ExtractFunctions(astNode *ast.AST) []string` - Extract function calls
- `ExtractTablesQualified(astNode *ast.AST) []QualifiedName` - Extract tables with schema info
- `ExtractColumnsQualified(astNode *ast.AST) []QualifiedName` - Extract columns with qualifiers

For now, use the AST Visitor pattern to manually traverse and extract metadata from parsed SQL.

---

### Performance Comparison

| Operation | Tokenizer+Parser API | High-Level API | Overhead |
|-----------|---------------------|----------------|----------|
| Single parse | 100% (baseline) | ~110% | +10% |
| Batch parse (10 queries) | 100% (with reuse) | ~105% | +5% |

**Recommendation:**
- Use high-level API for simple cases (< 100 queries/sec)
- Use tokenizer+parser API for performance-critical batch processing

---

### Complete Example

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func main() {
    sql := `
        SELECT u.id, u.name, COUNT(o.id) as order_count
        FROM users u
        LEFT JOIN orders o ON u.id = o.user_id
        WHERE u.created_at >= '2024-01-01'
        GROUP BY u.id, u.name
        HAVING COUNT(o.id) > 5
        ORDER BY order_count DESC
        LIMIT 10
    `

    // Parse SQL
    astNode, err := gosqlx.Parse(sql)
    if err != nil {
        log.Fatal("Parse error:", err)
    }
    defer ast.ReleaseAST(astNode)

    // Parse with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    astWithTimeout, err := gosqlx.ParseWithContext(ctx, sql)
    if err != nil {
        log.Fatal("Parse with context error:", err)
    }
    defer ast.ReleaseAST(astWithTimeout)

    // Validate SQL syntax
    if err := gosqlx.Validate(sql); err != nil {
        log.Fatal("Validation error:", err)
    }

    fmt.Println("SQL parsed and validated successfully!")
    fmt.Printf("Number of statements: %d\n", len(astNode.Statements))
}
```

---

## Tokenizer API

### Package: `github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer`

The tokenizer performs lexical analysis of SQL text, converting it into a stream of tokens.

### Functions

#### `GetTokenizer() *Tokenizer`
Retrieves a tokenizer instance from the object pool.

```go
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz) // ALWAYS defer the return
```

**Returns:** A pointer to a Tokenizer instance  
**Thread-Safe:** Yes  
**Pool Behavior:** Reuses existing instances when available

#### `PutTokenizer(t *Tokenizer)`
Returns a tokenizer instance to the object pool for reuse.

```go
tokenizer.PutTokenizer(tkz)
```

**Parameters:**
- `t`: The tokenizer instance to return to the pool

**Thread-Safe:** Yes  
**Important:** Always call this when done with a tokenizer

### Type: `Tokenizer`

#### Method: `Tokenize(input []byte) ([]models.TokenWithSpan, error)`
Tokenizes SQL input into tokens with position information.

```go
tokens, err := tkz.Tokenize([]byte("SELECT * FROM users"))
if err != nil {
    // Handle error
}
```

**Parameters:**
- `input`: SQL text as byte slice

**Returns:**
- `[]models.TokenWithSpan`: Array of tokens with position spans
- `error`: Tokenization error if any

**Features:**
- Zero-copy operation
- Unicode support (UTF-8)
- Position tracking (line, column)
- Dialect-specific tokens (PostgreSQL @>, MySQL backticks, etc.)

---

#### Method: `TokenizeContext(ctx context.Context, input []byte) ([]models.TokenWithSpan, error)`
Tokenizes SQL input with context support for cancellation and timeouts.

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

tokens, err := tkz.TokenizeContext(ctx, []byte("SELECT * FROM users"))
if err == context.DeadlineExceeded {
    log.Println("Tokenization timed out")
}
```

**Parameters:**
- `ctx`: Context for cancellation/timeout control
- `input`: SQL text as byte slice

**Returns:**
- `[]models.TokenWithSpan`: Array of tokens with position spans
- `error`: `context.Canceled`, `context.DeadlineExceeded`, or tokenization error

**Use Case:** Long-running tokenization with timeout/cancellation support

**Note:** Context is checked every 100 tokens for efficient cancellation

---

#### Method: `Reset()`
Resets the tokenizer state for reuse.

```go
tkz.Reset()
```

**Note:** Called automatically by the pool management

### Supported Token Types

| Token Type | Description | Example |
|------------|-------------|---------|
| `TokenTypeSelect` | SELECT keyword | `SELECT` |
| `TokenTypeFrom` | FROM keyword | `FROM` |
| `TokenTypeWhere` | WHERE keyword | `WHERE` |
| `TokenTypeIdentifier` | Column/table names | `users`, `id` |
| `TokenTypeNumber` | Numeric literals | `42`, `3.14` |
| `TokenTypeSingleQuotedString` | String literals | `'hello'` |
| `TokenTypeDoubleQuotedString` | Quoted identifiers | `"column name"` |
| `TokenTypeBacktickIdentifier` | MySQL identifiers | `` `column` `` |
| `TokenTypeBracketIdentifier` | SQL Server identifiers | `[column]` |

### Special Character Support

```go
// Unicode identifiers (all languages)
`SELECT "名前", "имя", "الاسم" FROM users`

// Emoji in strings
`SELECT * FROM users WHERE status = '🚀'`

// PostgreSQL operators
`SELECT * FROM users WHERE tags @> ARRAY['admin']`

// MySQL backticks
`SELECT `user_id` FROM `users``
```

## Parser API

### Package: `github.com/ajitpratap0/GoSQLX/pkg/sql/parser`

The parser builds an Abstract Syntax Tree (AST) from tokens.

### Functions

#### `NewParser() *Parser`
Creates a new parser instance from the pool.

```go
p := parser.NewParser()
defer p.Release() // ALWAYS defer the release
```

**Returns:** A pointer to a Parser instance  
**Thread-Safe:** Yes

### Type: `Parser`

#### Method: `Parse(tokens []token.Token) (*ast.AST, error)`
Parses tokens into an AST.

```go
astNode, err := p.Parse(tokens)
if err != nil {
    // Handle parse error
}
```

**Parameters:**
- `tokens`: Array of tokens to parse

**Returns:**
- `*ast.AST`: Root AST container with parsed statements
- `error`: Parse error if any

**Supported Statements:**
- SELECT (with JOIN, GROUP BY, ORDER BY, HAVING, CTEs, window functions)
- INSERT (single and multi-row)
- UPDATE (with WHERE)
- DELETE (with WHERE)
- CREATE TABLE, CREATE INDEX, CREATE VIEW, CREATE MATERIALIZED VIEW
- ALTER TABLE
- DROP TABLE, DROP INDEX, DROP VIEW
- MERGE statements

---

#### Method: `ParseContext(ctx context.Context, tokens []token.Token) (*ast.AST, error)`
Parses tokens with context support for cancellation and timeouts.

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

astNode, err := p.ParseContext(ctx, tokens)
if err == context.DeadlineExceeded {
    log.Println("Parsing timed out")
}
```

**Parameters:**
- `ctx`: Context for cancellation/timeout control
- `tokens`: Array of tokens to parse

**Returns:**
- `*ast.AST`: Parsed AST
- `error`: `context.Canceled`, `context.DeadlineExceeded`, or parse error

**Use Case:** Long-running parsing with timeout/cancellation support

---

#### Method: `ParseWithPositions(result *ConversionResult) (*ast.AST, error)`
Parses tokens with enhanced error reporting using position information.

```go
converter := parser.NewTokenConverter()
result, err := converter.Convert(tokens)
if err != nil {
    log.Fatal(err)
}

astNode, err := p.ParseWithPositions(result)
// Errors will include accurate line/column information
```

**Parameters:**
- `result`: ConversionResult containing tokens and position mappings

**Returns:**
- `*ast.AST`: Parsed AST
- `error`: Parse error with precise position information

**Use Case:** When you need detailed error location reporting

---

#### Method: `Release()`
Returns the parser to the pool.

```go
p.Release()
```

**Important:** Always call this when done

## AST API

### Package: `github.com/ajitpratap0/GoSQLX/pkg/sql/ast`

The AST package provides comprehensive node types for SQL syntax trees, supporting DDL, DML, CTEs, window functions, set operations, and advanced SQL features.

### Overview

**Key Features:**
- **Complete SQL Support**: SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, MERGE
- **Advanced Features**: CTEs, window functions, set operations, subqueries
- **Visitor Pattern**: Tree traversal support via `ast.Visitor` interface
- **Object Pooling**: Memory-efficient node management
- **Type Safety**: Strongly typed nodes with interfaces

### Core Interfaces

#### Interface: `Node`
Base interface for all AST nodes.

```go
type Node interface {
    TokenLiteral() string  // Returns the literal token representation
    Children() []Node      // Returns child nodes for tree traversal
}
```

**Example:**
```go
func PrintTree(node ast.Node, indent int) {
    fmt.Printf("%s%s\n", strings.Repeat("  ", indent), node.TokenLiteral())
    for _, child := range node.Children() {
        PrintTree(child, indent+1)
    }
}
```

#### Interface: `Statement`
Represents executable SQL statements.

```go
type Statement interface {
    Node
    statementNode()  // Marker method for type safety
}
```

**Implementing Types:**
- `SelectStatement`, `InsertStatement`, `UpdateStatement`, `DeleteStatement`
- `CreateTableStatement`, `CreateIndexStatement`, `CreateViewStatement`
- `CreateMaterializedViewStatement`, `RefreshMaterializedViewStatement`
- `AlterTableStatement`, `DropStatement`, `MergeStatement`
- `WithClause`, `CommonTableExpr`, `SetOperation`

#### Interface: `Expression`
Represents SQL expressions (values, conditions, computations).

```go
type Expression interface {
    Node
    expressionNode()  // Marker method for type safety
}
```

**Implementing Types:**
- `Identifier`, `LiteralValue`, `BinaryExpression`, `UnaryExpression`
- `FunctionCall`, `CaseExpression`, `CastExpression`
- `InExpression`, `BetweenExpression`, `ExistsExpression`
- `SubqueryExpression`, `AnyExpression`, `AllExpression`
- `RollupExpression`, `CubeExpression`, `GroupingSetsExpression`

---

### DML Statement Types

#### `SelectStatement`
Represents a SELECT query with full SQL support.

```go
type SelectStatement struct {
    With      *WithClause         // Optional CTE (WITH clause)
    Distinct  bool                // DISTINCT modifier
    Columns   []Expression        // SELECT columns
    From      []TableReference    // FROM tables
    TableName string              // Primary table name
    Joins     []JoinClause        // JOIN clauses
    Where     Expression          // WHERE condition
    GroupBy   []Expression        // GROUP BY columns (supports ROLLUP, CUBE, GROUPING SETS)
    Having    Expression          // HAVING condition
    Windows   []WindowSpec        // WINDOW definitions
    OrderBy   []OrderByExpression // ORDER BY with NULLS FIRST/LAST support
    Limit     *int                // LIMIT value
    Offset    *int                // OFFSET value
}
```

**Example Usage:**
```go
if stmt, ok := astNode.(*ast.SelectStatement); ok {
    // Check for CTE
    if stmt.With != nil {
        fmt.Printf("Has %d CTEs\n", len(stmt.With.CTEs))
    }

    // Process columns
    for _, col := range stmt.Columns {
        fmt.Println("Column:", col.TokenLiteral())
    }

    // Check for window functions
    if len(stmt.Windows) > 0 {
        fmt.Println("Uses window functions")
    }
}
```

**Supported SQL:**
```sql
WITH cte AS (SELECT * FROM source)
SELECT DISTINCT id, name, ROW_NUMBER() OVER (ORDER BY id) as rn
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
WHERE active = true
GROUP BY ROLLUP(region, city)
HAVING COUNT(*) > 5
ORDER BY name NULLS LAST
LIMIT 10 OFFSET 5
```

---

#### `InsertStatement`
Represents an INSERT statement with conflict handling.

```go
type InsertStatement struct {
    With       *WithClause      // Optional CTE
    TableName  string           // Target table
    Columns    []Expression     // Column list
    Values     []Expression     // Value expressions
    Query      *SelectStatement // INSERT ... SELECT
    Returning  []Expression     // RETURNING clause (PostgreSQL)
    OnConflict *OnConflict      // ON CONFLICT clause (PostgreSQL)
}
```

**Example:**
```go
if stmt, ok := astNode.(*ast.InsertStatement); ok {
    fmt.Printf("Insert into: %s\n", stmt.TableName)

    if stmt.Query != nil {
        fmt.Println("INSERT ... SELECT detected")
    }

    if stmt.OnConflict != nil {
        fmt.Println("Has ON CONFLICT handling")
    }
}
```

**Supported SQL:**
```sql
INSERT INTO users (name, email)
VALUES ('John', 'john@example.com')
ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name
RETURNING id, created_at
```

---

#### `UpdateStatement`
Represents an UPDATE statement with multi-table support.

```go
type UpdateStatement struct {
    With        *WithClause        // Optional CTE
    TableName   string             // Target table
    Alias       string             // Table alias
    Updates     []UpdateExpression // SET column = value pairs
    Assignments []UpdateExpression // Alternative field name
    From        []TableReference   // FROM clause for multi-table updates
    Where       Expression         // WHERE condition
    Returning   []Expression       // RETURNING clause (PostgreSQL)
}
```

**Supported SQL:**
```sql
WITH updated AS (SELECT id FROM active_users)
UPDATE users u
SET status = 'active', updated_at = NOW()
FROM updated
WHERE u.id = updated.id
RETURNING u.id, u.status
```

---

#### `DeleteStatement`
Represents a DELETE statement with USING support.

```go
type DeleteStatement struct {
    With      *WithClause      // Optional CTE
    TableName string           // Target table
    Alias     string           // Table alias
    Using     []TableReference // USING clause for multi-table deletes
    Where     Expression       // WHERE condition
    Returning []Expression     // RETURNING clause (PostgreSQL)
}
```

**Supported SQL:**
```sql
DELETE FROM orders o
USING users u
WHERE o.user_id = u.id AND u.deleted = true
RETURNING o.id
```

---

#### `MergeStatement`
Represents a MERGE statement (SQL:2003 F312).

```go
type MergeStatement struct {
    TargetTable TableReference     // Target table being merged into
    TargetAlias string             // Optional target alias
    SourceTable TableReference     // Source table/subquery
    SourceAlias string             // Optional source alias
    OnCondition Expression         // Join/match condition
    WhenClauses []*MergeWhenClause // WHEN MATCHED/NOT MATCHED clauses
}
```

**Supporting Types:**
```go
type MergeWhenClause struct {
    Type      string       // "MATCHED", "NOT_MATCHED", "NOT_MATCHED_BY_SOURCE"
    Condition Expression   // Optional AND condition
    Action    *MergeAction // UPDATE/INSERT/DELETE action
}

type MergeAction struct {
    ActionType    string       // "UPDATE", "INSERT", "DELETE"
    SetClauses    []SetClause  // For UPDATE
    Columns       []string     // For INSERT
    Values        []Expression // For INSERT
    DefaultValues bool         // For INSERT DEFAULT VALUES
}
```

**Supported SQL:**
```sql
MERGE INTO target t
USING source s ON t.id = s.id
WHEN MATCHED AND s.active = true THEN
    UPDATE SET t.name = s.name, t.updated = NOW()
WHEN MATCHED AND s.active = false THEN
    DELETE
WHEN NOT MATCHED THEN
    INSERT (id, name) VALUES (s.id, s.name)
```

---

### DDL Statement Types

#### `CreateTableStatement`
Represents a CREATE TABLE statement with partitioning support.

```go
type CreateTableStatement struct {
    IfNotExists bool                  // IF NOT EXISTS
    Temporary   bool                  // TEMP/TEMPORARY
    Name        string                // Table name
    Columns     []ColumnDef           // Column definitions
    Constraints []TableConstraint     // Table-level constraints
    Inherits    []string              // INHERITS clause (PostgreSQL)
    PartitionBy *PartitionBy          // PARTITION BY clause
    Partitions  []PartitionDefinition // Individual partition definitions
    Options     []TableOption         // ENGINE, CHARSET, etc. (MySQL)
}
```

**Supporting Types:**
```go
type ColumnDef struct {
    Name        string             // Column name
    Type        string             // Data type
    Constraints []ColumnConstraint // Column constraints
}

type ColumnConstraint struct {
    Type          string               // NOT NULL, UNIQUE, PRIMARY KEY, etc.
    Default       Expression           // DEFAULT value
    References    *ReferenceDefinition // FOREIGN KEY reference
    Check         Expression           // CHECK constraint
    AutoIncrement bool                 // AUTO_INCREMENT (MySQL)
}

type TableConstraint struct {
    Name       string               // Constraint name
    Type       string               // PRIMARY KEY, UNIQUE, FOREIGN KEY, CHECK
    Columns    []string             // Affected columns
    References *ReferenceDefinition // Foreign key details
    Check      Expression           // Check expression
}

type ReferenceDefinition struct {
    Table    string   // Referenced table
    Columns  []string // Referenced columns
    OnDelete string   // ON DELETE action
    OnUpdate string   // ON UPDATE action
    Match    string   // MATCH type
}

type PartitionBy struct {
    Type     string       // RANGE, LIST, HASH
    Columns  []string     // Partition columns
    Boundary []Expression // Boundary expressions
}

type PartitionDefinition struct {
    Name       string       // Partition name
    Type       string       // FOR VALUES, IN, LESS THAN
    Values     []Expression // Partition values
    LessThan   Expression   // LESS THAN (value)
    From       Expression   // FROM (value)
    To         Expression   // TO (value)
    InValues   []Expression // IN (values)
    Tablespace string       // Tablespace
}
```

**Supported SQL:**
```sql
CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount DECIMAL(10,2) CHECK (amount > 0),
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_order UNIQUE (user_id, created_at)
)
PARTITION BY RANGE (created_at);

CREATE TABLE orders_2024 PARTITION OF orders
    FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');
```

---

#### `CreateIndexStatement`
Represents a CREATE INDEX statement.

```go
type CreateIndexStatement struct {
    Unique      bool          // UNIQUE index
    IfNotExists bool          // IF NOT EXISTS
    Name        string        // Index name
    Table       string        // Table name
    Columns     []IndexColumn // Index columns
    Using       string        // Index method (BTREE, HASH, GIN, etc.)
    Where       Expression    // Partial index condition
}

type IndexColumn struct {
    Column    string // Column name
    Collate   string // Collation
    Direction string // ASC, DESC
    NullsLast bool   // NULLS LAST
}
```

**Supported SQL:**
```sql
CREATE UNIQUE INDEX CONCURRENTLY idx_users_email
ON users (email)
WHERE deleted_at IS NULL;
```

---

#### `CreateViewStatement`
Represents a CREATE VIEW statement.

```go
type CreateViewStatement struct {
    OrReplace   bool      // OR REPLACE
    Temporary   bool      // TEMP/TEMPORARY
    IfNotExists bool      // IF NOT EXISTS
    Name        string    // View name
    Columns     []string  // Optional column list
    Query       Statement // SELECT statement
    WithOption  string    // WITH CHECK OPTION, etc.
}
```

**Supported SQL:**
```sql
CREATE OR REPLACE VIEW active_users AS
SELECT id, name, email
FROM users
WHERE active = true
WITH CHECK OPTION;
```

---

#### `CreateMaterializedViewStatement`
Represents a CREATE MATERIALIZED VIEW statement.

```go
type CreateMaterializedViewStatement struct {
    IfNotExists bool      // IF NOT EXISTS
    Name        string    // View name
    Columns     []string  // Optional column list
    Query       Statement // SELECT statement
    WithData    *bool     // WITH DATA / WITH NO DATA
    Tablespace  string    // Tablespace (PostgreSQL)
}
```

**Supported SQL:**
```sql
CREATE MATERIALIZED VIEW sales_summary AS
SELECT region, SUM(amount) as total
FROM sales
GROUP BY region
WITH DATA;
```

---

#### `RefreshMaterializedViewStatement`
Represents a REFRESH MATERIALIZED VIEW statement.

```go
type RefreshMaterializedViewStatement struct {
    Concurrently bool   // CONCURRENTLY
    Name         string // View name
    WithData     *bool  // WITH DATA / WITH NO DATA
}
```

**Supported SQL:**
```sql
REFRESH MATERIALIZED VIEW CONCURRENTLY sales_summary;
```

---

#### `AlterTableStatement`
Represents an ALTER TABLE statement.

```go
type AlterTableStatement struct {
    Table   string             // Table name
    Actions []AlterTableAction // Actions to perform
}

type AlterTableAction struct {
    Type       string           // ADD COLUMN, DROP COLUMN, MODIFY COLUMN, etc.
    ColumnName string           // Affected column
    ColumnDef  *ColumnDef       // New column definition
    Constraint *TableConstraint // Constraint modification
}
```

**Supported SQL:**
```sql
ALTER TABLE users
    ADD COLUMN phone VARCHAR(20),
    DROP COLUMN legacy_field,
    ADD CONSTRAINT fk_dept FOREIGN KEY (dept_id) REFERENCES departments(id);
```

---

#### `DropStatement`
Represents a DROP statement for various object types.

```go
type DropStatement struct {
    ObjectType  string   // TABLE, VIEW, MATERIALIZED VIEW, INDEX, etc.
    IfExists    bool     // IF EXISTS
    Names       []string // Objects to drop (can be multiple)
    CascadeType string   // CASCADE, RESTRICT, or empty
}
```

**Supported SQL:**
```sql
DROP TABLE IF EXISTS temp_data, old_logs CASCADE;
DROP MATERIALIZED VIEW IF EXISTS sales_summary;
DROP INDEX idx_users_email;
```

---

### CTE and Set Operation Types

#### `WithClause`
Represents a WITH clause (Common Table Expressions).

```go
type WithClause struct {
    Recursive bool               // RECURSIVE modifier
    CTEs      []*CommonTableExpr // CTE definitions
}
```

#### `CommonTableExpr`
Represents a single CTE definition.

```go
type CommonTableExpr struct {
    Name         string    // CTE name
    Columns      []string  // Optional column list
    Statement    Statement // CTE query
    Materialized *bool     // MATERIALIZED/NOT MATERIALIZED (PostgreSQL)
}
```

**Supported SQL:**
```sql
WITH RECURSIVE employee_tree (id, name, level) AS (
    SELECT id, name, 1 FROM employees WHERE manager_id IS NULL
    UNION ALL
    SELECT e.id, e.name, t.level + 1
    FROM employees e
    JOIN employee_tree t ON e.manager_id = t.id
)
SELECT * FROM employee_tree;
```

---

#### `SetOperation`
Represents set operations (UNION, EXCEPT, INTERSECT).

```go
type SetOperation struct {
    Left     Statement // Left query
    Operator string    // UNION, EXCEPT, INTERSECT
    Right    Statement // Right query
    All      bool      // ALL modifier (e.g., UNION ALL)
}
```

**Supported SQL:**
```sql
SELECT name FROM users
UNION ALL
SELECT name FROM customers
EXCEPT
SELECT name FROM blocked_users;
```

---

### Expression Types

#### `Identifier`
Represents a column or table name with optional qualification.

```go
type Identifier struct {
    Name  string // Column/table name
    Table string // Optional table qualifier
}
```

**Example:**
```go
// For "users.id"
id := &ast.Identifier{Name: "id", Table: "users"}
```

---

#### `LiteralValue`
Represents a literal value in SQL.

```go
type LiteralValue struct {
    Value interface{} // Actual value
    Type  string      // INTEGER, FLOAT, STRING, BOOLEAN, NULL, etc.
}
```

**Example:**
```go
// For '42'
num := &ast.LiteralValue{Value: 42, Type: "INTEGER"}

// For 'hello'
str := &ast.LiteralValue{Value: "hello", Type: "STRING"}

// For NULL
null := &ast.LiteralValue{Value: nil, Type: "NULL"}
```

---

#### `BinaryExpression`
Represents binary operations (comparison, logical, arithmetic).

```go
type BinaryExpression struct {
    Left     Expression           // Left operand
    Operator string               // =, <>, >, <, AND, OR, +, -, *, /, etc.
    Right    Expression           // Right operand
    Not      bool                 // NOT modifier
    CustomOp *CustomBinaryOperator // PostgreSQL custom operators
}
```

**Supported Operators:**
- Comparison: `=`, `<>`, `!=`, `>`, `<`, `>=`, `<=`
- Logical: `AND`, `OR`
- Arithmetic: `+`, `-`, `*`, `/`, `%`
- String: `||` (concatenation), `LIKE`, `ILIKE`
- PostgreSQL: `@>`, `<@`, `&&`, `?`, `?|`, `?&`

---

#### `UnaryExpression`
Represents unary operations.

```go
type UnaryExpression struct {
    Operator UnaryOperator // NOT, -, +, etc.
    Expr     Expression    // Operand
}
```

---

#### `FunctionCall`
Represents function calls including window functions.

```go
type FunctionCall struct {
    Name      string       // Function name
    Arguments []Expression // Function arguments
    Over      *WindowSpec  // Window specification (for window functions)
    Distinct  bool         // DISTINCT modifier (for aggregates)
    Filter    Expression   // FILTER clause (PostgreSQL)
}
```

**Example:**
```go
// COUNT(DISTINCT user_id) FILTER (WHERE active)
countFunc := &ast.FunctionCall{
    Name:     "COUNT",
    Arguments: []ast.Expression{&ast.Identifier{Name: "user_id"}},
    Distinct: true,
    Filter:   &ast.BinaryExpression{...},
}

// ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC)
rowNumFunc := &ast.FunctionCall{
    Name: "ROW_NUMBER",
    Over: &ast.WindowSpec{
        PartitionBy: []ast.Expression{...},
        OrderBy:     []ast.OrderByExpression{...},
    },
}
```

---

#### `CaseExpression`
Represents CASE WHEN THEN ELSE expressions.

```go
type CaseExpression struct {
    Value       Expression   // Optional CASE value (for simple CASE)
    WhenClauses []WhenClause // WHEN ... THEN ... clauses
    ElseClause  Expression   // ELSE clause
}

type WhenClause struct {
    Condition Expression // WHEN condition
    Result    Expression // THEN result
}
```

**Supported SQL:**
```sql
-- Searched CASE
CASE WHEN status = 'active' THEN 1
     WHEN status = 'pending' THEN 0
     ELSE -1 END

-- Simple CASE
CASE status
    WHEN 'active' THEN 1
    WHEN 'pending' THEN 0
    ELSE -1 END
```

---

#### `CastExpression`
Represents CAST type conversion.

```go
type CastExpression struct {
    Expr Expression // Expression to cast
    Type string     // Target data type
}
```

**Supported SQL:**
```sql
CAST(amount AS DECIMAL(10,2))
CAST(created_at AS DATE)
```

---

#### `InExpression`
Represents IN expressions with value lists or subqueries.

```go
type InExpression struct {
    Expr     Expression   // Expression to check
    List     []Expression // Value list: IN (1, 2, 3)
    Subquery Statement    // Subquery: IN (SELECT ...)
    Not      bool         // NOT IN
}
```

**Supported SQL:**
```sql
status IN ('active', 'pending')
id NOT IN (SELECT blocked_id FROM blocked_users)
```

---

#### `BetweenExpression`
Represents BETWEEN range expressions.

```go
type BetweenExpression struct {
    Expr  Expression // Expression to check
    Lower Expression // Lower bound
    Upper Expression // Upper bound
    Not   bool       // NOT BETWEEN
}
```

**Supported SQL:**
```sql
created_at BETWEEN '2024-01-01' AND '2024-12-31'
price NOT BETWEEN 10 AND 100
```

---

#### `ExistsExpression`
Represents EXISTS subquery expressions.

```go
type ExistsExpression struct {
    Subquery Statement // Subquery to check
}
```

**Supported SQL:**
```sql
EXISTS (SELECT 1 FROM orders WHERE user_id = users.id)
```

---

#### `SubqueryExpression`
Represents scalar subquery expressions.

```go
type SubqueryExpression struct {
    Subquery Statement // Scalar subquery
}
```

**Supported SQL:**
```sql
(SELECT MAX(price) FROM products)
```

---

#### `AnyExpression` and `AllExpression`
Represents ANY/SOME and ALL subquery comparisons.

```go
type AnyExpression struct {
    Expr     Expression // Left operand
    Operator string     // Comparison operator
    Subquery Statement  // Subquery
}

type AllExpression struct {
    Expr     Expression // Left operand
    Operator string     // Comparison operator
    Subquery Statement  // Subquery
}
```

**Supported SQL:**
```sql
price > ANY (SELECT avg_price FROM categories)
score >= ALL (SELECT min_score FROM thresholds)
```

---

#### `ExtractExpression`
Represents EXTRACT function for date/time parts.

```go
type ExtractExpression struct {
    Field  string     // YEAR, MONTH, DAY, HOUR, etc.
    Source Expression // Date/time expression
}
```

**Supported SQL:**
```sql
EXTRACT(YEAR FROM created_at)
EXTRACT(MONTH FROM order_date)
```

---

#### `SubstringExpression`
Represents SUBSTRING function.

```go
type SubstringExpression struct {
    Str    Expression // Source string
    Start  Expression // Start position
    Length Expression // Optional length
}
```

**Supported SQL:**
```sql
SUBSTRING(name FROM 1 FOR 10)
SUBSTRING(code FROM 5)
```

---

#### `PositionExpression`
Represents POSITION function.

```go
type PositionExpression struct {
    Substr Expression // Substring to find
    Str    Expression // String to search in
}
```

**Supported SQL:**
```sql
POSITION('@' IN email)
```

---

### Grouping Set Types

#### `RollupExpression`
Represents ROLLUP for hierarchical grouping sets.

```go
type RollupExpression struct {
    Expressions []Expression // Columns for rollup
}
```

**Supported SQL:**
```sql
-- ROLLUP(region, city, store) generates:
-- (region, city, store), (region, city), (region), ()
GROUP BY ROLLUP(region, city, store)
```

---

#### `CubeExpression`
Represents CUBE for all combinations of grouping sets.

```go
type CubeExpression struct {
    Expressions []Expression // Columns for cube
}
```

**Supported SQL:**
```sql
-- CUBE(a, b) generates: (a, b), (a), (b), ()
GROUP BY CUBE(region, year)
```

---

#### `GroupingSetsExpression`
Represents explicit grouping sets.

```go
type GroupingSetsExpression struct {
    Sets [][]Expression // Each inner slice is one grouping set
}
```

**Supported SQL:**
```sql
GROUP BY GROUPING SETS ((region, city), (region), ())
```

---

### Window Function Types

#### `WindowSpec`
Represents a window specification.

```go
type WindowSpec struct {
    Name        string              // Named window reference
    PartitionBy []Expression        // PARTITION BY columns
    OrderBy     []OrderByExpression // ORDER BY within window
    FrameClause *WindowFrame        // Frame specification
}
```

---

#### `WindowFrame`
Represents window frame clause.

```go
type WindowFrame struct {
    Type  string           // ROWS or RANGE
    Start WindowFrameBound // Start bound
    End   *WindowFrameBound // End bound (optional)
}

type WindowFrameBound struct {
    Type  string     // CURRENT ROW, UNBOUNDED PRECEDING, etc.
    Value Expression // For N PRECEDING/FOLLOWING
}
```

**Supported SQL:**
```sql
-- ROWS frame
SUM(amount) OVER (
    PARTITION BY region
    ORDER BY date
    ROWS BETWEEN 2 PRECEDING AND CURRENT ROW
)

-- RANGE frame
AVG(price) OVER (
    ORDER BY date
    RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
)
```

---

#### `OrderByExpression`
Represents ORDER BY element with direction and NULL ordering.

```go
type OrderByExpression struct {
    Expression Expression // Column or expression
    Ascending  bool       // ASC (true) or DESC (false)
    NullsFirst *bool      // NULLS FIRST/LAST (nil = default)
}
```

**Supported SQL:**
```sql
ORDER BY name ASC NULLS LAST, created_at DESC NULLS FIRST
```

---

### Supporting Types

#### `TableReference`
Represents a table in FROM clause.

```go
type TableReference struct {
    Name  string // Table name
    Alias string // Optional alias
}
```

---

#### `JoinClause`
Represents a JOIN operation.

```go
type JoinClause struct {
    Type      string         // INNER, LEFT, RIGHT, FULL, CROSS
    Left      TableReference // Left table
    Right     TableReference // Right table
    Condition Expression     // ON condition
}
```

---

#### `UpdateExpression`
Represents SET clause in UPDATE.

```go
type UpdateExpression struct {
    Column Expression // Column to update
    Value  Expression // New value
}
```

---

#### `OnConflict`
Represents PostgreSQL ON CONFLICT clause.

```go
type OnConflict struct {
    Target     []Expression     // Target columns
    Constraint string           // Constraint name
    Action     OnConflictAction // DO UPDATE/NOTHING
}

type OnConflictAction struct {
    DoNothing bool               // DO NOTHING
    DoUpdate  []UpdateExpression // SET clauses
    Where     Expression         // WHERE condition
}
```

---

#### `ListExpression`
Represents a list of expressions.

```go
type ListExpression struct {
    Values []Expression // List items
}
```

---

#### `Values`
Represents VALUES clause.

```go
type Values struct {
    Rows [][]Expression // Value rows
}
```

---

### Root AST Type

#### `AST`
Root container for parsed SQL statements.

```go
type AST struct {
    Statements []Statement // Parsed statements
}

func (a AST) TokenLiteral() string
func (a AST) Children() []Node
```

**Example:**
```go
astNode, err := parser.Parse(tokens)
if err != nil {
    log.Fatal(err)
}

for _, stmt := range astNode.Statements {
    switch s := stmt.(type) {
    case *ast.SelectStatement:
        fmt.Println("SELECT statement")
    case *ast.InsertStatement:
        fmt.Println("INSERT into:", s.TableName)
    case *ast.UpdateStatement:
        fmt.Println("UPDATE:", s.TableName)
    case *ast.DeleteStatement:
        fmt.Println("DELETE from:", s.TableName)
    }
}
```

---

### Object Pool Functions

#### `NewAST() *AST`
Gets an AST instance from the pool.

```go
astObj := ast.NewAST()
defer ast.ReleaseAST(astObj)  // ALWAYS defer the release
```

#### `ReleaseAST(ast *AST)`
Returns an AST instance to the pool.

```go
ast.ReleaseAST(astObj)
```

**Best Practice:**
```go
func ParseSQL(sql string) (*ast.AST, error) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        return nil, err
    }

    p := parser.NewParser()
    defer p.Release()

    // AST is returned to caller - caller responsible for release
    return p.Parse(tokens)
}
```

---

### Visitor Pattern

The AST supports tree traversal via the `Children()` method:

```go
func VisitAll(node ast.Node, visitor func(ast.Node)) {
    visitor(node)
    for _, child := range node.Children() {
        VisitAll(child, visitor)
    }
}

// Usage: Find all table references
var tables []string
VisitAll(astNode, func(node ast.Node) {
    if tbl, ok := node.(*ast.TableReference); ok {
        tables = append(tables, tbl.Name)
    }
})
```

---

### Type Assertion Examples

```go
// Check statement type
switch stmt := astNode.Statements[0].(type) {
case *ast.SelectStatement:
    processSelect(stmt)
case *ast.InsertStatement:
    processInsert(stmt)
case *ast.UpdateStatement:
    processUpdate(stmt)
case *ast.DeleteStatement:
    processDelete(stmt)
case *ast.CreateTableStatement:
    processCreateTable(stmt)
case *ast.MergeStatement:
    processMerge(stmt)
}

// Check expression type
func processExpression(expr ast.Expression) {
    switch e := expr.(type) {
    case *ast.Identifier:
        fmt.Printf("Column: %s.%s\n", e.Table, e.Name)
    case *ast.LiteralValue:
        fmt.Printf("Literal: %v (%s)\n", e.Value, e.Type)
    case *ast.FunctionCall:
        fmt.Printf("Function: %s with %d args\n", e.Name, len(e.Arguments))
        if e.Over != nil {
            fmt.Println("  (window function)")
        }
    case *ast.BinaryExpression:
        fmt.Printf("Binary: %s\n", e.Operator)
    case *ast.CaseExpression:
        fmt.Printf("CASE with %d WHEN clauses\n", len(e.WhenClauses))
    }
}
```

## Models

### Package: `github.com/ajitpratap0/GoSQLX/pkg/models`

Core data structures used throughout the library.

### Type: `Token`
Represents a lexical token.

```go
type Token struct {
    Type  TokenType // Token type enum
    Value string    // Token value
}
```

### Type: `TokenWithSpan`
Token with position information.

```go
type TokenWithSpan struct {
    Token Token
    Start Location // Start position
    End   Location // End position
}
```

### Type: `Location`
Position in source text.

```go
type Location struct {
    Line   int // 1-based line number
    Column int // 1-based column number
    Index  int // 0-based byte offset
}
```

### Type: `TokenType`
Enumeration of token types.

```go
type TokenType int

const (
    TokenTypeEOF             TokenType = 0
    TokenTypeUnknown         TokenType = 1
    TokenTypeIdentifier      TokenType = 14
    TokenTypeNumber          TokenType = 11
    TokenTypeSingleQuotedString TokenType = 31
    TokenTypeDoubleQuotedString TokenType = 32
    // ... many more
)
```

## Error Handling

### Type: `TokenizerError`
Tokenization errors with position information.

```go
type TokenizerError struct {
    Message  string
    Location Location
}
```

**Example:**
```go
tokens, err := tkz.Tokenize(sqlBytes)
if err != nil {
    if tkErr, ok := err.(tokenizer.TokenizerError); ok {
        fmt.Printf("Error at line %d, column %d: %s\n",
            tkErr.Location.Line,
            tkErr.Location.Column,
            tkErr.Message)
    }
}
```

### Type: `ParseError`
Parsing errors with context.

```go
type ParseError struct {
    Message string
    Token   Token
}
```

## Performance Considerations

### Object Pooling Best Practices

1. **Always use defer for cleanup:**
```go
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz) // Ensures cleanup even on panic
```

2. **Don't store pooled objects:**
```go
// BAD: Storing pooled object
type MyStruct struct {
    tkz *Tokenizer // DON'T DO THIS
}

// GOOD: Get from pool when needed
func (m *MyStruct) Process(sql []byte) error {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    return tkz.Tokenize(sql)
}
```

3. **Batch operations efficiently:**
```go
func ProcessQueries(queries []string) [][]models.TokenWithSpan {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    results := make([][]models.TokenWithSpan, len(queries))
    for i, query := range queries {
        tokens, _ := tkz.Tokenize([]byte(query))
        results[i] = tokens
        tkz.Reset() // Reset between uses
    }
    return results
}
```

### Memory Optimization

- **Zero-copy tokenization**: The tokenizer works directly on input bytes
- **Pool reuse**: ~60-80% memory reduction vs creating new instances
- **Minimal allocations**: Most operations are allocation-free

### Concurrency Guidelines

All pool operations are thread-safe:

```go
func ConcurrentTokenization(queries []string) {
    var wg sync.WaitGroup
    for _, query := range queries {
        wg.Add(1)
        go func(sql string) {
            defer wg.Done()
            
            tkz := tokenizer.GetTokenizer()
            defer tokenizer.PutTokenizer(tkz)
            
            tokens, _ := tkz.Tokenize([]byte(sql))
            // Process tokens...
        }(query)
    }
    wg.Wait()
}
```

## Complete Example

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

func main() {
    sql := `
        SELECT u.id, u.name, COUNT(o.id) as order_count
        FROM users u
        LEFT JOIN orders o ON u.id = o.user_id
        WHERE u.created_at >= '2024-01-01'
        GROUP BY u.id, u.name
        HAVING COUNT(o.id) > 5
        ORDER BY order_count DESC
        LIMIT 10
    `
    
    // Step 1: Tokenize
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        log.Fatal("Tokenization error:", err)
    }
    
    // Step 2: Convert to parser tokens
    parserTokens := make([]token.Token, 0, len(tokens))
    for _, tok := range tokens {
        if tok.Token.Type == models.TokenTypeEOF {
            break
        }
        parserTokens = append(parserTokens, token.Token{
            Type:    fmt.Sprintf("%d", tok.Token.Type),
            Literal: tok.Token.Value,
        })
    }
    
    // Step 3: Parse
    p := parser.NewParser()
    defer p.Release()
    
    astNode, err := p.Parse(parserTokens)
    if err != nil {
        log.Fatal("Parse error:", err)
    }
    
    // Step 4: Analyze AST
    if stmt, ok := astNode.(*ast.SelectStatement); ok {
        fmt.Printf("Found SELECT with %d columns\n", len(stmt.Columns))
        fmt.Printf("Has WHERE: %v\n", stmt.Where != nil)
        fmt.Printf("Has GROUP BY: %v\n", len(stmt.GroupBy) > 0)
        fmt.Printf("Has ORDER BY: %v\n", len(stmt.OrderBy) > 0)
    }
}
```

## Keywords Package

### Package: `github.com/ajitpratap0/GoSQLX/pkg/sql/keywords`

The Keywords package provides SQL keyword recognition, categorization, and multi-dialect support for PostgreSQL, MySQL, SQL Server, Oracle, and SQLite.

### Overview

**Key Features:**
- **Multi-Dialect Support**: PostgreSQL, MySQL, SQL Server, Oracle, SQLite
- **Keyword Categorization**: Reserved, DML, DDL, functions, operators, data types
- **Compound Keywords**: GROUP BY, ORDER BY, LEFT JOIN, NULLS FIRST, etc.
- **Case-Insensitive**: Recognizes keywords in any case (SELECT, select, Select)
- **Thread-Safe**: All operations safe for concurrent use
- **Extensible**: Support for adding custom keywords

### Core Types

#### Type: `Keywords`

Main keyword registry for a specific SQL dialect.

```go
type Keywords struct {
    dialect SQLDialect
    // Internal keyword maps
}
```

**Usage:**
```go
kw := keywords.New(keywords.PostgreSQL)
if kw.IsKeyword("SELECT") {
    fmt.Println("SELECT is a keyword")
}
```

#### Type: `SQLDialect`

Supported SQL dialects.

```go
type SQLDialect int

const (
    PostgreSQL SQLDialect = iota  // PostgreSQL dialect
    MySQL                         // MySQL dialect
    SQLServer                     // SQL Server dialect
    Oracle                        // Oracle dialect
    SQLite                        // SQLite dialect
    Generic                       // SQL-99 standard keywords
)
```

**Example:**
```go
// Create keyword registry for specific dialect
pgKw := keywords.New(keywords.PostgreSQL)
myKw := keywords.New(keywords.MySQL)
genericKw := keywords.New(keywords.Generic)
```

#### Type: `KeywordCategory`

Keyword classification.

```go
type KeywordCategory int

const (
    CategoryReserved   KeywordCategory = iota  // Reserved keywords (SELECT, FROM, WHERE)
    CategoryDML                                // Data manipulation (INSERT, UPDATE, DELETE)
    CategoryDDL                                // Data definition (CREATE, ALTER, DROP)
    CategoryFunction                           // Function names (COUNT, SUM, AVG)
    CategoryOperator                           // Operators (AND, OR, NOT, LIKE)
    CategoryDataType                           // Data types (INTEGER, VARCHAR, TIMESTAMP)
)
```

### Core Functions

#### Function: `New`

Creates a keyword registry for a specific SQL dialect.

```go
func New(dialect SQLDialect) *Keywords
```

**Parameters:**
- `dialect`: SQL dialect to use (PostgreSQL, MySQL, SQLite, etc.)

**Returns:**
- `*Keywords`: Keyword registry instance

**Example:**
```go
kw := keywords.New(keywords.PostgreSQL)
```

#### Method: `IsKeyword`

Checks if a word is a SQL keyword (case-insensitive).

```go
func (k *Keywords) IsKeyword(word string) bool
```

**Parameters:**
- `word`: Word to check

**Returns:**
- `bool`: true if word is a keyword

**Example:**
```go
kw := keywords.New(keywords.Generic)

kw.IsKeyword("SELECT")  // true
kw.IsKeyword("select")  // true
kw.IsKeyword("SeLeCt")  // true
kw.IsKeyword("foo")     // false
```

#### Method: `IsReserved`

Checks if a keyword is reserved (cannot be used as identifier without quoting).

```go
func (k *Keywords) IsReserved(word string) bool
```

**Parameters:**
- `word`: Word to check

**Returns:**
- `bool`: true if word is a reserved keyword

**Example:**
```go
kw := keywords.New(keywords.PostgreSQL)

if kw.IsReserved("TABLE") {
    fmt.Println("TABLE is reserved - must quote if used as identifier")
}
```

#### Method: `GetKeyword`

Gets detailed keyword information.

```go
func (k *Keywords) GetKeyword(word string) *Keyword
```

**Parameters:**
- `word`: Keyword to look up

**Returns:**
- `*Keyword`: Keyword details (TokenType, Category), or nil if not found

**Example:**
```go
kw := keywords.New(keywords.Generic)
keyword := kw.GetKeyword("SELECT")
if keyword != nil {
    fmt.Printf("Type: %s, Category: %d\n", keyword.TokenType, keyword.Category)
}
```

#### Method: `GetTokenType`

Gets the token type for a keyword.

```go
func (k *Keywords) GetTokenType(word string) string
```

**Parameters:**
- `word`: Keyword to look up

**Returns:**
- `string`: Token type (e.g., "SELECT", "INSERT", "JOIN"), or empty string if not found

**Example:**
```go
kw := keywords.New(keywords.Generic)
tokenType := kw.GetTokenType("select")  // Returns "SELECT"
```

#### Method: `IsCompoundKeyword`

Checks if two words form a compound keyword (e.g., GROUP BY, LEFT JOIN).

```go
func (k *Keywords) IsCompoundKeyword(word1, word2 string) bool
```

**Parameters:**
- `word1`: First word
- `word2`: Second word

**Returns:**
- `bool`: true if words form a compound keyword

**Example:**
```go
kw := keywords.New(keywords.Generic)

kw.IsCompoundKeyword("GROUP", "BY")     // true
kw.IsCompoundKeyword("ORDER", "BY")     // true
kw.IsCompoundKeyword("LEFT", "JOIN")    // true
kw.IsCompoundKeyword("NULLS", "FIRST")  // true
kw.IsCompoundKeyword("SELECT", "FROM")  // false (not compound)
```

#### Method: `GetCompoundKeywordType`

Gets the token type for a compound keyword.

```go
func (k *Keywords) GetCompoundKeywordType(word1, word2 string) string
```

**Parameters:**
- `word1`: First word
- `word2`: Second word

**Returns:**
- `string`: Compound keyword token type, or empty string if not compound

**Example:**
```go
kw := keywords.New(keywords.Generic)

kw.GetCompoundKeywordType("GROUP", "BY")     // "GROUP BY"
kw.GetCompoundKeywordType("ORDER", "BY")     // "ORDER BY"
kw.GetCompoundKeywordType("LEFT", "JOIN")    // "LEFT JOIN"
kw.GetCompoundKeywordType("NULLS", "FIRST")  // "NULLS FIRST"
```

#### Method: `AddKeyword`

Adds a custom keyword (for extensions).

```go
func (k *Keywords) AddKeyword(word string, tokenType string, category KeywordCategory)
```

**Parameters:**
- `word`: Keyword to add
- `tokenType`: Token type for the keyword
- `category`: Keyword category

**Example:**
```go
kw := keywords.New(keywords.Generic)
kw.AddKeyword("CUSTOM", "CUSTOM", keywords.CategoryReserved)
```

### Keyword Categories

#### Reserved Keywords

Core SQL statement keywords that cannot be used as identifiers without quoting:

```
SELECT, FROM, WHERE, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP,
JOIN, INNER, LEFT, RIGHT, OUTER, FULL, CROSS, NATURAL,
GROUP, ORDER, HAVING, UNION, EXCEPT, INTERSECT,
WITH, RECURSIVE, AS, ON, USING,
WINDOW, PARTITION, OVER, ROWS, RANGE
```

#### DML Keywords

Data manipulation modifiers:

```
DISTINCT, ALL, FETCH, FIRST, NEXT, LAST, ONLY,
WITH TIES, NULLS, LIMIT, OFFSET
```

#### Compound Keywords

Multi-word keywords recognized as single tokens:

```
GROUP BY, ORDER BY,
LEFT JOIN, RIGHT JOIN, FULL JOIN, CROSS JOIN, NATURAL JOIN,
INNER JOIN, LEFT OUTER JOIN, RIGHT OUTER JOIN, FULL OUTER JOIN,
UNION ALL, WITH TIES, NULLS FIRST, NULLS LAST
```

#### Window Function Keywords

Window function names and frame specifications:

```
ROW_NUMBER, RANK, DENSE_RANK, NTILE, PERCENT_RANK, CUME_DIST,
LAG, LEAD, FIRST_VALUE, LAST_VALUE, NTH_VALUE,
ROWS BETWEEN, RANGE BETWEEN, UNBOUNDED PRECEDING, CURRENT ROW
```

### Dialect-Specific Keywords

#### PostgreSQL-Specific

```go
pgKw := keywords.New(keywords.PostgreSQL)

// PostgreSQL-specific keywords
pgKw.IsKeyword("ILIKE")        // Case-insensitive LIKE
pgKw.IsKeyword("SIMILAR")      // SIMILAR TO operator
pgKw.IsKeyword("MATERIALIZED") // Materialized views
pgKw.IsKeyword("CONCURRENTLY") // Concurrent operations
pgKw.IsKeyword("RETURNING")    // RETURNING clause
```

**PostgreSQL Keywords:**
```
MATERIALIZED, ILIKE, SIMILAR, FREEZE, ANALYSE, ANALYZE,
CONCURRENTLY, REINDEX, TOAST, NOWAIT, RETURNING
```

#### MySQL-Specific

```go
myKw := keywords.New(keywords.MySQL)

// MySQL-specific keywords
myKw.IsKeyword("UNSIGNED")     // Unsigned modifier
myKw.IsKeyword("ZEROFILL")     // Zero-fill display
myKw.IsKeyword("FORCE")        // Force index
myKw.IsKeyword("IGNORE")       // Ignore errors
```

**MySQL Keywords:**
```
BINARY, CHAR, VARCHAR, DATETIME, DECIMAL, UNSIGNED, ZEROFILL,
FORCE, IGNORE, INDEX, KEY, KILL, OPTION, PURGE, READ, WRITE,
STATUS, VARIABLES
```

#### SQLite-Specific

```go
sqliteKw := keywords.New(keywords.SQLite)

// SQLite-specific keywords
sqliteKw.IsKeyword("AUTOINCREMENT")  // Auto-increment
sqliteKw.IsKeyword("CONFLICT")       // Conflict resolution
sqliteKw.IsKeyword("REPLACE")        // Replace operation
```

**SQLite Keywords:**
```
ABORT, ACTION, AFTER, ATTACH, AUTOINCREMENT, CONFLICT, DATABASE,
DETACH, EXCLUSIVE, INDEXED, INSTEAD, PLAN, QUERY, RAISE, REPLACE,
TEMP, TEMPORARY, VACUUM, VIRTUAL
```

### Usage Examples

#### Basic Keyword Recognition

```go
package main

import (
    "fmt"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func main() {
    kw := keywords.New(keywords.PostgreSQL)

    // Check if word is a keyword
    if kw.IsKeyword("SELECT") {
        fmt.Println("SELECT is a keyword")
    }

    // Check if reserved
    if kw.IsReserved("TABLE") {
        fmt.Println("TABLE is reserved - quote if used as identifier")
    }

    // Get keyword info
    keyword := kw.GetKeyword("JOIN")
    if keyword != nil {
        fmt.Printf("Type: %s, Category: %d\n", keyword.TokenType, keyword.Category)
    }
}
```

#### Compound Keyword Detection

```go
kw := keywords.New(keywords.Generic)

// Check compound keywords
if kw.IsCompoundKeyword("GROUP", "BY") {
    fmt.Println("GROUP BY is a compound keyword")
}

if kw.IsCompoundKeyword("NULLS", "FIRST") {
    fmt.Println("NULLS FIRST is a compound keyword")
}

// Get compound keyword type
tokenType := kw.GetCompoundKeywordType("LEFT", "JOIN")
fmt.Printf("Token type: %s\n", tokenType)  // "LEFT JOIN"
```

#### Identifier Validation

```go
func ValidateIdentifier(name string) error {
    kw := keywords.New(keywords.PostgreSQL)

    if kw.IsReserved(name) {
        return fmt.Errorf("'%s' is a reserved keyword - must be quoted", name)
    }

    return nil
}

// Usage
err := ValidateIdentifier("table")  // Error: 'table' is reserved
err := ValidateIdentifier("users")  // OK
```

#### SQL Formatter

```go
func FormatKeyword(word string, style string) string {
    kw := keywords.New(keywords.Generic)

    if !kw.IsKeyword(word) {
        return word  // Not a keyword, return as-is
    }

    switch style {
    case "upper":
        return strings.ToUpper(word)
    case "lower":
        return strings.ToLower(word)
    case "title":
        return strings.Title(strings.ToLower(word))
    default:
        return word
    }
}

// Usage
formatted := FormatKeyword("select", "upper")  // "SELECT"
```

#### Dialect Switching

```go
func AnalyzeKeywords(sql string, dialect keywords.SQLDialect) {
    kw := keywords.New(dialect)
    words := strings.Fields(sql)

    for _, word := range words {
        if kw.IsKeyword(word) {
            category := kw.GetKeyword(word).Category
            fmt.Printf("%s: category=%d\n", word, category)
        }
    }
}

// Usage for different dialects
AnalyzeKeywords("SELECT * FROM users", keywords.PostgreSQL)
AnalyzeKeywords("SELECT * FROM users", keywords.MySQL)
```

### Integration with Tokenizer

The keywords package is used by the tokenizer to identify SQL keywords:

```go
// In tokenizer
kw := keywords.New(keywords.PostgreSQL)

// Check if identifier is actually a keyword
if kw.IsKeyword(identifierText) {
    tokenType = kw.GetTokenType(identifierText)
} else {
    tokenType = "IDENTIFIER"
}

// Check for compound keywords
if kw.IsCompoundKeyword(currentWord, nextWord) {
    tokenType = kw.GetCompoundKeywordType(currentWord, nextWord)
    // Consume both words
}
```

### Integration with Parser

The parser uses keyword information for syntax validation:

```go
// Check if next token is a specific keyword
if p.currentToken.Type == "GROUP" {
    // Expecting "BY" for GROUP BY
    if p.peekToken.Type == "BY" {
        // Parse GROUP BY clause
    }
}

// Compound keyword handling
if p.currentToken.Type == "NULLS" {
    if p.peekToken.Type == "FIRST" || p.peekToken.Type == "LAST" {
        // Parse NULLS FIRST/LAST clause
    }
}
```

### Case Sensitivity

All keyword matching is **case-insensitive**:

```go
kw := keywords.New(keywords.Generic)

kw.IsKeyword("SELECT")  // true
kw.IsKeyword("select")  // true
kw.IsKeyword("Select")  // true
kw.IsKeyword("SeLeCt")  // true
```

### Performance Characteristics

- **Lookup Time**: O(1) hash map lookups
- **Memory**: Pre-allocated keyword maps (~10KB per dialect)
- **Thread-Safe**: No synchronization overhead for reads
- **Cache-Friendly**: Keywords stored in contiguous memory

### Best Practices

#### 1. Create Once, Reuse

```go
// GOOD: Create once at package level
var globalKeywords = keywords.New(keywords.PostgreSQL)

func IsKeyword(word string) bool {
    return globalKeywords.IsKeyword(word)
}

// BAD: Creating repeatedly (wasteful)
func IsKeyword(word string) bool {
    kw := keywords.New(keywords.PostgreSQL)  // Creates new instance every call
    return kw.IsKeyword(word)
}
```

#### 2. Use Appropriate Dialect

```go
// Match your database
pgKeywords := keywords.New(keywords.PostgreSQL)   // For PostgreSQL
myKeywords := keywords.New(keywords.MySQL)        // For MySQL
genericKeywords := keywords.New(keywords.Generic) // For SQL-99 standard
```

#### 3. Check Reserved Keywords for Identifiers

```go
func ValidateTableName(name string) error {
    kw := keywords.New(keywords.PostgreSQL)

    if kw.IsReserved(name) {
        return fmt.Errorf("'%s' is reserved - must be quoted", name)
    }

    return nil
}
```

### Common Patterns

#### Pattern 1: Syntax Highlighting

```go
func HighlightSQL(sql string) string {
    kw := keywords.New(keywords.Generic)
    words := strings.Fields(sql)

    for i, word := range words {
        if kw.IsKeyword(word) {
            words[i] = fmt.Sprintf("<keyword>%s</keyword>", word)
        }
    }

    return strings.Join(words, " ")
}
```

#### Pattern 2: Keyword Case Normalization

```go
func NormalizeKeywords(sql string) string {
    kw := keywords.New(keywords.Generic)
    words := strings.Fields(sql)

    for i, word := range words {
        if kw.IsKeyword(word) {
            words[i] = strings.ToUpper(word)  // Normalize to uppercase
        }
    }

    return strings.Join(words, " ")
}
```

#### Pattern 3: Identifier Quoting

```go
func QuoteIfNeeded(identifier string, dialect keywords.SQLDialect) string {
    kw := keywords.New(dialect)

    if kw.IsReserved(identifier) {
        return fmt.Sprintf("\"%s\"", identifier)  // Quote reserved keywords
    }

    return identifier
}
```

## Errors Package

### Package: `github.com/ajitpratap0/GoSQLX/pkg/errors`

The Errors package provides a structured error system with error codes, rich context, and intelligent hints for debugging SQL parsing issues.

### Overview

**Key Features:**
- **Error Codes**: Unique codes (E1xxx, E2xxx, etc.) for programmatic error handling
- **Rich Context**: SQL source context with line/column highlighting
- **Intelligent Hints**: Actionable suggestions to fix errors
- **Documentation Links**: Auto-generated help URLs for each error code
- **Error Chaining**: Support for underlying cause errors (error wrapping)
- **Formatted Output**: Pretty-printed errors with context visualization

### Core Types

#### Type: `ErrorCode`

Unique identifier for each error type.

```go
type ErrorCode string
```

**Error Code Categories:**
- **E1xxx**: Tokenizer errors (lexical analysis)
- **E2xxx**: Parser syntax errors
- **E3xxx**: Semantic errors
- **E4xxx**: Unsupported features

#### Type: `Error`

Structured error with rich context and hints.

```go
type Error struct {
    Code     ErrorCode       // Unique error code (e.g., "E2001")
    Message  string          // Human-readable error message
    Location models.Location // Line and column where error occurred
    Context  *ErrorContext   // SQL context around the error
    Hint     string          // Suggestion to fix the error
    HelpURL  string          // Documentation link for this error
    Cause    error           // Underlying error if any
}
```

**Example:**
```go
err := &errors.Error{
    Code:     errors.ErrCodeUnexpectedToken,
    Message:  "expected FROM, got WHERE",
    Location: models.Location{Line: 1, Column: 15},
}
```

#### Type: `ErrorContext`

SQL source context for error display.

```go
type ErrorContext struct {
    SQL          string // Original SQL query
    StartLine    int    // Starting line number (1-indexed)
    EndLine      int    // Ending line number (1-indexed)
    HighlightCol int    // Column to highlight (1-indexed)
    HighlightLen int    // Length of highlight (characters)
}
```

### Error Codes

#### Tokenizer Errors (E1xxx)

Lexical analysis errors during tokenization:

| Code | Constant | Description |
|------|----------|-------------|
| E1001 | `ErrCodeUnexpectedChar` | Unexpected character in input |
| E1002 | `ErrCodeUnterminatedString` | String literal not closed |
| E1003 | `ErrCodeInvalidNumber` | Invalid numeric literal |
| E1004 | `ErrCodeInvalidOperator` | Invalid operator sequence |
| E1005 | `ErrCodeInvalidIdentifier` | Invalid identifier format |
| E1006 | `ErrCodeInputTooLarge` | Input exceeds size limits (DoS protection) |
| E1007 | `ErrCodeTokenLimitReached` | Token count exceeds limit (DoS protection) |
| E1008 | `ErrCodeTokenizerPanic` | Tokenizer panic recovered |

**Example:**
```go
// Unterminated string
sql := `SELECT * FROM users WHERE name = 'John`
// Error: E1002 - String literal not closed at line 1, column 37
```

#### Parser Syntax Errors (E2xxx)

Syntax errors during parsing:

| Code | Constant | Description |
|------|----------|-------------|
| E2001 | `ErrCodeUnexpectedToken` | Unexpected token encountered |
| E2002 | `ErrCodeExpectedToken` | Expected specific token not found |
| E2003 | `ErrCodeMissingClause` | Required SQL clause missing |
| E2004 | `ErrCodeInvalidSyntax` | General syntax error |
| E2005 | `ErrCodeIncompleteStatement` | Statement incomplete |
| E2006 | `ErrCodeInvalidExpression` | Invalid expression syntax |
| E2007 | `ErrCodeRecursionDepthLimit` | Recursion depth exceeded (DoS protection) |
| E2008 | `ErrCodeUnsupportedDataType` | Data type not supported |
| E2009 | `ErrCodeUnsupportedConstraint` | Constraint type not supported |
| E2010 | `ErrCodeUnsupportedJoin` | JOIN type not supported |
| E2011 | `ErrCodeInvalidCTE` | Invalid CTE (WITH clause) syntax |
| E2012 | `ErrCodeInvalidSetOperation` | Invalid set operation (UNION/EXCEPT/INTERSECT) |

**Example:**
```go
// Missing FROM clause
sql := `SELECT * WHERE id = 1`
// Error: E2003 - Required SQL clause missing: FROM
```

#### Semantic Errors (E3xxx)

Semantic validation errors:

| Code | Constant | Description |
|------|----------|-------------|
| E3001 | `ErrCodeUndefinedTable` | Table not defined |
| E3002 | `ErrCodeUndefinedColumn` | Column not defined |
| E3003 | `ErrCodeTypeMismatch` | Type mismatch in expression |
| E3004 | `ErrCodeAmbiguousColumn` | Ambiguous column reference |

**Example:**
```go
// Ambiguous column (multiple tables have 'id' column)
sql := `SELECT id FROM users u JOIN orders o ON u.id = o.user_id`
// Error: E3004 - Ambiguous column reference: 'id'
```

#### Unsupported Features (E4xxx)

Features not yet implemented:

| Code | Constant | Description |
|------|----------|-------------|
| E4001 | `ErrCodeUnsupportedFeature` | Feature not yet supported |
| E4002 | `ErrCodeUnsupportedDialect` | SQL dialect not supported |

### Error Builder Functions

#### Function: `NewError`

Creates a new structured error.

```go
func NewError(code ErrorCode, message string, location models.Location) *Error
```

**Parameters:**
- `code`: Error code (e.g., `ErrCodeUnexpectedToken`)
- `message`: Human-readable error message
- `location`: Line and column where error occurred

**Returns:**
- `*Error`: New structured error with auto-generated help URL

**Example:**
```go
err := errors.NewError(
    errors.ErrCodeExpectedToken,
    "expected FROM, got WHERE",
    models.Location{Line: 1, Column: 15},
)
// Auto-generated HelpURL: https://docs.gosqlx.dev/errors/E2002
```

#### Method: `WithContext`

Adds SQL context to the error (shows source code around error).

```go
func (e *Error) WithContext(sql string, highlightLen int) *Error
```

**Parameters:**
- `sql`: Original SQL query
- `highlightLen`: Number of characters to highlight

**Returns:**
- `*Error`: Error with context (chainable)

**Example:**
```go
err := errors.NewError(
    errors.ErrCodeUnexpectedToken,
    "unexpected WHERE",
    models.Location{Line: 1, Column: 9},
).WithContext("SELECT * WHERE id = 1", 5)  // Highlight "WHERE"
```

#### Method: `WithHint`

Adds a suggestion hint to fix the error.

```go
func (e *Error) WithHint(hint string) *Error
```

**Parameters:**
- `hint`: Actionable suggestion to fix the error

**Returns:**
- `*Error`: Error with hint (chainable)

**Example:**
```go
err := errors.NewError(
    errors.ErrCodeMissingClause,
    "missing FROM clause",
    models.Location{Line: 1, Column: 9},
).WithHint("Add 'FROM table_name' after SELECT columns")
```

#### Method: `WithCause`

Adds an underlying cause error (error wrapping).

```go
func (e *Error) WithCause(cause error) *Error
```

**Parameters:**
- `cause`: Underlying error that caused this error

**Returns:**
- `*Error`: Error with cause (chainable)

**Example:**
```go
err := errors.NewError(
    errors.ErrCodeTokenizerPanic,
    "tokenizer panic",
    models.Location{Line: 1, Column: 1},
).WithCause(underlyingErr)
```

### Helper Functions

#### Function: `IsCode`

Checks if an error has a specific error code.

```go
func IsCode(err error, code ErrorCode) bool
```

**Parameters:**
- `err`: Error to check
- `code`: Error code to match

**Returns:**
- `bool`: true if error has the specified code

**Example:**
```go
if errors.IsCode(err, errors.ErrCodeUnterminatedString) {
    fmt.Println("String literal not closed")
}
```

#### Function: `GetCode`

Returns the error code from an error.

```go
func GetCode(err error) ErrorCode
```

**Parameters:**
- `err`: Error to extract code from

**Returns:**
- `ErrorCode`: Error code, or empty string if not a structured error

**Example:**
```go
code := errors.GetCode(err)
if code == errors.ErrCodeMissingClause {
    // Handle missing clause error
}
```

### Usage Examples

#### Basic Error Creation

```go
package main

import (
    "fmt"
    "github.com/ajitpratap0/GoSQLX/pkg/errors"
    "github.com/ajitpratap0/GoSQLX/pkg/models"
)

func main() {
    // Create simple error
    err := errors.NewError(
        errors.ErrCodeUnexpectedToken,
        "expected FROM, got WHERE",
        models.Location{Line: 1, Column: 15},
    )

    fmt.Println(err)
    // Output:
    // Error E2001 at line 1, column 15: expected FROM, got WHERE
    // Help: https://docs.gosqlx.dev/errors/E2001
}
```

#### Error with Full Context

```go
sql := `SELECT * WHERE id = 1`

err := errors.NewError(
    errors.ErrCodeMissingClause,
    "missing FROM clause",
    models.Location{Line: 1, Column: 10},
).WithContext(sql, 5).WithHint("Add 'FROM table_name' after SELECT columns")

fmt.Println(err)
// Output:
// Error E2003 at line 1, column 10: missing FROM clause
//
//    1 | SELECT * WHERE id = 1
//              ^^^^^
//
// Hint: Add 'FROM table_name' after SELECT columns
// Help: https://docs.gosqlx.dev/errors/E2003
```

#### Multi-Line SQL Context

```go
sql := `SELECT id, name
FROM users
WHERE
GROUP BY id`

err := errors.NewError(
    errors.ErrCodeInvalidSyntax,
    "WHERE clause requires a condition",
    models.Location{Line: 3, Column: 1},
).WithContext(sql, 5)

fmt.Println(err)
// Output:
// Error E2004 at line 3, column 1: WHERE clause requires a condition
//
//    2 | FROM users
//    3 | WHERE
//        ^^^^^
//    4 | GROUP BY id
//
// Help: https://docs.gosqlx.dev/errors/E2004
```

#### Error Code Checking

```go
_, err := parser.Parse(tokens)
if err != nil {
    // Check for specific error codes
    if errors.IsCode(err, errors.ErrCodeUnterminatedString) {
        fmt.Println("Found unterminated string - check your quotes")
    } else if errors.IsCode(err, errors.ErrCodeMissingClause) {
        fmt.Println("SQL statement is incomplete")
    } else {
        fmt.Printf("Parse error: %v\n", err)
    }
}
```

#### Error Code Extraction

```go
_, err := parser.Parse(tokens)
if err != nil {
    code := errors.GetCode(err)

    switch code {
    case errors.ErrCodeTokenLimitReached:
        log.Error("Query too complex - DoS protection triggered")
    case errors.ErrCodeRecursionDepthLimit:
        log.Error("Query nesting too deep - DoS protection triggered")
    default:
        log.Errorf("Parse error %s: %v", code, err)
    }
}
```

#### Programmatic Error Handling

```go
func HandleParseError(err error) {
    if err == nil {
        return
    }

    // Extract structured error
    sqlErr, ok := err.(*errors.Error)
    if !ok {
        fmt.Printf("Non-SQL error: %v\n", err)
        return
    }

    // Log error details
    fmt.Printf("Error Code: %s\n", sqlErr.Code)
    fmt.Printf("Location: Line %d, Column %d\n", sqlErr.Location.Line, sqlErr.Location.Column)
    fmt.Printf("Message: %s\n", sqlErr.Message)

    if sqlErr.Hint != "" {
        fmt.Printf("Suggestion: %s\n", sqlErr.Hint)
    }

    // Check if tokenizer error
    if sqlErr.Code[0] == 'E' && sqlErr.Code[1] == '1' {
        fmt.Println("This is a tokenization error")
    }

    // Check if parser error
    if sqlErr.Code[0] == 'E' && sqlErr.Code[1] == '2' {
        fmt.Println("This is a syntax error")
    }
}
```

#### Chaining Error Context

```go
func ParseSQL(sql string) (*ast.AST, error) {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        // Enhance tokenizer error with context
        if sqlErr, ok := err.(*errors.Error); ok {
            return nil, sqlErr.WithContext(sql, 1)
        }
        return nil, err
    }

    p := parser.NewParser()
    defer p.Release()

    ast, err := p.Parse(tokens)
    if err != nil {
        // Enhance parser error with context and hints
        if sqlErr, ok := err.(*errors.Error); ok {
            enhanced := sqlErr.WithContext(sql, 1)

            // Add intelligent hints based on error code
            switch sqlErr.Code {
            case errors.ErrCodeMissingClause:
                enhanced = enhanced.WithHint("Check if all required clauses are present")
            case errors.ErrCodeUnexpectedToken:
                enhanced = enhanced.WithHint("Review SQL syntax around highlighted token")
            }

            return nil, enhanced
        }
        return nil, err
    }

    return ast, nil
}
```

### Error Formatting

The `Error` type implements the `error` interface with rich formatting:

```go
err := errors.NewError(
    errors.ErrCodeUnexpectedToken,
    "expected FROM, got WHERE",
    models.Location{Line: 2, Column: 1},
).WithContext(`SELECT id, name
WHERE id = 1`, 5).WithHint("Add 'FROM table_name' before WHERE clause")

fmt.Println(err.Error())
```

**Output:**
```
Error E2001 at line 2, column 1: expected FROM, got WHERE

   1 | SELECT id, name
   2 | WHERE id = 1
       ^^^^^

Hint: Add 'FROM table_name' before WHERE clause
Help: https://docs.gosqlx.dev/errors/E2001
```

### Error Context Visualization

The error context shows:
- **Line Before**: Provides context leading to the error
- **Error Line**: The line containing the error
- **Position Indicator**: `^` characters highlighting the error location
- **Line After**: Provides context following the error

**Example:**
```go
sql := `SELECT id, name, email
FROM users
WHERE
ORDER BY id`

err := errors.NewError(
    errors.ErrCodeInvalidSyntax,
    "WHERE clause requires a condition",
    models.Location{Line: 3, Column: 1},
).WithContext(sql, 5)
```

**Output:**
```
Error E2004 at line 3, column 1: WHERE clause requires a condition

   2 | FROM users
   3 | WHERE
       ^^^^^
   4 | ORDER BY id

Help: https://docs.gosqlx.dev/errors/E2004
```

### Best Practices

#### 1. Always Add Context for User Errors

```go
// GOOD: Rich error with context
err := errors.NewError(
    errors.ErrCodeMissingClause,
    "missing FROM clause",
    models.Location{Line: 1, Column: 10},
).WithContext(sql, 1).WithHint("Add 'FROM table_name' after SELECT columns")

// LESS HELPFUL: Plain error without context
err := errors.NewError(
    errors.ErrCodeMissingClause,
    "missing FROM clause",
    models.Location{Line: 1, Column: 10},
)
```

#### 2. Use Error Codes for Programmatic Handling

```go
// GOOD: Check error code for specific handling
if errors.IsCode(err, errors.ErrCodeTokenLimitReached) {
    return errors.New("Query too complex - please simplify")
}

// BAD: String matching (fragile)
if strings.Contains(err.Error(), "token limit") {
    // Fragile - message might change
}
```

#### 3. Provide Actionable Hints

```go
// GOOD: Specific, actionable hint
.WithHint("Add 'FROM table_name' after SELECT columns")

// LESS HELPFUL: Vague hint
.WithHint("Fix the syntax error")
```

#### 4. Chain Error Context in Libraries

```go
// GOOD: Preserve and enhance errors from lower layers
func ParseSQL(sql string) error {
    ast, err := parser.Parse(tokens)
    if err != nil {
        if sqlErr, ok := err.(*errors.Error); ok {
            return sqlErr.WithContext(sql, 1).WithHint("Check SQL syntax")
        }
        return err
    }
    return nil
}
```

### Error Categories by Code Prefix

**Quick Reference:**

| Prefix | Category | Examples |
|--------|----------|----------|
| E1xxx | Tokenizer Errors | E1002 (unterminated string), E1006 (input too large) |
| E2xxx | Parser Syntax Errors | E2001 (unexpected token), E2003 (missing clause) |
| E3xxx | Semantic Errors | E3001 (undefined table), E3004 (ambiguous column) |
| E4xxx | Unsupported Features | E4001 (unsupported feature), E4002 (unsupported dialect) |

### Common Error Patterns

#### Pattern 1: Tokenizer Error with Recovery

```go
tokens, err := tkz.Tokenize([]byte(sql))
if err != nil {
    if errors.IsCode(err, errors.ErrCodeUnterminatedString) {
        // Attempt recovery by adding closing quote
        sql = sql + "'"
        tokens, err = tkz.Tokenize([]byte(sql))
    }
}
```

#### Pattern 2: Parser Error with User-Friendly Message

```go
_, err := parser.Parse(tokens)
if err != nil {
    code := errors.GetCode(err)

    userMsg := map[errors.ErrorCode]string{
        errors.ErrCodeMissingClause:   "Your SQL is missing a required clause",
        errors.ErrCodeUnexpectedToken: "Unexpected word in your SQL query",
        errors.ErrCodeInvalidSyntax:   "SQL syntax is incorrect",
    }

    if msg, ok := userMsg[code]; ok {
        return fmt.Errorf("%s: %v", msg, err)
    }

    return err
}
```

#### Pattern 3: Error Logging with Structured Fields

```go
_, err := parser.Parse(tokens)
if err != nil {
    if sqlErr, ok := err.(*errors.Error); ok {
        log.WithFields(log.Fields{
            "error_code": sqlErr.Code,
            "line":       sqlErr.Location.Line,
            "column":     sqlErr.Location.Column,
            "hint":       sqlErr.Hint,
        }).Error(sqlErr.Message)
    }
}
```

## Metrics Package

### Package: `github.com/ajitpratap0/GoSQLX/pkg/metrics`

The Metrics package provides production performance monitoring and observability for GoSQLX operations with thread-safe atomic operations.

### Overview

**Key Features:**
- **Performance Monitoring**: Track tokenization operations, durations, and throughput
- **Memory Tracking**: Monitor object pool efficiency and hit rates
- **Error Analytics**: Categorize and count errors by type
- **Query Size Metrics**: Min, max, and average query sizes processed
- **Thread-Safe**: Lock-free atomic operations for counters
- **Zero Overhead When Disabled**: No performance impact when metrics collection is off
- **Production Ready**: Designed for high-throughput production environments

### Core Types

#### Type: `Metrics`

Internal metrics collector (not exported).

```go
type Metrics struct {
    // Tokenization metrics
    tokenizeOperations int64 // Total tokenization operations
    tokenizeErrors     int64 // Total tokenization errors
    tokenizeDuration   int64 // Total tokenization time (nanoseconds)
    lastTokenizeTime   int64 // Last tokenization timestamp

    // Memory metrics
    poolGets   int64 // Total pool retrievals
    poolPuts   int64 // Total pool returns
    poolMisses int64 // Pool misses (had to create new)

    // Query size metrics
    minQuerySize    int64 // Minimum query size processed
    maxQuerySize    int64 // Maximum query size processed
    totalQueryBytes int64 // Total bytes of SQL processed

    // Error tracking
    errorsByType map[string]int64
    errorsMutex  sync.RWMutex

    // Configuration
    enabled   bool
    startTime time.Time
}
```

#### Type: `Stats`

Performance statistics snapshot.

```go
type Stats struct {
    // Basic counts
    TokenizeOperations int64   `json:"tokenize_operations"`
    TokenizeErrors     int64   `json:"tokenize_errors"`
    ErrorRate          float64 `json:"error_rate"`

    // Performance metrics
    AverageDuration     time.Duration `json:"average_duration"`
    OperationsPerSecond float64       `json:"operations_per_second"`

    // Memory/Pool metrics
    PoolGets     int64   `json:"pool_gets"`
    PoolPuts     int64   `json:"pool_puts"`
    PoolBalance  int64   `json:"pool_balance"`
    PoolMissRate float64 `json:"pool_miss_rate"`

    // Query size metrics
    MinQuerySize        int64   `json:"min_query_size"`
    MaxQuerySize        int64   `json:"max_query_size"`
    AverageQuerySize    float64 `json:"average_query_size"`
    TotalBytesProcessed int64   `json:"total_bytes_processed"`

    // Timing
    Uptime            time.Duration `json:"uptime"`
    LastOperationTime time.Time     `json:"last_operation_time"`

    // Error breakdown
    ErrorsByType map[string]int64 `json:"errors_by_type"`
}
```

**Stats Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `TokenizeOperations` | int64 | Total tokenization operations performed |
| `TokenizeErrors` | int64 | Total tokenization errors encountered |
| `ErrorRate` | float64 | Error rate (errors / operations) |
| `AverageDuration` | time.Duration | Average tokenization duration |
| `OperationsPerSecond` | float64 | Throughput (ops/sec) |
| `PoolGets` | int64 | Total pool retrievals |
| `PoolPuts` | int64 | Total pool returns |
| `PoolBalance` | int64 | Pool balance (gets - puts) |
| `PoolMissRate` | float64 | Pool miss rate (misses / gets) |
| `MinQuerySize` | int64 | Minimum query size (bytes) |
| `MaxQuerySize` | int64 | Maximum query size (bytes) |
| `AverageQuerySize` | float64 | Average query size (bytes) |
| `TotalBytesProcessed` | int64 | Total SQL bytes processed |
| `Uptime` | time.Duration | Time since metrics enabled |
| `LastOperationTime` | time.Time | Timestamp of last operation |
| `ErrorsByType` | map[string]int64 | Error counts by error message |

### Configuration Functions

#### Function: `Enable`

Activates metrics collection.

```go
func Enable()
```

**Example:**
```go
import "github.com/ajitpratap0/GoSQLX/pkg/metrics"

func main() {
    // Enable metrics at application startup
    metrics.Enable()
    defer metrics.Disable()

    // Metrics will now be collected
    // ...
}
```

#### Function: `Disable`

Deactivates metrics collection.

```go
func Disable()
```

**Example:**
```go
// Disable metrics (stops collection)
metrics.Disable()
```

#### Function: `IsEnabled`

Checks if metrics collection is active.

```go
func IsEnabled() bool
```

**Returns:**
- `bool`: true if metrics collection is enabled

**Example:**
```go
if metrics.IsEnabled() {
    fmt.Println("Metrics collection is active")
}
```

### Recording Functions

#### Function: `RecordTokenization`

Records a tokenization operation (automatically called by tokenizer).

```go
func RecordTokenization(duration time.Duration, querySize int, err error)
```

**Parameters:**
- `duration`: Time taken for tokenization
- `querySize`: Size of SQL query in bytes
- `err`: Error if tokenization failed, nil otherwise

**Example:**
```go
start := time.Now()
tokens, err := tkz.Tokenize([]byte(sql))
metrics.RecordTokenization(time.Since(start), len(sql), err)
```

#### Function: `RecordPoolGet`

Records a pool retrieval (automatically called by object pools).

```go
func RecordPoolGet(fromPool bool)
```

**Parameters:**
- `fromPool`: true if object came from pool, false if new object created

**Example:**
```go
// When getting from pool
tkz := tokenizerPool.Get()
metrics.RecordPoolGet(tkz != nil)  // true if from pool, false if created new
```

#### Function: `RecordPoolPut`

Records a pool return (automatically called by object pools).

```go
func RecordPoolPut()
```

**Example:**
```go
// When returning to pool
tokenizerPool.Put(tkz)
metrics.RecordPoolPut()
```

### Query Functions

#### Function: `GetStats`

Returns current performance statistics snapshot.

```go
func GetStats() Stats
```

**Returns:**
- `Stats`: Current performance statistics

**Example:**
```go
stats := metrics.GetStats()

fmt.Printf("Operations: %d\n", stats.TokenizeOperations)
fmt.Printf("Errors: %d (%.2f%%)\n", stats.TokenizeErrors, stats.ErrorRate*100)
fmt.Printf("Avg Duration: %v\n", stats.AverageDuration)
fmt.Printf("Throughput: %.2f ops/sec\n", stats.OperationsPerSecond)
fmt.Printf("Pool Hit Rate: %.2f%%\n", (1-stats.PoolMissRate)*100)
```

#### Function: `LogStats`

Returns current statistics (alias for GetStats, useful for logging).

```go
func LogStats() Stats
```

**Returns:**
- `Stats`: Current performance statistics

**Example:**
```go
stats := metrics.LogStats()
log.Printf("Metrics: %+v", stats)
```

#### Function: `Reset`

Clears all metrics (useful for testing).

```go
func Reset()
```

**Example:**
```go
// Reset metrics to zero
metrics.Reset()
```

### Usage Examples

#### Basic Metrics Collection

```go
package main

import (
    "fmt"
    "time"

    "github.com/ajitpratap0/GoSQLX/pkg/metrics"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func main() {
    // Enable metrics collection
    metrics.Enable()
    defer metrics.Disable()

    // Process SQL queries
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)

    sql := "SELECT * FROM users WHERE active = true"
    tokens, err := tkz.Tokenize([]byte(sql))

    // Metrics are automatically recorded by tokenizer
    // Get current statistics
    stats := metrics.GetStats()
    fmt.Printf("Processed %d operations\n", stats.TokenizeOperations)
    fmt.Printf("Average duration: %v\n", stats.AverageDuration)
    fmt.Printf("Throughput: %.2f ops/sec\n", stats.OperationsPerSecond)
}
```

#### Production Monitoring

```go
func MonitorPerformance() {
    metrics.Enable()

    // Start metrics reporter
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()

    go func() {
        for range ticker.C {
            stats := metrics.GetStats()

            log.WithFields(log.Fields{
                "operations":      stats.TokenizeOperations,
                "errors":          stats.TokenizeErrors,
                "error_rate":      stats.ErrorRate,
                "avg_duration_us": stats.AverageDuration.Microseconds(),
                "ops_per_sec":     stats.OperationsPerSecond,
                "pool_hit_rate":   1 - stats.PoolMissRate,
                "avg_query_size":  stats.AverageQuerySize,
                "uptime":          stats.Uptime,
            }).Info("GoSQLX metrics")
        }
    }()
}
```

#### Error Tracking

```go
func AnalyzeErrors() {
    stats := metrics.GetStats()

    fmt.Printf("Total Errors: %d (%.2f%%)\n",
        stats.TokenizeErrors, stats.ErrorRate*100)

    fmt.Println("\nError Breakdown:")
    for errorType, count := range stats.ErrorsByType {
        percentage := float64(count) / float64(stats.TokenizeOperations) * 100
        fmt.Printf("  %s: %d (%.2f%%)\n", errorType, count, percentage)
    }
}
```

#### Pool Efficiency Monitoring

```go
func MonitorPoolEfficiency() {
    stats := metrics.GetStats()

    poolHitRate := (1 - stats.PoolMissRate) * 100
    fmt.Printf("Pool Statistics:\n")
    fmt.Printf("  Gets: %d\n", stats.PoolGets)
    fmt.Printf("  Puts: %d\n", stats.PoolPuts)
    fmt.Printf("  Balance: %d\n", stats.PoolBalance)
    fmt.Printf("  Hit Rate: %.2f%%\n", poolHitRate)
    fmt.Printf("  Miss Rate: %.2f%%\n", stats.PoolMissRate*100)

    if poolHitRate < 90 {
        log.Warn("Pool hit rate is below 90% - consider tuning pool size")
    }
}
```

#### Query Size Analysis

```go
func AnalyzeQuerySizes() {
    stats := metrics.GetStats()

    fmt.Printf("Query Size Statistics:\n")
    fmt.Printf("  Min: %d bytes\n", stats.MinQuerySize)
    fmt.Printf("  Max: %d bytes\n", stats.MaxQuerySize)
    fmt.Printf("  Average: %.2f bytes\n", stats.AverageQuerySize)
    fmt.Printf("  Total Processed: %d bytes (%.2f MB)\n",
        stats.TotalBytesProcessed,
        float64(stats.TotalBytesProcessed)/(1024*1024))

    // Detect potential issues
    if stats.MaxQuerySize > 1024*1024 {  // > 1MB
        log.Warn("Large query detected - consider query optimization")
    }
}
```

#### JSON Export

```go
func ExportMetricsJSON() ([]byte, error) {
    stats := metrics.GetStats()
    return json.MarshalIndent(stats, "", "  ")
}

func main() {
    metrics.Enable()
    // ... process queries

    // Export metrics as JSON
    jsonData, err := ExportMetricsJSON()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(string(jsonData))
    // Output:
    // {
    //   "tokenize_operations": 1000,
    //   "tokenize_errors": 5,
    //   "error_rate": 0.005,
    //   "average_duration": "150µs",
    //   "operations_per_second": 6666.67,
    //   ...
    // }
}
```

#### HTTP Metrics Endpoint

```go
func SetupMetricsEndpoint() {
    http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
        stats := metrics.GetStats()

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(stats)
    })

    http.ListenAndServe(":8080", nil)
}
```

#### Prometheus Integration

```go
import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    opsProcessed = promauto.NewCounter(prometheus.CounterOpts{
        Name: "gosqlx_tokenize_operations_total",
        Help: "Total number of tokenization operations",
    })

    opsErrors = promauto.NewCounter(prometheus.CounterOpts{
        Name: "gosqlx_tokenize_errors_total",
        Help: "Total number of tokenization errors",
    })

    avgDuration = promauto.NewGauge(prometheus.GaugeOpts{
        Name: "gosqlx_tokenize_duration_microseconds",
        Help: "Average tokenization duration in microseconds",
    })
)

func UpdatePrometheusMetrics() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        stats := metrics.GetStats()

        opsProcessed.Add(float64(stats.TokenizeOperations))
        opsErrors.Add(float64(stats.TokenizeErrors))
        avgDuration.Set(float64(stats.AverageDuration.Microseconds()))
    }
}
```

#### Performance Alerting

```go
func MonitorWithAlerting() {
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        stats := metrics.GetStats()

        // Alert on high error rate
        if stats.ErrorRate > 0.01 {  // > 1%
            alert("High error rate: %.2f%%", stats.ErrorRate*100)
        }

        // Alert on slow performance
        if stats.AverageDuration > 1*time.Millisecond {
            alert("Slow tokenization: %v", stats.AverageDuration)
        }

        // Alert on low pool efficiency
        if stats.PoolMissRate > 0.1 {  // > 10%
            alert("Low pool hit rate: %.2f%%", (1-stats.PoolMissRate)*100)
        }

        // Alert on low throughput
        if stats.OperationsPerSecond < 1000 {
            alert("Low throughput: %.2f ops/sec", stats.OperationsPerSecond)
        }
    }
}

func alert(format string, args ...interface{}) {
    msg := fmt.Sprintf(format, args...)
    log.Warn(msg)
    // Send to alerting system (PagerDuty, Slack, etc.)
}
```

### Integration Patterns

#### Pattern 1: Application Startup

```go
func main() {
    // Enable metrics at startup
    metrics.Enable()
    defer func() {
        // Log final stats before shutdown
        stats := metrics.GetStats()
        log.Printf("Final metrics: %+v", stats)
        metrics.Disable()
    }()

    // Run application
    // ...
}
```

#### Pattern 2: Periodic Reporting

```go
func StartMetricsReporter(interval time.Duration) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    for range ticker.C {
        stats := metrics.GetStats()
        reportMetrics(stats)
    }
}

func reportMetrics(stats metrics.Stats) {
    log.Printf("Operations: %d, Errors: %d (%.2f%%), Throughput: %.2f ops/sec",
        stats.TokenizeOperations,
        stats.TokenizeErrors,
        stats.ErrorRate*100,
        stats.OperationsPerSecond)
}
```

#### Pattern 3: Testing with Metrics

```go
func TestTokenizerPerformance(t *testing.T) {
    // Reset metrics before test
    metrics.Reset()
    metrics.Enable()
    defer metrics.Disable()

    // Run test operations
    for i := 0; i < 1000; i++ {
        tkz := tokenizer.GetTokenizer()
        tkz.Tokenize([]byte("SELECT * FROM users"))
        tokenizer.PutTokenizer(tkz)
    }

    // Verify metrics
    stats := metrics.GetStats()
    assert.Equal(t, int64(1000), stats.TokenizeOperations)
    assert.Equal(t, int64(0), stats.TokenizeErrors)
    assert.Less(t, stats.AverageDuration, 100*time.Microsecond)
    assert.Greater(t, stats.PoolMissRate, 0.0)
}
```

### Performance Characteristics

**Thread Safety:**
- All counter operations use atomic operations (lock-free)
- Error type tracking uses RWMutex for infrequent writes
- Safe for concurrent access from multiple goroutines

**Memory Overhead:**
- Fixed memory footprint (~200 bytes + error map)
- No allocations during metric recording
- Error map grows with unique error types (bounded by error variety)

**Performance Impact:**
- **Enabled**: ~50ns per RecordTokenization call (negligible)
- **Disabled**: ~1ns per call (just enabled check)
- **GetStats**: O(n) where n = number of unique error types (typically < 10)

### Best Practices

#### 1. Enable Early, Disable Late

```go
// GOOD: Enable at application startup
func main() {
    metrics.Enable()
    defer metrics.Disable()
    // ... application logic
}

// BAD: Enabling/disabling frequently
func processQuery(sql string) {
    metrics.Enable()   // Don't do this repeatedly
    // ...
    metrics.Disable()
}
```

#### 2. Use Periodic Reporting

```go
// GOOD: Periodic reporting (low overhead)
func StartReporting() {
    ticker := time.NewTicker(1 * time.Minute)
    go func() {
        for range ticker.C {
            stats := metrics.GetStats()
            reportToMonitoring(stats)
        }
    }()
}

// BAD: Report after every operation (high overhead)
func processQuery(sql string) {
    // ... process
    stats := metrics.GetStats()  // Don't do this after every query
    reportToMonitoring(stats)
}
```

#### 3. Monitor Pool Efficiency

```go
// Pool hit rate should be > 95% in production
stats := metrics.GetStats()
if stats.PoolMissRate > 0.05 {  // > 5% miss rate
    log.Warn("Pool efficiency is low - consider increasing pool size")
}
```

#### 4. Set Performance SLOs

```go
// Define Service Level Objectives
const (
    MaxErrorRate         = 0.01   // 1%
    MinOpsPerSecond     = 1000.0  // 1k ops/sec
    MaxAvgDuration      = 1 * time.Millisecond
    MinPoolHitRate      = 0.95    // 95%
)

func CheckSLOs() bool {
    stats := metrics.GetStats()

    if stats.ErrorRate > MaxErrorRate {
        return false
    }
    if stats.OperationsPerSecond < MinOpsPerSecond {
        return false
    }
    if stats.AverageDuration > MaxAvgDuration {
        return false
    }
    if (1 - stats.PoolMissRate) < MinPoolHitRate {
        return false
    }

    return true
}
```

### Metrics Dashboard Example

```go
func PrintMetricsDashboard() {
    stats := metrics.GetStats()

    fmt.Println("╔════════════════════════════════════════════════════════╗")
    fmt.Println("║          GoSQLX Performance Metrics                    ║")
    fmt.Println("╠════════════════════════════════════════════════════════╣")
    fmt.Printf("║ Operations:       %10d                          ║\n", stats.TokenizeOperations)
    fmt.Printf("║ Errors:           %10d (%.2f%%)                  ║\n",
        stats.TokenizeErrors, stats.ErrorRate*100)
    fmt.Printf("║ Avg Duration:     %10v                         ║\n", stats.AverageDuration)
    fmt.Printf("║ Throughput:       %10.2f ops/sec               ║\n", stats.OperationsPerSecond)
    fmt.Println("╠════════════════════════════════════════════════════════╣")
    fmt.Printf("║ Pool Gets:        %10d                          ║\n", stats.PoolGets)
    fmt.Printf("║ Pool Puts:        %10d                          ║\n", stats.PoolPuts)
    fmt.Printf("║ Pool Hit Rate:    %10.2f%%                      ║\n", (1-stats.PoolMissRate)*100)
    fmt.Println("╠════════════════════════════════════════════════════════╣")
    fmt.Printf("║ Avg Query Size:   %10.2f bytes                 ║\n", stats.AverageQuerySize)
    fmt.Printf("║ Min Query Size:   %10d bytes                   ║\n", stats.MinQuerySize)
    fmt.Printf("║ Max Query Size:   %10d bytes                   ║\n", stats.MaxQuerySize)
    fmt.Printf("║ Total Processed:  %10.2f MB                    ║\n",
        float64(stats.TotalBytesProcessed)/(1024*1024))
    fmt.Println("╠════════════════════════════════════════════════════════╣")
    fmt.Printf("║ Uptime:           %10v                         ║\n", stats.Uptime)
    fmt.Println("╚════════════════════════════════════════════════════════╝")
}
```

---

## Security Package

### Package: `github.com/ajitpratap0/GoSQLX/pkg/sql/security`

The Security package provides SQL injection pattern detection and security scanning capabilities. It analyzes parsed SQL AST to identify common injection patterns and vulnerabilities.

### Overview

The scanner detects the following 6 SQL injection patterns:

| Pattern Type | Description | Severity |
|-------------|-------------|----------|
| **Tautology** | Always-true conditions (1=1, 'a'='a') | CRITICAL |
| **Comment Bypass** | SQL comments used to bypass filters (--, /**/) | HIGH/MEDIUM |
| **UNION-Based** | Suspicious UNION SELECT with NULL columns or system tables | HIGH/CRITICAL |
| **Time-Based Blind** | SLEEP(), WAITFOR DELAY, pg_sleep(), BENCHMARK() | HIGH |
| **Out-of-Band** | xp_cmdshell, LOAD_FILE(), UTL_HTTP, etc. | CRITICAL |
| **Dangerous Functions** | EXEC(), sp_executesql, PREPARE FROM, etc. | MEDIUM/CRITICAL |

---

### Scanner Types

#### `type Scanner struct`

Scanner performs security analysis on SQL AST.

```go
type Scanner struct {
    // MinSeverity filters findings below this severity level
    MinSeverity Severity
}
```

#### `type ScanResult struct`

Contains all findings from a security scan.

```go
type ScanResult struct {
    Findings      []Finding `json:"findings"`
    TotalCount    int       `json:"total_count"`
    CriticalCount int       `json:"critical_count"`
    HighCount     int       `json:"high_count"`
    MediumCount   int       `json:"medium_count"`
    LowCount      int       `json:"low_count"`
}
```

**Methods:**
- `HasCritical() bool` - Returns true if any critical findings exist
- `HasHighOrAbove() bool` - Returns true if any high or critical findings exist
- `IsClean() bool` - Returns true if no findings exist

#### `type Finding struct`

Represents a single security finding.

```go
type Finding struct {
    Severity    Severity    `json:"severity"`
    Pattern     PatternType `json:"pattern"`
    Description string      `json:"description"`
    Risk        string      `json:"risk"`
    Line        int         `json:"line,omitempty"`
    Column      int         `json:"column,omitempty"`
    SQL         string      `json:"sql,omitempty"`
    Suggestion  string      `json:"suggestion,omitempty"`
}
```

---

### Severity Levels

```go
const (
    SeverityCritical Severity = "CRITICAL"  // Definite injection (e.g., OR 1=1 --)
    SeverityHigh     Severity = "HIGH"      // Likely injection (suspicious patterns)
    SeverityMedium   Severity = "MEDIUM"    // Potentially unsafe (needs review)
    SeverityLow      Severity = "LOW"       // Informational findings
)
```

---

### Pattern Detection

#### Pattern Types

```go
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

---

### Functions

#### `NewScanner() *Scanner`

Creates a new security scanner with default settings.

```go
scanner := security.NewScanner()
```

---

#### `NewScannerWithSeverity(minSeverity Severity) (*Scanner, error)`

Creates a scanner filtering by minimum severity.

```go
scanner, err := security.NewScannerWithSeverity(security.SeverityHigh)
if err != nil {
    log.Fatal(err)
}
// Only reports HIGH and CRITICAL findings
```

---

#### `(*Scanner) Scan(tree *ast.AST) *ScanResult`

Analyzes an AST for SQL injection patterns.

```go
scanner := security.NewScanner()
result := scanner.Scan(ast)

for _, finding := range result.Findings {
    fmt.Printf("%s: %s - %s\n",
        finding.Severity,
        finding.Pattern,
        finding.Description)
}
```

---

#### `(*Scanner) ScanSQL(sql string) *ScanResult`

Analyzes raw SQL string for injection patterns. Useful for detecting patterns that might not be in the AST.

```go
scanner := security.NewScanner()
result := scanner.ScanSQL("SELECT * FROM users WHERE id = 1 OR 1=1 --")

if result.HasCritical() {
    fmt.Println("CRITICAL: SQL injection detected!")
}
```

---

### Usage Examples

#### Example 1: Basic Security Scan

```go
package main

import (
    "fmt"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/security"
)

func main() {
    sql := "SELECT * FROM users WHERE username = 'admin' OR 1=1"

    // Parse SQL
    ast, err := parser.Parse([]byte(sql))
    if err != nil {
        log.Fatal(err)
    }

    // Scan for injection patterns
    scanner := security.NewScanner()
    result := scanner.Scan(ast)

    // Check results
    if result.HasCritical() {
        fmt.Printf("Found %d critical issues!\n", result.CriticalCount)
        for _, finding := range result.Findings {
            fmt.Printf("  - %s: %s\n", finding.Pattern, finding.Description)
            fmt.Printf("    Risk: %s\n", finding.Risk)
            fmt.Printf("    Suggestion: %s\n", finding.Suggestion)
        }
    }
}
```

---

#### Example 2: Integration with Query Validation

```go
func ValidateUserQuery(sql string) error {
    // Parse SQL
    ast, err := parser.Parse([]byte(sql))
    if err != nil {
        return fmt.Errorf("invalid SQL: %w", err)
    }

    // Security scan
    scanner := security.NewScanner()
    result := scanner.Scan(ast)

    // Block queries with critical findings
    if result.HasCritical() {
        return fmt.Errorf("security violation: %d critical issues detected",
            result.CriticalCount)
    }

    // Warn on high severity findings
    if result.HighCount > 0 {
        log.Printf("Warning: %d high-severity patterns detected", result.HighCount)
    }

    return nil
}
```

---

#### Example 3: Custom Severity Filtering

```go
// Only scan for HIGH and CRITICAL issues (skip MEDIUM and LOW)
scanner, err := security.NewScannerWithSeverity(security.SeverityHigh)
if err != nil {
    log.Fatal(err)
}

result := scanner.Scan(ast)
// result.Findings only contains HIGH and CRITICAL severity items
```

---

#### Example 4: Raw SQL Pattern Detection

```go
// Detect patterns in raw SQL (without full parsing)
scanner := security.NewScanner()

// Check for time-based injection patterns
result := scanner.ScanSQL("SELECT * FROM users; WAITFOR DELAY '0:0:5'")

for _, finding := range result.Findings {
    if finding.Pattern == security.PatternTimeBased {
        fmt.Println("Time-based blind injection attempt detected!")
    }
}
```

---

### Detected Patterns Detail

#### Tautology Detection

Detects always-true conditions commonly used for authentication bypass:

```sql
-- Detected as CRITICAL
SELECT * FROM users WHERE id = 1 OR 1=1
SELECT * FROM users WHERE name = 'x' OR 'a'='a'
SELECT * FROM users WHERE col = col
```

#### UNION-Based Injection

Detects suspicious UNION SELECT patterns for data extraction:

```sql
-- Detected as HIGH (multiple NULLs indicate column enumeration)
SELECT id FROM users UNION SELECT NULL, NULL, NULL

-- Detected as CRITICAL (system table access)
SELECT id FROM users UNION SELECT table_name FROM information_schema.tables
```

#### Time-Based Functions

Detects time-delay functions used in blind injection:

```sql
-- Detected as HIGH
SELECT * FROM users WHERE SLEEP(5)
SELECT * FROM users; WAITFOR DELAY '0:0:5'
SELECT * FROM users WHERE pg_sleep(5)
```

#### Dangerous Functions

Detects functions that can lead to system compromise:

```sql
-- Detected as CRITICAL (command execution)
EXEC xp_cmdshell 'dir'
SELECT LOAD_FILE('/etc/passwd')
SELECT * INTO OUTFILE '/tmp/data.txt' FROM users
```

---

### System Table Detection

The scanner precisely identifies access to system tables across multiple databases:

| Database | System Tables Detected |
|----------|----------------------|
| **PostgreSQL** | `pg_catalog.*`, `pg_*` |
| **MySQL** | `mysql.*`, `information_schema.*` |
| **SQL Server** | `sys.*`, `master.dbo.*`, `msdb.*`, `tempdb.*` |
| **SQLite** | `sqlite_*` |
| **Generic** | `information_schema.*` |

---

### Best Practices

#### 1. Scan All User-Supplied Queries

```go
func HandleUserQuery(w http.ResponseWriter, r *http.Request) {
    userSQL := r.FormValue("query")

    // ALWAYS scan user input
    ast, err := parser.Parse([]byte(userSQL))
    if err != nil {
        http.Error(w, "Invalid SQL", http.StatusBadRequest)
        return
    }

    scanner := security.NewScanner()
    result := scanner.Scan(ast)

    if result.HasHighOrAbove() {
        http.Error(w, "Potentially unsafe query", http.StatusForbidden)
        logSecurityEvent(userSQL, result)
        return
    }

    // Proceed with safe query
}
```

#### 2. Log Security Findings

```go
func logSecurityEvent(sql string, result *security.ScanResult) {
    for _, finding := range result.Findings {
        log.Printf("[SECURITY] %s: %s - %s (Risk: %s)",
            finding.Severity,
            finding.Pattern,
            finding.Description,
            finding.Risk)
    }
}
```

#### 3. Use Appropriate Severity Filters

```go
// For production: Block CRITICAL and HIGH, warn on MEDIUM
scanner, _ := security.NewScannerWithSeverity(security.SeverityMedium)

// For strict security: Block all findings
scanner := security.NewScanner() // Includes LOW severity
```

---

### Performance Considerations

- **Regex Compilation**: All regex patterns are pre-compiled at package initialization (sync.Once)
- **Thread Safety**: Scanner is safe for concurrent use across goroutines
- **Memory Efficiency**: No allocations during scanning beyond the result struct
- **Throughput**: Can scan 100,000+ queries/second on modern hardware