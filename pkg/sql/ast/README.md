# AST Package

## Overview

The `ast` package provides comprehensive Abstract Syntax Tree (AST) node definitions for SQL statements. It represents the parsed structure of SQL queries with 73.4% test coverage and full support for DDL, DML, CTEs, set operations, and window functions.

## Key Features

- **Complete SQL Statement Types**: SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP
- **Expression System**: Binary/unary operations, functions, literals, identifiers
- **Advanced SQL**: WITH (CTEs), UNION/EXCEPT/INTERSECT, window functions
- **Object Pooling**: Statement and expression pools for memory efficiency
- **Visitor Pattern**: AST traversal and inspection support
- **Type Safety**: Strongly-typed node hierarchy with Go interfaces

## Core Interfaces

### Node

Base interface for all AST nodes:

```go
type Node interface {
    TokenLiteral() string  // Returns the literal token value
    Children() []Node      // Returns child nodes for traversal
}
```

### Statement

Represents SQL statements (extends Node):

```go
type Statement interface {
    Node
    statementNode()  // Marker method
}
```

### Expression

Represents SQL expressions (extends Node):

```go
type Expression interface {
    Node
    expressionNode()  // Marker method
}
```

## Statement Types

### SelectStatement

Represents SELECT queries with full SQL features:

```go
type SelectStatement struct {
    Distinct bool
    Columns  []Expression        // SELECT columns
    From     []TableReference    // FROM clause
    Joins    []JoinClause       // JOIN clauses
    Where    Expression         // WHERE condition
    GroupBy  []Expression       // GROUP BY columns
    Having   Expression         // HAVING condition
    OrderBy  []OrderByExpression // ORDER BY with NULLS FIRST/LAST
    Limit    *int64             // LIMIT value
    Offset   *int64             // OFFSET value
}
```

**Example Usage**:

```go
if stmt, ok := astNode.(*ast.SelectStatement); ok {
    fmt.Printf("SELECT has %d columns\n", len(stmt.Columns))

    if stmt.Where != nil {
        fmt.Println("Has WHERE clause")
    }

    for _, join := range stmt.Joins {
        fmt.Printf("JOIN type: %s\n", join.Type)
    }
}
```

### InsertStatement

Represents INSERT operations:

```go
type InsertStatement struct {
    Table   string
    Columns []string
    Values  [][]Expression  // Multi-row support
}
```

### UpdateStatement

Represents UPDATE operations:

```go
type UpdateStatement struct {
    Table string
    Set   []UpdateSetClause
    Where Expression
}
```

### DeleteStatement

Represents DELETE operations:

```go
type DeleteStatement struct {
    Table string
    Where Expression
}
```

## Expression Types

### Identifier

Column, table, or alias names:

```go
type Identifier struct {
    Name string
}
```

### Literal

Constant values:

```go
type Literal struct {
    Type  LiteralType  // STRING, NUMBER, BOOLEAN, NULL
    Value interface{}
}
```

### BinaryExpression

Binary operations (=, >, AND, OR, etc.):

```go
type BinaryExpression struct {
    Left     Expression
    Operator string      // =, >, <, AND, OR, LIKE, etc.
    Right    Expression
}
```

### FunctionCall

Function invocations (with optional window spec):

```go
type FunctionCall struct {
    Name       string
    Arguments  []Expression
    Over       *WindowSpec  // For window functions
}
```

## Advanced Features

### Common Table Expressions (CTEs)

```go
type WithClause struct {
    Recursive bool
    CTEs      []*CommonTableExpr
}

type CommonTableExpr struct {
    Name         string
    Columns      []string       // Optional column list
    Statement    Statement      // CTE query
    Materialized *bool         // MATERIALIZED hint
}
```

**Example**:

```go
if stmt, ok := astNode.(*ast.SelectStatement); ok {
    // Check for CTEs
    // (CTEs are represented at statement level)
}
```

### Set Operations

```go
type SetOperation struct {
    Left     Statement
    Operator string  // UNION, EXCEPT, INTERSECT
    Right    Statement
    All      bool    // true for UNION ALL
}
```

### Window Functions

```go
type WindowSpec struct {
    PartitionBy []Expression
    OrderBy     []OrderByExpression
    Frame       *WindowFrame
}

type WindowFrame struct {
    Type   string  // ROWS or RANGE
    Start  *WindowFrameBound
    End    *WindowFrameBound
}
```

### ORDER BY with NULL Ordering

```go
type OrderByExpression struct {
    Expression Expression
    Ascending  bool
    NullsFirst *bool  // nil=database default, true=FIRST, false=LAST
}
```

## Object Pooling

### AST Pool

Reuse AST container objects:

```go
// Get from pool
astObj := ast.NewAST()
defer ast.ReleaseAST(astObj)  // ALWAYS defer release

// Use AST
astObj.Root = selectStmt
```

### Statement Pools

Individual pools for each statement type:

```go
// SELECT statements
selectStmt := ast.NewSelectStatement()
defer ast.ReleaseSelectStatement(selectStmt)

// INSERT statements
insertStmt := ast.NewInsertStatement()
defer ast.ReleaseInsertStatement(insertStmt)
```

### Expression Pools

```go
// Identifiers
id := ast.NewIdentifier("column_name")
defer ast.ReleaseIdentifier(id)

// Binary expressions
binExpr := ast.NewBinaryExpression()
defer ast.ReleaseBinaryExpression(binExpr)
```

## Visitor Pattern

### Walk Function

Traverse the AST with a visitor:

```go
ast.Walk(astNode, func(n ast.Node) bool {
    // Visit each node
    fmt.Printf("Visiting: %T\n", n)

    // Return true to continue, false to stop
    return true
})
```

### Inspector

Inspect specific node types:

```go
inspector := ast.NewInspector(astNode)

// Find all identifiers
inspector.WithStack(func(n ast.Node, push bool, stack []ast.Node) bool {
    if id, ok := n.(*ast.Identifier); ok {
        fmt.Printf("Found identifier: %s\n", id.Name)
    }
    return true
})
```

## Common Usage Patterns

### 1. Extract All Table Names

```go
func ExtractTables(stmt *ast.SelectStatement) []string {
    tables := []string{}

    for _, table := range stmt.From {
        if tableRef, ok := table.(*ast.TableReference); ok {
            tables = append(tables, tableRef.Name)
        }
    }

    for _, join := range stmt.Joins {
        if tableRef, ok := join.Table.(*ast.TableReference); ok {
            tables = append(tables, tableRef.Name)
        }
    }

    return tables
}
```

### 2. Find All WHERE Conditions

```go
func ExtractWhereConditions(stmt *ast.SelectStatement) []string {
    conditions := []string{}

    if stmt.Where != nil {
        // Traverse WHERE expression tree
        ast.Walk(stmt.Where, func(n ast.Node) bool {
            if binExpr, ok := n.(*ast.BinaryExpression); ok {
                conditions = append(conditions, binExpr.Operator)
            }
            return true
        })
    }

    return conditions
}
```

### 3. Detect Window Functions

```go
func HasWindowFunctions(stmt *ast.SelectStatement) bool {
    hasWindow := false

    for _, col := range stmt.Columns {
        ast.Walk(col, func(n ast.Node) bool {
            if funcCall, ok := n.(*ast.FunctionCall); ok {
                if funcCall.Over != nil {
                    hasWindow = true
                    return false  // Stop walking
                }
            }
            return true
        })

        if hasWindow {
            break
        }
    }

    return hasWindow
}
```

## Testing

Run AST tests:

```bash
# All tests (73.4% coverage)
go test -v ./pkg/sql/ast/

# With race detection
go test -race ./pkg/sql/ast/

# Coverage report
go test -cover -coverprofile=coverage.out ./pkg/sql/ast/
go tool cover -html=coverage.out

# Specific features
go test -v -run TestSelectStatement ./pkg/sql/ast/
go test -v -run TestWindowSpec ./pkg/sql/ast/
go test -v -run TestVisitor ./pkg/sql/ast/
```

## Best Practices

### 1. Always Use Object Pools

```go
// GOOD: Use pool
selectStmt := ast.NewSelectStatement()
defer ast.ReleaseSelectStatement(selectStmt)

// BAD: Direct instantiation
selectStmt := &ast.SelectStatement{}  // Misses pool benefits
```

### 2. Check Node Types Safely

```go
// GOOD: Type assertion with check
if selectStmt, ok := node.(*ast.SelectStatement); ok {
    // Use selectStmt
}

// BAD: Unsafe type assertion
selectStmt := node.(*ast.SelectStatement)  // Panics if wrong type
```

### 3. Use Visitor Pattern for Traversal

```go
// GOOD: Visitor pattern
ast.Walk(node, func(n ast.Node) bool {
    // Visit each node systematically
    return true
})

// BAD: Manual recursion
func traverse(n ast.Node) {
    // Complex, error-prone manual traversal
}
```

## Node Type Reference

### Statements

- `SelectStatement` - SELECT queries
- `InsertStatement` - INSERT operations
- `UpdateStatement` - UPDATE operations
- `DeleteStatement` - DELETE operations
- `CreateTableStatement` - CREATE TABLE DDL
- `AlterTableStatement` - ALTER TABLE DDL
- `DropTableStatement` - DROP TABLE DDL
- `WithClause` - Common Table Expressions
- `SetOperation` - UNION/EXCEPT/INTERSECT

### Expressions

- `Identifier` - Column/table/alias names
- `Literal` - Constant values
- `BinaryExpression` - Binary operations
- `UnaryExpression` - Unary operations
- `FunctionCall` - Function invocations
- `CaseExpression` - CASE WHEN expressions
- `InExpression` - IN predicates
- `BetweenExpression` - BETWEEN predicates
- `SubqueryExpression` - Subqueries in expressions

### Special Types

- `JoinClause` - JOIN specifications
- `TableReference` - Table references with aliases
- `WindowSpec` - Window function specifications
- `WindowFrame` - Window frame clauses
- `OrderByExpression` - ORDER BY with NULL ordering

## Related Packages

- **parser**: Builds AST from tokens
- **tokenizer**: Provides input to parser
- **visitor**: AST traversal utilities
- **token**: Token definitions

## Documentation

- [Main API Reference](../../../docs/API_REFERENCE.md)
- [Parser Package](../parser/README.md)
- [Architecture Guide](../../../docs/ARCHITECTURE.md)
- [Examples](../../../examples/)

## Version History

- **v1.5.0**: OrderByExpression with NullsFirst support (SQL-99 F851)
- **v1.4.0**: Production validation, pool optimization
- **v1.3.0**: Window functions (WindowSpec, WindowFrame, WindowFrameBound)
- **v1.2.0**: CTEs (WithClause, CommonTableExpr) and set operations
- **v1.0.0**: Core DML/DDL statements and expressions
