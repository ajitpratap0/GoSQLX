// Package ast provides Abstract Syntax Tree (AST) node definitions for SQL statements.
//
// This package implements a comprehensive AST representation for SQL with support for
// multiple SQL dialects (PostgreSQL, MySQL, SQL Server, Oracle, SQLite). It includes
// extensive object pooling for memory efficiency and high-performance SQL parsing.
//
// For complete documentation including architecture overview, usage examples, visitor
// pattern, and feature support matrix, see the package-level documentation in doc.go.
//
// Key features:
//   - Complete SQL-99/SQL:2003 statement support (DDL, DML, CTEs, window functions)
//   - PostgreSQL extensions (LATERAL, DISTINCT ON, FILTER, RETURNING, JSON operators)
//   - Advanced grouping (GROUPING SETS, ROLLUP, CUBE)
//   - MERGE statements (SQL:2003 F312)
//   - Object pooling for 60-80% memory reduction
//   - Thread-safe with zero race conditions
//   - Visitor pattern for AST traversal
//
// Quick Start Example:
//
//	// Get AST from pool
//	astObj := ast.NewAST()
//	defer ast.ReleaseAST(astObj)  // Always use defer
//
//	// Get SELECT statement from pool
//	stmt := ast.GetSelectStatement()
//	defer ast.PutSelectStatement(stmt)
//
//	// Build and use AST nodes...
//
// Version 1.6.0 adds PostgreSQL extensions including LATERAL JOIN, DISTINCT ON,
// FILTER clause, RETURNING clause, JSON/JSONB operators, and FETCH FIRST/NEXT.
package ast

import "fmt"

// Node represents any node in the Abstract Syntax Tree.
//
// Node is the base interface that all AST nodes must implement. It provides
// two core methods for tree inspection and traversal:
//
//   - TokenLiteral(): Returns the literal token value that starts this node
//   - Children(): Returns all child nodes for tree traversal
//
// The Node interface enables the visitor pattern for AST traversal. Use the
// Walk() and Inspect() functions from visitor.go to traverse the tree.
//
// Example - Checking node type:
//
//	switch node := astNode.(type) {
//	case *SelectStatement:
//	    fmt.Println("Found SELECT statement")
//	case *BinaryExpression:
//	    fmt.Printf("Binary operator: %s\n", node.Operator)
//	}
type Node interface {
	TokenLiteral() string
	Children() []Node
}

// Statement represents a SQL statement node in the AST.
//
// Statement extends the Node interface and represents top-level SQL statements
// such as SELECT, INSERT, UPDATE, DELETE, CREATE TABLE, etc. Statements form
// the root nodes of the syntax tree.
//
// All statement types implement both Node and Statement interfaces. The
// statementNode() method is a marker method to distinguish statements from
// expressions at compile time.
//
// Supported Statement Types:
//   - DML: SelectStatement, InsertStatement, UpdateStatement, DeleteStatement
//   - DDL: CreateTableStatement, AlterTableStatement, DropStatement
//   - Advanced: MergeStatement, TruncateStatement, WithClause, SetOperation
//   - Views: CreateViewStatement, CreateMaterializedViewStatement
//
// Example - Type assertion:
//
//	if stmt, ok := node.(Statement); ok {
//	    fmt.Printf("Statement type: %s\n", stmt.TokenLiteral())
//	}
type Statement interface {
	Node
	statementNode()
}

// Expression represents a SQL expression node in the AST.
//
// Expression extends the Node interface and represents SQL expressions that
// can appear within statements, such as literals, identifiers, binary operations,
// function calls, subqueries, etc.
//
// All expression types implement both Node and Expression interfaces. The
// expressionNode() method is a marker method to distinguish expressions from
// statements at compile time.
//
// Supported Expression Types:
//   - Basic: Identifier, LiteralValue, AliasedExpression
//   - Operators: BinaryExpression, UnaryExpression, BetweenExpression, InExpression
//   - Functions: FunctionCall (with window function support)
//   - Subqueries: SubqueryExpression, ExistsExpression, AnyExpression, AllExpression
//   - Conditional: CaseExpression, CastExpression
//   - Grouping: RollupExpression, CubeExpression, GroupingSetsExpression
//
// Example - Building an expression:
//
//	// Build: column = 'value'
//	expr := &BinaryExpression{
//	    Left:     &Identifier{Name: "column"},
//	    Operator: "=",
//	    Right:    &LiteralValue{Value: "value", Type: "STRING"},
//	}
type Expression interface {
	Node
	expressionNode()
}

// WithClause represents a WITH clause in a SQL statement.
// It supports both simple and recursive Common Table Expressions (CTEs).
// Phase 2 Complete: Full parser integration with all statement types.
type WithClause struct {
	Recursive bool
	CTEs      []*CommonTableExpr
}

func (w *WithClause) statementNode()      {}
func (w WithClause) TokenLiteral() string { return "WITH" }
func (w WithClause) Children() []Node {
	children := make([]Node, len(w.CTEs))
	for i, cte := range w.CTEs {
		children[i] = cte
	}
	return children
}

// CommonTableExpr represents a single Common Table Expression in a WITH clause.
// It supports optional column specifications and any statement type as the CTE query.
// Phase 2 Complete: Full parser support with column specifications.
// Phase 2.6: Added MATERIALIZED/NOT MATERIALIZED support for query optimization hints.
type CommonTableExpr struct {
	Name         string
	Columns      []string
	Statement    Statement
	Materialized *bool // nil = default, true = MATERIALIZED, false = NOT MATERIALIZED
}

func (c *CommonTableExpr) statementNode()      {}
func (c CommonTableExpr) TokenLiteral() string { return c.Name }
func (c CommonTableExpr) Children() []Node {
	return []Node{c.Statement}
}

// SetOperation represents set operations (UNION, EXCEPT, INTERSECT) between two statements.
// It supports the ALL modifier (e.g., UNION ALL) and proper left-associative parsing.
// Phase 2 Complete: Full parser support with left-associative precedence.
type SetOperation struct {
	Left     Statement
	Operator string // UNION, EXCEPT, INTERSECT
	Right    Statement
	All      bool // UNION ALL vs UNION
}

func (s *SetOperation) statementNode()      {}
func (s SetOperation) TokenLiteral() string { return s.Operator }
func (s SetOperation) Children() []Node {
	return []Node{s.Left, s.Right}
}

// JoinClause represents a JOIN clause in SQL
type JoinClause struct {
	Type      string // INNER, LEFT, RIGHT, FULL
	Left      TableReference
	Right     TableReference
	Condition Expression
}

func (j *JoinClause) expressionNode()     {}
func (j JoinClause) TokenLiteral() string { return j.Type + " JOIN" }
func (j JoinClause) Children() []Node {
	children := []Node{&j.Left, &j.Right}
	if j.Condition != nil {
		children = append(children, j.Condition)
	}
	return children
}

// TableReference represents a table reference in a FROM clause.
//
// TableReference can represent either a simple table name or a derived table
// (subquery). It supports PostgreSQL's LATERAL keyword for correlated subqueries.
//
// Fields:
//   - Name: Table name (empty if this is a derived table/subquery)
//   - Alias: Optional table alias (AS alias)
//   - Subquery: Subquery for derived tables: (SELECT ...) AS alias
//   - Lateral: LATERAL keyword for correlated subqueries (PostgreSQL v1.6.0)
//
// The Lateral field enables PostgreSQL's LATERAL JOIN feature, which allows
// subqueries in the FROM clause to reference columns from preceding tables.
//
// Example - Simple table reference:
//
//	TableReference{
//	    Name:  "users",
//	    Alias: "u",
//	}
//	// SQL: FROM users u
//
// Example - Derived table (subquery):
//
//	TableReference{
//	    Alias: "recent_orders",
//	    Subquery: selectStmt,
//	}
//	// SQL: FROM (SELECT ...) AS recent_orders
//
// Example - LATERAL JOIN (PostgreSQL v1.6.0):
//
//	TableReference{
//	    Lateral:  true,
//	    Alias:    "r",
//	    Subquery: correlatedSelectStmt,
//	}
//	// SQL: FROM users u, LATERAL (SELECT * FROM orders WHERE user_id = u.id) r
//
// New in v1.6.0: Lateral field for PostgreSQL LATERAL JOIN support.
type TableReference struct {
	Name     string           // Table name (empty if this is a derived table)
	Alias    string           // Optional alias
	Subquery *SelectStatement // For derived tables: (SELECT ...) AS alias
	Lateral  bool             // LATERAL keyword for correlated subqueries (PostgreSQL)
}

func (t *TableReference) statementNode() {}
func (t TableReference) TokenLiteral() string {
	if t.Name != "" {
		return t.Name
	}
	if t.Alias != "" {
		return t.Alias
	}
	return "subquery"
}
func (t TableReference) Children() []Node {
	if t.Subquery != nil {
		return []Node{t.Subquery}
	}
	return nil
}

// OrderByExpression represents an ORDER BY clause element with direction and NULL ordering
type OrderByExpression struct {
	Expression Expression // The expression to order by
	Ascending  bool       // true for ASC (default), false for DESC
	NullsFirst *bool      // nil = default behavior, true = NULLS FIRST, false = NULLS LAST
}

func (*OrderByExpression) expressionNode()        {}
func (o *OrderByExpression) TokenLiteral() string { return "ORDER BY" }
func (o *OrderByExpression) Children() []Node {
	if o.Expression != nil {
		return []Node{o.Expression}
	}
	return nil
}

// WindowSpec represents a window specification
type WindowSpec struct {
	Name        string
	PartitionBy []Expression
	OrderBy     []OrderByExpression
	FrameClause *WindowFrame
}

func (w *WindowSpec) statementNode()      {}
func (w WindowSpec) TokenLiteral() string { return "WINDOW" }
func (w WindowSpec) Children() []Node {
	children := make([]Node, 0)
	children = append(children, nodifyExpressions(w.PartitionBy)...)
	for _, orderBy := range w.OrderBy {
		orderBy := orderBy // G601: Create local copy to avoid memory aliasing
		children = append(children, &orderBy)
	}
	if w.FrameClause != nil {
		children = append(children, w.FrameClause)
	}
	return children
}

// WindowFrame represents window frame clause
type WindowFrame struct {
	Type  string // ROWS, RANGE
	Start WindowFrameBound
	End   *WindowFrameBound
}

func (w *WindowFrame) statementNode()      {}
func (w WindowFrame) TokenLiteral() string { return w.Type }
func (w WindowFrame) Children() []Node     { return nil }

// WindowFrameBound represents window frame bound
type WindowFrameBound struct {
	Type  string // CURRENT ROW, UNBOUNDED PRECEDING, etc.
	Value Expression
}

func (w *WindowFrameBound) expressionNode() {}
func (w WindowFrameBound) TokenLiteral() string {
	if w.Type != "" {
		return w.Type
	}
	return "BOUND"
}
func (w WindowFrameBound) Children() []Node {
	if w.Value != nil {
		return []Node{w.Value}
	}
	return nil
}

// SelectStatement represents a SELECT SQL statement with full SQL-99/SQL:2003 support.
//
// SelectStatement is the primary query statement type supporting:
//   - CTEs (WITH clause)
//   - DISTINCT and DISTINCT ON (PostgreSQL)
//   - Multiple FROM tables and subqueries
//   - All JOIN types with LATERAL support
//   - WHERE, GROUP BY, HAVING, ORDER BY clauses
//   - Window functions with PARTITION BY and frame specifications
//   - LIMIT/OFFSET and SQL-99 FETCH clause
//
// Fields:
//   - With: WITH clause for Common Table Expressions (CTEs)
//   - Distinct: DISTINCT keyword for duplicate elimination
//   - DistinctOnColumns: DISTINCT ON (expr, ...) for PostgreSQL (v1.6.0)
//   - Columns: SELECT list expressions (columns, *, functions, etc.)
//   - From: FROM clause table references (tables, subqueries, LATERAL)
//   - TableName: Table name for simple queries (pool optimization)
//   - Joins: JOIN clauses (INNER, LEFT, RIGHT, FULL, CROSS, NATURAL)
//   - Where: WHERE clause filter condition
//   - GroupBy: GROUP BY expressions (including ROLLUP, CUBE, GROUPING SETS)
//   - Having: HAVING clause filter condition
//   - Windows: Window specifications (WINDOW clause)
//   - OrderBy: ORDER BY expressions with NULLS FIRST/LAST
//   - Limit: LIMIT clause (number of rows)
//   - Offset: OFFSET clause (skip rows)
//   - Fetch: SQL-99 FETCH FIRST/NEXT clause (v1.6.0)
//
// Example - Basic SELECT:
//
//	SelectStatement{
//	    Columns: []Expression{&Identifier{Name: "id"}, &Identifier{Name: "name"}},
//	    From:    []TableReference{{Name: "users"}},
//	    Where:   &BinaryExpression{...},
//	}
//	// SQL: SELECT id, name FROM users WHERE ...
//
// Example - DISTINCT ON (PostgreSQL v1.6.0):
//
//	SelectStatement{
//	    DistinctOnColumns: []Expression{&Identifier{Name: "dept_id"}},
//	    Columns:           []Expression{&Identifier{Name: "dept_id"}, &Identifier{Name: "name"}},
//	    From:              []TableReference{{Name: "employees"}},
//	}
//	// SQL: SELECT DISTINCT ON (dept_id) dept_id, name FROM employees
//
// Example - Window function with FETCH (v1.6.0):
//
//	SelectStatement{
//	    Columns: []Expression{
//	        &FunctionCall{
//	            Name: "ROW_NUMBER",
//	            Over: &WindowSpec{
//	                OrderBy: []OrderByExpression{{Expression: &Identifier{Name: "salary"}, Ascending: false}},
//	            },
//	        },
//	    },
//	    From:  []TableReference{{Name: "employees"}},
//	    Fetch: &FetchClause{FetchValue: ptrInt64(10), FetchType: "FIRST"},
//	}
//	// SQL: SELECT ROW_NUMBER() OVER (ORDER BY salary DESC) FROM employees FETCH FIRST 10 ROWS ONLY
//
// New in v1.6.0:
//   - DistinctOnColumns for PostgreSQL DISTINCT ON
//   - Fetch for SQL-99 FETCH FIRST/NEXT clause
//   - Enhanced LATERAL JOIN support via TableReference.Lateral
//   - FILTER clause support via FunctionCall.Filter
type SelectStatement struct {
	With              *WithClause
	Distinct          bool
	DistinctOnColumns []Expression // PostgreSQL DISTINCT ON (expr, ...) clause
	Columns           []Expression
	From              []TableReference
	TableName         string // Added for pool operations
	Joins             []JoinClause
	Where             Expression
	GroupBy           []Expression
	Having            Expression
	Windows           []WindowSpec
	OrderBy           []OrderByExpression
	Limit             *int
	Offset            *int
	Fetch             *FetchClause // SQL-99 FETCH FIRST/NEXT clause (F861, F862)
	For               *ForClause   // Row-level locking clause (SQL:2003, PostgreSQL, MySQL)
}

// FetchClause represents the SQL-99 FETCH FIRST/NEXT clause (F861, F862)
// Syntax: [OFFSET n {ROW | ROWS}] FETCH {FIRST | NEXT} n [{ROW | ROWS}] {ONLY | WITH TIES}
// Examples:
//   - OFFSET 20 ROWS FETCH NEXT 10 ROWS ONLY
//   - FETCH FIRST 5 ROWS ONLY
//   - FETCH FIRST 10 PERCENT ROWS WITH TIES
type FetchClause struct {
	// OffsetValue is the number of rows to skip (OFFSET n ROWS)
	OffsetValue *int64
	// FetchValue is the number of rows to fetch (FETCH n ROWS)
	FetchValue *int64
	// FetchType is either "FIRST" or "NEXT"
	FetchType string
	// IsPercent indicates FETCH ... PERCENT ROWS
	IsPercent bool
	// WithTies indicates FETCH ... WITH TIES (includes tied rows)
	WithTies bool
}

func (f *FetchClause) expressionNode()     {}
func (f FetchClause) TokenLiteral() string { return "FETCH" }
func (f FetchClause) Children() []Node     { return nil }

// ForClause represents row-level locking clauses in SELECT statements (SQL:2003, PostgreSQL, MySQL)
// Syntax: FOR {UPDATE | SHARE | NO KEY UPDATE | KEY SHARE} [OF table_name [, ...]] [NOWAIT | SKIP LOCKED]
// Examples:
//   - FOR UPDATE
//   - FOR SHARE NOWAIT
//   - FOR UPDATE OF orders SKIP LOCKED
//   - FOR NO KEY UPDATE
//   - FOR KEY SHARE
type ForClause struct {
	// LockType specifies the type of lock:
	// "UPDATE" - exclusive lock for UPDATE operations
	// "SHARE" - shared lock for read operations
	// "NO KEY UPDATE" - PostgreSQL: exclusive lock that doesn't block SHARE locks on same row
	// "KEY SHARE" - PostgreSQL: shared lock that doesn't block UPDATE locks
	LockType string
	// Tables specifies which tables to lock (FOR UPDATE OF table_name)
	// Empty slice means lock all tables in the query
	Tables []string
	// NoWait indicates NOWAIT option (fail immediately if lock cannot be acquired)
	NoWait bool
	// SkipLocked indicates SKIP LOCKED option (skip rows that can't be locked)
	SkipLocked bool
}

func (f *ForClause) expressionNode()     {}
func (f ForClause) TokenLiteral() string { return "FOR" }
func (f ForClause) Children() []Node     { return nil }

func (s *SelectStatement) statementNode()      {}
func (s SelectStatement) TokenLiteral() string { return "SELECT" }

func (s SelectStatement) Children() []Node {
	children := make([]Node, 0)
	if s.With != nil {
		children = append(children, s.With)
	}
	children = append(children, nodifyExpressions(s.DistinctOnColumns)...)
	children = append(children, nodifyExpressions(s.Columns)...)
	for _, from := range s.From {
		from := from // G601: Create local copy to avoid memory aliasing
		children = append(children, &from)
	}
	for _, join := range s.Joins {
		join := join // G601: Create local copy to avoid memory aliasing
		children = append(children, &join)
	}
	if s.Where != nil {
		children = append(children, s.Where)
	}
	children = append(children, nodifyExpressions(s.GroupBy)...)
	if s.Having != nil {
		children = append(children, s.Having)
	}
	for _, window := range s.Windows {
		window := window // G601: Create local copy to avoid memory aliasing
		children = append(children, &window)
	}
	for _, orderBy := range s.OrderBy {
		orderBy := orderBy // G601: Create local copy to avoid memory aliasing
		children = append(children, &orderBy)
	}
	if s.Fetch != nil {
		children = append(children, s.Fetch)
	}
	if s.For != nil {
		children = append(children, s.For)
	}
	return children
}

// Helper function to convert []Expression to []Node
func nodifyExpressions(exprs []Expression) []Node {
	nodes := make([]Node, len(exprs))
	for i, expr := range exprs {
		nodes[i] = expr
	}
	return nodes
}

// RollupExpression represents ROLLUP(col1, col2, ...) in GROUP BY clause
// ROLLUP generates hierarchical grouping sets from right to left
// Example: ROLLUP(a, b, c) generates grouping sets:
//
//	(a, b, c), (a, b), (a), ()
type RollupExpression struct {
	Expressions []Expression
}

func (r *RollupExpression) expressionNode()     {}
func (r RollupExpression) TokenLiteral() string { return "ROLLUP" }
func (r RollupExpression) Children() []Node     { return nodifyExpressions(r.Expressions) }

// CubeExpression represents CUBE(col1, col2, ...) in GROUP BY clause
// CUBE generates all possible combinations of grouping sets
// Example: CUBE(a, b) generates grouping sets:
//
//	(a, b), (a), (b), ()
type CubeExpression struct {
	Expressions []Expression
}

func (c *CubeExpression) expressionNode()     {}
func (c CubeExpression) TokenLiteral() string { return "CUBE" }
func (c CubeExpression) Children() []Node     { return nodifyExpressions(c.Expressions) }

// GroupingSetsExpression represents GROUPING SETS(...) in GROUP BY clause
// Allows explicit specification of grouping sets
// Example: GROUPING SETS((a, b), (a), ())
type GroupingSetsExpression struct {
	Sets [][]Expression // Each inner slice is one grouping set
}

func (g *GroupingSetsExpression) expressionNode()     {}
func (g GroupingSetsExpression) TokenLiteral() string { return "GROUPING SETS" }
func (g GroupingSetsExpression) Children() []Node {
	children := make([]Node, 0)
	for _, set := range g.Sets {
		children = append(children, nodifyExpressions(set)...)
	}
	return children
}

// Identifier represents a column or table name
type Identifier struct {
	Name  string
	Table string // Optional table qualifier
}

func (i *Identifier) expressionNode()     {}
func (i Identifier) TokenLiteral() string { return i.Name }
func (i Identifier) Children() []Node     { return nil }

// FunctionCall represents a function call expression with full SQL-99/PostgreSQL support.
//
// FunctionCall supports:
//   - Scalar functions: UPPER(), LOWER(), COALESCE(), etc.
//   - Aggregate functions: COUNT(), SUM(), AVG(), MAX(), MIN(), etc.
//   - Window functions: ROW_NUMBER(), RANK(), DENSE_RANK(), LAG(), LEAD(), etc.
//   - DISTINCT modifier: COUNT(DISTINCT column)
//   - FILTER clause: Conditional aggregation (PostgreSQL v1.6.0)
//   - ORDER BY clause: For order-sensitive aggregates like STRING_AGG, ARRAY_AGG (v1.6.0)
//   - OVER clause: Window specifications for window functions
//
// Fields:
//   - Name: Function name (e.g., "COUNT", "SUM", "ROW_NUMBER")
//   - Arguments: Function arguments (expressions)
//   - Over: Window specification for window functions (OVER clause)
//   - Distinct: DISTINCT modifier for aggregates (COUNT(DISTINCT col))
//   - Filter: FILTER clause for conditional aggregation (PostgreSQL v1.6.0)
//   - OrderBy: ORDER BY clause for order-sensitive aggregates (v1.6.0)
//
// Example - Basic aggregate:
//
//	FunctionCall{
//	    Name:      "COUNT",
//	    Arguments: []Expression{&Identifier{Name: "id"}},
//	}
//	// SQL: COUNT(id)
//
// Example - Window function:
//
//	FunctionCall{
//	    Name: "ROW_NUMBER",
//	    Over: &WindowSpec{
//	        PartitionBy: []Expression{&Identifier{Name: "dept_id"}},
//	        OrderBy:     []OrderByExpression{{Expression: &Identifier{Name: "salary"}, Ascending: false}},
//	    },
//	}
//	// SQL: ROW_NUMBER() OVER (PARTITION BY dept_id ORDER BY salary DESC)
//
// Example - FILTER clause (PostgreSQL v1.6.0):
//
//	FunctionCall{
//	    Name:      "COUNT",
//	    Arguments: []Expression{&Identifier{Name: "id"}},
//	    Filter:    &BinaryExpression{Left: &Identifier{Name: "status"}, Operator: "=", Right: &LiteralValue{Value: "active"}},
//	}
//	// SQL: COUNT(id) FILTER (WHERE status = 'active')
//
// Example - ORDER BY in aggregate (PostgreSQL v1.6.0):
//
//	FunctionCall{
//	    Name:      "STRING_AGG",
//	    Arguments: []Expression{&Identifier{Name: "name"}, &LiteralValue{Value: ", "}},
//	    OrderBy:   []OrderByExpression{{Expression: &Identifier{Name: "name"}, Ascending: true}},
//	}
//	// SQL: STRING_AGG(name, ', ' ORDER BY name)
//
// Example - Window function with frame:
//
//	FunctionCall{
//	    Name:      "AVG",
//	    Arguments: []Expression{&Identifier{Name: "amount"}},
//	    Over: &WindowSpec{
//	        OrderBy: []OrderByExpression{{Expression: &Identifier{Name: "date"}, Ascending: true}},
//	        FrameClause: &WindowFrame{
//	            Type:  "ROWS",
//	            Start: WindowFrameBound{Type: "2 PRECEDING"},
//	            End:   &WindowFrameBound{Type: "CURRENT ROW"},
//	        },
//	    },
//	}
//	// SQL: AVG(amount) OVER (ORDER BY date ROWS BETWEEN 2 PRECEDING AND CURRENT ROW)
//
// New in v1.6.0:
//   - Filter: FILTER clause for conditional aggregation
//   - OrderBy: ORDER BY clause for order-sensitive aggregates (STRING_AGG, ARRAY_AGG, etc.)
//   - WithinGroup: ORDER BY clause for ordered-set aggregates (PERCENTILE_CONT, PERCENTILE_DISC, MODE, etc.)
type FunctionCall struct {
	Name        string
	Arguments   []Expression // Renamed from Args for consistency
	Over        *WindowSpec  // For window functions
	Distinct    bool
	Filter      Expression          // WHERE clause for aggregate functions
	OrderBy     []OrderByExpression // ORDER BY clause for aggregate functions (STRING_AGG, ARRAY_AGG, etc.)
	WithinGroup []OrderByExpression // ORDER BY clause for ordered-set aggregates (PERCENTILE_CONT, etc.)
}

func (f *FunctionCall) expressionNode()     {}
func (f FunctionCall) TokenLiteral() string { return f.Name }
func (f FunctionCall) Children() []Node {
	children := nodifyExpressions(f.Arguments)
	if f.Over != nil {
		children = append(children, f.Over)
	}
	if f.Filter != nil {
		children = append(children, f.Filter)
	}
	for _, orderBy := range f.OrderBy {
		orderBy := orderBy // G601: Create local copy to avoid memory aliasing
		children = append(children, &orderBy)
	}
	for _, orderBy := range f.WithinGroup {
		orderBy := orderBy // G601: Create local copy to avoid memory aliasing
		children = append(children, &orderBy)
	}
	return children
}

// CaseExpression represents a CASE expression
type CaseExpression struct {
	Value       Expression // Optional CASE value
	WhenClauses []WhenClause
	ElseClause  Expression
}

func (c *CaseExpression) expressionNode()     {}
func (c CaseExpression) TokenLiteral() string { return "CASE" }
func (c CaseExpression) Children() []Node {
	children := make([]Node, 0)
	if c.Value != nil {
		children = append(children, c.Value)
	}
	for _, when := range c.WhenClauses {
		when := when // G601: Create local copy to avoid memory aliasing
		children = append(children, &when)
	}
	if c.ElseClause != nil {
		children = append(children, c.ElseClause)
	}
	return children
}

// WhenClause represents WHEN ... THEN ... in CASE expression
type WhenClause struct {
	Condition Expression
	Result    Expression
}

func (w *WhenClause) expressionNode()     {}
func (w WhenClause) TokenLiteral() string { return "WHEN" }
func (w WhenClause) Children() []Node {
	return []Node{w.Condition, w.Result}
}

// ExistsExpression represents EXISTS (subquery)
type ExistsExpression struct {
	Subquery Statement
}

func (e *ExistsExpression) expressionNode()     {}
func (e ExistsExpression) TokenLiteral() string { return "EXISTS" }
func (e ExistsExpression) Children() []Node {
	return []Node{e.Subquery}
}

// InExpression represents expr IN (values) or expr IN (subquery)
type InExpression struct {
	Expr     Expression
	List     []Expression // For value list: IN (1, 2, 3)
	Subquery Statement    // For subquery: IN (SELECT ...)
	Not      bool
}

func (i *InExpression) expressionNode()     {}
func (i InExpression) TokenLiteral() string { return "IN" }
func (i InExpression) Children() []Node {
	children := []Node{i.Expr}
	if i.Subquery != nil {
		children = append(children, i.Subquery)
	} else {
		children = append(children, nodifyExpressions(i.List)...)
	}
	return children
}

// SubqueryExpression represents a scalar subquery (SELECT ...)
type SubqueryExpression struct {
	Subquery Statement
}

func (s *SubqueryExpression) expressionNode()     {}
func (s SubqueryExpression) TokenLiteral() string { return "SUBQUERY" }
func (s SubqueryExpression) Children() []Node     { return []Node{s.Subquery} }

// AnyExpression represents expr op ANY (subquery)
type AnyExpression struct {
	Expr     Expression
	Operator string
	Subquery Statement
}

func (a *AnyExpression) expressionNode()     {}
func (a AnyExpression) TokenLiteral() string { return "ANY" }
func (a AnyExpression) Children() []Node     { return []Node{a.Expr, a.Subquery} }

// AllExpression represents expr op ALL (subquery)
type AllExpression struct {
	Expr     Expression
	Operator string
	Subquery Statement
}

func (al *AllExpression) expressionNode()     {}
func (al AllExpression) TokenLiteral() string { return "ALL" }
func (al AllExpression) Children() []Node     { return []Node{al.Expr, al.Subquery} }

// BetweenExpression represents expr BETWEEN lower AND upper
type BetweenExpression struct {
	Expr  Expression
	Lower Expression
	Upper Expression
	Not   bool
}

func (b *BetweenExpression) expressionNode()     {}
func (b BetweenExpression) TokenLiteral() string { return "BETWEEN" }
func (b BetweenExpression) Children() []Node {
	return []Node{b.Expr, b.Lower, b.Upper}
}

// BinaryExpression represents binary operations between two expressions.
//
// BinaryExpression supports all standard SQL binary operators plus PostgreSQL-specific
// operators including JSON/JSONB operators added in v1.6.0.
//
// Fields:
//   - Left: Left-hand side expression
//   - Operator: Binary operator (=, <, >, +, -, *, /, AND, OR, ->, #>, etc.)
//   - Right: Right-hand side expression
//   - Not: NOT modifier for negation (NOT expr)
//   - CustomOp: PostgreSQL custom operators (OPERATOR(schema.name))
//
// Supported Operator Categories:
//   - Comparison: =, <>, <, >, <=, >=, <=> (spaceship)
//   - Arithmetic: +, -, *, /, %, DIV, // (integer division)
//   - Logical: AND, OR, XOR
//   - String: || (concatenation)
//   - Bitwise: &, |, ^, <<, >> (shifts)
//   - Pattern: LIKE, ILIKE, SIMILAR TO
//   - Range: OVERLAPS
//   - PostgreSQL JSON/JSONB (v1.6.0): ->, ->>, #>, #>>, @>, <@, ?, ?|, ?&, #-
//
// Example - Basic comparison:
//
//	BinaryExpression{
//	    Left:     &Identifier{Name: "age"},
//	    Operator: ">",
//	    Right:    &LiteralValue{Value: 18, Type: "INTEGER"},
//	}
//	// SQL: age > 18
//
// Example - Logical AND:
//
//	BinaryExpression{
//	    Left: &BinaryExpression{
//	        Left:     &Identifier{Name: "active"},
//	        Operator: "=",
//	        Right:    &LiteralValue{Value: true, Type: "BOOLEAN"},
//	    },
//	    Operator: "AND",
//	    Right: &BinaryExpression{
//	        Left:     &Identifier{Name: "status"},
//	        Operator: "=",
//	        Right:    &LiteralValue{Value: "pending", Type: "STRING"},
//	    },
//	}
//	// SQL: active = true AND status = 'pending'
//
// Example - PostgreSQL JSON operator -> (v1.6.0):
//
//	BinaryExpression{
//	    Left:     &Identifier{Name: "data"},
//	    Operator: "->",
//	    Right:    &LiteralValue{Value: "name", Type: "STRING"},
//	}
//	// SQL: data->'name'
//
// Example - PostgreSQL JSON operator ->> (v1.6.0):
//
//	BinaryExpression{
//	    Left:     &Identifier{Name: "data"},
//	    Operator: "->>",
//	    Right:    &LiteralValue{Value: "email", Type: "STRING"},
//	}
//	// SQL: data->>'email'  (returns text)
//
// Example - PostgreSQL JSON contains @> (v1.6.0):
//
//	BinaryExpression{
//	    Left:     &Identifier{Name: "attributes"},
//	    Operator: "@>",
//	    Right:    &LiteralValue{Value: `{"color": "red"}`, Type: "STRING"},
//	}
//	// SQL: attributes @> '{"color": "red"}'
//
// Example - PostgreSQL JSON key exists ? (v1.6.0):
//
//	BinaryExpression{
//	    Left:     &Identifier{Name: "profile"},
//	    Operator: "?",
//	    Right:    &LiteralValue{Value: "email", Type: "STRING"},
//	}
//	// SQL: profile ? 'email'
//
// Example - Custom PostgreSQL operator:
//
//	BinaryExpression{
//	    Left:     &Identifier{Name: "point1"},
//	    Operator: "",
//	    Right:    &Identifier{Name: "point2"},
//	    CustomOp: &CustomBinaryOperator{Parts: []string{"pg_catalog", "<->"}},
//	}
//	// SQL: point1 OPERATOR(pg_catalog.<->) point2
//
// New in v1.6.0:
//   - JSON/JSONB operators: ->, ->>, #>, #>>, @>, <@, ?, ?|, ?&, #-
//   - CustomOp field for PostgreSQL custom operators
//
// PostgreSQL JSON/JSONB Operator Reference:
//   - -> (Arrow): Extract JSON field or array element (returns JSON)
//   - ->> (LongArrow): Extract JSON field or array element as text
//   - #> (HashArrow): Extract JSON at path (returns JSON)
//   - #>> (HashLongArrow): Extract JSON at path as text
//   - @> (AtArrow): JSON contains (does left JSON contain right?)
//   - <@ (ArrowAt): JSON is contained by (is left JSON contained in right?)
//   - ? (Question): JSON key exists
//   - ?| (QuestionPipe): Any of the keys exist
//   - ?& (QuestionAnd): All of the keys exist
//   - #- (HashMinus): Delete key from JSON
type BinaryExpression struct {
	Left     Expression
	Operator string
	Right    Expression
	Not      bool                  // For NOT (expr)
	CustomOp *CustomBinaryOperator // For PostgreSQL custom operators
}

func (b *BinaryExpression) expressionNode() {}

func (b *BinaryExpression) TokenLiteral() string {
	if b.CustomOp != nil {
		return b.CustomOp.String()
	}
	return b.Operator
}

func (b BinaryExpression) Children() []Node { return []Node{b.Left, b.Right} }

// LiteralValue represents a literal value in SQL
type LiteralValue struct {
	Value interface{}
	Type  string // INTEGER, FLOAT, STRING, BOOLEAN, NULL, etc.
}

func (l *LiteralValue) expressionNode()     {}
func (l LiteralValue) TokenLiteral() string { return fmt.Sprintf("%v", l.Value) }
func (l LiteralValue) Children() []Node     { return nil }

// ListExpression represents a list of expressions (1, 2, 3)
type ListExpression struct {
	Values []Expression
}

func (l *ListExpression) expressionNode()     {}
func (l ListExpression) TokenLiteral() string { return "LIST" }
func (l ListExpression) Children() []Node     { return nodifyExpressions(l.Values) }

// TupleExpression represents a row constructor / tuple (col1, col2) for multi-column comparisons
// Used in: WHERE (user_id, status) IN ((1, 'active'), (2, 'pending'))
type TupleExpression struct {
	Expressions []Expression
}

func (t *TupleExpression) expressionNode()     {}
func (t TupleExpression) TokenLiteral() string { return "TUPLE" }
func (t TupleExpression) Children() []Node     { return nodifyExpressions(t.Expressions) }

// ArrayConstructorExpression represents PostgreSQL ARRAY constructor syntax.
// Creates an array value from a list of expressions or a subquery.
//
// Examples:
//
//	ARRAY[1, 2, 3]                    - Integer array literal
//	ARRAY['admin', 'moderator']      - Text array literal
//	ARRAY(SELECT id FROM users)      - Array from subquery
type ArrayConstructorExpression struct {
	Elements []Expression     // Elements inside ARRAY[...]
	Subquery *SelectStatement // For ARRAY(SELECT ...) syntax (optional)
}

func (a *ArrayConstructorExpression) expressionNode()     {}
func (a ArrayConstructorExpression) TokenLiteral() string { return "ARRAY" }
func (a ArrayConstructorExpression) Children() []Node {
	if a.Subquery != nil {
		return []Node{a.Subquery}
	}
	return nodifyExpressions(a.Elements)
}

// UnaryExpression represents operations like NOT expr
type UnaryExpression struct {
	Operator UnaryOperator
	Expr     Expression
}

func (u *UnaryExpression) expressionNode() {}

func (u *UnaryExpression) TokenLiteral() string {
	return u.Operator.String()
}

func (u UnaryExpression) Children() []Node { return []Node{u.Expr} }

// CastExpression represents CAST(expr AS type)
type CastExpression struct {
	Expr Expression
	Type string
}

func (c *CastExpression) expressionNode()     {}
func (c CastExpression) TokenLiteral() string { return "CAST" }
func (c CastExpression) Children() []Node     { return []Node{c.Expr} }

// AliasedExpression represents an expression with an alias (expr AS alias)
type AliasedExpression struct {
	Expr  Expression
	Alias string
}

func (a *AliasedExpression) expressionNode()     {}
func (a AliasedExpression) TokenLiteral() string { return a.Alias }
func (a AliasedExpression) Children() []Node     { return []Node{a.Expr} }

// ExtractExpression represents EXTRACT(field FROM source)
type ExtractExpression struct {
	Field  string
	Source Expression
}

func (e *ExtractExpression) expressionNode()     {}
func (e ExtractExpression) TokenLiteral() string { return "EXTRACT" }
func (e ExtractExpression) Children() []Node     { return []Node{e.Source} }

// PositionExpression represents POSITION(substr IN str)
type PositionExpression struct {
	Substr Expression
	Str    Expression
}

func (p *PositionExpression) expressionNode()     {}
func (p PositionExpression) TokenLiteral() string { return "POSITION" }
func (p PositionExpression) Children() []Node     { return []Node{p.Substr, p.Str} }

// SubstringExpression represents SUBSTRING(str FROM start [FOR length])
type SubstringExpression struct {
	Str    Expression
	Start  Expression
	Length Expression
}

func (s *SubstringExpression) expressionNode()     {}
func (s SubstringExpression) TokenLiteral() string { return "SUBSTRING" }
func (s SubstringExpression) Children() []Node {
	children := []Node{s.Str, s.Start}
	if s.Length != nil {
		children = append(children, s.Length)
	}
	return children
}

// IntervalExpression represents INTERVAL 'value' for date/time arithmetic
// Examples: INTERVAL '1 day', INTERVAL '2 hours', INTERVAL '1 year 2 months'
type IntervalExpression struct {
	Value string // The interval specification string (e.g., '1 day', '2 hours')
}

func (i *IntervalExpression) expressionNode()     {}
func (i IntervalExpression) TokenLiteral() string { return "INTERVAL" }
func (i IntervalExpression) Children() []Node     { return []Node{} }

// InsertStatement represents an INSERT SQL statement
type InsertStatement struct {
	With       *WithClause
	TableName  string
	Columns    []Expression
	Values     [][]Expression   // Multi-row support: each inner slice is one row of values
	Query      *SelectStatement // For INSERT ... SELECT
	Returning  []Expression
	OnConflict *OnConflict
}

func (i *InsertStatement) statementNode()      {}
func (i InsertStatement) TokenLiteral() string { return "INSERT" }

func (i InsertStatement) Children() []Node {
	children := make([]Node, 0)
	if i.With != nil {
		children = append(children, i.With)
	}
	children = append(children, nodifyExpressions(i.Columns)...)
	// Flatten multi-row values for Children()
	for _, row := range i.Values {
		children = append(children, nodifyExpressions(row)...)
	}
	if i.Query != nil {
		children = append(children, i.Query)
	}
	children = append(children, nodifyExpressions(i.Returning)...)
	if i.OnConflict != nil {
		children = append(children, i.OnConflict)
	}
	return children
}

// OnConflict represents ON CONFLICT DO UPDATE/NOTHING clause
type OnConflict struct {
	Target     []Expression // Target columns
	Constraint string       // Optional constraint name
	Action     OnConflictAction
}

func (o *OnConflict) expressionNode()     {}
func (o OnConflict) TokenLiteral() string { return "ON CONFLICT" }
func (o OnConflict) Children() []Node {
	children := nodifyExpressions(o.Target)
	if o.Action.DoUpdate != nil {
		for _, update := range o.Action.DoUpdate {
			update := update // G601: Create local copy to avoid memory aliasing
			children = append(children, &update)
		}
	}
	return children
}

// OnConflictAction represents DO UPDATE/NOTHING in ON CONFLICT clause
type OnConflictAction struct {
	DoNothing bool
	DoUpdate  []UpdateExpression
	Where     Expression
}

// UpsertClause represents INSERT ... ON DUPLICATE KEY UPDATE
type UpsertClause struct {
	Updates []UpdateExpression
}

func (u *UpsertClause) expressionNode()     {}
func (u UpsertClause) TokenLiteral() string { return "ON DUPLICATE KEY UPDATE" }
func (u UpsertClause) Children() []Node {
	children := make([]Node, len(u.Updates))
	for i, update := range u.Updates {
		update := update // G601: Create local copy to avoid memory aliasing
		children[i] = &update
	}
	return children
}

// Values represents VALUES clause
type Values struct {
	Rows [][]Expression
}

func (v *Values) statementNode()      {}
func (v Values) TokenLiteral() string { return "VALUES" }
func (v Values) Children() []Node {
	children := make([]Node, 0)
	for _, row := range v.Rows {
		children = append(children, nodifyExpressions(row)...)
	}
	return children
}

// UpdateStatement represents an UPDATE SQL statement
type UpdateStatement struct {
	With        *WithClause
	TableName   string
	Alias       string
	Updates     []UpdateExpression // Keep for backward compatibility
	Assignments []UpdateExpression // New field for consistency with span.go
	From        []TableReference
	Where       Expression
	Returning   []Expression
}

func (u *UpdateStatement) statementNode()      {}
func (u UpdateStatement) TokenLiteral() string { return "UPDATE" }

func (u UpdateStatement) Children() []Node {
	children := make([]Node, 0)
	if u.With != nil {
		children = append(children, u.With)
	}
	for _, update := range u.Updates {
		update := update // G601: Create local copy to avoid memory aliasing
		children = append(children, &update)
	}
	for _, assignment := range u.Assignments {
		assignment := assignment // G601: Create local copy to avoid memory aliasing
		children = append(children, &assignment)
	}
	for _, from := range u.From {
		from := from // G601: Create local copy to avoid memory aliasing
		children = append(children, &from)
	}
	if u.Where != nil {
		children = append(children, u.Where)
	}
	children = append(children, nodifyExpressions(u.Returning)...)
	return children
}

// CreateTableStatement represents a CREATE TABLE statement
type CreateTableStatement struct {
	IfNotExists bool
	Temporary   bool
	Name        string
	Columns     []ColumnDef
	Constraints []TableConstraint
	Inherits    []string
	PartitionBy *PartitionBy
	Partitions  []PartitionDefinition // Individual partition definitions
	Options     []TableOption
}

func (c *CreateTableStatement) statementNode()      {}
func (c CreateTableStatement) TokenLiteral() string { return "CREATE TABLE" }
func (c CreateTableStatement) Children() []Node {
	children := make([]Node, 0)
	for _, col := range c.Columns {
		col := col // G601: Create local copy to avoid memory aliasing
		children = append(children, &col)
	}
	for _, constraint := range c.Constraints {
		constraint := constraint // G601: Create local copy to avoid memory aliasing
		children = append(children, &constraint)
	}
	if c.PartitionBy != nil {
		children = append(children, c.PartitionBy)
	}
	for _, p := range c.Partitions {
		p := p // G601: Create local copy
		children = append(children, &p)
	}
	return children
}

// ColumnDef represents a column definition in CREATE TABLE
type ColumnDef struct {
	Name        string
	Type        string
	Constraints []ColumnConstraint
}

func (c *ColumnDef) expressionNode()     {}
func (c ColumnDef) TokenLiteral() string { return c.Name }
func (c ColumnDef) Children() []Node {
	children := make([]Node, len(c.Constraints))
	for i, constraint := range c.Constraints {
		constraint := constraint // G601: Create local copy to avoid memory aliasing
		children[i] = &constraint
	}
	return children
}

// ColumnConstraint represents a column constraint
type ColumnConstraint struct {
	Type          string // NOT NULL, UNIQUE, PRIMARY KEY, etc.
	Default       Expression
	References    *ReferenceDefinition
	Check         Expression
	AutoIncrement bool
}

func (c *ColumnConstraint) expressionNode()     {}
func (c ColumnConstraint) TokenLiteral() string { return c.Type }
func (c ColumnConstraint) Children() []Node {
	children := make([]Node, 0)
	if c.Default != nil {
		children = append(children, c.Default)
	}
	if c.References != nil {
		children = append(children, c.References)
	}
	if c.Check != nil {
		children = append(children, c.Check)
	}
	return children
}

// TableConstraint represents a table constraint
type TableConstraint struct {
	Name       string
	Type       string // PRIMARY KEY, UNIQUE, FOREIGN KEY, CHECK
	Columns    []string
	References *ReferenceDefinition
	Check      Expression
}

func (t *TableConstraint) expressionNode()     {}
func (t TableConstraint) TokenLiteral() string { return t.Type }
func (t TableConstraint) Children() []Node {
	children := make([]Node, 0)
	if t.References != nil {
		children = append(children, t.References)
	}
	if t.Check != nil {
		children = append(children, t.Check)
	}
	return children
}

// ReferenceDefinition represents a REFERENCES clause
type ReferenceDefinition struct {
	Table    string
	Columns  []string
	OnDelete string
	OnUpdate string
	Match    string
}

func (r *ReferenceDefinition) expressionNode()     {}
func (r ReferenceDefinition) TokenLiteral() string { return "REFERENCES" }
func (r ReferenceDefinition) Children() []Node     { return nil }

// PartitionBy represents a PARTITION BY clause
type PartitionBy struct {
	Type     string // RANGE, LIST, HASH
	Columns  []string
	Boundary []Expression
}

func (p *PartitionBy) expressionNode()     {}
func (p PartitionBy) TokenLiteral() string { return "PARTITION BY" }
func (p PartitionBy) Children() []Node     { return nodifyExpressions(p.Boundary) }

// TableOption represents table options like ENGINE, CHARSET, etc.
type TableOption struct {
	Name  string
	Value string
}

func (t *TableOption) expressionNode()     {}
func (t TableOption) TokenLiteral() string { return t.Name }
func (t TableOption) Children() []Node     { return nil }

// UpdateExpression represents a column=value expression in UPDATE
type UpdateExpression struct {
	Column Expression
	Value  Expression
}

func (u *UpdateExpression) expressionNode()     {}
func (u UpdateExpression) TokenLiteral() string { return "=" }
func (u UpdateExpression) Children() []Node     { return []Node{u.Column, u.Value} }

// DeleteStatement represents a DELETE SQL statement
type DeleteStatement struct {
	With      *WithClause
	TableName string
	Alias     string
	Using     []TableReference
	Where     Expression
	Returning []Expression
}

func (d *DeleteStatement) statementNode()      {}
func (d DeleteStatement) TokenLiteral() string { return "DELETE" }

func (d DeleteStatement) Children() []Node {
	children := make([]Node, 0)
	if d.With != nil {
		children = append(children, d.With)
	}
	for _, using := range d.Using {
		using := using // G601: Create local copy to avoid memory aliasing
		children = append(children, &using)
	}
	if d.Where != nil {
		children = append(children, d.Where)
	}
	children = append(children, nodifyExpressions(d.Returning)...)
	return children
}

// AlterTableStatement represents an ALTER TABLE statement
type AlterTableStatement struct {
	Table   string
	Actions []AlterTableAction
}

func (a *AlterTableStatement) statementNode()      {}
func (a AlterTableStatement) TokenLiteral() string { return "ALTER TABLE" }
func (a AlterTableStatement) Children() []Node {
	children := make([]Node, len(a.Actions))
	for i, action := range a.Actions {
		action := action // G601: Create local copy to avoid memory aliasing
		children[i] = &action
	}
	return children
}

// AlterTableAction represents an action in ALTER TABLE
type AlterTableAction struct {
	Type       string // ADD COLUMN, DROP COLUMN, MODIFY COLUMN, etc.
	ColumnName string
	ColumnDef  *ColumnDef
	Constraint *TableConstraint
}

func (a *AlterTableAction) expressionNode()     {}
func (a AlterTableAction) TokenLiteral() string { return a.Type }
func (a AlterTableAction) Children() []Node {
	children := make([]Node, 0)
	if a.ColumnDef != nil {
		children = append(children, a.ColumnDef)
	}
	if a.Constraint != nil {
		children = append(children, a.Constraint)
	}
	return children
}

// CreateIndexStatement represents a CREATE INDEX statement
type CreateIndexStatement struct {
	Unique      bool
	IfNotExists bool
	Name        string
	Table       string
	Columns     []IndexColumn
	Using       string
	Where       Expression
}

func (c *CreateIndexStatement) statementNode()      {}
func (c CreateIndexStatement) TokenLiteral() string { return "CREATE INDEX" }
func (c CreateIndexStatement) Children() []Node {
	children := make([]Node, 0)
	for _, col := range c.Columns {
		col := col // G601: Create local copy to avoid memory aliasing
		children = append(children, &col)
	}
	if c.Where != nil {
		children = append(children, c.Where)
	}
	return children
}

// IndexColumn represents a column in an index definition
type IndexColumn struct {
	Column    string
	Collate   string
	Direction string // ASC, DESC
	NullsLast bool
}

func (i *IndexColumn) expressionNode()     {}
func (i IndexColumn) TokenLiteral() string { return i.Column }
func (i IndexColumn) Children() []Node     { return nil }

// MergeStatement represents a MERGE statement (SQL:2003 F312)
// Syntax: MERGE INTO target USING source ON condition
//
//	WHEN MATCHED THEN UPDATE/DELETE
//	WHEN NOT MATCHED THEN INSERT
//	WHEN NOT MATCHED BY SOURCE THEN UPDATE/DELETE
type MergeStatement struct {
	TargetTable TableReference     // The table being merged into
	TargetAlias string             // Optional alias for target
	SourceTable TableReference     // The source table or subquery
	SourceAlias string             // Optional alias for source
	OnCondition Expression         // The join/match condition
	WhenClauses []*MergeWhenClause // List of WHEN clauses
}

func (m *MergeStatement) statementNode()      {}
func (m MergeStatement) TokenLiteral() string { return "MERGE" }
func (m MergeStatement) Children() []Node {
	children := []Node{&m.TargetTable, &m.SourceTable}
	if m.OnCondition != nil {
		children = append(children, m.OnCondition)
	}
	for _, when := range m.WhenClauses {
		children = append(children, when)
	}
	return children
}

// MergeWhenClause represents a WHEN clause in a MERGE statement
// Types: MATCHED, NOT_MATCHED, NOT_MATCHED_BY_SOURCE
type MergeWhenClause struct {
	Type      string       // "MATCHED", "NOT_MATCHED", "NOT_MATCHED_BY_SOURCE"
	Condition Expression   // Optional AND condition
	Action    *MergeAction // The action to perform (UPDATE/INSERT/DELETE)
}

func (w *MergeWhenClause) expressionNode()     {}
func (w MergeWhenClause) TokenLiteral() string { return "WHEN " + w.Type }
func (w MergeWhenClause) Children() []Node {
	children := make([]Node, 0)
	if w.Condition != nil {
		children = append(children, w.Condition)
	}
	if w.Action != nil {
		children = append(children, w.Action)
	}
	return children
}

// MergeAction represents the action in a WHEN clause
// ActionType: UPDATE, INSERT, DELETE
type MergeAction struct {
	ActionType    string       // "UPDATE", "INSERT", "DELETE"
	SetClauses    []SetClause  // For UPDATE: SET column = value pairs
	Columns       []string     // For INSERT: column list
	Values        []Expression // For INSERT: value list
	DefaultValues bool         // For INSERT: use DEFAULT VALUES
}

func (a *MergeAction) expressionNode()     {}
func (a MergeAction) TokenLiteral() string { return a.ActionType }
func (a MergeAction) Children() []Node {
	children := make([]Node, 0)
	for _, set := range a.SetClauses {
		set := set // G601: Create local copy
		children = append(children, &set)
	}
	for _, val := range a.Values {
		children = append(children, val)
	}
	return children
}

// SetClause represents a SET clause in UPDATE (also used in MERGE UPDATE)
type SetClause struct {
	Column string
	Value  Expression
}

func (s *SetClause) expressionNode()     {}
func (s SetClause) TokenLiteral() string { return s.Column }
func (s SetClause) Children() []Node {
	if s.Value != nil {
		return []Node{s.Value}
	}
	return nil
}

// CreateViewStatement represents a CREATE VIEW statement
// Syntax: CREATE [OR REPLACE] [TEMP|TEMPORARY] VIEW [IF NOT EXISTS] name [(columns)] AS select
type CreateViewStatement struct {
	OrReplace   bool
	Temporary   bool
	IfNotExists bool
	Name        string
	Columns     []string  // Optional column list
	Query       Statement // The SELECT statement
	WithOption  string    // PostgreSQL: WITH (CHECK OPTION | CASCADED | LOCAL)
}

func (c *CreateViewStatement) statementNode()      {}
func (c CreateViewStatement) TokenLiteral() string { return "CREATE VIEW" }
func (c CreateViewStatement) Children() []Node {
	if c.Query != nil {
		return []Node{c.Query}
	}
	return nil
}

// CreateMaterializedViewStatement represents a CREATE MATERIALIZED VIEW statement
// Syntax: CREATE MATERIALIZED VIEW [IF NOT EXISTS] name [(columns)] AS select [WITH [NO] DATA]
type CreateMaterializedViewStatement struct {
	IfNotExists bool
	Name        string
	Columns     []string  // Optional column list
	Query       Statement // The SELECT statement
	WithData    *bool     // nil = default, true = WITH DATA, false = WITH NO DATA
	Tablespace  string    // Optional tablespace (PostgreSQL)
}

func (c *CreateMaterializedViewStatement) statementNode()      {}
func (c CreateMaterializedViewStatement) TokenLiteral() string { return "CREATE MATERIALIZED VIEW" }
func (c CreateMaterializedViewStatement) Children() []Node {
	if c.Query != nil {
		return []Node{c.Query}
	}
	return nil
}

// RefreshMaterializedViewStatement represents a REFRESH MATERIALIZED VIEW statement
// Syntax: REFRESH MATERIALIZED VIEW [CONCURRENTLY] name [WITH [NO] DATA]
type RefreshMaterializedViewStatement struct {
	Concurrently bool
	Name         string
	WithData     *bool // nil = default, true = WITH DATA, false = WITH NO DATA
}

func (r *RefreshMaterializedViewStatement) statementNode()      {}
func (r RefreshMaterializedViewStatement) TokenLiteral() string { return "REFRESH MATERIALIZED VIEW" }
func (r RefreshMaterializedViewStatement) Children() []Node     { return nil }

// DropStatement represents a DROP statement for tables, views, indexes, etc.
// Syntax: DROP object_type [IF EXISTS] name [CASCADE|RESTRICT]
type DropStatement struct {
	ObjectType  string // TABLE, VIEW, MATERIALIZED VIEW, INDEX, etc.
	IfExists    bool
	Names       []string // Can drop multiple objects
	CascadeType string   // CASCADE, RESTRICT, or empty
}

func (d *DropStatement) statementNode()      {}
func (d DropStatement) TokenLiteral() string { return "DROP " + d.ObjectType }
func (d DropStatement) Children() []Node     { return nil }

// TruncateStatement represents a TRUNCATE TABLE statement
// Syntax: TRUNCATE [TABLE] table_name [, table_name ...] [RESTART IDENTITY | CONTINUE IDENTITY] [CASCADE | RESTRICT]
type TruncateStatement struct {
	Tables           []string // Table names to truncate
	RestartIdentity  bool     // RESTART IDENTITY - reset sequences
	ContinueIdentity bool     // CONTINUE IDENTITY - keep sequences (default)
	CascadeType      string   // CASCADE, RESTRICT, or empty
}

func (t *TruncateStatement) statementNode()      {}
func (t TruncateStatement) TokenLiteral() string { return "TRUNCATE TABLE" }
func (t TruncateStatement) Children() []Node     { return nil }

// PartitionDefinition represents a partition definition in CREATE TABLE
// Syntax: PARTITION name VALUES { LESS THAN (expr) | IN (list) | FROM (expr) TO (expr) }
type PartitionDefinition struct {
	Name       string
	Type       string       // FOR VALUES, IN, LESS THAN
	Values     []Expression // Partition values or bounds
	LessThan   Expression   // For RANGE: LESS THAN (value)
	From       Expression   // For RANGE: FROM (value)
	To         Expression   // For RANGE: TO (value)
	InValues   []Expression // For LIST: IN (values)
	Tablespace string       // Optional tablespace
}

func (p *PartitionDefinition) expressionNode()     {}
func (p PartitionDefinition) TokenLiteral() string { return "PARTITION " + p.Name }
func (p PartitionDefinition) Children() []Node {
	children := make([]Node, 0)
	for _, v := range p.Values {
		children = append(children, v)
	}
	if p.LessThan != nil {
		children = append(children, p.LessThan)
	}
	if p.From != nil {
		children = append(children, p.From)
	}
	if p.To != nil {
		children = append(children, p.To)
	}
	for _, v := range p.InValues {
		children = append(children, v)
	}
	return children
}

// AST represents the root of the Abstract Syntax Tree
type AST struct {
	Statements []Statement
}

func (a AST) TokenLiteral() string { return "" }

func (a AST) Children() []Node {
	children := make([]Node, len(a.Statements))
	for i, stmt := range a.Statements {
		children[i] = stmt
	}
	return children
}
