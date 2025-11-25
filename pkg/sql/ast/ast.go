// Package ast provides Abstract Syntax Tree (AST) node definitions for SQL statements.
// It includes comprehensive support for DDL and DML operations, Common Table Expressions (CTEs),
// set operations, and window functions, with object pooling for performance optimization.
//
// Phase 2 Features (v1.2.0+):
//   - WithClause and CommonTableExpr for CTE support
//   - SetOperation for UNION, EXCEPT, INTERSECT operations
//   - Recursive CTE support with proper AST representation
//   - Integration with all statement types
//
// Phase 2.5 Features (v1.3.0+):
//   - WindowSpec for window function specifications
//   - WindowFrame and WindowFrameBound for frame clauses
//   - Enhanced FunctionCall with Over field for window functions
//   - Complete window function AST integration
package ast

import "fmt"

// Node represents any node in the AST
type Node interface {
	TokenLiteral() string
	Children() []Node
}

// Statement represents a SQL statement
type Statement interface {
	Node
	statementNode()
}

// Expression represents a SQL expression
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
type CommonTableExpr struct {
	Name         string
	Columns      []string
	Statement    Statement
	Materialized *bool // TODO: Add MATERIALIZED/NOT MATERIALIZED parsing support
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

// TableReference represents a table in FROM clause
type TableReference struct {
	Name  string
	Alias string
}

func (t *TableReference) statementNode()      {}
func (t TableReference) TokenLiteral() string { return t.Name }
func (t TableReference) Children() []Node     { return nil }

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

// SelectStatement represents a SELECT SQL statement
type SelectStatement struct {
	With      *WithClause
	Distinct  bool
	Columns   []Expression
	From      []TableReference
	TableName string // Added for pool operations
	Joins     []JoinClause
	Where     Expression
	GroupBy   []Expression
	Having    Expression
	Windows   []WindowSpec
	OrderBy   []OrderByExpression
	Limit     *int
	Offset    *int
}

func (s *SelectStatement) statementNode()      {}
func (s SelectStatement) TokenLiteral() string { return "SELECT" }

func (s SelectStatement) Children() []Node {
	children := make([]Node, 0)
	if s.With != nil {
		children = append(children, s.With)
	}
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

// FunctionCall represents a function call expression
type FunctionCall struct {
	Name      string
	Arguments []Expression // Renamed from Args for consistency
	Over      *WindowSpec  // For window functions
	Distinct  bool
	Filter    Expression // WHERE clause for aggregate functions
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

// BinaryExpression represents operations like WHERE column = value
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

// InsertStatement represents an INSERT SQL statement
type InsertStatement struct {
	With       *WithClause
	TableName  string
	Columns    []Expression
	Values     []Expression
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
	children = append(children, nodifyExpressions(i.Values)...)
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
