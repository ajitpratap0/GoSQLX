// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ast

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// WithClause represents a WITH clause in a SQL statement.
// It supports both simple and recursive Common Table Expressions (CTEs).
// Phase 2 Complete: Full parser integration with all statement types.
type WithClause struct {
	Recursive bool
	CTEs      []*CommonTableExpr
	Pos       models.Location // Source position of the WITH keyword (1-based line and column)
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
	ScalarExpr   Expression      // ClickHouse: WITH <expr> AS <name> (scalar CTE, no subquery)
	Materialized *bool           // nil = default, true = MATERIALIZED, false = NOT MATERIALIZED
	Pos          models.Location // Source position of the CTE name (1-based line and column)
}

func (c *CommonTableExpr) statementNode()      {}
func (c CommonTableExpr) TokenLiteral() string { return c.Name }
func (c CommonTableExpr) Children() []Node {
	var nodes []Node
	if c.Statement != nil {
		nodes = append(nodes, c.Statement)
	}
	if c.ScalarExpr != nil {
		nodes = append(nodes, c.ScalarExpr)
	}
	return nodes
}

// JoinClause represents a JOIN clause in SQL
type JoinClause struct {
	Type      string // INNER, LEFT, RIGHT, FULL
	Left      TableReference
	Right     TableReference
	Condition Expression
	Pos       models.Location // Source position of the JOIN keyword (1-based line and column)
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
	Name       string           // Table name (empty if this is a derived table)
	Alias      string           // Optional alias
	Subquery   *SelectStatement // For derived tables: (SELECT ...) AS alias
	Lateral    bool             // LATERAL keyword for correlated subqueries (PostgreSQL)
	TableHints []string         // SQL Server table hints: WITH (NOLOCK), WITH (ROWLOCK, UPDLOCK), etc.
	Final      bool             // ClickHouse FINAL modifier: forces MergeTree part merge
	// TableFunc is a function-call table reference such as
	// Snowflake LATERAL FLATTEN(input => col), TABLE(my_func(1,2)),
	// IDENTIFIER('t'), or PostgreSQL unnest(array_col). When set, Name
	// holds the function name and TableFunc carries the call itself.
	TableFunc *FunctionCall
	// TimeTravel is the Snowflake time-travel clause applied to this table
	// reference: AT / BEFORE (TIMESTAMP|OFFSET|STATEMENT => expr) or
	// CHANGES (INFORMATION => DEFAULT|APPEND_ONLY).
	TimeTravel *TimeTravelClause
	// ForSystemTime is the MariaDB temporal table clause (10.3.4+).
	// Example: SELECT * FROM t FOR SYSTEM_TIME AS OF '2024-01-01'
	ForSystemTime *ForSystemTimeClause // MariaDB temporal query
	// Pivot is the SQL Server / Oracle PIVOT clause for row-to-column transformation.
	// Example: SELECT * FROM t PIVOT (SUM(sales) FOR region IN ([North], [South])) AS pvt
	Pivot *PivotClause
	// Unpivot is the SQL Server / Oracle UNPIVOT clause for column-to-row transformation.
	// Example: SELECT * FROM t UNPIVOT (sales FOR region IN (north_sales, south_sales)) AS unpvt
	Unpivot *UnpivotClause
	// MatchRecognize is the SQL:2016 row-pattern recognition clause (Snowflake, Oracle).
	MatchRecognize *MatchRecognizeClause
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
	var nodes []Node
	if t.Subquery != nil {
		nodes = append(nodes, t.Subquery)
	}
	if t.TableFunc != nil {
		nodes = append(nodes, t.TableFunc)
	}
	if t.TimeTravel != nil {
		nodes = append(nodes, t.TimeTravel)
	}
	if t.Pivot != nil {
		nodes = append(nodes, t.Pivot)
	}
	if t.Unpivot != nil {
		nodes = append(nodes, t.Unpivot)
	}
	if t.MatchRecognize != nil {
		nodes = append(nodes, t.MatchRecognize)
	}
	return nodes
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
func (w WindowFrame) Children() []Node {
	// Start is a value type, always include it to support visitor traversal.
	children := []Node{&w.Start}
	if w.End != nil {
		children = append(children, w.End)
	}
	return children
}

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

// TopClause represents SQL Server's TOP N [PERCENT] clause
// Syntax: SELECT TOP n [PERCENT] columns...
// Count is an Expression to support TOP (10), TOP (@var), TOP (subquery)
type TopClause struct {
	Count     Expression // Number of rows (or percentage) as an expression
	IsPercent bool       // Whether PERCENT keyword was specified
	WithTies  bool       // Whether WITH TIES was specified (SQL Server)
}

func (t *TopClause) expressionNode()     {}
func (t TopClause) TokenLiteral() string { return "TOP" }
func (t TopClause) Children() []Node {
	if t.Count != nil {
		return []Node{t.Count}
	}
	return nil
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
	if o.Action.Where != nil {
		children = append(children, o.Action.Where)
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

// ── MariaDB Temporal Table Types (10.3.4+) ────────────────────────────────

// SystemTimeClauseType identifies the kind of FOR SYSTEM_TIME clause.
type SystemTimeClauseType int

const (
	SystemTimeAsOf    SystemTimeClauseType = iota // FOR SYSTEM_TIME AS OF <point>
	SystemTimeBetween                             // FOR SYSTEM_TIME BETWEEN <start> AND <end>
	SystemTimeFromTo                              // FOR SYSTEM_TIME FROM <start> TO <end>
	SystemTimeAll                                 // FOR SYSTEM_TIME ALL
)

// ForSystemTimeClause represents a temporal query on a system-versioned table.
//
//	SELECT * FROM t FOR SYSTEM_TIME AS OF TIMESTAMP '2024-01-01';
//	SELECT * FROM t FOR SYSTEM_TIME BETWEEN '2020-01-01' AND '2024-01-01';
//	SELECT * FROM t FOR SYSTEM_TIME ALL;
type ForSystemTimeClause struct {
	Type  SystemTimeClauseType
	Point Expression      // used for AS OF
	Start Expression      // used for BETWEEN, FROM
	End   Expression      // used for BETWEEN (AND), TO
	Pos   models.Location // Source position of the FOR keyword (1-based line and column)
}

// expressionNode satisfies the Expression interface so ForSystemTimeClause can be
// stored in TableReference.ForSystemTime without a separate interface type.
// Semantically it is a table-level clause, not a scalar expression.
func (c *ForSystemTimeClause) expressionNode()     {}
func (c ForSystemTimeClause) TokenLiteral() string { return "FOR SYSTEM_TIME" }
func (c ForSystemTimeClause) Children() []Node {
	var nodes []Node
	if c.Point != nil {
		nodes = append(nodes, c.Point)
	}
	if c.Start != nil {
		nodes = append(nodes, c.Start)
	}
	if c.End != nil {
		nodes = append(nodes, c.End)
	}
	return nodes
}

// TimeTravelClause represents the Snowflake time-travel / change-tracking
// modifier on a table reference:
//
//	SELECT ... FROM t AT (TIMESTAMP => '2024-01-01'::TIMESTAMP)
//	SELECT ... FROM t BEFORE (STATEMENT => '...uuid...')
//	SELECT ... FROM t CHANGES (INFORMATION => DEFAULT) AT (...)
//
// Kind is one of "AT", "BEFORE", "CHANGES". Named holds the
// `name => expr` arguments keyed by upper-cased name (e.g. TIMESTAMP,
// OFFSET, STATEMENT, INFORMATION). Multiple clauses may chain (CHANGES
// plus AT); extra clauses are appended to Chained.
type TimeTravelClause struct {
	Kind    string // "AT" | "BEFORE" | "CHANGES"
	Named   map[string]Expression
	Chained []*TimeTravelClause
	Pos     models.Location
}

func (c *TimeTravelClause) expressionNode()     {}
func (c TimeTravelClause) TokenLiteral() string { return c.Kind }
func (c TimeTravelClause) Children() []Node {
	var nodes []Node
	for _, v := range c.Named {
		if v != nil {
			nodes = append(nodes, v)
		}
	}
	for _, ch := range c.Chained {
		if ch != nil {
			nodes = append(nodes, ch)
		}
	}
	return nodes
}

// PivotClause represents the SQL Server / Oracle PIVOT operator for row-to-column
// transformation in a FROM clause.
//
//	PIVOT (SUM(sales) FOR region IN ([North], [South], [East], [West])) AS pvt
type PivotClause struct {
	AggregateFunction Expression      // The aggregate function, e.g. SUM(sales)
	PivotColumn       string          // The column used for pivoting, e.g. region
	InValues          []string        // The values to pivot on, e.g. [North], [South]
	Pos               models.Location // Source position of the PIVOT keyword
}

func (p *PivotClause) expressionNode()     {}
func (p PivotClause) TokenLiteral() string { return "PIVOT" }
func (p PivotClause) Children() []Node {
	if p.AggregateFunction != nil {
		return []Node{p.AggregateFunction}
	}
	return nil
}

// UnpivotClause represents the SQL Server / Oracle UNPIVOT operator for column-to-row
// transformation in a FROM clause.
//
//	UNPIVOT (sales FOR region IN (north_sales, south_sales, east_sales)) AS unpvt
type UnpivotClause struct {
	ValueColumn string          // The target value column, e.g. sales
	NameColumn  string          // The target name column, e.g. region
	InColumns   []string        // The source columns to unpivot, e.g. north_sales, south_sales
	Pos         models.Location // Source position of the UNPIVOT keyword
}

func (u *UnpivotClause) expressionNode()     {}
func (u UnpivotClause) TokenLiteral() string { return "UNPIVOT" }
func (u UnpivotClause) Children() []Node     { return nil }

// PeriodDefinition represents a PERIOD FOR clause in CREATE TABLE.
//
//	PERIOD FOR app_time (start_col, end_col)
//	PERIOD FOR SYSTEM_TIME (row_start, row_end)
type PeriodDefinition struct {
	Name     *Identifier // period name (e.g., "app_time") or SYSTEM_TIME
	StartCol *Identifier
	EndCol   *Identifier
	Pos      models.Location // Source position of the PERIOD FOR keyword (1-based line and column)
}

// MatchRecognizeClause represents the SQL:2016 MATCH_RECOGNIZE clause for
// row-pattern recognition in a FROM clause (Snowflake, Oracle, Databricks).
//
//	MATCH_RECOGNIZE (
//	  PARTITION BY symbol
//	  ORDER BY ts
//	  MEASURES MATCH_NUMBER() AS m
//	  ALL ROWS PER MATCH
//	  PATTERN (UP+ DOWN+)
//	  DEFINE UP AS price > PREV(price), DOWN AS price < PREV(price)
//	)
type MatchRecognizeClause struct {
	PartitionBy  []Expression
	OrderBy      []OrderByExpression
	Measures     []MeasureDef
	RowsPerMatch string // "ONE ROW PER MATCH" or "ALL ROWS PER MATCH" (empty = default)
	AfterMatch   string // raw text: "SKIP TO NEXT ROW", "SKIP PAST LAST ROW", etc.
	Pattern      string // raw pattern text: "UP+ DOWN+"
	Definitions  []PatternDef
	Pos          models.Location
}

// MeasureDef is one MEASURES entry: expr AS alias.
type MeasureDef struct {
	Expr  Expression
	Alias string
}

// PatternDef is one DEFINE entry: variable_name AS boolean_condition.
type PatternDef struct {
	Name      string
	Condition Expression
}

func (m *MatchRecognizeClause) expressionNode()     {}
func (m MatchRecognizeClause) TokenLiteral() string { return "MATCH_RECOGNIZE" }
func (m MatchRecognizeClause) Children() []Node {
	var nodes []Node
	nodes = append(nodes, nodifyExpressions(m.PartitionBy)...)
	for _, ob := range m.OrderBy {
		ob := ob
		nodes = append(nodes, &ob)
	}
	for _, md := range m.Measures {
		if md.Expr != nil {
			nodes = append(nodes, md.Expr)
		}
	}
	for _, pd := range m.Definitions {
		if pd.Condition != nil {
			nodes = append(nodes, pd.Condition)
		}
	}
	return nodes
}

// expressionNode satisfies the Expression interface so PeriodDefinition can be
// stored in CreateTableStatement.PeriodDefinitions without a separate interface type.
// Semantically it is a table column constraint, not a scalar expression.
func (p *PeriodDefinition) expressionNode()     {}
func (p PeriodDefinition) TokenLiteral() string { return "PERIOD FOR" }
func (p PeriodDefinition) Children() []Node {
	var nodes []Node
	if p.Name != nil {
		nodes = append(nodes, p.Name)
	}
	if p.StartCol != nil {
		nodes = append(nodes, p.StartCol)
	}
	if p.EndCol != nil {
		nodes = append(nodes, p.EndCol)
	}
	return nodes
}

// ── MariaDB Hierarchical Query / CONNECT BY (10.2+) ───────────────────────

// ConnectByClause represents the CONNECT BY hierarchical query clause (MariaDB 10.2+).
//
//	SELECT id, name FROM t
//	  START WITH parent_id IS NULL
//	  CONNECT BY NOCYCLE PRIOR id = parent_id;
type ConnectByClause struct {
	NoCycle   bool            // NOCYCLE modifier — prevents loops in cyclic graphs
	Condition Expression      // the PRIOR expression (e.g., PRIOR id = parent_id)
	Pos       models.Location // Source position of the CONNECT BY keyword (1-based line and column)
}

// expressionNode satisfies the Expression interface so ConnectByClause can be
// stored in SelectStatement.ConnectBy without a separate interface type.
// Semantically it is a query-level clause, not a scalar expression.
func (c *ConnectByClause) expressionNode()     {}
func (c ConnectByClause) TokenLiteral() string { return "CONNECT BY" }
func (c ConnectByClause) Children() []Node {
	if c.Condition != nil {
		return []Node{c.Condition}
	}
	return nil
}

// SampleClause represents a ClickHouse SAMPLE clause on a SELECT statement.
//
// ClickHouse supports three sampling forms:
//
//	SAMPLE 0.1         — ratio (10% of data)
//	SAMPLE 1000        — approximate row count
//	SAMPLE 1/10        — fraction (1 part out of 10)
//	SAMPLE 1/10 OFFSET 2/10 — fraction with offset
//
// The clause is dialect-specific to ClickHouse (and partly Snowflake/Redshift
// via TABLESAMPLE, but this implementation targets SAMPLE).
// Value is stored as a raw string to preserve the original representation
// (e.g., "0.1", "1000", "1/10").
// ArrayJoinClause represents a ClickHouse ARRAY JOIN or LEFT ARRAY JOIN clause.
// Syntax: [LEFT] ARRAY JOIN expr [AS alias], expr [AS alias], ...
type ArrayJoinClause struct {
	Left     bool               // true for LEFT ARRAY JOIN
	Elements []ArrayJoinElement // One or more join elements
	Pos      models.Location
}

// ArrayJoinElement is a single expression in an ARRAY JOIN clause with an optional alias.
type ArrayJoinElement struct {
	Expr  Expression
	Alias string
}

type SampleClause struct {
	// Value is the sampling size/ratio as a raw token string (e.g., "0.1", "1000", "1/10").
	Value string
	// Denominator is set when the fraction form "N/D" is used (denominator part).
	Denominator string
	// Offset is the optional OFFSET fraction (e.g., "2/10" in SAMPLE 1/10 OFFSET 2/10).
	Offset string
	// OffsetDenominator is set for fractional offsets.
	OffsetDenominator string
	Pos               models.Location
}

func (s *SampleClause) expressionNode()     {}
func (s SampleClause) TokenLiteral() string { return "SAMPLE" }
func (s SampleClause) Children() []Node     { return nil }
