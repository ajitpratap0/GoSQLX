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
	// Search and Cycle are the SQL:1999 SEARCH / CYCLE clauses of a
	// recursive CTE (PostgreSQL 14+, Oracle); nil when absent.
	Search *CTESearchClause
	Cycle  *CTECycleClause
	// NameQuote records the delimiters of Name when they must be kept, and
	// ColumnQuotes those of each Columns entry by index (nil when no
	// column keeps delimiters); see NameQuote.
	NameQuote    NameQuote
	ColumnQuotes []NameQuote
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
	if c.Cycle != nil {
		nodes = append(nodes, c.Cycle)
	}
	return nodes
}

// JoinClause represents a JOIN clause in SQL
//
// Left is a non-owning copy: the parser sets Joins[0].Left to a value copy
// of From[0] (sharing its pointers) and later Lefts to name-only references.
// Release code must not Put through Left; From owns those nodes.
//
// Condition holds the ON expression. A JOIN ... USING (col, ...) clause is
// stored in Using instead, one *Identifier per column, and leaves Condition
// nil. CROSS, NATURAL and APPLY joins have neither.
type JoinClause struct {
	Type      string // INNER, LEFT, RIGHT, FULL
	Left      TableReference
	Right     TableReference
	Condition Expression      // ON condition (nil for USING / CROSS / NATURAL)
	Using     []Expression    // USING (col, ...) columns; when set, Condition is nil and renderers emit USING
	Pos       models.Location // Source position of the JOIN keyword (1-based line and column)

	Global         bool       // ClickHouse GLOBAL JOIN
	Comma          bool       // MySQL ", t" after an explicit join: rendered as a comma, Type is CROSS
	Strictness     string     // ClickHouse ANY / ALL / ASOF / SEMI / ANTI, Snowflake ASOF
	Hint           string     // SQL Server HASH / LOOP / MERGE / REMOTE join hint, or MySQL STRAIGHT_JOIN
	MatchCondition Expression // Snowflake ASOF JOIN ... MATCH_CONDITION (expr)
}

func (j *JoinClause) expressionNode()     {}
func (j JoinClause) TokenLiteral() string { return j.Type + " JOIN" }

// Children returns Left, Right, Condition when present, and then the USING
// columns in order.
//
// The value receiver is kept for API compatibility. Called on a value it
// returns addresses into the receiver copy (one heap copy per call), while
// Walk and Inspect use childrenInPlace and visit the stored fields in place
// (#557).
func (j JoinClause) Children() []Node { return j.childrenInPlace() }

// childrenInPlace is Children for a JoinClause reached through a pointer:
// Left and Right are returned as pointers into *j itself.
func (j *JoinClause) childrenInPlace() []Node {
	if j.MatchCondition != nil {
		nodes := []Node{&j.Left, &j.Right, j.MatchCondition}
		if j.Condition != nil {
			nodes = append(nodes, j.Condition)
		}
		for _, u := range j.Using {
			if u != nil {
				nodes = append(nodes, u)
			}
		}
		return nodes
	}
	if len(j.Using) == 0 {
		if j.Condition != nil {
			return []Node{&j.Left, &j.Right, j.Condition}
		}
		return []Node{&j.Left, &j.Right}
	}
	nodes := make([]Node, 0, 3+len(j.Using))
	nodes = append(nodes, &j.Left, &j.Right)
	if j.Condition != nil {
		nodes = append(nodes, j.Condition)
	}
	for _, u := range j.Using {
		if u != nil {
			nodes = append(nodes, u)
		}
	}
	return nodes
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
//   - SetSubquery: Derived table whose body is a set operation:
//     (SELECT ... UNION SELECT ...) AS alias. At most one of Subquery and
//     SetSubquery is set.
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
// Example - Derived table whose body is a set operation:
//
//	TableReference{
//	    Alias:       "u",
//	    SetSubquery: &SetOperation{Left: s1, Operator: "UNION", Right: s2},
//	}
//	// SQL: FROM (SELECT ... UNION SELECT ...) u
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
	Final    bool             // ClickHouse FINAL modifier: forces MergeTree part merge
	// WithOrdinality is the PostgreSQL WITH ORDINALITY modifier on a
	// table function: unnest(arr) WITH ORDINALITY appends a bigint column
	// numbering the function's output rows. Only set when TableFunc is set.
	//
	// The three flags are kept together so they share one word of padding;
	// TableReference is copied by value on the parser hot path.
	WithOrdinality bool
	// Only is the PostgreSQL ONLY modifier (FROM ONLY parent): the table's
	// inheritance children are excluded.
	Only bool
	// NameQuote and AliasQuote record the parts of Name and Alias the
	// source delimited and that must stay delimited (see NameQuote). They
	// share the flags' word of padding.
	NameQuote  NameQuote
	AliasQuote NameQuote
	TableHints []string // SQL Server table hints: WITH (NOLOCK), WITH (ROWLOCK, UPDLOCK), etc.
	// TableFunc is a function-call table reference such as
	// Snowflake LATERAL FLATTEN(input => col), TABLE(my_func(1,2)),
	// IDENTIFIER('t'), or PostgreSQL unnest(array_col). When set, Name
	// holds the function name and TableFunc carries the call itself.
	TableFunc *FunctionCall
	// ColumnAliases is the column alias list of a table function's alias:
	// unnest(arr) AS g(elem) or generate_series(1, 3) WITH ORDINALITY
	// AS s(n, idx). It is nil unless TableFunc and Alias are set. It is a
	// pointer so the many references without a list cost one word instead
	// of a slice header.
	ColumnAliases *ColumnAliasList
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
	// SetSubquery is a derived table whose body is a set operation:
	// FROM (SELECT 1 UNION SELECT 2) t. At most one of Subquery and
	// SetSubquery is set; a body that is a single SELECT (including one
	// with a WITH clause or extra parentheses) is always held in Subquery.
	SetSubquery *SetOperation
	// Modifiers holds the rarer table modifiers: TABLESAMPLE / SAMPLE,
	// Oracle flashback and @dblink, MySQL PARTITION selection and index
	// hints, SQLite INDEXED BY, SQL Server OPENJSON WITH schema. It is one
	// pointer because TableReference is copied by value on the parser hot
	// path.
	Modifiers *TableModifiers
}

// ColumnAliasList is the column alias list that follows a table alias, as
// in unnest(arr) AS g(a, b). Names holds the column names in order.
type ColumnAliasList struct {
	Names []string
	// Types holds a column type per name for PostgreSQL record-returning
	// functions (jsonb_to_recordset(j) AS t(a int, b text)); nil otherwise.
	Types []string
	// Quotes holds the NameQuote of each name by index; it is nil when no
	// name keeps delimiters.
	Quotes []NameQuote
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
	if t.SetSubquery != nil {
		nodes = append(nodes, t.SetSubquery)
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
	if t.ForSystemTime != nil {
		nodes = append(nodes, t.ForSystemTime)
	}
	if m := t.Modifiers; m != nil {
		if m.TableSample != nil {
			nodes = append(nodes, m.TableSample)
		}
		if m.Flashback != nil {
			nodes = append(nodes, m.Flashback)
		}
		if m.PartitionFor != nil {
			nodes = append(nodes, m.PartitionFor)
		}
	}
	if t.DialectModifiers().Values != nil {
		nodes = append(nodes, t.DialectModifiers().Values)
	}
	if g := t.Modifiers; g != nil && g.Group != nil {
		nodes = append(nodes, g.Group)
	}
	return nodes
}

// OrderByExpression represents an ORDER BY clause element with direction and NULL ordering
type OrderByExpression struct {
	Expression Expression // The expression to order by
	Ascending  bool       // true for ASC (default), false for DESC
	NullsFirst *bool      // nil = default behavior, true = NULLS FIRST, false = NULLS LAST
	// WithFill — ClickHouse "WITH FILL FROM x TO y STEP z" modifier.
	// Fields are nil when the corresponding part is absent.
	WithFill *WithFillClause
	// UsingOperator is the PostgreSQL ORDER BY expr USING <op> sort
	// operator (<, >, <=, >=); when set it replaces ASC / DESC.
	UsingOperator string
}

// WithFillClause — ClickHouse "WITH FILL [FROM x] [TO y] [STEP z]".
type WithFillClause struct {
	From Expression
	To   Expression
	Step Expression
	Pos  models.Location
}

func (w *WithFillClause) expressionNode()     {}
func (w WithFillClause) TokenLiteral() string { return "WITH FILL" }
func (w WithFillClause) Children() []Node {
	var out []Node
	if w.From != nil {
		out = append(out, w.From)
	}
	if w.To != nil {
		out = append(out, w.To)
	}
	if w.Step != nil {
		out = append(out, w.Step)
	}
	return out
}

func (*OrderByExpression) expressionNode()        {}
func (o *OrderByExpression) TokenLiteral() string { return "ORDER BY" }
func (o *OrderByExpression) Children() []Node {
	var children []Node
	if o.Expression != nil {
		children = append(children, o.Expression)
	}
	if o.WithFill != nil {
		children = append(children, o.WithFill)
	}
	return children
}

// WindowSpec represents a window specification
type WindowSpec struct {
	// Name is the window name outside the parentheses. In an OVER clause it is
	// a bare named-window reference (OVER w); in SelectStatement.Windows it is
	// the definition name (WINDOW w AS (...)). It is never rendered inside the
	// parentheses of the spec it names.
	Name string
	// BaseWindow is the existing window name that a parenthesized spec refines,
	// e.g. OVER (w ORDER BY z) or WINDOW w2 AS (w1 ORDER BY b)
	// (SQL:2003 §7.11 <existing window name>). It is rendered first inside the
	// parentheses.
	BaseWindow  string
	PartitionBy []Expression
	OrderBy     []OrderByExpression
	FrameClause *WindowFrame
	// NameQuote and BaseWindowQuote record the delimiters of Name and
	// BaseWindow when they must be kept (see NameQuote).
	NameQuote       NameQuote
	BaseWindowQuote NameQuote
}

func (w *WindowSpec) statementNode()      {}
func (w WindowSpec) TokenLiteral() string { return "WINDOW" }
func (w WindowSpec) Children() []Node {
	n := len(w.PartitionBy) + len(w.OrderBy)
	if w.FrameClause != nil {
		n++
	}
	children := make([]Node, 0, n)
	for _, e := range w.PartitionBy {
		children = append(children, e)
	}
	for i := range w.OrderBy {
		children = append(children, &w.OrderBy[i])
	}
	if w.FrameClause != nil {
		children = append(children, w.FrameClause)
	}
	return children
}

// WindowFrame represents window frame clause
type WindowFrame struct {
	Type  string // ROWS, RANGE or GROUPS
	Start WindowFrameBound
	End   *WindowFrameBound
	// Exclude is the optional frame exclusion (SQL:2011): "CURRENT ROW",
	// "GROUP", "TIES" or "NO OTHERS". Empty when absent.
	Exclude string
}

func (w *WindowFrame) statementNode()      {}
func (w WindowFrame) TokenLiteral() string { return w.Type }

// Children returns Start and, when present, End.
//
// The value receiver is kept for API compatibility. Called on a value it
// returns addresses into the receiver copy (one heap copy per call), while
// Walk and Inspect use childrenInPlace and visit the stored fields in place
// (#557).
func (w WindowFrame) Children() []Node { return w.childrenInPlace() }

// childrenInPlace is Children for a WindowFrame reached through a pointer:
// Start is a value type, always included, and returned as a pointer into *w.
func (w *WindowFrame) childrenInPlace() []Node {
	if w.End != nil {
		return []Node{&w.Start, w.End}
	}
	return []Node{&w.Start}
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
	// Parenthesized records TOP (n); renderers keep the parentheses, and add
	// them for any count that is not a plain number.
	Parenthesized bool
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
	// FetchExpr is the row count when it is not a plain integer
	// (FETCH NEXT @n ROWS ONLY); FetchValue wins when both are set.
	FetchExpr Expression
}

func (f *FetchClause) expressionNode()     {}
func (f FetchClause) TokenLiteral() string { return "FETCH" }
func (f FetchClause) Children() []Node {
	if f.FetchExpr != nil {
		return []Node{f.FetchExpr}
	}
	return nil
}

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
	// Wait is the Oracle / MariaDB WAIT n timeout, or nil.
	Wait Expression
	// LockInShareMode records MySQL's LOCK IN SHARE MODE spelling of a
	// SHARE lock (LockType "SHARE").
	LockInShareMode bool
}

func (f *ForClause) expressionNode()     {}
func (f ForClause) TokenLiteral() string { return "FOR" }
func (f ForClause) Children() []Node {
	if f.Wait != nil {
		return []Node{f.Wait}
	}
	return nil
}

// OnConflict represents ON CONFLICT DO UPDATE/NOTHING clause
type OnConflict struct {
	Target     []Expression // Target columns
	Constraint string       // Optional constraint name
	Action     OnConflictAction
	// TargetWhere is the partial-index predicate of the conflict target:
	// ON CONFLICT (a) WHERE b > 0 DO ...
	TargetWhere Expression
}

func (o *OnConflict) expressionNode()     {}
func (o OnConflict) TokenLiteral() string { return "ON CONFLICT" }
func (o OnConflict) Children() []Node {
	children := nodifyExpressions(o.Target)
	if o.Action.DoUpdate != nil {
		for i := range o.Action.DoUpdate {
			children = append(children, &o.Action.DoUpdate[i])
		}
	}
	if o.Action.Where != nil {
		children = append(children, o.Action.Where)
	}
	if o.TargetWhere != nil {
		children = append(children, o.TargetWhere)
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
	for i := range u.Updates {
		children[i] = &u.Updates[i]
	}
	return children
}

// QuerySetting is one name = value pair of a ClickHouse query-level SETTINGS
// clause (SELECT ... SETTINGS max_threads = 4). It is plain data, not a Node:
// SelectStatement.Children exposes only Value, so setting names are never
// mistaken for column references.
type QuerySetting struct {
	Name  string
	Value Expression
	Pos   models.Location
}

// ColumnDef represents a column definition in CREATE TABLE
type ColumnDef struct {
	Name        string
	Type        string
	Constraints []ColumnConstraint
	// NameQuote records the delimiters of Name when they must be kept
	// (see NameQuote).
	NameQuote NameQuote
}

func (c *ColumnDef) expressionNode()     {}
func (c ColumnDef) TokenLiteral() string { return c.Name }
func (c ColumnDef) Children() []Node {
	children := make([]Node, len(c.Constraints))
	for i := range c.Constraints {
		children[i] = &c.Constraints[i]
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

	// Name is the CONSTRAINT <name> written before the constraint.
	Name string
	// Keyword, Value, Expr and Args carry the payload of the dialect
	// constraint kinds listed in ast_columns.go (COMMENT, COLLATE, ON UPDATE,
	// generated columns, identity columns, ClickHouse MATERIALIZED / ALIAS /
	// TTL / CODEC, ...). Keyword is a spelling or mode the source chose
	// (AUTOINCREMENT, CHARSET, STORED), Value a name or literal text, Expr an
	// expression and Args the raw text of a parenthesised argument list.
	Keyword string
	Value   string
	Expr    Expression
	Args    string
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
	if c.Expr != nil {
		children = append(children, c.Expr)
	}
	return children
}

// TableConstraint represents a table constraint. Type is PRIMARY KEY, UNIQUE,
// FOREIGN KEY or CHECK, or one of the index and dialect element kinds listed
// in ast_columns.go (KEY, INDEX, FULLTEXT, SPATIAL, LIKE, PROJECTION).
type TableConstraint struct {
	Name       string
	Type       string
	Columns    []string
	References *ReferenceDefinition
	Check      Expression

	// ColumnSuffix holds, parallel to Columns, each key part's prefix length
	// and sort order as written ("(191)", "DESC", "(10) DESC"); it is empty
	// when no part has one.
	ColumnSuffix []string
	// Keyword is the KEY or INDEX word written after UNIQUE, FULLTEXT or
	// SPATIAL; IndexName the index name; Using the index method (BTREE,
	// HASH); Cluster CLUSTERED or NONCLUSTERED; Deferrable the DEFERRABLE
	// timing clause; Exprs the key parts of a functional index or the
	// expression of a ClickHouse INDEX; Text the verbatim ClickHouse INDEX
	// TYPE or PROJECTION body; Granularity the ClickHouse GRANULARITY value;
	// LikeTable and LikeOptions the PostgreSQL LIKE source and its
	// INCLUDING / EXCLUDING options.
	Keyword   string
	IndexName string
	// IndexNameQuote records the delimiters of IndexName when they must be
	// kept (see NameQuote).
	IndexNameQuote NameQuote
	Using          string
	Cluster        string
	Deferrable     string
	Exprs          []Expression
	Text           string
	Granularity    string
	LikeTable      string
	// LikeTableQuote records the delimiters of LikeTable when they must
	// be kept (see NameQuote).
	LikeTableQuote NameQuote
	LikeOptions    []string
	// NameQuote records the delimiters of Name, and ColumnQuotes those of
	// each Columns entry by index (nil when none keeps delimiters); see
	// NameQuote.
	NameQuote    NameQuote
	ColumnQuotes []NameQuote
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
	for _, e := range t.Exprs {
		if e != nil {
			children = append(children, e)
		}
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
	// TableQuote records the delimiters of Table, and ColumnQuotes those of
	// each Columns entry by index (nil when none keeps delimiters); see
	// NameQuote.
	TableQuote   NameQuote
	ColumnQuotes []NameQuote
}

func (r *ReferenceDefinition) expressionNode()     {}
func (r ReferenceDefinition) TokenLiteral() string { return "REFERENCES" }
func (r ReferenceDefinition) Children() []Node     { return nil }

// PartitionBy represents a PARTITION BY clause
type PartitionBy struct {
	Type     string // RANGE, LIST, HASH
	Columns  []string
	Boundary []Expression
	// Expressions holds the partition key when it is not a plain column
	// list (RANGE (YEAR(d))); it is written instead of Columns.
	Expressions []Expression
	// Partitions is the HASH / KEY partition count (PARTITIONS n).
	Partitions Expression
	// Interval is the Oracle INTERVAL (expr) of interval partitioning, or
	// the MariaDB SYSTEM_TIME INTERVAL n unit.
	Interval Expression
	// Linear is MySQL LINEAR HASH / LINEAR KEY.
	Linear bool
}

func (p *PartitionBy) expressionNode()     {}
func (p PartitionBy) TokenLiteral() string { return "PARTITION BY" }
func (p PartitionBy) Children() []Node {
	nodes := nodifyExpressions(p.Boundary)
	nodes = append(nodes, nodifyExpressions(p.Expressions)...)
	if p.Partitions != nil {
		nodes = append(nodes, p.Partitions)
	}
	if p.Interval != nil {
		nodes = append(nodes, p.Interval)
	}
	return nodes
}

// TableOption represents table options like ENGINE, CHARSET, etc.
type TableOption struct {
	Name  string
	Value string
	// Form says how the option is written (zero value: Name=Value); see
	// ddl_objects.go.
	Form TableOptionForm
	// ValueKind says how Value is written (zero value: a bare word).
	ValueKind TableOptionValueKind
	// Args holds the expressions of a TableOptionArgs option.
	Args []Expression
	// ValueArgs holds the argument expressions of a parenthesized word
	// value (ENGINE = Distributed(cluster, db, t, rand())). Value keeps the
	// text the renderers write; ValueArgs only lets tree walkers reach the
	// arguments, so editing it does not change the rendered SQL.
	ValueArgs []Expression
	// Sub holds the entries of a TableOptionList option.
	Sub []OptionParam
}

func (t *TableOption) expressionNode()     {}
func (t TableOption) TokenLiteral() string { return t.Name }
func (t TableOption) Children() []Node {
	if len(t.Args) == 0 && len(t.ValueArgs) == 0 {
		return nil
	}
	children := nodifyExpressions(t.Args)
	return appendExprChildren(children, t.ValueArgs)
}

// IndexColumn represents a column in an index definition
type IndexColumn struct {
	Column  string
	Collate string
	// CollateQuoted records that the collation name was written as a
	// double-quoted identifier (COLLATE "C"); it is re-quoted on output
	// because PostgreSQL folds a bare C to c.
	CollateQuoted bool
	Direction     string // ASC, DESC
	NullsLast     bool
	// NullsFirst is NULLS FIRST.
	NullsFirst bool
	// Expr is the indexed expression when it is not a plain column
	// (lower(email), (a + b), email(10)); it is written instead of Column.
	Expr Expression
	// OpClass is the PostgreSQL operator class (jsonb_path_ops).
	OpClass string
	// ColumnQuote records the delimiters of Column when they must be kept
	// (see NameQuote).
	ColumnQuote NameQuote
}

func (i *IndexColumn) expressionNode()     {}
func (i IndexColumn) TokenLiteral() string { return i.Column }
func (i IndexColumn) Children() []Node {
	if i.Expr != nil {
		return []Node{i.Expr}
	}
	return nil
}

// PartitionDefinition represents a partition definition in CREATE TABLE
// Syntax: PARTITION name VALUES { LESS THAN (expr) | IN (list) | FROM (expr) TO (expr) }
type PartitionDefinition struct {
	Name string
	// NameQuote records the delimiters of Name when they must be kept (see
	// NameQuote).
	NameQuote  NameQuote
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
	SystemTimeAsOf        SystemTimeClauseType = iota // FOR SYSTEM_TIME AS OF <point>
	SystemTimeBetween                                 // FOR SYSTEM_TIME BETWEEN <start> AND <end>
	SystemTimeFromTo                                  // FOR SYSTEM_TIME FROM <start> TO <end>
	SystemTimeAll                                     // FOR SYSTEM_TIME ALL
	SystemTimeContainedIn                             // FOR SYSTEM_TIME CONTAINED IN (<start>, <end>) (SQL Server)
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

// PivotClause represents the SQL Server / Oracle / Snowflake / BigQuery PIVOT
// operator for row-to-column transformation in a FROM clause.
//
//	PIVOT (SUM(sales) FOR region IN ([North], [South], [East], [West])) AS pvt
//	PIVOT (SUM(sales) AS total, COUNT(*) AS n FOR quarter IN ('Q1' AS q1, 'Q2' AS q2))
//
// The first aggregate is AggregateFunction (with optional AggregateAlias);
// Oracle / BigQuery allow further aggregates, which are kept in
// ExtraAggregates in source order.
type PivotClause struct {
	AggregateFunction Expression       // The aggregate function, e.g. SUM(sales)
	AggregateAlias    string           // Optional alias of AggregateFunction; quoted aliases retain source delimiters
	ExtraAggregates   []PivotAggregate // Second and later aggregates (Oracle / BigQuery), in source order
	PivotColumn       string           // The column used for pivoting, e.g. region
	InValues          []string         // The values to pivot on, e.g. [North], 'Q1' AS q1
	Pos               models.Location  // Source position of the PIVOT keyword
	// PivotExtensions holds XML, dynamic IN lists and source aliases.
	PivotExtensions
}

// PivotAggregate is an additional aggregate in a multi-aggregate PIVOT, e.g.
// the "COUNT(*) AS n" in PIVOT (SUM(x) AS total, COUNT(*) AS n FOR ...).
type PivotAggregate struct {
	Function Expression // The aggregate function call
	Alias    string     // Optional alias; quoted aliases retain source delimiters
}

func (p *PivotClause) expressionNode()     {}
func (p PivotClause) TokenLiteral() string { return "PIVOT" }
func (p PivotClause) Children() []Node {
	var nodes []Node
	if p.AggregateFunction != nil {
		nodes = append(nodes, p.AggregateFunction)
	}
	for _, a := range p.ExtraAggregates {
		if a.Function != nil {
			nodes = append(nodes, a.Function)
		}
	}
	return p.pivotExtensionChildren(nodes)
}

// UnpivotClause represents the SQL Server / Oracle / Snowflake / BigQuery
// UNPIVOT operator for column-to-row transformation in a FROM clause.
//
//	UNPIVOT (sales FOR region IN (north_sales, south_sales, east_sales)) AS unpvt
//	UNPIVOT INCLUDE NULLS ((h1, h2) FOR half IN ((q1, q2) AS 'H1', (q3, q4) AS 'H2'))
//
// In the multi-column form (Oracle / BigQuery) ValueColumns holds the value
// column set and ValueColumn is empty; each InColumns entry is then a
// parenthesized column set such as "(q1, q2) AS 'H1'".
type UnpivotClause struct {
	NullHandling string          // "", "INCLUDE NULLS" or "EXCLUDE NULLS" (Oracle / Snowflake / BigQuery)
	ValueColumn  string          // The target value column; quoted names retain source delimiters
	ValueColumns []string        // The target value columns; quoted names retain source delimiters
	NameColumn   string          // The target name column, e.g. region
	InColumns    []string        // The source columns to unpivot, e.g. north_sales, south_sales
	Pos          models.Location // Source position of the UNPIVOT keyword
	// SourceAlias is the alias of the unpivoted source table or derived table.
	SourceAlias string
	// SourceAliasQuote records the delimiters of SourceAlias.
	SourceAliasQuote NameQuote
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
	for i := range m.OrderBy {
		nodes = append(nodes, &m.OrderBy[i])
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
