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

// QueryExpression is a Statement that can appear as the source of INSERT ... SELECT.
// Only *SelectStatement and *SetOperation satisfy this interface.
type QueryExpression interface {
	Statement
	queryExpressionNode()
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

func (s *SetOperation) statementNode()       {}
func (s *SetOperation) queryExpressionNode() {}
func (s SetOperation) TokenLiteral() string  { return s.Operator }
func (s SetOperation) Children() []Node {
	var nodes []Node
	if s.Left != nil {
		nodes = append(nodes, s.Left)
	}
	if s.Right != nil {
		nodes = append(nodes, s.Right)
	}
	return nodes
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
	Top               *TopClause   // SQL Server TOP N [PERCENT] clause
	Columns           []Expression
	From              []TableReference
	TableName         string // Added for pool operations
	Joins             []JoinClause
	ArrayJoin         *ArrayJoinClause // ClickHouse ARRAY JOIN / LEFT ARRAY JOIN clause
	PrewhereClause    Expression       // ClickHouse PREWHERE clause (applied before WHERE, before reading data)
	Sample            *SampleClause    // ClickHouse SAMPLE clause (comes after FROM/FINAL, before PREWHERE)
	Where             Expression
	GroupBy           []Expression
	Having            Expression
	Qualify           Expression // Snowflake / BigQuery QUALIFY clause (filters after window functions)
	// StartWith is the optional seed condition for CONNECT BY (MariaDB 10.2+).
	// Example: START WITH parent_id IS NULL
	StartWith Expression // MariaDB hierarchical query seed
	// ConnectBy holds the hierarchy traversal condition (MariaDB 10.2+).
	// Example: CONNECT BY PRIOR id = parent_id
	ConnectBy *ConnectByClause // MariaDB hierarchical query
	Windows   []WindowSpec
	OrderBy   []OrderByExpression
	Limit     *int
	Offset    *int
	Fetch     *FetchClause    // SQL-99 FETCH FIRST/NEXT clause (F861, F862)
	For       *ForClause      // Row-level locking clause (SQL:2003, PostgreSQL, MySQL)
	Pos       models.Location // Source position of the SELECT keyword (1-based line and column)
}

func (s *SelectStatement) statementNode()       {}
func (s *SelectStatement) queryExpressionNode() {}
func (s SelectStatement) TokenLiteral() string  { return "SELECT" }

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
	if s.Sample != nil {
		children = append(children, s.Sample)
	}
	if s.PrewhereClause != nil {
		children = append(children, s.PrewhereClause)
	}
	if s.Where != nil {
		children = append(children, s.Where)
	}
	children = append(children, nodifyExpressions(s.GroupBy)...)
	if s.Having != nil {
		children = append(children, s.Having)
	}
	if s.Qualify != nil {
		children = append(children, s.Qualify)
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
	if s.StartWith != nil {
		children = append(children, s.StartWith)
	}
	if s.ConnectBy != nil {
		children = append(children, s.ConnectBy)
	}
	return children
}

// InsertStatement represents an INSERT SQL statement
type InsertStatement struct {
	With           *WithClause
	TableName      string
	Columns        []Expression
	Output         []Expression    // SQL Server OUTPUT clause columns
	Values         [][]Expression  // Multi-row support: each inner slice is one row of values
	Query          QueryExpression // For INSERT ... SELECT (SelectStatement or SetOperation)
	Returning      []Expression
	OnConflict     *OnConflict
	OnDuplicateKey *UpsertClause   // MySQL: ON DUPLICATE KEY UPDATE
	Pos            models.Location // Source position of the INSERT keyword (1-based line and column)
}

func (i *InsertStatement) statementNode()      {}
func (i InsertStatement) TokenLiteral() string { return "INSERT" }

func (i InsertStatement) Children() []Node {
	children := make([]Node, 0)
	if i.With != nil {
		children = append(children, i.With)
	}
	children = append(children, nodifyExpressions(i.Columns)...)
	children = append(children, nodifyExpressions(i.Output)...)
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
	if i.OnDuplicateKey != nil {
		children = append(children, i.OnDuplicateKey)
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
	Assignments []UpdateExpression // SET clause assignments
	From        []TableReference
	Where       Expression
	Returning   []Expression
	Pos         models.Location // Source position of the UPDATE keyword (1-based line and column)
}

// GetUpdates returns Assignments for backward compatibility.
//
// Deprecated: Use Assignments directly instead.
func (u *UpdateStatement) GetUpdates() []UpdateExpression {
	return u.Assignments
}

func (u *UpdateStatement) statementNode()      {}
func (u UpdateStatement) TokenLiteral() string { return "UPDATE" }

func (u UpdateStatement) Children() []Node {
	children := make([]Node, 0)
	if u.With != nil {
		children = append(children, u.With)
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
	IfNotExists  bool
	Temporary    bool
	Name         string
	Columns      []ColumnDef
	Constraints  []TableConstraint
	Inherits     []string
	PartitionBy  *PartitionBy
	Partitions   []PartitionDefinition // Individual partition definitions
	Options      []TableOption
	WithoutRowID bool // SQLite: CREATE TABLE ... WITHOUT ROWID

	// WithSystemVersioning enables system-versioned temporal history (MariaDB 10.3.4+).
	// Example: CREATE TABLE t (...) WITH SYSTEM VERSIONING
	WithSystemVersioning bool

	// PeriodDefinitions holds PERIOD FOR clauses for application-time or system-time periods.
	// Example: PERIOD FOR app_time (start_col, end_col)
	PeriodDefinitions []*PeriodDefinition
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

// DeleteStatement represents a DELETE SQL statement
type DeleteStatement struct {
	With      *WithClause
	TableName string
	Alias     string
	Using     []TableReference
	Where     Expression
	Returning []Expression
	Pos       models.Location // Source position of the DELETE keyword (1-based line and column)
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

// AlterTableStatement represents an ALTER TABLE statement.
//
// # Maintenance note
//
// AlterTableStatement is NOT produced by the parser. Parser.Parse* methods
// return [AlterStatement] (defined in alter.go) with Type == AlterTypeTable.
// AlterTableStatement is retained only so that existing code that constructs
// it directly (e.g. in tests or manual AST construction) continues to compile.
//
// Migration guide - prefer AlterStatement for all new code:
//
//	// Wrong (type assertion will never succeed at runtime):
//	stmt := tree.Statements[0].(*ast.AlterTableStatement)
//
//	// Correct:
//	stmt := tree.Statements[0].(*ast.AlterStatement)
//	tableName := stmt.Name // AlterStatement.Name holds the table name
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
	Output      []Expression       // SQL Server OUTPUT clause columns
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
	children = append(children, nodifyExpressions(m.Output)...)
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

// PragmaStatement represents a SQLite PRAGMA statement.
// Examples: PRAGMA table_info(users), PRAGMA journal_mode = WAL, PRAGMA integrity_check
type PragmaStatement struct {
	Name  string // Pragma name, e.g. "table_info"
	Arg   string // Optional: parenthesized arg, e.g. "users"
	Value string // Optional: assigned value, e.g. "WAL"
}

func (p *PragmaStatement) statementNode()      {}
func (p PragmaStatement) TokenLiteral() string { return "PRAGMA" }
func (p PragmaStatement) Children() []Node     { return nil }

// ShowStatement represents MySQL SHOW commands (SHOW TABLES, SHOW DATABASES, SHOW CREATE TABLE x, etc.)
type ShowStatement struct {
	ShowType   string // TABLES, DATABASES, CREATE TABLE, COLUMNS, INDEX, etc.
	ObjectName string // For SHOW CREATE TABLE x, SHOW COLUMNS FROM x, etc.
	From       string // For SHOW ... FROM database
}

func (s *ShowStatement) statementNode()      {}
func (s ShowStatement) TokenLiteral() string { return "SHOW" }
func (s ShowStatement) Children() []Node     { return nil }

// DescribeStatement represents MySQL DESCRIBE/DESC/EXPLAIN table commands
type DescribeStatement struct {
	TableName string
}

func (d *DescribeStatement) statementNode()      {}
func (d DescribeStatement) TokenLiteral() string { return "DESCRIBE" }
func (d DescribeStatement) Children() []Node     { return nil }

// UnsupportedStatement represents a SQL statement that was parsed but not
// fully modeled in the AST. The parser consumed and validated the tokens
// but no dedicated AST node exists yet for this statement kind.
//
// Consumers should use Kind to identify the operation (e.g., "USE", "COPY",
// "CREATE STAGE") and RawSQL for the original text. Tools that do
// switch stmt.(type) should handle this case explicitly rather than
// falling through to a default that assumes the statement is well-structured.
type UnsupportedStatement struct {
	Kind   string // Operation kind: "USE", "COPY", "PUT", "GET", "LIST", "REMOVE", "CREATE STAGE", etc.
	RawSQL string // Original SQL fragment for round-trip fidelity
}

func (u *UnsupportedStatement) statementNode()      {}
func (u UnsupportedStatement) TokenLiteral() string { return u.Kind }
func (u UnsupportedStatement) Children() []Node     { return nil }

// ReplaceStatement represents MySQL REPLACE INTO statement
type ReplaceStatement struct {
	TableName string
	Columns   []Expression
	Values    [][]Expression
}

func (r *ReplaceStatement) statementNode()      {}
func (r ReplaceStatement) TokenLiteral() string { return "REPLACE" }
func (r ReplaceStatement) Children() []Node {
	children := make([]Node, 0)
	children = append(children, nodifyExpressions(r.Columns)...)
	for _, row := range r.Values {
		children = append(children, nodifyExpressions(row)...)
	}
	return children
}

// ── MariaDB SEQUENCE DDL (10.3+) ───────────────────────────────────────────

// CycleOption represents the CYCLE behavior for a sequence.
type CycleOption int

const (
	// CycleUnspecified means no CYCLE or NOCYCLE clause was given (database default applies).
	CycleUnspecified CycleOption = iota
	// CycleBehavior means CYCLE — sequence wraps around when it reaches min/max.
	CycleBehavior
	// NoCycleBehavior means NOCYCLE / NO CYCLE — sequence errors on overflow.
	NoCycleBehavior
)

// SequenceOptions holds configuration for CREATE SEQUENCE and ALTER SEQUENCE.
// Fields are pointers so that unspecified options are distinguishable from zero values.
type SequenceOptions struct {
	StartWith   *LiteralValue // START WITH n
	IncrementBy *LiteralValue // INCREMENT BY n (default 1)
	MinValue    *LiteralValue // MINVALUE n or nil when NO MINVALUE
	MaxValue    *LiteralValue // MAXVALUE n or nil when NO MAXVALUE
	Cache       *LiteralValue // CACHE n or nil when NO CACHE / NOCACHE
	CycleMode   CycleOption   // CYCLE / NOCYCLE / NO CYCLE (CycleUnspecified if not specified)
	NoCache     bool          // NOCACHE (explicit; Cache=nil alone is ambiguous)
	Restart     bool          // bare RESTART (reset to start value)
	RestartWith *LiteralValue // RESTART WITH n (explicit restart value)
}

// CreateSequenceStatement represents:
//
//	CREATE [OR REPLACE] SEQUENCE [IF NOT EXISTS] name [options...]
type CreateSequenceStatement struct {
	Name        *Identifier
	OrReplace   bool
	IfNotExists bool
	Options     SequenceOptions
	Pos         models.Location // Source position of the CREATE keyword (1-based line and column)
}

func (s *CreateSequenceStatement) statementNode()       {}
func (s *CreateSequenceStatement) TokenLiteral() string { return "CREATE" }
func (s *CreateSequenceStatement) Children() []Node {
	if s.Name != nil {
		return []Node{s.Name}
	}
	return nil
}

// DropSequenceStatement represents:
//
//	DROP SEQUENCE [IF EXISTS | IF NOT EXISTS] name
type DropSequenceStatement struct {
	Name     *Identifier
	IfExists bool
	Pos      models.Location // Source position of the DROP keyword (1-based line and column)
}

func (s *DropSequenceStatement) statementNode()       {}
func (s *DropSequenceStatement) TokenLiteral() string { return "DROP" }
func (s *DropSequenceStatement) Children() []Node {
	if s.Name != nil {
		return []Node{s.Name}
	}
	return nil
}

// AlterSequenceStatement represents:
//
//	ALTER SEQUENCE [IF EXISTS] name [options...]
type AlterSequenceStatement struct {
	Name     *Identifier
	IfExists bool
	Options  SequenceOptions
	Pos      models.Location // Source position of the ALTER keyword (1-based line and column)
}

func (s *AlterSequenceStatement) statementNode()       {}
func (s *AlterSequenceStatement) TokenLiteral() string { return "ALTER" }
func (s *AlterSequenceStatement) Children() []Node {
	if s.Name != nil {
		return []Node{s.Name}
	}
	return nil
}
