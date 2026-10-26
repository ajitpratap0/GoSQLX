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

// DMLTargetFields holds the dialect-specific parts of UPDATE and DELETE that
// surround the target table. UpdateStatement.Extras and DeleteStatement.Extras
// point to it; they are nil for a statement that uses none of these parts, so
// a plain UPDATE t SET ... WHERE ... does not carry them.
//
// The first target stays in the statement's TableName and Alias when it is a
// plain table name, so code that only looks at TableName keeps working; Tables
// holds every further target (MySQL UPDATE t1, t2 / DELETE t1, t2 FROM ...),
// or all of them when TableName is empty (a derived-table target such as
// Oracle UPDATE (SELECT ...) SET ...).
type DMLTargetFields struct {
	// Modifiers are the keywords written between the verb and the target,
	// upper-cased and in source order: MySQL LOW_PRIORITY, QUICK, IGNORE;
	// SQLite OR ROLLBACK / OR ABORT / OR REPLACE / OR FAIL / OR IGNORE.
	// Renderers write only known modifiers (see DMLModifierText).
	Modifiers []string
	// Top is the SQL Server TOP (n) [PERCENT] row limit.
	Top *TopClause
	// Only is the PostgreSQL ONLY modifier (UPDATE ONLY t, DELETE FROM ONLY t).
	Only bool
	// Tables are the targets after TableName/Alias (see the type comment).
	Tables []TableReference
	// Joins are the JOIN clauses of a multi-table statement: MySQL
	// UPDATE t JOIN u ON ... SET, and the joins after DELETE ... FROM or
	// DELETE ... USING.
	Joins []JoinClause
	// Output is the SQL Server OUTPUT list (items may be AliasedExpression).
	Output []Expression
	// OutputInto is the SQL Server OUTPUT ... INTO target.
	OutputInto *OutputInto
	// OrderBy and Limit are the MySQL/MariaDB/SQLite ORDER BY ... LIMIT n
	// row limit of a single-table UPDATE or DELETE.
	OrderBy []OrderByExpression
	Limit   Expression
	// ReturningInto holds the Oracle RETURNING ... INTO :bind targets.
	ReturningInto []Expression
}

// noDMLTargetFields is the read-only stand-in returned for a statement
// without Extras. Nothing may write through it.
var noDMLTargetFields DMLTargetFields

// dmlExtras returns x, or a read-only empty DMLTargetFields when it is nil,
// so renderers and walkers can read the fields without nil checks.
func dmlExtras(x *DMLTargetFields) *DMLTargetFields {
	if x != nil {
		return x
	}
	return &noDMLTargetFields
}

// EnsureExtras returns u.Extras, allocating it first when it is nil. Use it
// to set one of the DMLTargetFields.
func (u *UpdateStatement) EnsureExtras() *DMLTargetFields {
	if u.Extras == nil {
		u.Extras = &DMLTargetFields{}
	}
	return u.Extras
}

// EnsureExtras returns d.Extras, allocating it first when it is nil. Use it
// to set one of the DMLTargetFields.
func (d *DeleteStatement) EnsureExtras() *DMLTargetFields {
	if d.Extras == nil {
		d.Extras = &DMLTargetFields{}
	}
	return d.Extras
}

// IsZero reports whether no field of d is set.
func (d *DMLTargetFields) IsZero() bool {
	return len(d.Modifiers) == 0 && d.Top == nil && !d.Only && len(d.Tables) == 0 &&
		len(d.Joins) == 0 && len(d.Output) == 0 && d.OutputInto == nil &&
		len(d.OrderBy) == 0 && d.Limit == nil && len(d.ReturningInto) == 0
}

// dmlTargetChildren appends the nodes of d to children.
func (d *DMLTargetFields) dmlTargetChildren(children []Node) []Node {
	if d.Top != nil {
		children = append(children, d.Top)
	}
	for i := range d.Tables {
		children = append(children, &d.Tables[i])
	}
	for i := range d.Joins {
		children = append(children, &d.Joins[i])
	}
	children = append(children, nodifyExpressions(d.Output)...)
	if d.OutputInto != nil {
		children = append(children, d.OutputInto)
	}
	for i := range d.OrderBy {
		children = append(children, &d.OrderBy[i])
	}
	if d.Limit != nil {
		children = append(children, d.Limit)
	}
	children = append(children, nodifyExpressions(d.ReturningInto)...)
	return children
}

// OutputInto is the INTO part of a SQL Server OUTPUT clause:
// OUTPUT inserted.id INTO @ids (id) or INTO dbo.archive (id, total).
type OutputInto struct {
	// Target is the table name or table variable (@ids).
	Target string
	// Columns is the optional column list.
	Columns []Expression
}

func (o *OutputInto) expressionNode()     {}
func (o OutputInto) TokenLiteral() string { return "INTO" }
func (o OutputInto) Children() []Node     { return nodifyExpressions(o.Columns) }

// InsertDialectFields holds the dialect-specific parts of INSERT. It is
// embedded in InsertStatement, so its fields are accessed directly.
type InsertDialectFields struct {
	// Modifiers are the keywords between INSERT and INTO, upper-cased and in
	// source order: MySQL IGNORE / LOW_PRIORITY / HIGH_PRIORITY / DELAYED,
	// SQLite OR REPLACE / OR IGNORE / OR ABORT / OR FAIL / OR ROLLBACK,
	// Snowflake OVERWRITE. Renderers write only known modifiers.
	Modifiers []string
	// Overriding is the PostgreSQL OVERRIDING {SYSTEM | USER} VALUE kind:
	// "SYSTEM" or "USER".
	Overriding string
	// RowAlias is the MySQL 8.0.19+ row alias: VALUES (...) AS RowAlias
	// [(RowAliasColumns)] ON DUPLICATE KEY UPDATE ...
	RowAlias        string
	RowAliasColumns []string
	// OutputInto is the SQL Server OUTPUT ... INTO target.
	OutputInto *OutputInto
	// ReturningInto holds the Oracle RETURNING ... INTO :bind targets.
	ReturningInto []Expression
	// TableFunction is the ClickHouse INSERT INTO FUNCTION f(...) target;
	// TableName is empty when it is set.
	TableFunction *FunctionCall
	// Settings is the ClickHouse INSERT ... SETTINGS name = value list.
	Settings []QuerySetting
	// DataFormat is the ClickHouse FORMAT name of the inserted data
	// (INSERT INTO t FORMAT CSV).
	DataFormat string
	// MultiTable is the Oracle INSERT ALL / INSERT FIRST body; Query holds the
	// source subquery and TableName is empty.
	MultiTable *MultiTableInsert
	// TableNameQuote records the delimiters of TableName when they must be
	// kept (see NameQuote).
	TableNameQuote NameQuote
	// LogErrors is the Oracle error logging clause LOG ERRORS [INTO table]
	// [(tag)] [REJECT LIMIT n | UNLIMITED].
	LogErrors *LogErrorsClause
}

// LogErrorsClause is the Oracle DML error logging clause:
//
//	LOG ERRORS INTO err$_dest ('nightly load') REJECT LIMIT UNLIMITED
type LogErrorsClause struct {
	// Into is the error table, possibly schema-qualified; empty when the
	// default error table is meant. IntoQuote records its delimiters.
	Into      string
	IntoQuote NameQuote
	// Tag is the optional simple expression identifying the statement in the
	// error table.
	Tag Expression
	// RejectLimit is the REJECT LIMIT value: an integer's digits or UNLIMITED;
	// empty when the clause is absent.
	RejectLimit string
}

func (l *LogErrorsClause) expressionNode()     {}
func (l LogErrorsClause) TokenLiteral() string { return "LOG ERRORS" }

// Children returns the tag expression.
func (l LogErrorsClause) Children() []Node {
	if l.Tag == nil {
		return nil
	}
	return []Node{l.Tag}
}

// insertDialectChildren appends the nodes of d to children.
func (d *InsertDialectFields) insertDialectChildren(children []Node) []Node {
	if d.TableFunction != nil {
		children = append(children, d.TableFunction)
	}
	if d.OutputInto != nil {
		children = append(children, d.OutputInto)
	}
	children = append(children, nodifyExpressions(d.ReturningInto)...)
	for i := range d.Settings {
		if v := d.Settings[i].Value; v != nil {
			children = append(children, v)
		}
	}
	if d.MultiTable != nil {
		children = append(children, d.MultiTable)
	}
	if d.LogErrors != nil {
		children = append(children, d.LogErrors)
	}
	return children
}

// MultiTableInsert is the Oracle multi-table insert body:
//
//	INSERT ALL INTO a VALUES (...) INTO b VALUES (...) SELECT ...
//	INSERT {ALL | FIRST} WHEN c THEN INTO a ... [ELSE INTO b ...] SELECT ...
type MultiTableInsert struct {
	// First marks INSERT FIRST (otherwise INSERT ALL).
	First bool
	// Branches are the INTO groups in source order. An unconditional
	// INSERT ALL has one branch with a nil When.
	Branches []MultiInsertBranch
}

func (m *MultiTableInsert) expressionNode() {}

// TokenLiteral returns "INSERT ALL" or "INSERT FIRST".
func (m MultiTableInsert) TokenLiteral() string {
	if m.First {
		return "INSERT FIRST"
	}
	return "INSERT ALL"
}

// Children returns each branch's condition and INTO clauses in order.
func (m MultiTableInsert) Children() []Node {
	var children []Node
	for i := range m.Branches {
		b := &m.Branches[i]
		if b.When != nil {
			children = append(children, b.When)
		}
		for j := range b.Into {
			children = append(children, nodifyExpressions(b.Into[j].Columns)...)
			children = append(children, nodifyExpressions(b.Into[j].Values)...)
		}
	}
	return children
}

// MultiInsertBranch is one WHEN ... THEN group (or the ELSE group, or the
// unconditional group of INSERT ALL) of a multi-table insert.
type MultiInsertBranch struct {
	When Expression // nil for ELSE and for the unconditional form
	Else bool
	Into []MultiInsertInto
}

// MultiInsertInto is one INTO table [(cols)] [VALUES (...)] clause of a
// multi-table insert.
type MultiInsertInto struct {
	Table   string
	Columns []Expression
	Values  []Expression // nil when the clause has no VALUES list
}

// DefaultExpr is the DEFAULT keyword used as a value: INSERT ... VALUES
// (DEFAULT) and UPDATE ... SET c = DEFAULT.
type DefaultExpr struct{}

func (d *DefaultExpr) expressionNode()     {}
func (d DefaultExpr) TokenLiteral() string { return "DEFAULT" }
func (d DefaultExpr) Children() []Node     { return nil }

// SQL returns "DEFAULT".
func (d *DefaultExpr) SQL() string { return "DEFAULT" }
