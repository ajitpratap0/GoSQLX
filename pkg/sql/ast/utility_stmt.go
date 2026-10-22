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

// This file holds the utility-statement family: session, transaction,
// privilege and maintenance statements (BEGIN, COMMIT, SET, USE, CALL, GRANT,
// VACUUM, ...). The parser records the statement text exactly as written
// (rebuilt from its tokens, with comments removed and whitespace collapsed)
// next to whatever structure is cheap to extract, and SQL() returns that text
// so formatting never changes the meaning of a statement GoSQLX does not
// model in full.

package ast

import (
	"bytes"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// UtilityStatement is a statement GoSQLX recognizes but does not model in
// detail, such as GRANT, REVOKE, COMMENT ON, VACUUM, ANALYZE, LOCK, KILL,
// PREPARE / EXECUTE, SHOW with filters, or T-SQL DECLARE / IF / PRINT.
// Unlike UnsupportedStatement, it is not a placeholder: Text reproduces the
// statement and re-parses to the same node.
type UtilityStatement struct {
	// Kind is the statement's leading keyword, upper-cased: "GRANT",
	// "REVOKE", "COMMENT", "SHOW", "VACUUM", "DECLARE", ...
	Kind string
	// Text is the full statement text as written.
	Text string
	Pos  models.Location
}

func (u *UtilityStatement) statementNode()      {}
func (u UtilityStatement) TokenLiteral() string { return u.Kind }
func (u UtilityStatement) Children() []Node     { return nil }

// SQL returns the statement text as written.
func (u *UtilityStatement) SQL() string {
	if u == nil {
		return ""
	}
	if u.Text != "" {
		return u.Text
	}
	return u.Kind
}

// TransactionStatement is a transaction-control statement: BEGIN,
// START TRANSACTION, COMMIT, ROLLBACK [TO SAVEPOINT name], SAVEPOINT name,
// RELEASE SAVEPOINT name, END (PostgreSQL / SQLite) and the T-SQL
// BEGIN / COMMIT / ROLLBACK / SAVE TRANSACTION forms.
type TransactionStatement struct {
	// Action is the normalized operation: "BEGIN", "START TRANSACTION",
	// "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE SAVEPOINT" or "END".
	Action string
	// Savepoint names the savepoint of SAVEPOINT, RELEASE SAVEPOINT,
	// ROLLBACK TO and T-SQL SAVE TRANSACTION; empty otherwise.
	Savepoint string
	// Text is the full statement text as written, including modifiers such
	// as ISOLATION LEVEL, READ ONLY, WORK or AND CHAIN.
	Text string
	Pos  models.Location
}

func (t *TransactionStatement) statementNode()      {}
func (t TransactionStatement) TokenLiteral() string { return t.Action }
func (t TransactionStatement) Children() []Node     { return nil }

// SQL returns the statement text as written. A node built without Text
// renders Action followed by the savepoint, if any.
func (t *TransactionStatement) SQL() string {
	if t == nil {
		return ""
	}
	if t.Text != "" {
		return t.Text
	}
	if t.Savepoint == "" {
		return t.Action
	}
	if t.Action == "ROLLBACK" {
		return "ROLLBACK TO SAVEPOINT " + QuoteName(t.Savepoint)
	}
	return t.Action + " " + QuoteName(t.Savepoint)
}

// SetStatement is a SET statement that assigns a session, global or user
// variable or a session property: SET search_path TO a, b; SET @a := 1;
// SET GLOBAL max_connections = 500; SET NAMES utf8mb4; SET NOCOUNT ON;
// SET TRANSACTION ISOLATION LEVEL ...; SET LOCAL statement_timeout = '5s'.
type SetStatement struct {
	// Scope is the scope keyword, upper-cased: GLOBAL, SESSION, LOCAL,
	// PERSIST or PERSIST_ONLY; empty when none was written.
	Scope string
	// Name is the variable or property set, as written ("search_path",
	// "@a", "@@session.sql_mode", "NAMES", "TRANSACTION", "NOCOUNT"). For a
	// list of assignments (SET @a = 1, @b = 2) it is the first one.
	Name string
	// Text is the full statement text as written.
	Text string
	Pos  models.Location
}

func (s *SetStatement) statementNode()      {}
func (s SetStatement) TokenLiteral() string { return "SET" }
func (s SetStatement) Children() []Node     { return nil }

// SQL returns the statement text as written.
func (s *SetStatement) SQL() string {
	if s == nil {
		return ""
	}
	if s.Text != "" {
		return s.Text
	}
	out := "SET"
	if s.Scope != "" {
		out += " " + s.Scope
	}
	if s.Name != "" {
		out += " " + s.Name
	}
	return out
}

// UseStatement switches the current database, schema, warehouse or role:
// USE app (MySQL, SQL Server, ClickHouse), USE [Northwind] (SQL Server),
// USE WAREHOUSE compute_wh / USE SCHEMA db.s (Snowflake).
type UseStatement struct {
	// ObjectKind is the Snowflake object kind, upper-cased: WAREHOUSE,
	// DATABASE, SCHEMA, ROLE or SECONDARY ROLES; empty for a plain USE.
	ObjectKind string
	// Name is the (possibly qualified) name switched to.
	Name string
	// Text is the full statement text as written.
	Text string
	Pos  models.Location
}

func (u *UseStatement) statementNode()      {}
func (u UseStatement) TokenLiteral() string { return "USE" }
func (u UseStatement) Children() []Node     { return nil }

// SQL returns the statement text as written. A node built without Text
// renders USE [kind] name with the name quoted where needed.
func (u *UseStatement) SQL() string {
	if u == nil {
		return ""
	}
	if u.Text != "" {
		return u.Text
	}
	out := "USE "
	if u.ObjectKind != "" {
		out += u.ObjectKind + " "
	}
	return out + QuoteQualifiedName(u.Name)
}

// CallStatement invokes a stored procedure: CALL name(arg, ...).
type CallStatement struct {
	// Name is the (possibly qualified) procedure name.
	Name string
	// Arguments are the call arguments; empty for CALL p() and CALL p.
	Arguments []Expression
	// NoParens records CALL p written without an argument list (MySQL).
	NoParens bool
	Pos      models.Location
}

func (c *CallStatement) statementNode()      {}
func (c CallStatement) TokenLiteral() string { return "CALL" }

// Children returns the call arguments.
func (c CallStatement) Children() []Node {
	if len(c.Arguments) == 0 {
		return nil
	}
	nodes := make([]Node, 0, len(c.Arguments))
	for _, a := range c.Arguments {
		if a != nil {
			nodes = append(nodes, a)
		}
	}
	return nodes
}

// SQL returns CALL name(args).
func (c *CallStatement) SQL() string {
	if c == nil {
		return ""
	}
	var buf bytes.Buffer
	buf.WriteString("CALL ")
	buf.WriteString(QuoteQualifiedName(c.Name))
	if c.NoParens && len(c.Arguments) == 0 {
		return buf.String()
	}
	buf.WriteByte('(')
	args := make([]string, 0, len(c.Arguments))
	for _, a := range c.Arguments {
		args = append(args, exprSQL(a))
	}
	buf.WriteString(strings.Join(args, ", "))
	buf.WriteByte(')')
	return buf.String()
}

// Prefix returns the keyword and object kind that precede the table name of
// a DESCRIBE statement, e.g. "DESCRIBE", "DESC" or "DESCRIBE TABLE".
func (d *DescribeStatement) Prefix() string {
	kw := d.Keyword
	if kw == "" {
		kw = "DESCRIBE"
	}
	if d.ObjectKind == "" {
		return kw
	}
	return kw + " " + d.ObjectKind
}
