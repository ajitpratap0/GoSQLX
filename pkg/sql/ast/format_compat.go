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

// Package ast — backward-compatibility shims.
//
// This file re-adds Format(FormatOptions) string methods that were removed in
// the refactor/move-formatting PR (#342). They now delegate to pkg/formatter
// via the FormatStatementFunc / FormatExpressionFunc / FormatASTFunc hooks
// that pkg/formatter sets in its init() function, avoiding the import cycle
//
//	pkg/sql/ast → pkg/formatter → pkg/sql/ast
//
// If pkg/formatter has not been imported the methods fall back to SQL() output
// so that existing code continues to compile and run (with unformatted output).
//
// All methods are marked deprecated; callers should migrate to
// pkg/formatter.FormatStatement(), FormatExpression() or FormatAST() directly.
package ast

// ─── helpers ─────────────────────────────────────────────────────────────────

// callFormatStmt dispatches to the registered hook or falls back to SQL().
func callFormatStmt(s Statement, opts FormatOptions) string {
	if FormatStatementFunc != nil {
		return FormatStatementFunc(s, opts)
	}
	if sql, ok := s.(interface{ SQL() string }); ok {
		return sql.SQL()
	}
	return ""
}

// callFormatExpr dispatches to the registered hook or falls back to SQL().
func callFormatExpr(e Expression, opts FormatOptions) string {
	if FormatExpressionFunc != nil {
		return FormatExpressionFunc(e, opts)
	}
	if sql, ok := e.(interface{ SQL() string }); ok {
		return sql.SQL()
	}
	return ""
}

// ─── AST ─────────────────────────────────────────────────────────────────────

// Format returns the formatted SQL for the full AST.
//
// Deprecated: use pkg/formatter.FormatAST() instead.
func (a AST) Format(opts FormatOptions) string {
	if FormatASTFunc != nil {
		return FormatASTFunc(&a, opts)
	}
	return a.SQL()
}

// ─── Statement types ─────────────────────────────────────────────────────────

// Format returns the formatted SQL for this SELECT statement.
//
// Deprecated: use pkg/formatter.FormatStatement() instead.
func (s *SelectStatement) Format(opts FormatOptions) string {
	return callFormatStmt(s, opts)
}

// Format returns the formatted SQL for this INSERT statement.
//
// Deprecated: use pkg/formatter.FormatStatement() instead.
func (i *InsertStatement) Format(opts FormatOptions) string {
	return callFormatStmt(i, opts)
}

// Format returns the formatted SQL for this UPDATE statement.
//
// Deprecated: use pkg/formatter.FormatStatement() instead.
func (u *UpdateStatement) Format(opts FormatOptions) string {
	return callFormatStmt(u, opts)
}

// Format returns the formatted SQL for this DELETE statement.
//
// Deprecated: use pkg/formatter.FormatStatement() instead.
func (d *DeleteStatement) Format(opts FormatOptions) string {
	return callFormatStmt(d, opts)
}

// Format returns the formatted SQL for this CREATE TABLE statement.
//
// Deprecated: use pkg/formatter.FormatStatement() instead.
func (c *CreateTableStatement) Format(opts FormatOptions) string {
	return callFormatStmt(c, opts)
}

// Format returns the formatted SQL for this ALTER TABLE statement.
//
// Deprecated: use pkg/formatter.FormatStatement() instead.
func (a *AlterTableStatement) Format(opts FormatOptions) string {
	return callFormatStmt(a, opts)
}

// Format returns the formatted SQL for this CREATE INDEX statement.
//
// Deprecated: use pkg/formatter.FormatStatement() instead.
func (c *CreateIndexStatement) Format(opts FormatOptions) string {
	return callFormatStmt(c, opts)
}

// Format returns the formatted SQL for this MERGE statement.
//
// Deprecated: use pkg/formatter.FormatStatement() instead.
func (m *MergeStatement) Format(opts FormatOptions) string {
	return callFormatStmt(m, opts)
}

// Format returns the formatted SQL for this CREATE VIEW statement.
//
// Deprecated: use pkg/formatter.FormatStatement() instead.
func (c *CreateViewStatement) Format(opts FormatOptions) string {
	return callFormatStmt(c, opts)
}

// Format returns the formatted SQL for this CREATE MATERIALIZED VIEW statement.
//
// Deprecated: use pkg/formatter.FormatStatement() instead.
func (c *CreateMaterializedViewStatement) Format(opts FormatOptions) string {
	return callFormatStmt(c, opts)
}

// Format returns the formatted SQL for this REFRESH MATERIALIZED VIEW statement.
//
// Deprecated: use pkg/formatter.FormatStatement() instead.
func (r *RefreshMaterializedViewStatement) Format(opts FormatOptions) string {
	return callFormatStmt(r, opts)
}

// Format returns the formatted SQL for this DROP statement.
//
// Deprecated: use pkg/formatter.FormatStatement() instead.
func (d *DropStatement) Format(opts FormatOptions) string {
	return callFormatStmt(d, opts)
}

// Format returns the formatted SQL for this TRUNCATE statement.
//
// Deprecated: use pkg/formatter.FormatStatement() instead.
func (t *TruncateStatement) Format(opts FormatOptions) string {
	return callFormatStmt(t, opts)
}

// Format returns the formatted SQL for this SET operation.
//
// Deprecated: use pkg/formatter.FormatStatement() instead.
func (s *SetOperation) Format(opts FormatOptions) string {
	return callFormatStmt(s, opts)
}

// ─── Expression types ────────────────────────────────────────────────────────

// Format returns the formatted SQL for this CASE expression.
//
// Deprecated: use pkg/formatter.FormatExpression() instead.
func (c *CaseExpression) Format(opts FormatOptions) string {
	return callFormatExpr(c, opts)
}

// Format returns the formatted SQL for this BETWEEN expression.
//
// Deprecated: use pkg/formatter.FormatExpression() instead.
func (b *BetweenExpression) Format(opts FormatOptions) string {
	return callFormatExpr(b, opts)
}

// Format returns the formatted SQL for this IN expression.
//
// Deprecated: use pkg/formatter.FormatExpression() instead.
func (i *InExpression) Format(opts FormatOptions) string {
	return callFormatExpr(i, opts)
}

// Format returns the formatted SQL for this EXISTS expression.
//
// Deprecated: use pkg/formatter.FormatExpression() instead.
func (e *ExistsExpression) Format(opts FormatOptions) string {
	return callFormatExpr(e, opts)
}

// Format returns the formatted SQL for this subquery expression.
//
// Deprecated: use pkg/formatter.FormatExpression() instead.
func (s *SubqueryExpression) Format(opts FormatOptions) string {
	return callFormatExpr(s, opts)
}
