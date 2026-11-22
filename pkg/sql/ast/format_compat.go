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

// This file contains backward-compatibility shims for the Format(FormatOptions)
// string methods that were removed in the refactor/move-formatting PR (#342).
// They now delegate to pkg/formatter via hooks (FormatStatementFunc, etc.) that
// pkg/formatter sets in its init() function, avoiding the import cycle:
//
//	pkg/sql/ast → pkg/formatter → pkg/sql/ast
//
// If pkg/formatter has not been imported the methods fall back to SQL() output.
// All methods are marked deprecated; callers should migrate to
// pkg/formatter.FormatStatement(), FormatExpression() or FormatAST() directly.
//
// These legacy string-returning methods cannot report target-dialect rendering
// errors and return an empty string on failure. Error-aware callers must use
// pkg/formatter.FormatStatementChecked, FormatExpressionChecked or FormatASTChecked.
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
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatASTChecked() instead.
func (a AST) Format(opts FormatOptions) string {
	if FormatASTFunc != nil {
		return FormatASTFunc(&a, opts)
	}
	return a.SQL()
}

// ─── Statement types ─────────────────────────────────────────────────────────

// Format returns the formatted SQL for this SELECT statement.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatStatementChecked() instead.
func (s *SelectStatement) Format(opts FormatOptions) string {
	return callFormatStmt(s, opts)
}

// Format returns the formatted SQL for this INSERT statement.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatStatementChecked() instead.
func (i *InsertStatement) Format(opts FormatOptions) string {
	return callFormatStmt(i, opts)
}

// Format returns the formatted SQL for this UPDATE statement.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatStatementChecked() instead.
func (u *UpdateStatement) Format(opts FormatOptions) string {
	return callFormatStmt(u, opts)
}

// Format returns the formatted SQL for this DELETE statement.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatStatementChecked() instead.
func (d *DeleteStatement) Format(opts FormatOptions) string {
	return callFormatStmt(d, opts)
}

// Format returns the formatted SQL for this CREATE TABLE statement.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatStatementChecked() instead.
func (c *CreateTableStatement) Format(opts FormatOptions) string {
	return callFormatStmt(c, opts)
}

// Format returns the formatted SQL for this ALTER TABLE statement.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatStatementChecked() instead.
func (a *AlterTableStatement) Format(opts FormatOptions) string {
	return callFormatStmt(a, opts)
}

// Format returns the formatted SQL for this CREATE INDEX statement.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatStatementChecked() instead.
func (c *CreateIndexStatement) Format(opts FormatOptions) string {
	return callFormatStmt(c, opts)
}

// Format returns the formatted SQL for this MERGE statement.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatStatementChecked() instead.
func (m *MergeStatement) Format(opts FormatOptions) string {
	return callFormatStmt(m, opts)
}

// Format returns the formatted SQL for this CREATE VIEW statement.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatStatementChecked() instead.
func (c *CreateViewStatement) Format(opts FormatOptions) string {
	return callFormatStmt(c, opts)
}

// Format returns the formatted SQL for this CREATE MATERIALIZED VIEW statement.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatStatementChecked() instead.
func (c *CreateMaterializedViewStatement) Format(opts FormatOptions) string {
	return callFormatStmt(c, opts)
}

// Format returns the formatted SQL for this REFRESH MATERIALIZED VIEW statement.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatStatementChecked() instead.
func (r *RefreshMaterializedViewStatement) Format(opts FormatOptions) string {
	return callFormatStmt(r, opts)
}

// Format returns the formatted SQL for this DROP statement.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatStatementChecked() instead.
func (d *DropStatement) Format(opts FormatOptions) string {
	return callFormatStmt(d, opts)
}

// Format returns the formatted SQL for this TRUNCATE statement.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatStatementChecked() instead.
func (t *TruncateStatement) Format(opts FormatOptions) string {
	return callFormatStmt(t, opts)
}

// Format returns the formatted SQL for this SET operation.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatStatementChecked() instead.
func (s *SetOperation) Format(opts FormatOptions) string {
	return callFormatStmt(s, opts)
}

// ─── Expression types ────────────────────────────────────────────────────────

// Format returns the formatted SQL for this CASE expression.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatExpressionChecked() instead.
func (c *CaseExpression) Format(opts FormatOptions) string {
	return callFormatExpr(c, opts)
}

// Format returns the formatted SQL for this BETWEEN expression.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatExpressionChecked() instead.
func (b *BetweenExpression) Format(opts FormatOptions) string {
	return callFormatExpr(b, opts)
}

// Format returns the formatted SQL for this IN expression.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatExpressionChecked() instead.
func (i *InExpression) Format(opts FormatOptions) string {
	return callFormatExpr(i, opts)
}

// Format returns the formatted SQL for this EXISTS expression.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatExpressionChecked() instead.
func (e *ExistsExpression) Format(opts FormatOptions) string {
	return callFormatExpr(e, opts)
}

// Format returns the formatted SQL for this subquery expression.
//
// Rendering errors return an empty string; use the checked API to report them.
//
// Deprecated: use pkg/formatter.FormatExpressionChecked() instead.
func (s *SubqueryExpression) Format(opts FormatOptions) string {
	return callFormatExpr(s, opts)
}
