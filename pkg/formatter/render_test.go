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

// render_test.go ports all format tests from pkg/sql/ast/format_test.go and
// pkg/sql/ast/format_coverage_test.go to use the visitor-based formatter API.
package formatter_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// ─── helper ──────────────────────────────────────────────────────────────────

func fmtStmt(stmt ast.Statement, opts ast.FormatOptions) string {
	return formatter.FormatStatement(stmt, opts)
}

func fmtExpr(expr ast.Expression, opts ast.FormatOptions) string {
	return formatter.FormatExpression(expr, opts)
}

// ─── SELECT ──────────────────────────────────────────────────────────────────

func TestRenderSelect_Compact(t *testing.T) {
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "a"}, &ast.Identifier{Name: "b"}},
		From:    []ast.TableReference{{Name: "users"}},
		Where: &ast.BinaryExpression{
			Left:     &ast.Identifier{Name: "active"},
			Operator: "=",
			Right:    &ast.LiteralValue{Value: "true"},
		},
	}

	result := fmtStmt(stmt, ast.CompactStyle())
	if strings.Contains(result, "\n") {
		t.Errorf("CompactStyle should be single line, got: %s", result)
	}
	if !strings.Contains(result, "SELECT") {
		t.Errorf("should contain SELECT, got: %s", result)
	}
	if !strings.Contains(result, "FROM users") {
		t.Errorf("should contain FROM users, got: %s", result)
	}
	if !strings.Contains(result, "WHERE") {
		t.Errorf("should contain WHERE, got: %s", result)
	}
}

func TestRenderSelect_Readable(t *testing.T) {
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "a"}, &ast.Identifier{Name: "b"}},
		From:    []ast.TableReference{{Name: "users"}},
		Where: &ast.BinaryExpression{
			Left:     &ast.Identifier{Name: "active"},
			Operator: "=",
			Right:    &ast.LiteralValue{Value: "true"},
		},
	}

	result := fmtStmt(stmt, ast.ReadableStyle())
	lines := strings.Split(result, "\n")
	if len(lines) < 3 {
		t.Errorf("ReadableStyle should have multiple lines, got %d: %s", len(lines), result)
	}
	if !strings.HasPrefix(lines[0], "SELECT") {
		t.Errorf("first line should start with SELECT, got: %s", lines[0])
	}
	if !strings.Contains(result, "FROM") {
		t.Errorf("should contain uppercase FROM, got: %s", result)
	}
	if !strings.Contains(result, "WHERE") {
		t.Errorf("should contain uppercase WHERE, got: %s", result)
	}
	if !strings.HasSuffix(strings.TrimSpace(result), ";") {
		t.Errorf("ReadableStyle should end with semicolon, got: %s", result)
	}
}

func TestRenderSelect_LowercaseKeywords(t *testing.T) {
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
		From:    []ast.TableReference{{Name: "t"}},
	}

	opts := ast.FormatOptions{KeywordCase: ast.KeywordLower, NewlinePerClause: false}
	result := fmtStmt(stmt, opts)
	if !strings.Contains(result, "select") {
		t.Errorf("should contain lowercase select, got: %s", result)
	}
	if !strings.Contains(result, "from") {
		t.Errorf("should contain lowercase from, got: %s", result)
	}
}

func TestRenderSelect_Distinct(t *testing.T) {
	stmt := &ast.SelectStatement{
		Distinct: true,
		Columns:  []ast.Expression{&ast.Identifier{Name: "a"}},
		From:     []ast.TableReference{{Name: "t"}},
	}
	result := fmtStmt(stmt, ast.CompactStyle())
	if !strings.Contains(result, "DISTINCT") {
		t.Errorf("expected DISTINCT, got: %s", result)
	}
}

func TestRenderSelect_AllClauses(t *testing.T) {
	lim := 10
	off := 5
	fv := int64(3)
	stmt := &ast.SelectStatement{
		With: &ast.WithClause{
			Recursive: true,
			CTEs: []*ast.CommonTableExpr{
				{Name: "cte", Columns: []string{"x"}, Statement: &ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "1"}}}},
			},
		},
		DistinctOnColumns: []ast.Expression{&ast.Identifier{Name: "a"}},
		Columns:           []ast.Expression{&ast.Identifier{Name: "a"}, &ast.Identifier{Name: "b"}},
		From:              []ast.TableReference{{Name: "t"}},
		Joins:             []ast.JoinClause{{Type: "INNER", Right: ast.TableReference{Name: "t2"}, Condition: &ast.Identifier{Name: "true"}}},
		Where:             &ast.Identifier{Name: "x > 0"},
		GroupBy:           []ast.Expression{&ast.Identifier{Name: "a"}},
		Having:            &ast.Identifier{Name: "count(*) > 1"},
		Windows:           []ast.WindowSpec{{Name: "w", OrderBy: []ast.OrderByExpression{{Expression: &ast.Identifier{Name: "a"}, Ascending: true}}}},
		OrderBy:           []ast.OrderByExpression{{Expression: &ast.Identifier{Name: "a"}, Ascending: false}},
		Limit:             &lim,
		Offset:            &off,
		Fetch:             &ast.FetchClause{FetchType: "FIRST", FetchValue: &fv},
		For:               &ast.ForClause{LockType: "UPDATE"},
	}

	result := fmtStmt(stmt, ast.ReadableStyle())
	for _, want := range []string{"WITH RECURSIVE", "DISTINCT ON", "FROM", "INNER JOIN", "WHERE", "GROUP BY", "HAVING", "WINDOW", "ORDER BY", "LIMIT", "OFFSET", "FETCH", "FOR UPDATE"} {
		if !strings.Contains(result, want) {
			t.Errorf("missing %q in: %s", want, result)
		}
	}
}

func TestRenderSelect_Nil(t *testing.T) {
	var stmt *ast.SelectStatement
	if fmtStmt(stmt, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

// ─── INSERT ──────────────────────────────────────────────────────────────────

func TestRenderInsert_Readable(t *testing.T) {
	stmt := &ast.InsertStatement{
		TableName: "users",
		Columns:   []ast.Expression{&ast.Identifier{Name: "name"}, &ast.Identifier{Name: "age"}},
		Values: [][]ast.Expression{
			{&ast.LiteralValue{Value: "'Alice'"}, &ast.LiteralValue{Value: "30"}},
		},
	}

	result := fmtStmt(stmt, ast.ReadableStyle())
	if !strings.Contains(result, "INSERT INTO") {
		t.Errorf("should contain INSERT INTO, got: %s", result)
	}
	if !strings.Contains(result, "VALUES") {
		t.Errorf("should contain VALUES, got: %s", result)
	}
	if !strings.HasSuffix(strings.TrimSpace(result), ";") {
		t.Errorf("should end with semicolon, got: %s", result)
	}
}

func TestRenderInsert_WithQuery(t *testing.T) {
	stmt := &ast.InsertStatement{
		With: &ast.WithClause{CTEs: []*ast.CommonTableExpr{
			{Name: "c", Statement: &ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "x"}}}},
		}},
		TableName: "t",
		Columns:   []ast.Expression{&ast.Identifier{Name: "a"}},
		Query:     &ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "x"}}},
		Returning: []ast.Expression{&ast.Identifier{Name: "id"}},
	}
	result := fmtStmt(stmt, ast.ReadableStyle())
	for _, want := range []string{"WITH", "INSERT INTO", "RETURNING"} {
		if !strings.Contains(result, want) {
			t.Errorf("missing %q in: %s", want, result)
		}
	}
}

func TestRenderInsert_OnConflict(t *testing.T) {
	stmt := &ast.InsertStatement{
		TableName: "t",
		Values:    [][]ast.Expression{{&ast.LiteralValue{Value: "1"}}},
		OnConflict: &ast.OnConflict{
			Target: []ast.Expression{&ast.Identifier{Name: "id"}},
			Action: ast.OnConflictAction{DoNothing: true},
		},
	}
	result := fmtStmt(stmt, ast.CompactStyle())
	if !strings.Contains(result, "ON CONFLICT") {
		t.Errorf("expected ON CONFLICT, got: %s", result)
	}
}

func TestRenderInsert_Nil(t *testing.T) {
	var stmt *ast.InsertStatement
	if fmtStmt(stmt, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

// ─── UPDATE ──────────────────────────────────────────────────────────────────

func TestRenderUpdate_Readable(t *testing.T) {
	stmt := &ast.UpdateStatement{
		TableName: "users",
		Assignments: []ast.UpdateExpression{
			{Column: &ast.Identifier{Name: "name"}, Value: &ast.LiteralValue{Value: "'Bob'"}},
		},
		Where: &ast.BinaryExpression{Left: &ast.Identifier{Name: "id"}, Operator: "=", Right: &ast.LiteralValue{Value: "1"}},
	}

	result := fmtStmt(stmt, ast.ReadableStyle())
	if !strings.Contains(result, "UPDATE") {
		t.Errorf("should contain UPDATE, got: %s", result)
	}
	if !strings.Contains(result, "SET") {
		t.Errorf("should contain SET, got: %s", result)
	}
	if !strings.Contains(result, "WHERE") {
		t.Errorf("should contain WHERE, got: %s", result)
	}
	lines := strings.Split(result, "\n")
	if len(lines) < 3 {
		t.Errorf("should have multiple lines, got: %s", result)
	}
}

func TestRenderUpdate_AllClauses(t *testing.T) {
	stmt := &ast.UpdateStatement{
		With: &ast.WithClause{CTEs: []*ast.CommonTableExpr{
			{Name: "c", Statement: &ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "x"}}}},
		}},
		TableName:   "t",
		Alias:       "tt",
		Assignments: []ast.UpdateExpression{{Column: &ast.Identifier{Name: "x"}, Value: &ast.LiteralValue{Value: "1"}}},
		From:        []ast.TableReference{{Name: "other"}},
		Where:       &ast.Identifier{Name: "true"},
		Returning:   []ast.Expression{&ast.Identifier{Name: "id"}},
	}
	result := fmtStmt(stmt, ast.ReadableStyle())
	for _, want := range []string{"WITH", "UPDATE t tt", "SET", "FROM", "WHERE", "RETURNING"} {
		if !strings.Contains(result, want) {
			t.Errorf("missing %q in: %s", want, result)
		}
	}
}

func TestRenderUpdate_Nil(t *testing.T) {
	var stmt *ast.UpdateStatement
	if fmtStmt(stmt, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

// ─── DELETE ──────────────────────────────────────────────────────────────────

func TestRenderDelete_Readable(t *testing.T) {
	stmt := &ast.DeleteStatement{
		TableName: "users",
		Where:     &ast.BinaryExpression{Left: &ast.Identifier{Name: "id"}, Operator: "=", Right: &ast.LiteralValue{Value: "1"}},
	}

	result := fmtStmt(stmt, ast.ReadableStyle())
	if !strings.Contains(result, "DELETE FROM") {
		t.Errorf("should contain DELETE FROM, got: %s", result)
	}
	if !strings.Contains(result, "WHERE") {
		t.Errorf("should contain WHERE, got: %s", result)
	}
}

func TestRenderDelete_AllClauses(t *testing.T) {
	stmt := &ast.DeleteStatement{
		With: &ast.WithClause{CTEs: []*ast.CommonTableExpr{
			{Name: "c", Statement: &ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "x"}}}},
		}},
		TableName: "t",
		Alias:     "tt",
		Using:     []ast.TableReference{{Name: "other"}},
		Where:     &ast.Identifier{Name: "true"},
		Returning: []ast.Expression{&ast.Identifier{Name: "id"}},
	}
	result := fmtStmt(stmt, ast.ReadableStyle())
	for _, want := range []string{"WITH", "DELETE FROM t tt", "USING", "WHERE", "RETURNING"} {
		if !strings.Contains(result, want) {
			t.Errorf("missing %q in: %s", want, result)
		}
	}
}

func TestRenderDelete_Nil(t *testing.T) {
	var stmt *ast.DeleteStatement
	if fmtStmt(stmt, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

// ─── CREATE TABLE ─────────────────────────────────────────────────────────────

func TestRenderCreateTable_Readable(t *testing.T) {
	stmt := &ast.CreateTableStatement{
		Name: "users",
		Columns: []ast.ColumnDef{
			{Name: "id", Type: "INT"},
			{Name: "name", Type: "TEXT"},
		},
	}

	result := fmtStmt(stmt, ast.ReadableStyle())
	if !strings.Contains(result, "CREATE TABLE") {
		t.Errorf("should contain CREATE TABLE, got: %s", result)
	}
	if !strings.Contains(result, "\n") {
		t.Errorf("should have newlines for readable, got: %s", result)
	}
}

func TestRenderCreateTable_AllFeatures(t *testing.T) {
	stmt := &ast.CreateTableStatement{
		Name:        "t",
		Temporary:   true,
		IfNotExists: true,
		Columns: []ast.ColumnDef{
			{Name: "id", Type: "INT"},
			{Name: "name", Type: "TEXT"},
		},
		Constraints: []ast.TableConstraint{
			{Type: "PRIMARY KEY", Columns: []string{"id"}},
		},
		Inherits:    []string{"parent"},
		PartitionBy: &ast.PartitionBy{Type: "HASH", Columns: []string{"id"}},
		Options:     []ast.TableOption{{Name: "engine", Value: "InnoDB"}},
	}

	readable := fmtStmt(stmt, ast.ReadableStyle())
	for _, want := range []string{"CREATE TEMPORARY TABLE IF NOT EXISTS", "INHERITS", "PARTITION BY"} {
		if !strings.Contains(readable, want) {
			t.Errorf("missing %q in readable: %s", want, readable)
		}
	}

	compact := fmtStmt(stmt, ast.CompactStyle())
	if strings.Contains(compact, "\n") {
		t.Errorf("compact should be single line: %s", compact)
	}
}

func TestRenderCreateTable_Nil(t *testing.T) {
	var stmt *ast.CreateTableStatement
	if fmtStmt(stmt, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

func TestRenderFormatWithTabs(t *testing.T) {
	stmt := &ast.CreateTableStatement{
		Name:    "t",
		Columns: []ast.ColumnDef{{Name: "id", Type: "INT"}},
	}
	opts := ast.FormatOptions{
		IndentStyle:      ast.IndentTabs,
		IndentWidth:      1,
		NewlinePerClause: true,
	}
	result := fmtStmt(stmt, opts)
	if !strings.Contains(result, "\t") {
		t.Errorf("should use tabs: %s", result)
	}
}

// ─── SET OPERATIONS ──────────────────────────────────────────────────────────

func TestRenderSetOperation(t *testing.T) {
	s := &ast.SetOperation{
		Left:     &ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "a"}}, From: []ast.TableReference{{Name: "t1"}}},
		Right:    &ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "b"}}, From: []ast.TableReference{{Name: "t2"}}},
		Operator: "UNION",
		All:      true,
	}
	result := fmtStmt(s, ast.ReadableStyle())
	if !strings.Contains(result, "UNION ALL") {
		t.Errorf("expected UNION ALL, got: %s", result)
	}
	if !strings.HasSuffix(strings.TrimSpace(result), ";") {
		t.Error("ReadableStyle should add semicolon")
	}

	compact := fmtStmt(s, ast.CompactStyle())
	if strings.Contains(compact, "\n") {
		t.Errorf("compact should be single line: %s", compact)
	}
}

func TestRenderSetOperation_Nil(t *testing.T) {
	var s *ast.SetOperation
	if fmtStmt(s, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

// ─── ALTER TABLE ─────────────────────────────────────────────────────────────

func TestRenderAlterTable_Readable(t *testing.T) {
	stmt := &ast.AlterTableStatement{
		Table: "users",
		Actions: []ast.AlterTableAction{
			{Type: "ADD COLUMN", ColumnDef: &ast.ColumnDef{Name: "email", Type: "VARCHAR(255)"}},
		},
	}

	result := fmtStmt(stmt, ast.ReadableStyle())
	if !strings.Contains(result, "ALTER TABLE") {
		t.Error("expected ALTER TABLE keyword")
	}
	if !strings.Contains(result, "ADD COLUMN") {
		t.Error("expected ADD COLUMN")
	}
	if !strings.Contains(result, "email") {
		t.Error("expected column name email")
	}
	if !strings.HasSuffix(result, ";") {
		t.Error("ReadableStyle should end with semicolon")
	}
}

func TestRenderAlterTable_DropColumn(t *testing.T) {
	stmt := &ast.AlterTableStatement{
		Table: "users",
		Actions: []ast.AlterTableAction{
			{Type: "DROP COLUMN", ColumnName: "age"},
		},
	}
	result := fmtStmt(stmt, ast.CompactStyle())
	if !strings.Contains(result, "DROP COLUMN age") {
		t.Errorf("expected DROP COLUMN age, got: %s", result)
	}
}

func TestRenderAlterTable_MultipleActions(t *testing.T) {
	stmt := &ast.AlterTableStatement{
		Table: "users",
		Actions: []ast.AlterTableAction{
			{Type: "ADD COLUMN", ColumnDef: &ast.ColumnDef{Name: "email", Type: "TEXT"}},
			{Type: "DROP COLUMN", ColumnName: "age"},
		},
	}
	result := fmtStmt(stmt, ast.CompactStyle())
	if !strings.Contains(result, ",") {
		t.Errorf("expected comma between actions, got: %s", result)
	}
}

func TestRenderAlterTable_Nil(t *testing.T) {
	var stmt *ast.AlterTableStatement
	if fmtStmt(stmt, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

// ─── CREATE INDEX ─────────────────────────────────────────────────────────────

func TestRenderCreateIndex_Readable(t *testing.T) {
	stmt := &ast.CreateIndexStatement{
		Unique:      true,
		IfNotExists: true,
		Name:        "idx_users_email",
		Table:       "users",
		Columns:     []ast.IndexColumn{{Column: "email", Direction: "ASC"}},
		Using:       "btree",
	}

	result := fmtStmt(stmt, ast.ReadableStyle())
	if !strings.Contains(result, "CREATE UNIQUE INDEX IF NOT EXISTS") {
		t.Errorf("expected CREATE UNIQUE INDEX IF NOT EXISTS, got: %s", result)
	}
	if !strings.Contains(result, "ON users") {
		t.Errorf("expected ON users, got: %s", result)
	}
	if !strings.Contains(result, "USING btree") {
		t.Errorf("expected USING btree, got: %s", result)
	}
	if !strings.Contains(result, "email ASC") {
		t.Errorf("expected email ASC, got: %s", result)
	}
}

func TestRenderCreateIndex_WithWhere(t *testing.T) {
	stmt := &ast.CreateIndexStatement{
		Name:    "idx_active",
		Table:   "users",
		Columns: []ast.IndexColumn{{Column: "id"}},
		Where:   &ast.BinaryExpression{Left: &ast.Identifier{Name: "active"}, Operator: "=", Right: &ast.LiteralValue{Value: "true"}},
	}
	result := fmtStmt(stmt, ast.CompactStyle())
	if !strings.Contains(result, "WHERE") {
		t.Errorf("expected WHERE clause, got: %s", result)
	}
}

func TestRenderCreateIndex_Nil(t *testing.T) {
	var stmt *ast.CreateIndexStatement
	if fmtStmt(stmt, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

func TestRenderCreateIndex_NullsLast(t *testing.T) {
	stmt := &ast.CreateIndexStatement{
		Name:    "idx_test",
		Table:   "t",
		Columns: []ast.IndexColumn{{Column: "a", NullsLast: true, Collate: "en_US"}},
	}
	result := fmtStmt(stmt, ast.ReadableStyle())
	if !strings.Contains(result, "COLLATE en_US") {
		t.Errorf("expected COLLATE, got: %s", result)
	}
	if !strings.Contains(result, "NULLS LAST") {
		t.Errorf("expected NULLS LAST, got: %s", result)
	}
}

// ─── CREATE VIEW ─────────────────────────────────────────────────────────────

func TestRenderCreateView_Readable(t *testing.T) {
	stmt := &ast.CreateViewStatement{
		OrReplace: true,
		Name:      "active_users",
		Columns:   []string{"id", "name"},
		Query: &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "id"}, &ast.Identifier{Name: "name"}},
			From:    []ast.TableReference{{Name: "users"}},
			Where:   &ast.BinaryExpression{Left: &ast.Identifier{Name: "active"}, Operator: "=", Right: &ast.LiteralValue{Value: "true"}},
		},
	}

	result := fmtStmt(stmt, ast.ReadableStyle())
	if !strings.Contains(result, "CREATE OR REPLACE VIEW") {
		t.Errorf("expected CREATE OR REPLACE VIEW, got: %s", result)
	}
	if !strings.Contains(result, "(id, name)") {
		t.Errorf("expected column list, got: %s", result)
	}
	if !strings.Contains(result, "AS") {
		t.Errorf("expected AS keyword, got: %s", result)
	}
}

func TestRenderCreateView_Nil(t *testing.T) {
	var stmt *ast.CreateViewStatement
	if fmtStmt(stmt, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

func TestRenderCreateView_WithOption(t *testing.T) {
	stmt := &ast.CreateViewStatement{
		Name:       "v",
		Query:      &ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "1"}}},
		WithOption: "WITH CHECK OPTION",
	}
	result := fmtStmt(stmt, ast.ReadableStyle())
	if !strings.Contains(result, "WITH CHECK OPTION") {
		t.Errorf("expected WITH CHECK OPTION, got: %s", result)
	}
}

// ─── CREATE MATERIALIZED VIEW ────────────────────────────────────────────────

func TestRenderCreateMaterializedView_Readable(t *testing.T) {
	withData := true
	stmt := &ast.CreateMaterializedViewStatement{
		IfNotExists: true,
		Name:        "mv_stats",
		Columns:     []string{"cnt"},
		Query: &ast.SelectStatement{
			Columns: []ast.Expression{&ast.FunctionCall{Name: "count", Arguments: []ast.Expression{&ast.Identifier{Name: "*"}}}},
			From:    []ast.TableReference{{Name: "events"}},
		},
		WithData: &withData,
	}

	result := fmtStmt(stmt, ast.ReadableStyle())
	if !strings.Contains(result, "CREATE MATERIALIZED VIEW IF NOT EXISTS") {
		t.Errorf("expected CREATE MATERIALIZED VIEW IF NOT EXISTS, got: %s", result)
	}
	if !strings.Contains(result, "WITH DATA") {
		t.Errorf("expected WITH DATA, got: %s", result)
	}
}

func TestRenderCreateMaterializedView_NoData(t *testing.T) {
	noData := false
	stmt := &ast.CreateMaterializedViewStatement{
		Name:     "mv_test",
		Query:    &ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "1"}}},
		WithData: &noData,
	}
	result := fmtStmt(stmt, ast.CompactStyle())
	if !strings.Contains(result, "WITH NO DATA") {
		t.Errorf("expected WITH NO DATA, got: %s", result)
	}
}

func TestRenderCreateMaterializedView_Nil(t *testing.T) {
	var stmt *ast.CreateMaterializedViewStatement
	if fmtStmt(stmt, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

func TestRenderCreateMaterializedView_Tablespace(t *testing.T) {
	stmt := &ast.CreateMaterializedViewStatement{
		Name:       "mv_ts",
		Query:      &ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "1"}}},
		Tablespace: "fast_ssd",
	}
	result := fmtStmt(stmt, ast.ReadableStyle())
	if !strings.Contains(result, "TABLESPACE fast_ssd") {
		t.Errorf("expected TABLESPACE, got: %s", result)
	}
}

// ─── REFRESH MATERIALIZED VIEW ───────────────────────────────────────────────

func TestRenderRefreshMaterializedView_Readable(t *testing.T) {
	withData := true
	stmt := &ast.RefreshMaterializedViewStatement{
		Concurrently: true,
		Name:         "mv_stats",
		WithData:     &withData,
	}

	result := fmtStmt(stmt, ast.ReadableStyle())
	if !strings.Contains(result, "REFRESH MATERIALIZED VIEW CONCURRENTLY") {
		t.Errorf("expected REFRESH MATERIALIZED VIEW CONCURRENTLY, got: %s", result)
	}
	if !strings.Contains(result, "WITH DATA") {
		t.Errorf("expected WITH DATA, got: %s", result)
	}
}

func TestRenderRefreshMaterializedView_Nil(t *testing.T) {
	var stmt *ast.RefreshMaterializedViewStatement
	if fmtStmt(stmt, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

// ─── DROP ─────────────────────────────────────────────────────────────────────

func TestRenderDrop_Readable(t *testing.T) {
	stmt := &ast.DropStatement{
		ObjectType:  "TABLE",
		IfExists:    true,
		Names:       []string{"users", "orders"},
		CascadeType: "CASCADE",
	}

	result := fmtStmt(stmt, ast.ReadableStyle())
	if !strings.Contains(result, "DROP TABLE IF EXISTS") {
		t.Errorf("expected DROP TABLE IF EXISTS, got: %s", result)
	}
	if !strings.Contains(result, "users, orders") {
		t.Errorf("expected multiple table names, got: %s", result)
	}
	if !strings.Contains(result, "CASCADE") {
		t.Errorf("expected CASCADE, got: %s", result)
	}
}

func TestRenderDrop_Simple(t *testing.T) {
	stmt := &ast.DropStatement{
		ObjectType: "INDEX",
		Names:      []string{"idx_test"},
	}
	result := fmtStmt(stmt, ast.CompactStyle())
	expected := "DROP INDEX idx_test"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestRenderDrop_Nil(t *testing.T) {
	var stmt *ast.DropStatement
	if fmtStmt(stmt, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

// ─── TRUNCATE ─────────────────────────────────────────────────────────────────

func TestRenderTruncate_Readable(t *testing.T) {
	stmt := &ast.TruncateStatement{
		Tables:          []string{"users", "orders"},
		RestartIdentity: true,
		CascadeType:     "CASCADE",
	}

	result := fmtStmt(stmt, ast.ReadableStyle())
	if !strings.Contains(result, "TRUNCATE TABLE") {
		t.Errorf("expected TRUNCATE TABLE, got: %s", result)
	}
	if !strings.Contains(result, "users, orders") {
		t.Errorf("expected table names, got: %s", result)
	}
	if !strings.Contains(result, "RESTART IDENTITY") {
		t.Errorf("expected RESTART IDENTITY, got: %s", result)
	}
	if !strings.Contains(result, "CASCADE") {
		t.Errorf("expected CASCADE, got: %s", result)
	}
}

func TestRenderTruncate_ContinueIdentity(t *testing.T) {
	stmt := &ast.TruncateStatement{
		Tables:           []string{"t"},
		ContinueIdentity: true,
	}
	result := fmtStmt(stmt, ast.ReadableStyle())
	if !strings.Contains(result, "CONTINUE IDENTITY") {
		t.Errorf("expected CONTINUE IDENTITY, got: %s", result)
	}
}

func TestRenderTruncate_Nil(t *testing.T) {
	var stmt *ast.TruncateStatement
	if fmtStmt(stmt, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

// ─── MERGE ───────────────────────────────────────────────────────────────────

func TestRenderMerge_Readable(t *testing.T) {
	stmt := &ast.MergeStatement{
		TargetTable: ast.TableReference{Name: "target"},
		TargetAlias: "t",
		SourceTable: ast.TableReference{Name: "source"},
		SourceAlias: "s",
		OnCondition: &ast.BinaryExpression{Left: &ast.Identifier{Name: "t.id"}, Operator: "=", Right: &ast.Identifier{Name: "s.id"}},
		WhenClauses: []*ast.MergeWhenClause{
			{
				Type: "MATCHED",
				Action: &ast.MergeAction{
					ActionType: "UPDATE",
					SetClauses: []ast.SetClause{{Column: "name", Value: &ast.Identifier{Name: "s.name"}}},
				},
			},
			{
				Type: "NOT_MATCHED",
				Action: &ast.MergeAction{
					ActionType: "INSERT",
					Columns:    []string{"id", "name"},
					Values:     []ast.Expression{&ast.Identifier{Name: "s.id"}, &ast.Identifier{Name: "s.name"}},
				},
			},
		},
	}
	result := fmtStmt(stmt, ast.ReadableStyle())
	for _, kw := range []string{"MERGE INTO", "USING", "ON", "WHEN MATCHED", "UPDATE SET", "WHEN NOT MATCHED", "INSERT", "VALUES"} {
		if !strings.Contains(result, kw) {
			t.Errorf("expected %q in:\n%s", kw, result)
		}
	}
}

func TestRenderMerge_Nil(t *testing.T) {
	var stmt *ast.MergeStatement
	if fmtStmt(stmt, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

func TestRenderMerge_Delete(t *testing.T) {
	stmt := &ast.MergeStatement{
		TargetTable: ast.TableReference{Name: "t"},
		SourceTable: ast.TableReference{Name: "s"},
		OnCondition: &ast.BinaryExpression{Left: &ast.Identifier{Name: "t.id"}, Operator: "=", Right: &ast.Identifier{Name: "s.id"}},
		WhenClauses: []*ast.MergeWhenClause{
			{Type: "MATCHED", Action: &ast.MergeAction{ActionType: "DELETE"}},
		},
	}
	result := fmtStmt(stmt, ast.ReadableStyle())
	if !strings.Contains(result, "DELETE") {
		t.Errorf("expected DELETE in:\n%s", result)
	}
}

func TestRenderMerge_DefaultValues(t *testing.T) {
	stmt := &ast.MergeStatement{
		TargetTable: ast.TableReference{Name: "t"},
		SourceTable: ast.TableReference{Name: "s"},
		OnCondition: &ast.BinaryExpression{Left: &ast.Identifier{Name: "t.id"}, Operator: "=", Right: &ast.Identifier{Name: "s.id"}},
		WhenClauses: []*ast.MergeWhenClause{
			{Type: "NOT_MATCHED", Action: &ast.MergeAction{ActionType: "INSERT", DefaultValues: true}},
		},
	}
	result := fmtStmt(stmt, ast.ReadableStyle())
	if !strings.Contains(result, "DEFAULT VALUES") {
		t.Errorf("expected DEFAULT VALUES in:\n%s", result)
	}
}

func TestRenderMerge_WhenCondition(t *testing.T) {
	stmt := &ast.MergeStatement{
		TargetTable: ast.TableReference{Name: "t"},
		SourceTable: ast.TableReference{Name: "s"},
		OnCondition: &ast.BinaryExpression{Left: &ast.Identifier{Name: "t.id"}, Operator: "=", Right: &ast.Identifier{Name: "s.id"}},
		WhenClauses: []*ast.MergeWhenClause{
			{
				Type:      "MATCHED",
				Condition: &ast.BinaryExpression{Left: &ast.Identifier{Name: "s.active"}, Operator: "=", Right: &ast.LiteralValue{Value: "true"}},
				Action:    &ast.MergeAction{ActionType: "DELETE"},
			},
		},
	}
	result := fmtStmt(stmt, ast.ReadableStyle())
	if !strings.Contains(result, "AND") {
		t.Errorf("expected AND condition in:\n%s", result)
	}
}

// ─── CASE expression ─────────────────────────────────────────────────────────

func TestRenderCase_Simple(t *testing.T) {
	expr := &ast.CaseExpression{
		Value: &ast.Identifier{Name: "status"},
		WhenClauses: []ast.WhenClause{
			{Condition: &ast.LiteralValue{Value: "1"}, Result: &ast.LiteralValue{Value: "'active'"}},
			{Condition: &ast.LiteralValue{Value: "2"}, Result: &ast.LiteralValue{Value: "'inactive'"}},
		},
		ElseClause: &ast.LiteralValue{Value: "'unknown'"},
	}
	result := fmtExpr(expr, ast.ReadableStyle())
	for _, kw := range []string{"CASE", "WHEN", "THEN", "ELSE", "END"} {
		if !strings.Contains(result, kw) {
			t.Errorf("expected %q in: %s", kw, result)
		}
	}
	if !strings.Contains(result, "status") {
		t.Errorf("expected simple CASE value in: %s", result)
	}
}

func TestRenderCase_Searched(t *testing.T) {
	expr := &ast.CaseExpression{
		WhenClauses: []ast.WhenClause{
			{Condition: &ast.BinaryExpression{Left: &ast.Identifier{Name: "x"}, Operator: ">", Right: &ast.LiteralValue{Value: "0"}}, Result: &ast.LiteralValue{Value: "'pos'"}},
		},
	}
	result := fmtExpr(expr, ast.ReadableStyle())
	if !strings.Contains(result, "CASE WHEN") {
		t.Errorf("expected searched CASE in: %s", result)
	}
}

func TestRenderCase_Nil(t *testing.T) {
	var expr *ast.CaseExpression
	if fmtExpr(expr, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

func TestRenderCase_LowerKeywords(t *testing.T) {
	expr := &ast.CaseExpression{
		WhenClauses: []ast.WhenClause{
			{Condition: &ast.LiteralValue{Value: "true"}, Result: &ast.LiteralValue{Value: "1"}},
		},
	}
	opts := ast.FormatOptions{KeywordCase: ast.KeywordLower}
	result := fmtExpr(expr, opts)
	if !strings.Contains(result, "case") || !strings.Contains(result, "when") || !strings.Contains(result, "end") {
		t.Errorf("expected lowercase keywords in: %s", result)
	}
}

// ─── BETWEEN expression ──────────────────────────────────────────────────────

func TestRenderBetween(t *testing.T) {
	expr := &ast.BetweenExpression{
		Expr:  &ast.Identifier{Name: "age"},
		Lower: &ast.LiteralValue{Value: "18"},
		Upper: &ast.LiteralValue{Value: "65"},
	}
	result := fmtExpr(expr, ast.ReadableStyle())
	expected := "age BETWEEN 18 AND 65"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestRenderBetween_Not(t *testing.T) {
	expr := &ast.BetweenExpression{
		Expr:  &ast.Identifier{Name: "age"},
		Lower: &ast.LiteralValue{Value: "18"},
		Upper: &ast.LiteralValue{Value: "65"},
		Not:   true,
	}
	result := fmtExpr(expr, ast.ReadableStyle())
	if !strings.Contains(result, "NOT BETWEEN") {
		t.Errorf("expected NOT BETWEEN in: %s", result)
	}
}

func TestRenderBetween_Nil(t *testing.T) {
	var expr *ast.BetweenExpression
	if fmtExpr(expr, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

// ─── IN expression ────────────────────────────────────────────────────────────

func TestRenderIn_Values(t *testing.T) {
	expr := &ast.InExpression{
		Expr: &ast.Identifier{Name: "id"},
		List: []ast.Expression{&ast.LiteralValue{Value: "1"}, &ast.LiteralValue{Value: "2"}, &ast.LiteralValue{Value: "3"}},
	}
	result := fmtExpr(expr, ast.ReadableStyle())
	expected := "id IN (1, 2, 3)"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestRenderIn_Not(t *testing.T) {
	expr := &ast.InExpression{
		Expr: &ast.Identifier{Name: "id"},
		List: []ast.Expression{&ast.LiteralValue{Value: "1"}},
		Not:  true,
	}
	result := fmtExpr(expr, ast.ReadableStyle())
	if !strings.Contains(result, "NOT IN") {
		t.Errorf("expected NOT IN in: %s", result)
	}
}

func TestRenderIn_Subquery(t *testing.T) {
	expr := &ast.InExpression{
		Expr: &ast.Identifier{Name: "id"},
		Subquery: &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
			From:    []ast.TableReference{{Name: "other"}},
		},
	}
	result := fmtExpr(expr, ast.ReadableStyle())
	if !strings.Contains(result, "IN (") || !strings.Contains(result, "SELECT") {
		t.Errorf("expected IN (SELECT ...) in: %s", result)
	}
}

func TestRenderIn_Nil(t *testing.T) {
	var expr *ast.InExpression
	if fmtExpr(expr, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

// ─── EXISTS expression ────────────────────────────────────────────────────────

func TestRenderExists(t *testing.T) {
	expr := &ast.ExistsExpression{
		Subquery: &ast.SelectStatement{
			Columns: []ast.Expression{&ast.LiteralValue{Value: "1"}},
			From:    []ast.TableReference{{Name: "users"}},
			Where:   &ast.BinaryExpression{Left: &ast.Identifier{Name: "active"}, Operator: "=", Right: &ast.LiteralValue{Value: "true"}},
		},
	}
	result := fmtExpr(expr, ast.ReadableStyle())
	if !strings.Contains(result, "EXISTS") || !strings.Contains(result, "SELECT") {
		t.Errorf("expected EXISTS (SELECT ...) in: %s", result)
	}
}

func TestRenderExists_Nil(t *testing.T) {
	var expr *ast.ExistsExpression
	if fmtExpr(expr, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

// ─── Subquery expression ─────────────────────────────────────────────────────

func TestRenderSubquery(t *testing.T) {
	expr := &ast.SubqueryExpression{
		Subquery: &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "max_id"}},
			From:    []ast.TableReference{{Name: "orders"}},
		},
	}
	result := fmtExpr(expr, ast.CompactStyle())
	if !strings.HasPrefix(result, "(") || !strings.HasSuffix(result, ")") {
		t.Errorf("expected wrapped in parens: %s", result)
	}
	if !strings.Contains(result, "SELECT") {
		t.Errorf("expected SELECT in: %s", result)
	}
}

func TestRenderSubquery_Nil(t *testing.T) {
	var expr *ast.SubqueryExpression
	if fmtExpr(expr, ast.CompactStyle()) != "" {
		t.Error("nil should return empty string")
	}
}

// ─── FormatAST ───────────────────────────────────────────────────────────────

func TestFormatAST_MultiStatement(t *testing.T) {
	a := &ast.AST{
		Statements: []ast.Statement{
			&ast.SelectStatement{
				Columns: []ast.Expression{&ast.Identifier{Name: "a"}},
				From:    []ast.TableReference{{Name: "t1"}},
			},
			&ast.SelectStatement{
				Columns: []ast.Expression{&ast.Identifier{Name: "b"}},
				From:    []ast.TableReference{{Name: "t2"}},
			},
		},
	}

	result := formatter.FormatAST(a, ast.CompactStyle())
	if !strings.Contains(result, "SELECT a FROM t1") {
		t.Errorf("should contain first statement, got: %s", result)
	}
	if !strings.Contains(result, "SELECT b FROM t2") {
		t.Errorf("should contain second statement, got: %s", result)
	}
}

func TestFormatAST_Nil(t *testing.T) {
	result := formatter.FormatAST(nil, ast.CompactStyle())
	if result != "" {
		t.Errorf("nil AST should return empty string, got: %q", result)
	}
}

// ─── NilStatement fallback ───────────────────────────────────────────────────

func TestFormatStatement_NilStatement(t *testing.T) {
	result := formatter.FormatStatement(nil, ast.CompactStyle())
	if result != "" {
		t.Error("nil statement should return empty string")
	}
}

// ─── keyword case ─────────────────────────────────────────────────────────────

func TestRenderKeywordCase_Upper(t *testing.T) {
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
		From:    []ast.TableReference{{Name: "t"}},
	}
	result := fmtStmt(stmt, ast.FormatOptions{KeywordCase: ast.KeywordUpper})
	if !strings.Contains(result, "SELECT") || !strings.Contains(result, "FROM") {
		t.Errorf("expected uppercase keywords, got: %s", result)
	}
}

func TestRenderKeywordCase_Lower(t *testing.T) {
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
		From:    []ast.TableReference{{Name: "t"}},
	}
	result := fmtStmt(stmt, ast.FormatOptions{KeywordCase: ast.KeywordLower})
	if !strings.Contains(result, "select") || !strings.Contains(result, "from") {
		t.Errorf("expected lowercase keywords, got: %s", result)
	}
}

// ─── roundtrip ───────────────────────────────────────────────────────────────

func TestRenderRoundtrip_CompactMatchesSQL(t *testing.T) {
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "id"}, &ast.Identifier{Name: "name"}},
		From:    []ast.TableReference{{Name: "users"}},
		Where: &ast.BinaryExpression{
			Left:     &ast.Identifier{Name: "active"},
			Operator: "=",
			Right:    &ast.LiteralValue{Value: "true"},
		},
	}

	compact := fmtStmt(stmt, ast.CompactStyle())
	sqlStr := stmt.SQL()
	if compact != sqlStr {
		t.Errorf("CompactStyle should match SQL() output\nCompact: %s\nSQL():   %s", compact, sqlStr)
	}
}
