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

// Package parser - select_helpers_test.go
// Focused unit tests for the decomposed SELECT clause helper methods:
//   - parseDistinctModifier
//   - parseTopClause
//   - parseWhereClause
//   - parseGroupByClause
//   - parseOrderByClause
//   - parseLimitOffsetClause
//
// Each test drives the full parse pipeline (tokenize → ParseFromModelTokens) so
// that the helper method is exercised through the normal entry point, then the
// relevant sub-tree of the resulting AST is inspected.

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// parseSQLWithDialect tokenizes and parses sql using the given dialect,
// returning the first SelectStatement from the resulting AST.
func parseSQLWithDialect(t *testing.T, sql string, dialect keywords.SQLDialect) *ast.SelectStatement {
	t.Helper()
	tkz, err := tokenizer.NewWithDialect(dialect)
	if err != nil {
		t.Fatalf("tokenizer.NewWithDialect(%s): %v", dialect, err)
	}
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize(%q): %v", sql, err)
	}
	p := NewParser(WithDialect(string(dialect)))
	defer p.Release()
	result, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("parse(%q): %v", sql, err)
	}
	if len(result.Statements) == 0 {
		t.Fatalf("expected at least one statement, got none")
	}
	stmt, ok := result.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", result.Statements[0])
	}
	return stmt
}

// -----------------------------------------------------------------------------
// parseDistinctModifier
// -----------------------------------------------------------------------------

// TestParseDistinctModifier_NoDistinct ensures a plain SELECT has Distinct=false.
func TestParseDistinctModifier_NoDistinct(t *testing.T) {
	stmt := parseSQLWithDialect(t, "SELECT id FROM users", keywords.DialectPostgreSQL)
	if stmt.Distinct {
		t.Error("expected Distinct=false for plain SELECT")
	}
}

// TestParseDistinctModifier_Distinct verifies that SELECT DISTINCT sets Distinct=true.
func TestParseDistinctModifier_Distinct(t *testing.T) {
	stmt := parseSQLWithDialect(t, "SELECT DISTINCT name FROM users", keywords.DialectPostgreSQL)
	if !stmt.Distinct {
		t.Error("expected Distinct=true for SELECT DISTINCT")
	}
	if len(stmt.DistinctOnColumns) != 0 {
		t.Errorf("expected empty DistinctOnColumns, got %d entries", len(stmt.DistinctOnColumns))
	}
}

// TestParseDistinctModifier_DistinctOn verifies PostgreSQL DISTINCT ON (expr, ...).
func TestParseDistinctModifier_DistinctOn(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT DISTINCT ON (dept_id) dept_id, name FROM employees",
		keywords.DialectPostgreSQL,
	)
	if !stmt.Distinct {
		t.Error("expected Distinct=true for DISTINCT ON")
	}
	if len(stmt.DistinctOnColumns) != 1 {
		t.Errorf("expected 1 DISTINCT ON column, got %d", len(stmt.DistinctOnColumns))
	}
}

// TestParseDistinctModifier_DistinctOnMultiple checks multiple DISTINCT ON columns.
func TestParseDistinctModifier_DistinctOnMultiple(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT DISTINCT ON (dept_id, salary) dept_id, salary, name FROM employees",
		keywords.DialectPostgreSQL,
	)
	if len(stmt.DistinctOnColumns) != 2 {
		t.Errorf("expected 2 DISTINCT ON columns, got %d", len(stmt.DistinctOnColumns))
	}
}

// TestParseDistinctModifier_All checks that SELECT ALL is consumed without error
// and leaves Distinct=false.
func TestParseDistinctModifier_All(t *testing.T) {
	stmt := parseSQLWithDialect(t, "SELECT ALL id FROM users", keywords.DialectPostgreSQL)
	if stmt.Distinct {
		t.Error("SELECT ALL must not set Distinct=true")
	}
}

// -----------------------------------------------------------------------------
// parseTopClause
// -----------------------------------------------------------------------------

// TestParseTopClause_Basic checks a simple TOP n clause (SQL Server dialect).
func TestParseTopClause_Basic(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT TOP 10 id, name FROM users",
		keywords.DialectSQLServer,
	)
	if stmt.Top == nil {
		t.Fatal("expected non-nil TopClause")
	}
	if stmt.Top.IsPercent {
		t.Error("IsPercent should be false")
	}
	if stmt.Top.WithTies {
		t.Error("WithTies should be false")
	}
}

// TestParseTopClause_Percent checks TOP n PERCENT.
func TestParseTopClause_Percent(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT TOP 25 PERCENT salary FROM employees",
		keywords.DialectSQLServer,
	)
	if stmt.Top == nil {
		t.Fatal("expected non-nil TopClause")
	}
	if !stmt.Top.IsPercent {
		t.Error("expected IsPercent=true for TOP PERCENT")
	}
}

// TestParseTopClause_WithTies checks TOP n WITH TIES.
func TestParseTopClause_WithTies(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT TOP 5 WITH TIES id FROM ranked",
		keywords.DialectSQLServer,
	)
	if stmt.Top == nil {
		t.Fatal("expected non-nil TopClause")
	}
	if !stmt.Top.WithTies {
		t.Error("expected WithTies=true")
	}
}

// TestParseTopClause_AbsentInMySQL confirms TOP is absent for MySQL queries.
func TestParseTopClause_AbsentInMySQL(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT id, name FROM users LIMIT 10",
		keywords.DialectMySQL,
	)
	if stmt.Top != nil {
		t.Errorf("expected nil TopClause for MySQL, got %+v", stmt.Top)
	}
}

// TestParseTopClause_RejectedInMySQL ensures TOP causes an error in MySQL mode.
func TestParseTopClause_RejectedInMySQL(t *testing.T) {
	tkz, err := tokenizer.NewWithDialect(keywords.DialectMySQL)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := tkz.Tokenize([]byte("SELECT TOP 10 id FROM users"))
	if err != nil {
		t.Fatal(err)
	}
	p := NewParser(WithDialect(string(keywords.DialectMySQL)))
	defer p.Release()
	_, parseErr := p.ParseFromModelTokens(tokens)
	if parseErr == nil {
		t.Fatal("expected error: TOP should be rejected in MySQL dialect")
	}
}

// -----------------------------------------------------------------------------
// parseWhereClause
// -----------------------------------------------------------------------------

// TestParseWhereClause_Absent checks that Where is nil when there is no WHERE.
func TestParseWhereClause_Absent(t *testing.T) {
	stmt := parseSQLWithDialect(t, "SELECT id FROM users", keywords.DialectPostgreSQL)
	if stmt.Where != nil {
		t.Errorf("expected nil Where, got %T", stmt.Where)
	}
}

// TestParseWhereClause_SimpleEquality verifies a basic WHERE id = 1.
func TestParseWhereClause_SimpleEquality(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT id FROM users WHERE id = 1",
		keywords.DialectPostgreSQL,
	)
	if stmt.Where == nil {
		t.Fatal("expected non-nil Where clause")
	}
}

// TestParseWhereClause_AndCondition checks WHERE with AND.
func TestParseWhereClause_AndCondition(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT id FROM users WHERE active = true AND age > 18",
		keywords.DialectPostgreSQL,
	)
	if stmt.Where == nil {
		t.Fatal("expected non-nil Where clause")
	}
	if _, ok := stmt.Where.(*ast.BinaryExpression); !ok {
		t.Errorf("expected *ast.BinaryExpression for AND condition, got %T", stmt.Where)
	}
}

// TestParseWhereClause_InExpression checks WHERE id IN (1, 2, 3).
func TestParseWhereClause_InExpression(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT id FROM users WHERE id IN (1, 2, 3)",
		keywords.DialectPostgreSQL,
	)
	if stmt.Where == nil {
		t.Fatal("expected non-nil Where clause")
	}
	if _, ok := stmt.Where.(*ast.InExpression); !ok {
		t.Errorf("expected *ast.InExpression, got %T", stmt.Where)
	}
}

// TestParseWhereClause_BetweenExpression checks WHERE salary BETWEEN 1000 AND 5000.
func TestParseWhereClause_BetweenExpression(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT id FROM emp WHERE salary BETWEEN 1000 AND 5000",
		keywords.DialectPostgreSQL,
	)
	if stmt.Where == nil {
		t.Fatal("expected non-nil Where clause")
	}
	if _, ok := stmt.Where.(*ast.BetweenExpression); !ok {
		t.Errorf("expected *ast.BetweenExpression, got %T", stmt.Where)
	}
}

// -----------------------------------------------------------------------------
// parseGroupByClause
// -----------------------------------------------------------------------------

// TestParseGroupByClause_Absent checks that GroupBy is nil when there is no GROUP BY.
func TestParseGroupByClause_Absent(t *testing.T) {
	stmt := parseSQLWithDialect(t, "SELECT id FROM users", keywords.DialectPostgreSQL)
	if len(stmt.GroupBy) != 0 {
		t.Errorf("expected empty GroupBy, got %d items", len(stmt.GroupBy))
	}
}

// TestParseGroupByClause_SingleColumn checks GROUP BY single column.
func TestParseGroupByClause_SingleColumn(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT dept_id, COUNT(*) FROM employees GROUP BY dept_id",
		keywords.DialectPostgreSQL,
	)
	if len(stmt.GroupBy) != 1 {
		t.Errorf("expected 1 GROUP BY expression, got %d", len(stmt.GroupBy))
	}
}

// TestParseGroupByClause_MultipleColumns checks GROUP BY with multiple columns.
func TestParseGroupByClause_MultipleColumns(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT dept_id, job, COUNT(*) FROM emp GROUP BY dept_id, job",
		keywords.DialectPostgreSQL,
	)
	if len(stmt.GroupBy) != 2 {
		t.Errorf("expected 2 GROUP BY expressions, got %d", len(stmt.GroupBy))
	}
}

// TestParseGroupByClause_Rollup checks GROUP BY ROLLUP(...).
func TestParseGroupByClause_Rollup(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT a, b, SUM(c) FROM t GROUP BY ROLLUP(a, b)",
		keywords.DialectPostgreSQL,
	)
	if len(stmt.GroupBy) != 1 {
		t.Fatalf("expected 1 GROUP BY item (rollup), got %d", len(stmt.GroupBy))
	}
	if _, ok := stmt.GroupBy[0].(*ast.RollupExpression); !ok {
		t.Errorf("expected *ast.RollupExpression, got %T", stmt.GroupBy[0])
	}
}

// TestParseGroupByClause_WithHaving checks that HAVING is correctly separated from GROUP BY.
func TestParseGroupByClause_WithHaving(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT dept_id, COUNT(*) FROM employees GROUP BY dept_id HAVING COUNT(*) > 5",
		keywords.DialectPostgreSQL,
	)
	if len(stmt.GroupBy) != 1 {
		t.Errorf("expected 1 GROUP BY expression, got %d", len(stmt.GroupBy))
	}
	if stmt.Having == nil {
		t.Error("expected non-nil Having clause")
	}
}

// -----------------------------------------------------------------------------
// parseOrderByClause
// -----------------------------------------------------------------------------

// TestParseOrderByClause_Absent checks that OrderBy is nil when absent.
func TestParseOrderByClause_Absent(t *testing.T) {
	stmt := parseSQLWithDialect(t, "SELECT id FROM users", keywords.DialectPostgreSQL)
	if len(stmt.OrderBy) != 0 {
		t.Errorf("expected empty OrderBy, got %d items", len(stmt.OrderBy))
	}
}

// TestParseOrderByClause_Ascending checks ORDER BY col ASC.
func TestParseOrderByClause_Ascending(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT id FROM users ORDER BY name ASC",
		keywords.DialectPostgreSQL,
	)
	if len(stmt.OrderBy) != 1 {
		t.Fatalf("expected 1 ORDER BY expression, got %d", len(stmt.OrderBy))
	}
	if !stmt.OrderBy[0].Ascending {
		t.Error("expected Ascending=true for ASC")
	}
}

// TestParseOrderByClause_Descending checks ORDER BY col DESC.
func TestParseOrderByClause_Descending(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT id FROM users ORDER BY created_at DESC",
		keywords.DialectPostgreSQL,
	)
	if len(stmt.OrderBy) != 1 {
		t.Fatalf("expected 1 ORDER BY expression, got %d", len(stmt.OrderBy))
	}
	if stmt.OrderBy[0].Ascending {
		t.Error("expected Ascending=false for DESC")
	}
}

// TestParseOrderByClause_Multiple checks ORDER BY with multiple columns.
func TestParseOrderByClause_Multiple(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT id FROM users ORDER BY last_name ASC, first_name ASC",
		keywords.DialectPostgreSQL,
	)
	if len(stmt.OrderBy) != 2 {
		t.Errorf("expected 2 ORDER BY expressions, got %d", len(stmt.OrderBy))
	}
}

// TestParseOrderByClause_NullsFirst checks ORDER BY col NULLS FIRST.
func TestParseOrderByClause_NullsFirst(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT id FROM users ORDER BY score DESC NULLS FIRST",
		keywords.DialectPostgreSQL,
	)
	if len(stmt.OrderBy) != 1 {
		t.Fatalf("expected 1 ORDER BY expression, got %d", len(stmt.OrderBy))
	}
	if stmt.OrderBy[0].NullsFirst == nil {
		t.Fatal("expected NullsFirst to be set")
	}
	if !*stmt.OrderBy[0].NullsFirst {
		t.Error("expected NullsFirst=true")
	}
}

// TestParseOrderByClause_NullsLast checks ORDER BY col NULLS LAST.
func TestParseOrderByClause_NullsLast(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT id FROM users ORDER BY score ASC NULLS LAST",
		keywords.DialectPostgreSQL,
	)
	if len(stmt.OrderBy) != 1 {
		t.Fatalf("expected 1 ORDER BY expression, got %d", len(stmt.OrderBy))
	}
	if stmt.OrderBy[0].NullsFirst == nil {
		t.Fatal("expected NullsFirst to be set (NULLS LAST means false)")
	}
	if *stmt.OrderBy[0].NullsFirst {
		t.Error("expected NullsFirst=false for NULLS LAST")
	}
}

// -----------------------------------------------------------------------------
// parseLimitOffsetClause
// -----------------------------------------------------------------------------

// TestParseLimitOffsetClause_Absent checks that Limit and Offset are nil when absent.
func TestParseLimitOffsetClause_Absent(t *testing.T) {
	stmt := parseSQLWithDialect(t, "SELECT id FROM users", keywords.DialectPostgreSQL)
	if stmt.Limit != nil {
		t.Errorf("expected nil Limit, got %v", *stmt.Limit)
	}
	if stmt.Offset != nil {
		t.Errorf("expected nil Offset, got %v", *stmt.Offset)
	}
}

// TestParseLimitOffsetClause_LimitOnly checks LIMIT n.
func TestParseLimitOffsetClause_LimitOnly(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT id FROM users LIMIT 10",
		keywords.DialectPostgreSQL,
	)
	if stmt.Limit == nil {
		t.Fatal("expected non-nil Limit")
	}
	if *stmt.Limit != 10 {
		t.Errorf("expected Limit=10, got %d", *stmt.Limit)
	}
	if stmt.Offset != nil {
		t.Errorf("expected nil Offset, got %v", *stmt.Offset)
	}
}

// TestParseLimitOffsetClause_LimitAndOffset checks LIMIT n OFFSET m.
func TestParseLimitOffsetClause_LimitAndOffset(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT id FROM users LIMIT 10 OFFSET 20",
		keywords.DialectPostgreSQL,
	)
	if stmt.Limit == nil || *stmt.Limit != 10 {
		t.Errorf("expected Limit=10, got %v", stmt.Limit)
	}
	if stmt.Offset == nil || *stmt.Offset != 20 {
		t.Errorf("expected Offset=20, got %v", stmt.Offset)
	}
}

// TestParseLimitOffsetClause_OffsetOnly checks OFFSET n without LIMIT.
func TestParseLimitOffsetClause_OffsetOnly(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT id FROM users OFFSET 5",
		keywords.DialectPostgreSQL,
	)
	if stmt.Limit != nil {
		t.Errorf("expected nil Limit, got %d", *stmt.Limit)
	}
	if stmt.Offset == nil || *stmt.Offset != 5 {
		t.Errorf("expected Offset=5, got %v", stmt.Offset)
	}
}

// TestParseLimitOffsetClause_MySQLComma checks MySQL LIMIT offset, count syntax.
func TestParseLimitOffsetClause_MySQLComma(t *testing.T) {
	stmt := parseSQLWithDialect(t,
		"SELECT id FROM users LIMIT 5, 10",
		keywords.DialectMySQL,
	)
	// MySQL LIMIT 5, 10 means offset=5, limit=10
	if stmt.Limit == nil || *stmt.Limit != 10 {
		t.Errorf("expected Limit=10 (MySQL LIMIT offset, count), got %v", stmt.Limit)
	}
	if stmt.Offset == nil || *stmt.Offset != 5 {
		t.Errorf("expected Offset=5 (MySQL LIMIT offset, count), got %v", stmt.Offset)
	}
}

// TestParseLimitOffsetClause_RejectedInSQLServer confirms LIMIT is an error in SQL Server.
func TestParseLimitOffsetClause_RejectedInSQLServer(t *testing.T) {
	tkz, err := tokenizer.NewWithDialect(keywords.DialectSQLServer)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := tkz.Tokenize([]byte("SELECT id FROM users LIMIT 10"))
	if err != nil {
		t.Fatal(err)
	}
	p := NewParser(WithDialect(string(keywords.DialectSQLServer)))
	defer p.Release()
	_, parseErr := p.ParseFromModelTokens(tokens)
	if parseErr == nil {
		t.Fatal("expected error: LIMIT should be rejected in SQL Server dialect")
	}
}
