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

package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestTSQL_TopSelect(t *testing.T) {
	result, err := ParseWithDialect("SELECT TOP 10 id, name FROM users WHERE active = 1", keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt, ok := result.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatal("expected SelectStatement")
	}
	if stmt.Top == nil {
		t.Fatal("expected Top clause")
	}
	lit, ok2 := stmt.Top.Count.(*ast.LiteralValue)
	if !ok2 {
		t.Fatal("expected Top.Count to be LiteralValue")
	}
	if lit.Value != "10" {
		t.Errorf("expected Top.Count value '10', got %q", lit.Value)
	}
	if stmt.Top.IsPercent {
		t.Error("expected IsPercent=false")
	}
	if len(stmt.Columns) != 2 {
		t.Errorf("expected 2 columns, got %d", len(stmt.Columns))
	}
}

func TestTSQL_TopPercent(t *testing.T) {
	result, err := ParseWithDialect("SELECT TOP 50 PERCENT id, name FROM employees ORDER BY salary DESC", keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := result.Statements[0].(*ast.SelectStatement)
	if stmt.Top == nil {
		t.Fatal("expected Top clause")
	}
	lit, ok := stmt.Top.Count.(*ast.LiteralValue)
	if !ok {
		t.Fatal("expected Top.Count to be LiteralValue")
	}
	if lit.Value != "50" {
		t.Errorf("expected Top.Count value '50', got %q", lit.Value)
	}
	if !stmt.Top.IsPercent {
		t.Error("expected IsPercent=true")
	}
}

func TestTSQL_CrossApply(t *testing.T) {
	sql := `SELECT u.name, o.total
FROM users u
CROSS APPLY (
    SELECT TOP 3 total FROM orders WHERE user_id = u.id ORDER BY total DESC
) AS o`
	result, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := result.Statements[0].(*ast.SelectStatement)
	if len(stmt.Joins) != 1 {
		t.Fatalf("expected 1 join, got %d", len(stmt.Joins))
	}
	if stmt.Joins[0].Type != "CROSS APPLY" {
		t.Errorf("expected join type 'CROSS APPLY', got %q", stmt.Joins[0].Type)
	}
	if stmt.Joins[0].Right.Subquery == nil {
		t.Error("expected subquery in CROSS APPLY")
	}
	if stmt.Joins[0].Right.Alias != "o" {
		t.Errorf("expected alias 'o', got %q", stmt.Joins[0].Right.Alias)
	}
}

func TestTSQL_OuterApply(t *testing.T) {
	sql := `SELECT u.name, o.cnt
FROM users u
OUTER APPLY (
    SELECT COUNT(*) as cnt FROM orders WHERE user_id = u.id
) AS o`
	result, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := result.Statements[0].(*ast.SelectStatement)
	if len(stmt.Joins) != 1 {
		t.Fatalf("expected 1 join, got %d", len(stmt.Joins))
	}
	if stmt.Joins[0].Type != "OUTER APPLY" {
		t.Errorf("expected join type 'OUTER APPLY', got %q", stmt.Joins[0].Type)
	}
}

func TestTSQL_SquareBracketIdentifiers(t *testing.T) {
	sql := `SELECT [user_id], [first_name] FROM [dbo].[users] WHERE [active] = 1`
	result, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := result.Statements[0].(*ast.SelectStatement)
	if len(stmt.Columns) != 2 {
		t.Errorf("expected 2 columns, got %d", len(stmt.Columns))
	}
}

func TestTSQL_OffsetFetch(t *testing.T) {
	sql := `SELECT id, title FROM posts ORDER BY created_at DESC OFFSET 20 ROWS FETCH NEXT 10 ROWS ONLY`
	result, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := result.Statements[0].(*ast.SelectStatement)
	if stmt.Offset == nil || *stmt.Offset != 20 {
		t.Error("expected offset 20")
	}
	if stmt.Fetch == nil {
		t.Fatal("expected Fetch clause")
	}
	if stmt.Fetch.FetchValue == nil || *stmt.Fetch.FetchValue != 10 {
		t.Error("expected fetch 10")
	}
}

func TestTSQL_MergeStatement(t *testing.T) {
	sql := `MERGE INTO target_table AS target
USING source_table AS source
ON target.id = source.id
WHEN MATCHED THEN
    UPDATE SET target.value = source.value
WHEN NOT MATCHED THEN
    INSERT (id, value) VALUES (source.id, source.value)`
	result, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt, ok := result.Statements[0].(*ast.MergeStatement)
	if !ok {
		t.Fatal("expected MergeStatement")
	}
	if len(stmt.WhenClauses) != 2 {
		t.Errorf("expected 2 WHEN clauses, got %d", len(stmt.WhenClauses))
	}
}

func TestTSQL_InsertOutput(t *testing.T) {
	sql := `INSERT INTO users (name, email) OUTPUT INSERTED.id, INSERTED.name VALUES ('John', 'john@example.com')`
	result, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := result.Statements[0].(*ast.InsertStatement)
	if len(stmt.Output) != 2 {
		t.Errorf("expected 2 OUTPUT columns, got %d", len(stmt.Output))
	}
}

func TestTSQL_NegativeNumberInFunction(t *testing.T) {
	sql := `SELECT DATEADD(MONTH, -6, GETDATE())`
	result, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := result.Statements[0].(*ast.SelectStatement)
	// The first column should be a function call; verify the -6 arg is a UnaryExpression
	fc, ok := stmt.Columns[0].(*ast.FunctionCall)
	if !ok {
		t.Fatal("expected FunctionCall")
	}
	unary, ok := fc.Arguments[1].(*ast.UnaryExpression)
	if !ok {
		t.Fatalf("expected UnaryExpression for -6, got %T", fc.Arguments[1])
	}
	if unary.Operator != ast.Minus {
		t.Errorf("expected operator Minus, got %v", unary.Operator)
	}
}

func TestTSQL_TopWithParentheses(t *testing.T) {
	result, err := ParseWithDialect("SELECT TOP (10) id, name FROM users", keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := result.Statements[0].(*ast.SelectStatement)
	if stmt.Top == nil {
		t.Fatal("expected Top clause")
	}
	lit, ok := stmt.Top.Count.(*ast.LiteralValue)
	if !ok {
		t.Fatalf("expected LiteralValue, got %T", stmt.Top.Count)
	}
	if lit.Value != "10" {
		t.Errorf("expected '10', got %q", lit.Value)
	}
}

func TestTSQL_TargetAsColumnName(t *testing.T) {
	// TARGET should be usable as identifier in SQL Server (non-reserved keyword)
	sql := `SELECT target, source FROM my_table`
	_, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error in SQL Server dialect: %v", err)
	}
}

func TestTSQL_WithNolock(t *testing.T) {
	sql := `SELECT id, name FROM users WITH (NOLOCK) WHERE active = 1`
	result, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt, ok := result.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatal("expected SelectStatement")
	}
	if len(stmt.From) == 0 {
		t.Fatal("expected FROM clause")
	}
	if len(stmt.From[0].TableHints) != 1 {
		t.Fatalf("expected 1 table hint, got %d", len(stmt.From[0].TableHints))
	}
	if stmt.From[0].TableHints[0] != "NOLOCK" {
		t.Errorf("expected hint 'NOLOCK', got %q", stmt.From[0].TableHints[0])
	}
}

func TestTSQL_WithMultipleHints(t *testing.T) {
	sql := `SELECT id FROM orders WITH (ROWLOCK, UPDLOCK) WHERE status = 'pending'`
	result, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := result.Statements[0].(*ast.SelectStatement)
	if len(stmt.From[0].TableHints) != 2 {
		t.Fatalf("expected 2 table hints, got %d", len(stmt.From[0].TableHints))
	}
	if stmt.From[0].TableHints[0] != "ROWLOCK" {
		t.Errorf("expected hint 'ROWLOCK', got %q", stmt.From[0].TableHints[0])
	}
	if stmt.From[0].TableHints[1] != "UPDLOCK" {
		t.Errorf("expected hint 'UPDLOCK', got %q", stmt.From[0].TableHints[1])
	}
}

func TestTSQL_WithNolockAlias(t *testing.T) {
	sql := `SELECT u.id FROM users u WITH (NOLOCK) WHERE u.active = 1`
	result, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := result.Statements[0].(*ast.SelectStatement)
	if stmt.From[0].Alias != "u" {
		t.Errorf("expected alias 'u', got %q", stmt.From[0].Alias)
	}
	if len(stmt.From[0].TableHints) != 1 {
		t.Fatalf("expected 1 table hint, got %d", len(stmt.From[0].TableHints))
	}
	if stmt.From[0].TableHints[0] != "NOLOCK" {
		t.Errorf("expected hint 'NOLOCK', got %q", stmt.From[0].TableHints[0])
	}
}

func TestTSQL_TopWithTies(t *testing.T) {
	sql := `SELECT TOP 10 WITH TIES id, salary FROM employees ORDER BY salary DESC`
	result, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt, ok := result.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatal("expected SelectStatement")
	}
	if stmt.Top == nil {
		t.Fatal("expected Top clause")
	}
	lit, ok := stmt.Top.Count.(*ast.LiteralValue)
	if !ok {
		t.Fatalf("expected LiteralValue, got %T", stmt.Top.Count)
	}
	if lit.Value != "10" {
		t.Errorf("expected '10', got %q", lit.Value)
	}
	if stmt.Top.IsPercent {
		t.Error("expected IsPercent=false")
	}
	if !stmt.Top.WithTies {
		t.Error("expected WithTies=true")
	}
}

func TestTSQL_TopPercentWithTies(t *testing.T) {
	sql := `SELECT TOP (10) PERCENT WITH TIES id FROM employees ORDER BY salary DESC`
	result, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt := result.Statements[0].(*ast.SelectStatement)
	if stmt.Top == nil {
		t.Fatal("expected Top clause")
	}
	if !stmt.Top.IsPercent {
		t.Error("expected IsPercent=true")
	}
	if !stmt.Top.WithTies {
		t.Error("expected WithTies=true")
	}
}

func TestTSQL_OuterWithoutApplyError(t *testing.T) {
	sql := `SELECT * FROM users u OUTER JOIN orders o ON u.id = o.user_id`
	_, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err == nil {
		t.Fatal("expected error for OUTER without APPLY")
	}
	if !strings.Contains(err.Error(), "APPLY") {
		t.Errorf("expected error to mention APPLY, got: %v", err)
	}
}

// TestTSQL_TestdataFiles validates all testdata/mssql/ files that should parse
func TestTSQL_TestdataFiles(t *testing.T) {
	// Files that are expected to pass
	expectedPass := map[string]bool{
		"01_top_select.sql":      true,
		"02_top_percent.sql":     true,
		"03_square_brackets.sql": true,
		"04_offset_fetch.sql":    true,
		"05_merge_statement.sql": true,
		"06_cte_basic.sql":       true,
		// "07_recursive_cte.sql" uses OPTION (MAXRECURSION) - not yet supported
		"08_window_row_number.sql": true,
		"09_window_rank.sql":       true,
		"10_window_lag_lead.sql":   true,
		"11_pivot.sql":             true,
		"12_unpivot.sql":           true,
		"13_cross_apply.sql":       true,
		"14_outer_apply.sql":       true,
		"15_try_convert.sql":       true,
		"16_string_functions.sql":  true,
		"17_iif_function.sql":      true,
		"18_datepart.sql":          true,
		"19_json_functions.sql":    true,
		"20_output_clause.sql":     true,
	}

	files, err := filepath.Glob("../../../testdata/mssql/*.sql")
	if err != nil {
		t.Skipf("could not find testdata: %v", err)
	}
	if len(files) == 0 {
		// Try from repo root
		files, _ = filepath.Glob("testdata/mssql/*.sql")
	}
	if len(files) == 0 {
		t.Skip("no testdata/mssql/ files found")
	}

	for _, f := range files {
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatalf("failed to read %s: %v", name, err)
			}
			sql := strings.TrimSpace(string(data))
			_, parseErr := ParseWithDialect(sql, keywords.DialectSQLServer)
			if expectedPass[name] {
				if parseErr != nil {
					t.Errorf("expected %s to parse, got: %v", name, parseErr)
				}
			} else {
				// These are known to not yet be supported (OPTION)
				t.Logf("%s: %v (not yet supported)", name, parseErr)
			}
		})
	}
}

func TestTSQL_PivotBasic(t *testing.T) {
	sql := `SELECT * FROM (
    SELECT product, region, sales
    FROM sales_data
) AS SourceTable
PIVOT (
    SUM(sales) FOR region IN ([North], [South], [East], [West])
) AS PivotTable`

	result, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(result.Statements))
	}
	stmt, ok := result.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", result.Statements[0])
	}
	if len(stmt.From) == 0 {
		t.Fatal("expected at least one FROM reference")
	}
	ref := stmt.From[0]
	if ref.Pivot == nil {
		t.Fatal("expected Pivot clause on table reference")
	}
	if ref.Pivot.PivotColumn != "region" {
		t.Errorf("expected pivot column 'region', got %q", ref.Pivot.PivotColumn)
	}
	if len(ref.Pivot.InValues) != 4 {
		t.Errorf("expected 4 IN values, got %d", len(ref.Pivot.InValues))
	}
	expected := []string{"North", "South", "East", "West"}
	for i, v := range expected {
		if i < len(ref.Pivot.InValues) && ref.Pivot.InValues[i] != v {
			t.Errorf("IN value [%d]: expected %q, got %q", i, v, ref.Pivot.InValues[i])
		}
	}
	if ref.Pivot.AggregateFunction == nil {
		t.Error("expected aggregate function in PIVOT")
	}
	if ref.Alias != "PivotTable" {
		t.Errorf("expected alias 'PivotTable', got %q", ref.Alias)
	}
}

func TestTSQL_UnpivotBasic(t *testing.T) {
	sql := `SELECT product, region, sales FROM (
    SELECT product, north_sales, south_sales, east_sales, west_sales
    FROM regional_sales
) AS SourceTable
UNPIVOT (
    sales FOR region IN (north_sales, south_sales, east_sales, west_sales)
) AS UnpivotTable`

	result, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(result.Statements))
	}
	stmt, ok := result.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", result.Statements[0])
	}
	if len(stmt.From) == 0 {
		t.Fatal("expected at least one FROM reference")
	}
	ref := stmt.From[0]
	if ref.Unpivot == nil {
		t.Fatal("expected Unpivot clause on table reference")
	}
	if ref.Unpivot.ValueColumn != "sales" {
		t.Errorf("expected value column 'sales', got %q", ref.Unpivot.ValueColumn)
	}
	if ref.Unpivot.NameColumn != "region" {
		t.Errorf("expected name column 'region', got %q", ref.Unpivot.NameColumn)
	}
	if len(ref.Unpivot.InColumns) != 4 {
		t.Errorf("expected 4 IN columns, got %d", len(ref.Unpivot.InColumns))
	}
	expected := []string{"north_sales", "south_sales", "east_sales", "west_sales"}
	for i, v := range expected {
		if i < len(ref.Unpivot.InColumns) && ref.Unpivot.InColumns[i] != v {
			t.Errorf("IN column [%d]: expected %q, got %q", i, v, ref.Unpivot.InColumns[i])
		}
	}
	if ref.Alias != "UnpivotTable" {
		t.Errorf("expected alias 'UnpivotTable', got %q", ref.Alias)
	}
}

func TestTSQL_PivotWithoutAlias(t *testing.T) {
	sql := `SELECT * FROM sales_data PIVOT (SUM(amount) FOR quarter IN (Q1, Q2, Q3, Q4))`

	result, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt, ok := result.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", result.Statements[0])
	}
	ref := stmt.From[0]
	if ref.Pivot == nil {
		t.Fatal("expected Pivot clause")
	}
	if ref.Name != "sales_data" {
		t.Errorf("expected table name 'sales_data', got %q", ref.Name)
	}
	if ref.Pivot.PivotColumn != "quarter" {
		t.Errorf("expected pivot column 'quarter', got %q", ref.Pivot.PivotColumn)
	}
	if len(ref.Pivot.InValues) != 4 {
		t.Errorf("expected 4 IN values, got %d", len(ref.Pivot.InValues))
	}
}

func TestTSQL_PivotWithASAlias(t *testing.T) {
	sql := `SELECT * FROM t PIVOT (COUNT(id) FOR status IN (active, inactive)) AS pvt`

	result, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stmt, ok := result.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", result.Statements[0])
	}
	ref := stmt.From[0]
	if ref.Pivot == nil {
		t.Fatal("expected Pivot clause")
	}
	if ref.Alias != "pvt" {
		t.Errorf("expected alias 'pvt', got %q", ref.Alias)
	}
}

// TestPivotIdentifierInNonTSQLDialects verifies PIVOT/UNPIVOT remain valid
// identifiers in dialects that don't recognize the contextual clause.
// Regression for global-tokenizer-keyword leak.
func TestPivotIdentifierInNonTSQLDialects(t *testing.T) {
	cases := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectPostgreSQL, "SELECT pivot FROM users"},
		{keywords.DialectPostgreSQL, "SELECT unpivot FROM users"},
		{keywords.DialectMySQL, "SELECT pivot, unpivot FROM t"},
		{keywords.DialectSQLite, "SELECT pivot FROM t AS pivot"},
	}
	for _, tc := range cases {
		t.Run(string(tc.dialect)+"_"+tc.sql, func(t *testing.T) {
			if _, err := ParseWithDialect(tc.sql, tc.dialect); err != nil {
				t.Fatalf("expected pivot/unpivot to parse as identifier in %s, got: %v", tc.dialect, err)
			}
		})
	}
}
