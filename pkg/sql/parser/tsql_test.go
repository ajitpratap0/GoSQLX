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
	if stmt.Top.Count != 10 {
		t.Errorf("expected Top.Count=10, got %d", stmt.Top.Count)
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
	if stmt.Top.Count != 50 {
		t.Errorf("expected Top.Count=50, got %d", stmt.Top.Count)
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
	_, err := ParseWithDialect(sql, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestTSQL_TestdataFiles validates all testdata/mssql/ files that should parse
func TestTSQL_TestdataFiles(t *testing.T) {
	// Files that are expected to pass
	expectedPass := map[string]bool{
		"01_top_select.sql":        true,
		"02_top_percent.sql":       true,
		"03_square_brackets.sql":   true,
		"04_offset_fetch.sql":      true,
		"05_merge_statement.sql":   true,
		"06_cte_basic.sql":         true,
		// "07_recursive_cte.sql" uses OPTION (MAXRECURSION) — not yet supported
		"08_window_row_number.sql": true,
		"09_window_rank.sql":       true,
		"10_window_lag_lead.sql":   true,
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
				// These are known to not yet be supported (PIVOT, UNPIVOT, OPTION)
				t.Logf("%s: %v (not yet supported)", name, parseErr)
			}
		})
	}
}
