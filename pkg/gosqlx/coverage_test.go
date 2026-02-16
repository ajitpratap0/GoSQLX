package gosqlx

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// mustParseHelper parses SQL or fatals the test on error.
func mustParseHelper(t *testing.T, sql string) *ast.AST {
	t.Helper()
	result, err := Parse(sql)
	if err != nil {
		t.Fatalf("Parse(%q) failed: %v", sql, err)
	}
	return result
}

// TestParseWithRecovery covers the ParseWithRecovery function (previously 0%).
func TestParseWithRecovery(t *testing.T) {
	tests := []struct {
		name       string
		sql        string
		wantStmts  bool
		wantErrors bool
	}{
		{
			name:      "valid single statement",
			sql:       "SELECT * FROM users",
			wantStmts: true,
		},
		{
			name:      "valid multiple statements",
			sql:       "SELECT * FROM users; SELECT * FROM orders",
			wantStmts: true,
		},
		{
			name:       "invalid SQL produces errors",
			sql:        "SELEKT * FROM users",
			wantErrors: true,
		},
		{
			name:       "mixed valid and invalid",
			sql:        "SELECT * FROM users; SELEKT * FROM orders",
			wantErrors: true,
		},
		{
			name: "empty input",
			sql:  "",
		},
		{
			name:       "unclosed string literal",
			sql:        "SELECT * FROM users WHERE name = 'unclosed",
			wantErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmts, errs := ParseWithRecovery(tt.sql)
			if tt.wantErrors && len(errs) == 0 {
				t.Error("expected errors but got none")
			}
			if tt.wantStmts && len(stmts) == 0 {
				t.Error("expected statements but got none")
			}
			// Verify parsed statement content for known-valid inputs
			if tt.name == "valid single statement" {
				if len(stmts) != 1 {
					t.Fatalf("expected 1 statement, got %d", len(stmts))
				}
				if _, ok := stmts[0].(*ast.SelectStatement); !ok {
					t.Errorf("expected *ast.SelectStatement, got %T", stmts[0])
				}
			}
			if tt.name == "valid multiple statements" {
				if len(stmts) != 2 {
					t.Fatalf("expected 2 statements, got %d", len(stmts))
				}
				for i, stmt := range stmts {
					if _, ok := stmt.(*ast.SelectStatement); !ok {
						t.Errorf("statement[%d]: expected *ast.SelectStatement, got %T", i, stmt)
					}
				}
			}
			if tt.name == "mixed valid and invalid" && len(stmts) > 0 {
				if _, ok := stmts[0].(*ast.SelectStatement); !ok {
					t.Errorf("recovered statement: expected *ast.SelectStatement, got %T", stmts[0])
				}
			}
		})
	}
}

// TestParseEdgeCases covers edge cases for Parse.
func TestParseEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		wantErr bool
	}{
		{"whitespace only", "   \t\n  ", true},
		{"very long SQL", "SELECT " + strings.Repeat("col, ", 500) + "col FROM t", false},
		{"line comment then SQL", "-- comment\nSELECT * FROM users", false},
		{"block comment then SQL", "/* block */ SELECT * FROM users", false},
		{"multi-statement", "SELECT 1; SELECT 2; SELECT 3", false},
		{"unicode quoted identifiers", `SELECT "名前" FROM "テーブル"`, false},
		{"unicode string literal", "SELECT * FROM users WHERE name = '日本語'", false},
		{"subquery", "SELECT * FROM (SELECT id FROM users) AS sub", false},
		{"CASE expression", "SELECT CASE WHEN x > 0 THEN 'pos' WHEN x < 0 THEN 'neg' ELSE 'zero' END FROM t", false},
		{"CAST expression", "SELECT CAST(x AS INTEGER) FROM t", false},
		{"BETWEEN expression", "SELECT * FROM t WHERE x BETWEEN 1 AND 10", false},
		{"IN expression", "SELECT * FROM t WHERE x IN (1, 2, 3)", false},
		{"EXISTS subquery", "SELECT * FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.id = t.id)", false},
		{"GROUP BY HAVING", "SELECT dept, COUNT(*) FROM emp GROUP BY dept HAVING COUNT(*) > 5", false},
		{"UNION", "SELECT * FROM t1 UNION SELECT * FROM t2", false},
		{"INTERSECT", "SELECT * FROM t1 INTERSECT SELECT * FROM t2", false},
		{"nested functions", "SELECT COALESCE(NULLIF(a, ''), b) FROM t", false},
		{"multiple JOINs", "SELECT * FROM a JOIN b ON a.id = b.aid LEFT JOIN c ON b.id = c.bid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Parse(tt.sql)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result == nil || len(result.Statements) == 0 {
				t.Error("expected non-empty AST")
			}
		})
	}
}

// TestValidateEdgeCases covers edge cases for Validate.
func TestValidateEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		wantErr bool
	}{
		{"empty", "", true},
		{"whitespace only", "   ", true},
		{"comment only", "-- just a comment", true},
		{"trailing semicolon", "SELECT 1;", false},
		{"CREATE TABLE", "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)", false},
		{"DROP TABLE", "DROP TABLE t", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.sql)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(%q) error = %v, wantErr %v", tt.sql, err, tt.wantErr)
			}
		})
	}
}

// TestFormatEdgeCases covers edge cases for Format.
func TestFormatEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		opts    FormatOptions
		wantErr bool
	}{
		{"whitespace only", "   ", DefaultFormatOptions(), true},
		{"custom indent", "SELECT a, b FROM t WHERE x = 1", FormatOptions{IndentSize: 8, SingleLineLimit: 40}, false},
		{"uppercase keywords", "select * from users", FormatOptions{UppercaseKeywords: true, SingleLineLimit: 80}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Format(tt.sql, tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result == "" {
				t.Error("expected non-empty result")
			}
		})
	}
}

// TestExtractEdgeCases covers more extract paths for collectFromExpression coverage.
func TestExtractEdgeCases(t *testing.T) {
	t.Run("columns from CASE", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT CASE WHEN status = 'active' THEN name ELSE email END FROM users")
		cols := ExtractColumns(r)
		if len(cols) == 0 {
			t.Error("expected columns")
		}
	})

	t.Run("columns from CAST", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT CAST(age AS TEXT) FROM users")
		cols := ExtractColumns(r)
		if len(cols) == 0 {
			t.Error("expected columns from CAST expression")
		}
	})

	t.Run("columns from IN", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT * FROM t WHERE status IN ('a', 'b', 'c')")
		cols := ExtractColumns(r)
		if len(cols) == 0 {
			t.Error("expected columns from IN expression")
		}
	})

	t.Run("columns from BETWEEN", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT * FROM t WHERE age BETWEEN min_age AND max_age")
		cols := ExtractColumns(r)
		if len(cols) == 0 {
			t.Error("expected columns from BETWEEN expression")
		}
	})

	t.Run("columns from unary NOT", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT * FROM t WHERE NOT active")
		cols := ExtractColumns(r)
		if len(cols) == 0 {
			t.Error("expected columns from NOT expression")
		}
	})

	t.Run("tables from UNION", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT * FROM t1 UNION SELECT * FROM t2")
		tables := ExtractTables(r)
		if len(tables) < 2 {
			t.Errorf("expected >= 2 tables, got %d", len(tables))
		}
	})

	t.Run("tables from subquery", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT * FROM (SELECT * FROM inner_t) AS sub JOIN outer_t ON sub.id = outer_t.id")
		tables := ExtractTables(r)
		if len(tables) == 0 {
			t.Error("expected tables")
		}
	})

	t.Run("functions from nested calls", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT COALESCE(NULLIF(a, ''), UPPER(b)) FROM t")
		fns := ExtractFunctions(r)
		if len(fns) < 2 {
			t.Errorf("expected >= 2 functions, got %d", len(fns))
		}
	})

	t.Run("qualified columns", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id")
		cols := ExtractColumnsQualified(r)
		if len(cols) == 0 {
			t.Error("expected qualified columns")
		}
	})

	t.Run("qualified tables", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT * FROM t1 JOIN t2 ON t1.id = t2.fk")
		tables := ExtractTablesQualified(r)
		if len(tables) == 0 {
			t.Error("expected qualified tables")
		}
	})

	t.Run("metadata", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT u.name, COUNT(*) FROM users u WHERE u.active = true GROUP BY u.name")
		meta := ExtractMetadata(r)
		if len(meta.Tables) == 0 {
			t.Error("expected tables")
		}
	})

	t.Run("DELETE", func(t *testing.T) {
		r := mustParseHelper(t, "DELETE FROM users WHERE created_at < '2020-01-01'")
		tables := ExtractTables(r)
		if len(tables) == 0 {
			t.Error("expected tables")
		}
	})

	t.Run("UPDATE", func(t *testing.T) {
		r := mustParseHelper(t, "UPDATE users SET name = 'test', email = 'x@x.com' WHERE id = 1")
		cols := ExtractColumns(r)
		if len(cols) == 0 {
			t.Error("expected columns from UPDATE")
		}
	})

	t.Run("INSERT", func(t *testing.T) {
		r := mustParseHelper(t, "INSERT INTO users (name, email) VALUES ('test', 'x@x.com')")
		tables := ExtractTables(r)
		if len(tables) == 0 {
			t.Error("expected tables")
		}
	})

	t.Run("aliased expressions", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT name AS user_name, age AS user_age FROM users")
		cols := ExtractColumns(r)
		if len(cols) == 0 {
			t.Error("expected columns from aliased expressions")
		}
	})

	t.Run("qualified columns complex", func(t *testing.T) {
		r := mustParseHelper(t, `SELECT u.name, CASE WHEN u.age > 18 THEN 'adult' ELSE 'minor' END,
			CAST(u.salary AS TEXT) FROM users u`)
		cols := ExtractColumnsQualified(r)
		if len(cols) == 0 {
			t.Error("expected qualified columns from complex query")
		}
	})

	t.Run("function with filter", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT COUNT(*) FILTER (WHERE active) FROM users")
		cols := ExtractColumns(r)
		if len(cols) == 0 {
			t.Error("expected columns from FILTER expression")
		}
	})

	t.Run("multiple function calls", func(t *testing.T) {
		r := mustParseHelper(t, `SELECT UPPER(name), LOWER(email), LENGTH(name) FROM users`)
		fns := ExtractFunctions(r)
		if len(fns) < 3 {
			t.Errorf("expected >= 3 functions, got %d", len(fns))
		}
		cols := ExtractColumns(r)
		if len(cols) == 0 {
			t.Error("expected columns from function arguments")
		}
	})

	// Cover INSERT/UPDATE/DELETE/CTE/SetOperation paths in all collectors
	t.Run("qualified cols from INSERT with SELECT", func(t *testing.T) {
		r := mustParseHelper(t, "INSERT INTO t2 (name) SELECT name FROM t1 WHERE id > 0")
		cols := ExtractColumnsQualified(r)
		if len(cols) == 0 {
			t.Error("expected qualified columns from INSERT...SELECT")
		}
	})

	t.Run("qualified cols from UPDATE", func(t *testing.T) {
		r := mustParseHelper(t, "UPDATE users SET name = 'test' WHERE id = 1")
		cols := ExtractColumnsQualified(r)
		if len(cols) == 0 {
			t.Error("expected qualified columns from UPDATE")
		}
	})

	t.Run("qualified cols from DELETE", func(t *testing.T) {
		r := mustParseHelper(t, "DELETE FROM users WHERE id = 1")
		cols := ExtractColumnsQualified(r)
		if len(cols) == 0 {
			t.Error("expected qualified columns from DELETE")
		}
	})

	t.Run("qualified cols from CTE", func(t *testing.T) {
		r := mustParseHelper(t, "WITH cte AS (SELECT u.id, u.name FROM users u) SELECT cte.id FROM cte")
		cols := ExtractColumnsQualified(r)
		if len(cols) == 0 {
			t.Error("expected qualified columns from CTE")
		}
	})

	t.Run("qualified cols from UNION", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT u.name FROM users u UNION SELECT o.name FROM orders o")
		cols := ExtractColumnsQualified(r)
		if len(cols) == 0 {
			t.Error("expected qualified columns from UNION")
		}
	})

	t.Run("functions from INSERT with values", func(t *testing.T) {
		r := mustParseHelper(t, "INSERT INTO t (name) VALUES (UPPER('test'))")
		fns := ExtractFunctions(r)
		if len(fns) == 0 {
			t.Error("expected functions from INSERT VALUES")
		}
	})

	t.Run("functions from UPDATE", func(t *testing.T) {
		r := mustParseHelper(t, "UPDATE users SET name = UPPER('test') WHERE LENGTH(name) > 5")
		fns := ExtractFunctions(r)
		if len(fns) >= 0 {
			// UPPER and LENGTH expected
			if len(fns) < 2 {
				t.Errorf("expected >= 2 functions from UPDATE, got %d", len(fns))
			}
		}
	})

	t.Run("functions from DELETE", func(t *testing.T) {
		r := mustParseHelper(t, "DELETE FROM users WHERE LENGTH(name) = 0")
		fns := ExtractFunctions(r)
		if len(fns) == 0 {
			t.Error("expected functions from DELETE WHERE")
		}
	})

	t.Run("functions from CTE", func(t *testing.T) {
		r := mustParseHelper(t, "WITH cte AS (SELECT COUNT(*) as cnt FROM users) SELECT cnt FROM cte")
		fns := ExtractFunctions(r)
		if len(fns) == 0 {
			t.Error("expected functions from CTE")
		}
	})

	t.Run("functions from UNION", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT COUNT(*) FROM t1 UNION SELECT SUM(x) FROM t2")
		fns := ExtractFunctions(r)
		if len(fns) < 2 {
			t.Errorf("expected >= 2 functions from UNION, got %d", len(fns))
		}
	})

	t.Run("functions from CASE expression", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT CASE WHEN COUNT(*) > 0 THEN MAX(x) ELSE MIN(x) END FROM t")
		fns := ExtractFunctions(r)
		if len(fns) < 2 {
			t.Errorf("expected >= 2 functions from CASE, got %d", len(fns))
		}
	})

	t.Run("functions from IN expression", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT * FROM t WHERE UPPER(name) IN ('A', 'B')")
		fns := ExtractFunctions(r)
		if len(fns) == 0 {
			t.Error("expected functions from IN expression")
		}
	})

	t.Run("functions from BETWEEN", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT * FROM t WHERE ABS(x) BETWEEN 0 AND 100")
		fns := ExtractFunctions(r)
		if len(fns) == 0 {
			t.Error("expected functions from BETWEEN expression")
		}
	})

	t.Run("tables from CTE", func(t *testing.T) {
		r := mustParseHelper(t, "WITH cte AS (SELECT * FROM users) SELECT * FROM cte")
		tables := ExtractTables(r)
		if len(tables) == 0 {
			t.Error("expected tables from CTE")
		}
	})

	t.Run("tables from INSERT", func(t *testing.T) {
		r := mustParseHelper(t, "INSERT INTO t2 (name) SELECT name FROM t1")
		tables := ExtractTables(r)
		if len(tables) < 2 {
			t.Errorf("expected >= 2 tables from INSERT...SELECT, got %d", len(tables))
		}
	})

	t.Run("tables from UPDATE with subquery in WHERE", func(t *testing.T) {
		r := mustParseHelper(t, "UPDATE users SET active = true WHERE id IN (SELECT id FROM admins)")
		tables := ExtractTables(r)
		if len(tables) < 2 {
			t.Errorf("expected >= 2 tables from UPDATE with subquery, got %d", len(tables))
		}
	})

	t.Run("qualified tables from CTE", func(t *testing.T) {
		r := mustParseHelper(t, "WITH cte AS (SELECT * FROM users) SELECT * FROM cte")
		tables := ExtractTablesQualified(r)
		if len(tables) == 0 {
			t.Error("expected qualified tables from CTE")
		}
	})

	t.Run("columns from GROUP BY and HAVING", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT dept, COUNT(*) FROM emp GROUP BY dept HAVING COUNT(*) > 5")
		cols := ExtractColumns(r)
		if len(cols) == 0 {
			t.Error("expected columns from GROUP BY/HAVING")
		}
	})

	t.Run("columns from ORDER BY", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT name, age FROM users ORDER BY age DESC")
		cols := ExtractColumns(r)
		if len(cols) == 0 {
			t.Error("expected columns from ORDER BY")
		}
	})

	t.Run("qualified cols with GROUP BY HAVING ORDER BY", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT u.dept, COUNT(*) FROM users u GROUP BY u.dept HAVING COUNT(*) > 5 ORDER BY u.dept")
		cols := ExtractColumnsQualified(r)
		if len(cols) == 0 {
			t.Error("expected qualified columns from GROUP BY/HAVING/ORDER BY")
		}
	})

	t.Run("functions from HAVING and ORDER BY", func(t *testing.T) {
		r := mustParseHelper(t, "SELECT dept, COUNT(*) FROM emp GROUP BY dept HAVING SUM(salary) > 1000 ORDER BY COUNT(*)")
		fns := ExtractFunctions(r)
		if len(fns) < 2 {
			t.Errorf("expected >= 2 functions from HAVING/ORDER BY, got %d", len(fns))
		}
	})

	t.Run("nil AST", func(t *testing.T) {
		tables := ExtractTables(nil)
		if len(tables) != 0 {
			t.Error("expected empty for nil AST")
		}
		cols := ExtractColumns(nil)
		if len(cols) != 0 {
			t.Error("expected empty for nil AST")
		}
		fns := ExtractFunctions(nil)
		if len(fns) != 0 {
			t.Error("expected empty for nil AST")
		}
	})
}

// TestParseBytesEdgeCases adds more coverage for ParseBytes.
func TestParseBytesEdgeCases(t *testing.T) {
	t.Run("empty bytes", func(t *testing.T) {
		_, err := ParseBytes([]byte(""))
		if err == nil {
			t.Error("expected error for empty bytes")
		}
	})

	t.Run("nil bytes", func(t *testing.T) {
		_, err := ParseBytes(nil)
		if err == nil {
			t.Error("expected error for nil bytes")
		}
	})
}

// TestValidateMultipleEdgeCases adds coverage.
func TestValidateMultipleEdgeCases(t *testing.T) {
	t.Run("nil slice", func(t *testing.T) {
		err := ValidateMultiple(nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("empty string in slice", func(t *testing.T) {
		err := ValidateMultiple([]string{""})
		if err == nil {
			t.Error("expected error for empty SQL")
		}
	})
}

// TestParseMultipleEdgeCases adds coverage.
func TestParseMultipleEdgeCases(t *testing.T) {
	t.Run("nil slice", func(t *testing.T) {
		results, err := ParseMultiple(nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(results) != 0 {
			t.Errorf("expected empty, got %d", len(results))
		}
	})
}
