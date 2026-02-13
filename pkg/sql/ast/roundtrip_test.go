package ast_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestRoundtrip(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{"simple select", "SELECT * FROM users"},
		{"select columns", "SELECT id, name FROM users"},
		{"select where", "SELECT id FROM users WHERE active = TRUE"},
		{"select and", "SELECT id FROM users WHERE active = TRUE AND age > 18"},
		{"select or", "SELECT id FROM users WHERE a = 1 OR b = 2"},
		{"select distinct", "SELECT DISTINCT status FROM orders"},
		{"select limit offset", "SELECT * FROM users LIMIT 10 OFFSET 20"},
		{"select order by", "SELECT * FROM users ORDER BY name"},
		{"select order by desc", "SELECT * FROM users ORDER BY name DESC"},
		{"select group by having", "SELECT dept, COUNT(*) FROM emp GROUP BY dept HAVING COUNT(*) > 5"},
		{"select alias", "SELECT COUNT(*) AS total FROM users"},
		{"insert values", "INSERT INTO users (name, email) VALUES ('Alice', 'a@b.com')"},
		{"insert multi row", "INSERT INTO users (name) VALUES ('Alice'), ('Bob')"},
		{"update simple", "UPDATE users SET name = 'Bob' WHERE id = 1"},
		{"delete simple", "DELETE FROM users WHERE id = 1"},
		{"select in list", "SELECT * FROM users WHERE id IN (1, 2, 3)"},
		{"select between", "SELECT * FROM users WHERE age BETWEEN 18 AND 65"},
		{"select is null", "SELECT * FROM users WHERE email IS NULL"},
		{"select like", "SELECT * FROM users WHERE name LIKE '%alice%'"},
		{"select subquery", "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders)"},
		{"select exists", "SELECT * FROM users WHERE EXISTS (SELECT 1 FROM orders WHERE orders.user_id = users.id)"},
		{"select case", "SELECT CASE WHEN x > 0 THEN 'pos' ELSE 'neg' END FROM t"},
		{"select cast", "SELECT CAST(price AS INTEGER) FROM products"},
		{"left join", "SELECT * FROM users LEFT JOIN orders ON users.id = orders.user_id"},
		{"inner join", "SELECT * FROM a INNER JOIN b ON a.id = b.a_id"},
		{"create table", "CREATE TABLE users (id INTEGER PRIMARY KEY, name VARCHAR(255) NOT NULL)"},
		{"drop table", "DROP TABLE IF EXISTS users CASCADE"},
		{"union", "SELECT id FROM a UNION SELECT id FROM b"},
		{"union all", "SELECT id FROM a UNION ALL SELECT id FROM b"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast1, err := gosqlx.Parse(tt.sql)
			if err != nil {
				t.Fatalf("Failed to parse original SQL %q: %v", tt.sql, err)
			}
			generated := ast1.SQL()
			if generated == "" {
				t.Fatalf("SQL() returned empty string for %q", tt.sql)
			}
			ast2, err := gosqlx.Parse(generated)
			if err != nil {
				t.Fatalf("Failed to parse generated SQL %q (from %q): %v", generated, tt.sql, err)
			}
			generated2 := ast2.SQL()
			if generated != generated2 {
				t.Errorf("Non-idempotent roundtrip:\n  original:    %s\n  generated1:  %s\n  generated2:  %s", tt.sql, generated, generated2)
			}
			if len(ast1.Statements) != len(ast2.Statements) {
				t.Errorf("Statement count mismatch: %d vs %d", len(ast1.Statements), len(ast2.Statements))
			}
		})
	}
}

func TestRoundtripAST_SQL(t *testing.T) {
	a := ast.AST{Statements: []ast.Statement{&ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "1"}}}}}
	if got := a.SQL(); got != "SELECT 1" {
		t.Errorf("AST.SQL() = %q, want %q", got, "SELECT 1")
	}
}
