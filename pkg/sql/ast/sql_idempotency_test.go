package ast_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

// TestSQL_Idempotency verifies that parse(sql) → .SQL() → parse → .SQL() produces
// stable output: the second serialization must match the first. This ensures the
// AST→SQL roundtrip is idempotent.
func TestSQL_Idempotency(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{"simple select", "SELECT * FROM users"},
		{"select with where", "SELECT id, name FROM users WHERE active = TRUE"},
		{"select distinct", "SELECT DISTINCT status FROM orders"},
		{"select with join", "SELECT u.name FROM users u LEFT JOIN orders o ON u.id = o.user_id"},
		{"select with order limit offset", "SELECT * FROM products ORDER BY price DESC LIMIT 10 OFFSET 5"},
		{"select with group by having", "SELECT dept, COUNT(*) FROM employees GROUP BY dept HAVING COUNT(*) > 5"},
		{"insert values", "INSERT INTO users (name, email) VALUES ('Alice', 'a@b.com')"},
		{"insert multi-row", "INSERT INTO t (a) VALUES ('x'), ('y')"},
		{"update with where", "UPDATE users SET name = 'Bob' WHERE id = 1"},
		{"delete with where", "DELETE FROM users WHERE id = 1"},
		{"create table", "CREATE TABLE users (id INTEGER PRIMARY KEY, name VARCHAR(255) NOT NULL)"},
		{"drop table", "DROP TABLE IF EXISTS users CASCADE"},
		{"CTE", "WITH cte AS (SELECT * FROM t) SELECT * FROM cte"},
		{"union all", "SELECT id FROM a UNION ALL SELECT id FROM b"},
		{"between", "SELECT * FROM t WHERE x BETWEEN 1 AND 10"},
		{"in list", "SELECT * FROM t WHERE status IN ('a', 'b')"},
		{"case expression", "SELECT CASE WHEN x > 0 THEN 'pos' ELSE 'neg' END FROM t"},
		{"cast", "SELECT CAST(price AS INTEGER) FROM t"},
		{"exists subquery", "SELECT * FROM t WHERE EXISTS (SELECT 1 FROM u)"},
		{"window function", "SELECT ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) FROM t"},
		{"insert on conflict", "INSERT INTO t (a) VALUES (1) ON CONFLICT (a) DO NOTHING"},
		{"null check", "SELECT * FROM t WHERE email IS NULL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// First parse
			ast1, err := gosqlx.Parse(tt.sql)
			if err != nil {
				t.Fatalf("first parse failed: %v", err)
			}
			sql1 := ast1.SQL()

			// Second parse from serialized output
			ast2, err := gosqlx.Parse(sql1)
			if err != nil {
				t.Fatalf("second parse failed (from %q): %v", sql1, err)
			}
			sql2 := ast2.SQL()

			// The two serializations must match (idempotency)
			if sql1 != sql2 {
				t.Errorf("idempotency failure:\n  input:  %s\n  pass1:  %s\n  pass2:  %s", tt.sql, sql1, sql2)
			}
		})
	}
}
