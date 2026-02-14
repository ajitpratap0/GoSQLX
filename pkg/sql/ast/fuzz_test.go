package ast_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// FuzzFormat fuzzes the AST formatter by parsing arbitrary SQL then formatting.
// Neither parse nor format should panic — errors are fine, panics are bugs.
func FuzzFormat(f *testing.F) {
	seeds := []string{
		"SELECT 1",
		"SELECT * FROM users",
		"SELECT id, name FROM users WHERE active = TRUE",
		"SELECT DISTINCT status FROM orders",
		"SELECT * FROM users LIMIT 10 OFFSET 20",
		"SELECT * FROM users ORDER BY name DESC",
		"SELECT dept, COUNT(*) FROM emp GROUP BY dept HAVING COUNT(*) > 5",
		"SELECT COUNT(*) AS total FROM users",
		"INSERT INTO users (name, email) VALUES ('Alice', 'a@b.com')",
		"INSERT INTO users (name) VALUES ('Alice'), ('Bob')",
		"UPDATE users SET name = 'Bob' WHERE id = 1",
		"DELETE FROM users WHERE id = 1",
		"SELECT * FROM users WHERE id IN (1, 2, 3)",
		"SELECT * FROM users WHERE age BETWEEN 18 AND 65",
		"SELECT * FROM users WHERE email IS NULL",
		"SELECT * FROM users WHERE name LIKE '%alice%'",
		"SELECT * FROM users WHERE id IN (SELECT user_id FROM orders)",
		"SELECT * FROM users WHERE EXISTS (SELECT 1 FROM orders WHERE orders.user_id = users.id)",
		"SELECT CASE WHEN x > 0 THEN 'pos' ELSE 'neg' END FROM t",
		"SELECT CAST(price AS INTEGER) FROM products",
		"SELECT * FROM users LEFT JOIN orders ON users.id = orders.user_id",
		"CREATE TABLE users (id INTEGER PRIMARY KEY, name VARCHAR(255) NOT NULL)",
		"DROP TABLE IF EXISTS users CASCADE",
		"SELECT id FROM a UNION SELECT id FROM b",
		"SELECT id FROM a UNION ALL SELECT id FROM b",
		"WITH cte AS (SELECT 1) SELECT * FROM cte",
		"SELECT ROW_NUMBER() OVER (PARTITION BY a ORDER BY b) FROM t",
		"SELECT data->>'name' FROM t",
		"MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.a = s.a",
		"",
		"SELECT",
		";;;",
		"SELECT (((",
	}

	for _, s := range seeds {
		f.Add(s)
	}

	formatStyles := []ast.FormatOptions{
		ast.CompactStyle(),
		ast.ReadableStyle(),
		{KeywordCase: ast.KeywordLower, NewlinePerClause: true, IndentWidth: 4},
		{KeywordCase: ast.KeywordPreserve},
	}

	f.Fuzz(func(t *testing.T, sql string) {
		parsed, err := gosqlx.Parse(sql)
		if err != nil {
			return // parse errors are expected for fuzzed input
		}
		defer ast.ReleaseAST(parsed)

		// Format with multiple styles — must not panic
		for _, style := range formatStyles {
			_ = parsed.Format(style)
		}
	})
}
