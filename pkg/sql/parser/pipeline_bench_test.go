package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// BenchmarkFullPipeline benchmarks the complete SQL processing pipeline:
// tokenize → convert → parse for various query complexities.
func BenchmarkFullPipeline(b *testing.B) {
	queries := map[string]string{
		"simple_select":   "SELECT id, name FROM users WHERE active = true",
		"join":            "SELECT u.name, o.total FROM users u INNER JOIN orders o ON u.id = o.user_id WHERE o.status = 'completed'",
		"aggregate":       "SELECT department, COUNT(*) as cnt, AVG(salary) as avg_sal FROM employees GROUP BY department HAVING COUNT(*) > 5 ORDER BY avg_sal DESC",
		"subquery":        "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders WHERE total > 100)",
		"cte":             "WITH active_users AS (SELECT id, name FROM users WHERE active = true) SELECT au.name, COUNT(o.id) FROM active_users au JOIN orders o ON au.id = o.user_id GROUP BY au.name",
		"window_function": "SELECT name, salary, ROW_NUMBER() OVER (PARTITION BY department ORDER BY salary DESC) as rank FROM employees",
		"insert":          "INSERT INTO users (name, email, active) VALUES ('John', 'john@example.com', true)",
		"update":          "UPDATE users SET name = 'Jane', updated_at = NOW() WHERE id = 42",
		"delete":          "DELETE FROM sessions WHERE expires_at < NOW()",
		"complex":         "SELECT u.id, u.name, o.total, ROW_NUMBER() OVER (PARTITION BY u.id ORDER BY o.created_at DESC) as rn FROM users u LEFT JOIN orders o ON u.id = o.user_id WHERE u.active = true AND o.total > 50 ORDER BY u.name, o.total DESC LIMIT 100",
	}

	for name, sql := range queries {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			sqlBytes := []byte(sql)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Step 1: Tokenize
				tkz := tokenizer.GetTokenizer()
				tokens, err := tkz.Tokenize(sqlBytes)
				tokenizer.PutTokenizer(tkz)
				if err != nil {
					b.Fatal(err)
				}

				// Step 2: Convert
				converter := NewTokenConverter()
				result, err := converter.Convert(tokens)
				if err != nil {
					b.Fatal(err)
				}

				// Step 3: Parse
				p := NewParser()
				_, err = p.ParseWithPositions(result)
				p.Release()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkParseError benchmarks error handling performance for invalid SQL.
func BenchmarkParseError(b *testing.B) {
	queries := map[string]string{
		"missing_from":       "SELECT * WHERE x = 1",
		"missing_table":      "SELECT * FROM",
		"bad_syntax":         "SELECTT * FROM users",
		"incomplete_insert":  "INSERT INTO users",
		"trailing_comma":     "SELECT a, b, FROM t",
		"unmatched_paren":    "SELECT (a + b FROM t",
		"empty":              "",
	}

	for name, sql := range queries {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			sqlBytes := []byte(sql)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tkz := tokenizer.GetTokenizer()
				tokens, err := tkz.Tokenize(sqlBytes)
				tokenizer.PutTokenizer(tkz)
				if err != nil {
					continue // tokenizer error path
				}

				converter := NewTokenConverter()
				result, err := converter.Convert(tokens)
				if err != nil {
					continue // conversion error path
				}

				p := NewParser()
				_, _ = p.ParseWithPositions(result)
				p.Release()
			}
		})
	}
}
