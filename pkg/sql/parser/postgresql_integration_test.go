// Package parser - postgresql_integration_test.go
// Integration tests for PostgreSQL-specific features (LATERAL, Aggregate ORDER BY, JSON operators)

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// TestParser_PostgreSQL_IntegrationAllFeatures tests a query combining LATERAL, ORDER BY in aggregates, and JSON operators
func TestParser_PostgreSQL_IntegrationAllFeatures(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		description string
	}{
		{
			name: "LATERAL_with_JSON_and_aggregate_ORDER_BY",
			sql: `SELECT
				u.id,
				u.data ->> 'name' AS user_name,
				u.data -> 'settings' ->> 'theme' AS theme,
				recent_orders.order_list
			FROM users u
			LEFT JOIN LATERAL (
				SELECT STRING_AGG(product_name, ', ' ORDER BY order_date DESC) AS order_list
				FROM orders o
				WHERE o.user_id = u.id
				AND o.data @> '{"status": "completed"}'
			) AS recent_orders ON true
			WHERE u.data ->> 'active' = 'true'`,
			description: "Combines LATERAL JOIN, JSON operators (->>, ->, @>), and STRING_AGG with ORDER BY",
		},
		{
			name: "JSON_array_agg_with_lateral",
			sql: `SELECT
				p.id,
				p.metadata -> 'category' AS category,
				top_reviews.review_summary
			FROM products p
			LEFT JOIN LATERAL (
				SELECT ARRAY_AGG(r.rating ORDER BY r.created_at DESC NULLS LAST) AS review_summary
				FROM reviews r
				WHERE r.product_id = p.id
				AND r.data #> '{author,verified}' = 'true'
			) AS top_reviews ON true
			WHERE p.metadata @> '{"active": true}'`,
			description: "LATERAL with ARRAY_AGG ORDER BY and JSON path operators",
		},
		{
			name: "complex_json_aggregation",
			sql: `SELECT
				department,
				JSON_AGG(employee_data ORDER BY hire_date) AS employees,
				STRING_AGG(name, '; ' ORDER BY name ASC NULLS FIRST) AS employee_names
			FROM employees
			WHERE profile -> 'skills' @> '["go"]'
			GROUP BY department`,
			description: "JSON_AGG and STRING_AGG with ORDER BY and JSON containment",
		},
		{
			name: "multiple_lateral_with_json",
			sql: `SELECT
				u.id,
				u.data ->> 'email' AS email,
				orders.total_amount,
				reviews.avg_rating
			FROM users u
			LEFT JOIN LATERAL (
				SELECT SUM(amount ORDER BY order_date) AS total_amount
				FROM orders o WHERE o.user_id = u.id
			) AS orders ON true
			LEFT JOIN LATERAL (
				SELECT AVG(rating ORDER BY created_at DESC) AS avg_rating
				FROM reviews r WHERE r.user_data ->> 'user_id' = u.id
			) AS reviews ON true`,
			description: "Multiple LATERAL JOINs with JSON operators and aggregate ORDER BY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("Tokenize error: %v", err)
			}

			parser := NewParser()
			defer parser.Release()

			result, err := parser.ParseFromModelTokens(tokens)
			if err != nil {
				t.Fatalf("Parse error for %s: %v\nSQL: %s", tt.description, err, tt.sql)
			}
			defer ast.ReleaseAST(result)

			if len(result.Statements) == 0 {
				t.Fatal("Expected at least one statement")
			}

			selectStmt, ok := result.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("Expected SelectStatement, got %T", result.Statements[0])
			}

			t.Logf("✓ Successfully parsed: %s", tt.description)
			t.Logf("  Columns: %d, Joins: %d", len(selectStmt.Columns), len(selectStmt.Joins))
		})
	}
}

// BenchmarkParser_JSONOperators benchmarks JSON operator parsing performance
func BenchmarkParser_JSONOperators(b *testing.B) {
	benchmarks := []struct {
		name string
		sql  string
	}{
		{
			name: "simple_arrow",
			sql:  "SELECT data -> 'name' FROM users",
		},
		{
			name: "long_arrow",
			sql:  "SELECT data ->> 'email' FROM users",
		},
		{
			name: "chained_operators",
			sql:  "SELECT data -> 'user' -> 'profile' ->> 'email' FROM users",
		},
		{
			name: "containment_check",
			sql:  "SELECT * FROM users WHERE data @> '{\"active\": true}'",
		},
		{
			name: "path_operators",
			sql:  "SELECT data #> '{a,b,c}', data #>> '{x,y}' FROM items",
		},
		{
			name: "containment_operators",
			sql:  "SELECT * FROM users WHERE data @> '{\"email\": true}' AND data <@ '{\"admin\": false}'",
		},
		{
			name: "complex_json_query",
			sql: `SELECT
				u.data -> 'profile' ->> 'name',
				u.data #> '{settings,notifications}',
				COUNT(*) FILTER (WHERE u.data @> '{"premium": true}')
			FROM users u
			WHERE u.data ->> 'email' IS NOT NULL
			AND u.data -> 'metadata' @> '{"verified": true}'`,
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(bm.sql))
			if err != nil {
				b.Fatalf("Tokenize error: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				parser := NewParser()
				result, err := parser.ParseFromModelTokens(tokens)
				if err != nil {
					b.Fatalf("Parse error: %v", err)
				}
				ast.ReleaseAST(result)
				parser.Release()
			}
		})
	}
}

// BenchmarkParser_LateralJoin benchmarks LATERAL JOIN parsing performance
func BenchmarkParser_LateralJoin(b *testing.B) {
	sql := `SELECT u.name, recent_orders.order_date, recent_orders.total
		FROM users u
		LEFT JOIN LATERAL (
			SELECT order_date, total
			FROM orders
			WHERE user_id = u.id
			ORDER BY order_date DESC
			LIMIT 1
		) AS recent_orders ON true`

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		b.Fatalf("Tokenize error: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		parser := NewParser()
		result, err := parser.ParseFromModelTokens(tokens)
		if err != nil {
			b.Fatalf("Parse error: %v", err)
		}
		ast.ReleaseAST(result)
		parser.Release()
	}
}

// BenchmarkParser_AggregateOrderBy benchmarks aggregate ORDER BY parsing performance
func BenchmarkParser_AggregateOrderBy(b *testing.B) {
	sql := `SELECT
		STRING_AGG(name, ', ' ORDER BY name DESC NULLS LAST) AS names,
		ARRAY_AGG(value ORDER BY created_at, priority DESC) AS value_list,
		JSON_AGG(data ORDER BY timestamp) AS json_data
	FROM items
	GROUP BY category`

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		b.Fatalf("Tokenize error: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		parser := NewParser()
		result, err := parser.ParseFromModelTokens(tokens)
		if err != nil {
			b.Fatalf("Parse error: %v", err)
		}
		ast.ReleaseAST(result)
		parser.Release()
	}
}
