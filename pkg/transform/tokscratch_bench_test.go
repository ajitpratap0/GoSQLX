// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// Queries copied from benchmarks/compare/corpus.go, which lives in a separate module.
var transformScratchBenchCorpus = []struct{ ID, Name, SQL string }{
	{
		ID:   "simple_select",
		Name: "Simple SELECT",
		SQL:  "SELECT id, name FROM users",
	},
	{
		ID:   "select_where",
		Name: "SELECT with WHERE, ORDER BY, LIMIT",
		SQL:  "SELECT id, name, email FROM users WHERE active = 1 AND created_at > '2024-01-01' ORDER BY name LIMIT 10",
	},
	{
		ID:   "join",
		Name: "Two-table JOIN",
		SQL:  "SELECT u.id, u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE o.total > 100 ORDER BY o.total DESC LIMIT 50",
	},
	{
		ID:   "aggregate",
		Name: "GROUP BY with HAVING",
		SQL:  "SELECT status, COUNT(*), SUM(total) FROM orders GROUP BY status HAVING COUNT(*) > 10",
	},
	{
		ID:   "subquery",
		Name: "IN subquery",
		SQL:  "SELECT name FROM users WHERE id IN (SELECT user_id FROM orders WHERE total > 1000)",
	},
	{
		ID:   "cte",
		Name: "Common table expression",
		SQL:  "WITH recent AS (SELECT user_id, total FROM orders WHERE total > 100) SELECT user_id, SUM(total) FROM recent GROUP BY user_id",
	},
	{
		ID:   "window",
		Name: "Window function",
		SQL:  "SELECT name, salary, ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) FROM employees",
	},
	{
		ID:   "complex",
		Name: "Multi-JOIN analytical query",
		SQL: "SELECT c.name, p.category, COUNT(o.id), SUM(oi.quantity * oi.price) " +
			"FROM customers c " +
			"JOIN orders o ON c.id = o.customer_id " +
			"JOIN order_items oi ON o.id = oi.order_id " +
			"LEFT JOIN products p ON oi.product_id = p.id " +
			"WHERE o.created_at >= '2024-01-01' AND p.category IS NOT NULL " +
			"GROUP BY c.name, p.category " +
			"HAVING SUM(oi.quantity * oi.price) > 500 " +
			"ORDER BY c.name, p.category LIMIT 100",
	},
	{
		ID:   "insert",
		Name: "INSERT VALUES",
		SQL:  "INSERT INTO users (id, name, email) VALUES (1, 'alice', 'alice@example.com')",
	},
	{
		ID:   "update",
		Name: "UPDATE with WHERE",
		SQL:  "UPDATE users SET name = 'bob', active = 0 WHERE id = 42",
	},
	{
		ID:   "delete",
		Name: "DELETE with WHERE",
		SQL:  "DELETE FROM sessions WHERE expires_at < '2024-01-01'",
	},
}

func BenchmarkTransformParse(b *testing.B) {
	for _, q := range transformScratchBenchCorpus {
		b.Run(q.ID, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tree, err := ParseSQL(q.SQL)
				if err != nil {
					b.Fatal(err)
				}
				ast.ReleaseAST(tree)
			}
		})
	}
}
