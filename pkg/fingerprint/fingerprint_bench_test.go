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

package fingerprint_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/fingerprint"
)

var portableQueries = []struct{ ID, SQL string }{
	{
		ID:  "simple_select",
		SQL: "SELECT id, name FROM users",
	},
	{
		ID:  "select_where",
		SQL: "SELECT id, name, email FROM users WHERE active = 1 AND created_at > '2024-01-01' ORDER BY name LIMIT 10",
	},
	{
		ID:  "join",
		SQL: "SELECT u.id, u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE o.total > 100 ORDER BY o.total DESC LIMIT 50",
	},
	{
		ID:  "aggregate",
		SQL: "SELECT status, COUNT(*), SUM(total) FROM orders GROUP BY status HAVING COUNT(*) > 10",
	},
	{
		ID:  "subquery",
		SQL: "SELECT name FROM users WHERE id IN (SELECT user_id FROM orders WHERE total > 1000)",
	},
	{
		ID:  "cte",
		SQL: "WITH recent AS (SELECT user_id, total FROM orders WHERE total > 100) SELECT user_id, SUM(total) FROM recent GROUP BY user_id",
	},
	{
		ID:  "window",
		SQL: "SELECT name, salary, ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) FROM employees",
	},
	{
		ID: "complex",
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
		ID:  "insert",
		SQL: "INSERT INTO users (id, name, email) VALUES (1, 'alice', 'alice@example.com')",
	},
	{
		ID:  "update",
		SQL: "UPDATE users SET name = 'bob', active = 0 WHERE id = 42",
	},
	{
		ID:  "delete",
		SQL: "DELETE FROM sessions WHERE expires_at < '2024-01-01'",
	},
}

func BenchmarkNormalize(b *testing.B)   { benchmarkQueries(b, fingerprint.Normalize) }
func BenchmarkFingerprint(b *testing.B) { benchmarkQueries(b, fingerprint.Fingerprint) }
func benchmarkQueries(b *testing.B, fn func(string) (string, error)) {
	for _, q := range portableQueries {
		b.Run(q.ID, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := fn(q.SQL); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
