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

package ast_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// benchSQL7 is a 7-line analytical query (joins, aggregates, ORDER BY, LIMIT).
const benchSQL7 = `SELECT u.id, u.name, COUNT(o.id) AS order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
WHERE u.active = TRUE AND u.created_at > '2024-01-01'
GROUP BY u.id, u.name
HAVING COUNT(o.id) > 5
ORDER BY order_count DESC LIMIT 100`

// benchSQL15 is a 15-line query exercising CTE, IN, BETWEEN, CASE, window
// function, CAST, LIKE, IS NULL, unary NOT, LIMIT and OFFSET.
const benchSQL15 = `WITH recent AS (
    SELECT user_id, SUM(total) AS spend
    FROM orders
    WHERE status IN ('paid', 'shipped') AND created_at BETWEEN '2024-01-01' AND '2024-12-31'
    GROUP BY user_id
)
SELECT u.id, u.email,
       CASE WHEN r.spend > 1000 THEN 'vip' ELSE 'standard' END AS tier,
       ROW_NUMBER() OVER (PARTITION BY u.country ORDER BY r.spend DESC) AS rnk,
       CAST(r.spend AS INTEGER) AS spend_int
FROM users u
INNER JOIN recent r ON u.id = r.user_id
WHERE u.email LIKE '%@example.com' AND u.deleted_at IS NULL AND NOT u.banned
ORDER BY rnk, u.id
LIMIT 50 OFFSET 10`

func benchmarkSQL(b *testing.B, sql string) {
	b.Helper()
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		b.Fatalf("parse: %v", err)
	}
	out := tree.SQL()
	if out == "" {
		b.Fatal("empty SQL() output")
	}
	b.ReportMetric(float64(len(out)), "out-bytes")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tree.SQL()
	}
}

func BenchmarkSQL(b *testing.B) {
	b.Run("7line", func(b *testing.B) { benchmarkSQL(b, benchSQL7) })
	b.Run("15line", func(b *testing.B) { benchmarkSQL(b, benchSQL15) })
}

func BenchmarkSQL_Micro(b *testing.B) {
	strLit := &ast.LiteralValue{Value: "paid", Type: "string"}
	intLit := &ast.LiteralValue{Value: "1000", Type: "int"}
	bin := &ast.BinaryExpression{
		Left:     &ast.Identifier{Table: "u", Name: "a"},
		Operator: "=",
		Right:    &ast.Identifier{Table: "o", Name: "b"},
	}
	b.Run("LiteralString", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = strLit.SQL()
		}
	})
	b.Run("LiteralInt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = intLit.SQL()
		}
	})
	b.Run("BinaryExpression", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = bin.SQL()
		}
	})
}
