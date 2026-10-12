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

const inspectSelectJoinWindowSQL = `WITH recent AS (
    SELECT o.customer_id, SUM(o.total) AS spend
    FROM orders o
    WHERE o.created_at > '2024-01-01'
    GROUP BY o.customer_id
)
SELECT c.id, c.name, r.spend,
       ROW_NUMBER() OVER (PARTITION BY c.region ORDER BY r.spend DESC) AS rn,
       CASE WHEN r.spend > 1000 THEN 'gold' WHEN r.spend > 100 THEN 'silver' ELSE 'bronze' END AS tier
FROM customers c
JOIN recent r ON r.customer_id = c.id
LEFT JOIN regions g ON g.code = c.region
WHERE c.active = 1 AND c.name LIKE 'A%'
ORDER BY r.spend DESC, c.name ASC
LIMIT 50`

const inspectInsertMultirowSQL = `INSERT INTO t (a, b, c) VALUES
    (1, 'a', 1.5), (2, 'b', 2.5), (3, 'c', 3.5), (4, 'd', 4.5), (5, 'e', 5.5),
    (6, 'f', 6.5), (7, 'g', 7.5), (8, 'h', 8.5), (9, 'i', 9.5), (10, 'j', 10.5)`

// BenchmarkInspect measures one full ast.Inspect traversal of an already
// parsed tree, i.e. the per-walk cost every linter rule, security check and
// fingerprint pass pays (#557).
func BenchmarkInspect(b *testing.B) {
	cases := []struct {
		name string
		sql  string
	}{
		{"select_join_window", inspectSelectJoinWindowSQL},
		{"insert_multirow", inspectInsertMultirowSQL},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			tree, err := gosqlx.Parse(c.sql)
			if err != nil {
				b.Fatalf("parse: %v", err)
			}
			defer ast.ReleaseAST(tree)
			visited := 0
			f := func(n ast.Node) bool {
				if n != nil {
					visited++
				}
				return true
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, stmt := range tree.Statements {
					ast.Inspect(stmt, f)
				}
			}
			b.StopTimer()
			if visited == 0 {
				b.Fatal("Inspect visited no nodes")
			}
		})
	}
}
