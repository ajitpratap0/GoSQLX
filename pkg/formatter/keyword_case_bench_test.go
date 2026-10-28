// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// keywordCaseBenchSQL mixes the constructs whose lower-case rendering goes
// through expression slotting: CASE, BETWEEN, IN, window specs, ORDER BY,
// functions, subqueries and set operations.
const keywordCaseBenchSQL = `WITH recent AS (
  SELECT o.id, o.customer_id, o.total, o.created_at
  FROM orders o
  WHERE o.created_at BETWEEN '2024-01-01' AND '2024-12-31' AND o.status IN ('paid', 'shipped')
)
SELECT c.id, c.name,
  CASE WHEN SUM(r.total) > 1000 THEN 'gold' WHEN SUM(r.total) > 100 THEN 'silver' ELSE 'bronze' END AS tier,
  COUNT(*) AS n,
  ROW_NUMBER() OVER (PARTITION BY c.region ORDER BY SUM(r.total) DESC) AS rnk,
  COALESCE(MAX(r.created_at), NULL) AS last_order
FROM customers c
LEFT JOIN recent r ON r.customer_id = c.id
WHERE c.active = TRUE AND NOT EXISTS (SELECT 1 FROM bans b WHERE b.customer_id = c.id)
GROUP BY c.id, c.name, c.region
HAVING COUNT(*) > 2
ORDER BY tier, n DESC
LIMIT 50`

func BenchmarkFormatAST_KeywordCase(b *testing.B) {
	tree, err := gosqlx.Parse(keywordCaseBenchSQL)
	if err != nil {
		b.Fatalf("parse: %v", err)
	}
	binary, _ := scalingBinaryExpression(512, false)
	nested, _ := scalingNestedExpression(64, false)
	for _, input := range []struct {
		name string
		tree *ast.AST
	}{{"query", tree}, {"binary512", binary}, {"nested64", nested}} {
		for _, mode := range []struct {
			name string
			kc   ast.KeywordCase
		}{{"upper", ast.KeywordUpper}, {"lower", ast.KeywordLower}} {
			b.Run(input.name+"/"+mode.name, func(b *testing.B) {
				opts := ast.ReadableStyle()
				opts.KeywordCase = mode.kc
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if out := formatter.FormatAST(input.tree, opts); out == "" {
						b.Fatal("empty output")
					}
				}
			})
		}
	}
}
