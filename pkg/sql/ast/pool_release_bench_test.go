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

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// These benchmarks measure the PutExpression release path in isolation.
// The *AfterBigList variants first release one 20,000-element IN list on the
// same goroutine (so the work queue that grew to hold it lands in this P's
// sync.Pool private slot) and then measure ordinary small releases. Before
// issue #555 every later Put cleared the whole grown queue, making a leaf
// release ~100x slower. They must not use RunParallel: the prelude and the
// loop have to share a P for the measurement to be meaningful.

const bigListLen = 20_000

func releaseBigInList() {
	in := ast.GetInExpression()
	for i := 0; i < bigListLen; i++ {
		in.List = append(in.List, ast.GetLiteralValue())
	}
	ast.PutExpression(in)
}

func putLeafLoop(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ast.PutExpression(ast.GetIdentifier())
	}
}

func putBinaryLoop(b *testing.B) {
	for i := 0; i < b.N; i++ {
		be := ast.GetBinaryExpression()
		be.Left = ast.GetIdentifier()
		be.Right = ast.GetIdentifier()
		ast.PutExpression(be)
	}
}

func BenchmarkPutLeaf(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	putLeafLoop(b)
}

func BenchmarkPutLeafAfterBigList(b *testing.B) {
	b.ReportAllocs()
	releaseBigInList()
	b.ResetTimer()
	putLeafLoop(b)
}

func BenchmarkPutBinary(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	putBinaryLoop(b)
}

func BenchmarkPutBinaryAfterBigList(b *testing.B) {
	b.ReportAllocs()
	releaseBigInList()
	b.ResetTimer()
	putBinaryLoop(b)
}

// Fixtures for the parse+release benchmarks (issue #556). drawnTypesSQL
// produces the node types the parser does draw from pools: two
// TupleExpressions, an ArrayConstructorExpression, an
// ArraySubscriptExpression and an ArraySliceExpression.
const (
	sampleJoinSQL = "SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id"
	mediumCTESQL  = `WITH recent AS (SELECT user_id, MAX(created_at) AS last_seen FROM events WHERE created_at > '2026-01-01' GROUP BY user_id)
SELECT u.id, u.name, r.last_seen,
  CASE WHEN r.last_seen > '2026-06-01' THEN 'active' WHEN r.last_seen IS NULL THEN 'never' ELSE 'stale' END AS status,
  ROW_NUMBER() OVER (PARTITION BY u.region ORDER BY r.last_seen DESC) AS rn,
  COUNT(*) OVER () AS total
FROM users u LEFT JOIN recent r ON r.user_id = u.id
WHERE u.deleted_at IS NULL AND (u.plan = 'pro' OR u.credits > 100) ORDER BY rn LIMIT 50`
	drawnTypesSQL = "SELECT arr[1:2], arr[3], ARRAY[1, 2] FROM t WHERE (a, b) IN ((1, 2))"
)

var parseReleaseQueries = []struct {
	name string
	sql  string
}{
	{"SampleJoin", sampleJoinSQL},
	{"MediumCTE", mediumCTESQL},
	{"DrawnTypes", drawnTypesSQL},
}

// benchTokens tokenizes sql once so the benchmarks measure parse and release
// only.
func benchTokens(b *testing.B, sql string) []models.TokenWithSpan {
	b.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		b.Fatalf("tokenize %q: %v", sql, err)
	}
	return tokens
}

// BenchmarkParseRelease compares parsing with and without returning the tree
// through ReleaseAST, the documented low-level usage pattern.
func BenchmarkParseRelease(b *testing.B) {
	for _, q := range parseReleaseQueries {
		tokens := benchTokens(b, q.sql)
		b.Run(q.name+"/NoRelease", func(b *testing.B) {
			p := parser.NewParser()
			defer p.Release()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := p.ParseFromModelTokens(tokens); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(q.name+"/Release", func(b *testing.B) {
			p := parser.NewParser()
			defer p.Release()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tree, err := p.ParseFromModelTokens(tokens)
				if err != nil {
					b.Fatal(err)
				}
				ast.ReleaseAST(tree)
			}
		})
	}
}

// BenchmarkReleaseASTOnly times ReleaseAST alone: trees are parsed in chunks
// with the timer stopped and then released with the timer running.
func BenchmarkReleaseASTOnly(b *testing.B) {
	const chunk = 512
	for _, q := range parseReleaseQueries {
		tokens := benchTokens(b, q.sql)
		b.Run(q.name, func(b *testing.B) {
			p := parser.NewParser()
			defer p.Release()
			trees := make([]*ast.AST, chunk)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i += chunk {
				n := chunk
				if b.N-i < n {
					n = b.N - i
				}
				b.StopTimer()
				for j := 0; j < n; j++ {
					tree, err := p.ParseFromModelTokens(tokens)
					if err != nil {
						b.Fatal(err)
					}
					trees[j] = tree
				}
				b.StartTimer()
				for j := 0; j < n; j++ {
					ast.ReleaseAST(trees[j])
					trees[j] = nil
				}
			}
		})
	}
}
