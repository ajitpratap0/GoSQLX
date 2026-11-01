// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package parser_test

// Parse-stage benchmark matrix (perf plan section 2.2, task W0-03).
//
//	BenchmarkParseStage/preprocess/<q>   token normalisation into the pooled parser buffer
//	BenchmarkParseStage/parseonly/<q>    parseTokens on a preprocessed stream, tree released
//	BenchmarkParseStage/release/<q>      ast.ReleaseAST alone, on trees built outside the timer
//
// <q> is one of the 11 portable queries from internal/benchcorpus. The stages
// partition gosqlx.Parse as: tokenize (tokenizer matrix) + preprocess +
// parseonly, where parseonly includes the ReleaseAST that returns the tree to
// its pools; subtract the release stage to get the cost of building the tree.
// The parser pool round trip (GetParser/PutParser) is counted once, in
// parseonly; preprocess holds one parser outside its loop so a preprocess
// change is not diluted by pool overhead (p.preprocess still clears tokenBuf
// on every call, as Reset does in production).
// Dialect coverage comes from the ParseRW matrix in package gosqlx.

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// releaseBatch is how many trees the release stage builds per timer pause.
const releaseBatch = 256

var stageSink int

func stageQueries(tb testing.TB) []benchcorpus.Query {
	tb.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		tb.Fatalf("load benchmark corpus: %v", err)
	}
	return set.Portable()
}

// stageTokens returns an owned token stream for sql.
func stageTokens(tb testing.TB, sql string) []models.TokenWithSpan {
	tb.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	toks, err := tkz.TokenizeString(sql)
	if err != nil {
		tb.Fatalf("tokenize %q: %v", sql, err)
	}
	return append([]models.TokenWithSpan(nil), toks...)
}

func BenchmarkParseStage(b *testing.B) {
	queries := stageQueries(b)

	b.Run("preprocess", func(b *testing.B) {
		for _, q := range queries {
			toks := stageTokens(b, q.SQL)
			b.Run(q.ID, func(b *testing.B) {
				p := parser.GetParser()
				defer parser.PutParser(p)
				b.ReportAllocs()
				for b.Loop() {
					stageSink += parser.BenchPreprocess(p, toks)
				}
			})
		}
	})

	b.Run("parseonly", func(b *testing.B) {
		for _, q := range queries {
			pre := parser.BenchPreprocessOwned(stageTokens(b, q.SQL))
			b.Run(q.ID, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					p := parser.GetParser()
					tree, err := parser.BenchParseTokens(p, pre)
					parser.PutParser(p)
					if err != nil {
						b.Fatal(err)
					}
					ast.ReleaseAST(tree)
				}
			})
		}
	})

	b.Run("release", func(b *testing.B) {
		for _, q := range queries {
			pre := parser.BenchPreprocessOwned(stageTokens(b, q.SQL))
			b.Run(q.ID, func(b *testing.B) {
				b.ReportAllocs()
				trees := make([]*ast.AST, 0, releaseBatch)
				b.ResetTimer()
				for done := 0; done < b.N; {
					n := min(releaseBatch, b.N-done)
					b.StopTimer()
					trees = trees[:0]
					for range n {
						p := parser.GetParser()
						tree, err := parser.BenchParseTokens(p, pre)
						parser.PutParser(p)
						if err != nil {
							b.Fatal(err)
						}
						trees = append(trees, tree)
					}
					b.StartTimer()
					for _, tree := range trees {
						ast.ReleaseAST(tree)
					}
					done += n
				}
			})
		}
	})
}

// The stage split must compose back into the real entry point, or the stage
// numbers describe something other than the Parse path.
func TestParseStageCompositionMatchesParse(t *testing.T) {
	queries := stageQueries(t)
	if len(queries) != 11 {
		t.Fatalf("portable queries = %d, want 11", len(queries))
	}
	for _, q := range queries {
		toks := stageTokens(t, q.SQL)

		p := parser.GetParser()
		want, err := p.ParseFromModelTokens(toks)
		parser.PutParser(p)
		if err != nil {
			t.Fatalf("%s: ParseFromModelTokens: %v", q.ID, err)
		}
		wantSQL := want.SQL()
		ast.ReleaseAST(want)

		pre := parser.BenchPreprocessOwned(toks)
		// parseTokens must not consume or mutate its input, or the parseonly
		// and release stages would measure a different stream after op 1.
		for i := 0; i < 3; i++ {
			p := parser.GetParser()
			got, err := parser.BenchParseTokens(p, pre)
			parser.PutParser(p)
			if err != nil {
				t.Fatalf("%s: parse round %d: %v", q.ID, i, err)
			}
			if gotSQL := got.SQL(); gotSQL != wantSQL {
				t.Fatalf("%s round %d: staged parse = %q, full parse = %q", q.ID, i, gotSQL, wantSQL)
			}
			ast.ReleaseAST(got)
		}

		p = parser.GetParser()
		n := parser.BenchPreprocess(p, toks)
		parser.PutParser(p)
		if n != len(pre) {
			t.Errorf("%s: pooled preprocess kept %d tokens, owned copy %d", q.ID, n, len(pre))
		}
	}
}
