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

package formatter_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// renderSink keeps the compiler from discarding rendered output.
var renderSink string

// renderStyles are the AST-to-SQL styles measured by BenchmarkRender. "sql" is
// the AST's own SQL() method, the byte-identical baseline for "compact".
var renderStyles = []struct {
	name string
	opts func() ast.FormatOptions
}{
	{"compact", ast.CompactStyle},
	{"readable", ast.ReadableStyle},
	{"lower", func() ast.FormatOptions {
		o := ast.ReadableStyle()
		o.KeywordCase = ast.KeywordLower
		return o
	}},
}

// corpusDialects lists the dialects that have a real-world corpus, the eight
// the matrix covers, in keywords.AllDialects order.
func corpusDialects() []string {
	have := map[string]bool{}
	for _, c := range benchcorpus.Corpora {
		if c.Kind == benchcorpus.KindRealWorld {
			have[c.Dialect] = true
		}
	}
	var out []string
	for _, d := range benchcorpus.Dialects() {
		if have[d] {
			out = append(out, d)
		}
	}
	return out
}

func mustParseAST(tb testing.TB, sql string) *ast.AST {
	tb.Helper()
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		tb.Fatalf("parse %q: %v", sql, err)
	}
	return tree
}

func portableQueries(tb testing.TB) []benchcorpus.Query {
	tb.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		tb.Fatalf("load benchmark corpus: %v", err)
	}
	qs := set.Portable()
	if len(qs) == 0 {
		tb.Fatal("benchmark corpus has no portable queries")
	}
	return qs
}

// BenchmarkRender measures AST-to-SQL rendering only; the AST is parsed once
// outside the timer. It covers the three formatter styles and AST.SQL().
func BenchmarkRender(b *testing.B) {
	queries := portableQueries(b)
	for _, style := range renderStyles {
		b.Run(style.name, func(b *testing.B) {
			opts := style.opts()
			for _, q := range queries {
				b.Run(q.ID, func(b *testing.B) {
					tree := mustParseAST(b, q.SQL)
					defer ast.ReleaseAST(tree)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						out, err := formatter.FormatASTChecked(tree, opts)
						if err != nil {
							b.Fatal(err)
						}
						renderSink = out
					}
				})
			}
		})
	}
	b.Run("sql", func(b *testing.B) {
		for _, q := range queries {
			b.Run(q.ID, func(b *testing.B) {
				tree := mustParseAST(b, q.SQL)
				defer ast.ReleaseAST(tree)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					renderSink = tree.SQL()
				}
			})
		}
	})
}

// dialectTrees parses every real-world statement of dialect that parses and
// renders cleanly both with and without a target dialect. Statements are
// filtered once, outside the timer, so the benchmark loop never hits an error
// path. The caller releases the trees.
func dialectTrees(tb testing.TB, dialect string) []*ast.AST {
	tb.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		tb.Fatalf("load benchmark corpus: %v", err)
	}
	var trees []*ast.AST
	for _, st := range set.RealWorld(dialect) {
		tree, err := gosqlx.ParseWithDialect(st.SQL, keywords.SQLDialect(dialect))
		if err != nil {
			continue
		}
		generic := ast.CompactStyle()
		targeted := generic
		targeted.Dialect = dialect
		_, e1 := formatter.FormatASTChecked(tree, generic)
		_, e2 := formatter.FormatASTChecked(tree, targeted)
		if e1 != nil || e2 != nil {
			ast.ReleaseAST(tree)
			continue
		}
		trees = append(trees, tree)
	}
	return trees
}

// renderRWOpts builds the options of one BenchmarkRenderRW variant: "dialect"
// renders for the target dialect, "nodialect" uses the generic path.
func renderRWOpts(dialect, mode string) ast.FormatOptions {
	opts := ast.CompactStyle()
	if mode == "dialect" {
		opts.Dialect = dialect
	}
	return opts
}

// BenchmarkRenderRW renders real-world statements of each dialect, one
// statement per operation cycling through the corpus, with and without the
// target-dialect rendering path. The difference is the dialect overhead.
func BenchmarkRenderRW(b *testing.B) {
	for _, dialect := range corpusDialects() {
		trees := dialectTrees(b, dialect)
		b.Cleanup(func() {
			for _, t := range trees {
				ast.ReleaseAST(t)
			}
		})
		if len(trees) == 0 {
			b.Fatalf("%s: no renderable real-world statements", dialect)
		}
		b.Run(dialect, func(b *testing.B) {
			for _, mode := range []string{"nodialect", "dialect"} {
				opts := renderRWOpts(dialect, mode)
				b.Run(mode, func(b *testing.B) {
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						out, err := formatter.FormatASTChecked(trees[i%len(trees)], opts)
						if err != nil {
							b.Fatal(err)
						}
						renderSink = out
					}
				})
			}
		})
	}
}

// BenchmarkRenderScale renders ASTs that grow 10x per step in one dimension,
// to expose super-linear rendering cost.
func BenchmarkRenderScale(b *testing.B) {
	for _, shape := range benchcorpus.ScaleShapes {
		b.Run(shape, func(b *testing.B) {
			for _, n := range benchcorpus.ScaleSizes {
				b.Run(fmt.Sprint(n), func(b *testing.B) {
					tree := mustParseAST(b, benchcorpus.ScaleSQL(shape, n))
					defer ast.ReleaseAST(tree)
					opts := ast.CompactStyle()
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						out, err := formatter.FormatASTChecked(tree, opts)
						if err != nil {
							b.Fatal(err)
						}
						renderSink = out
					}
				})
			}
		})
	}
}

// TestRenderBenchStylesDiffer guards the style matrix: on a query with
// keywords and clauses the four renderings must be distinct, keep every
// identifier, and the compact and SQL() outputs must agree, otherwise a
// benchmark variant would silently measure the same work as another.
func TestRenderBenchStylesDiffer(t *testing.T) {
	const sql = "SELECT u.id, u.name FROM users u WHERE u.active = 1 ORDER BY u.name LIMIT 10"
	tree := mustParseAST(t, sql)
	defer ast.ReleaseAST(tree)

	out := map[string]string{"sql": tree.SQL()}
	for _, style := range renderStyles {
		got, err := formatter.FormatASTChecked(tree, style.opts())
		if err != nil {
			t.Fatalf("%s: %v", style.name, err)
		}
		out[style.name] = got
	}

	for name, got := range out {
		for _, ident := range []string{"u.id", "u.name", "users"} {
			if !strings.Contains(got, ident) {
				t.Errorf("%s: %q lost identifier %q", name, got, ident)
			}
		}
	}
	if out["compact"] != out["sql"] {
		t.Errorf("compact and SQL() disagree:\n compact: %q\n sql:     %q", out["compact"], out["sql"])
	}
	if strings.Contains(out["compact"], "\n") {
		t.Errorf("compact output has a newline: %q", out["compact"])
	}
	if !strings.Contains(out["readable"], "\n") || !strings.Contains(out["readable"], "SELECT") {
		t.Errorf("readable output should be multi-line with upper-case keywords: %q", out["readable"])
	}
	if !strings.Contains(out["lower"], "select") || strings.Contains(out["lower"], "SELECT") {
		t.Errorf("lower output should use lower-case keywords: %q", out["lower"])
	}
}

// TestRenderBenchDialectInputs guards BenchmarkRenderRW: every dialect with a
// real-world corpus yields renderable trees, and the dialect path keeps the
// statement renderable.
func TestRenderBenchDialectInputs(t *testing.T) {
	if got := len(corpusDialects()); got != 8 {
		t.Fatalf("matrix covers %d dialects, want 8", got)
	}
	for _, dialect := range corpusDialects() {
		trees := dialectTrees(t, dialect)
		if len(trees) == 0 {
			t.Errorf("%s: no renderable real-world statements", dialect)
		}
		for _, tree := range trees {
			ast.ReleaseAST(tree)
		}
	}
}

// TestRenderRWDialectPathDiffers guards the wiring of the "dialect" variant:
// RenderRW/<d>/dialect must set FormatOptions.Dialect to the target and
// RenderRW/<d>/nodialect must leave it empty. It deliberately does not assert
// a performance difference, so optimizing the dialect path never breaks it.
func TestRenderRWDialectPathDiffers(t *testing.T) {
	for _, d := range corpusDialects() {
		if got := renderRWOpts(d, "dialect").Dialect; got != d {
			t.Errorf("%s: dialect variant Dialect = %q, want %q", d, got, d)
		}
		if got := renderRWOpts(d, "nodialect").Dialect; got != "" {
			t.Errorf("%s: nodialect variant Dialect = %q, want empty", d, got)
		}
	}

	// Behavioural check: the dialect options really take the target path.
	tree := mustParseAST(t, "SELECT id FROM t ORDER BY id LIMIT 10")
	defer ast.ReleaseAST(tree)
	targeted, err := formatter.FormatASTChecked(tree, renderRWOpts("sqlserver", "dialect"))
	if err != nil {
		t.Fatal(err)
	}
	upper := strings.ToUpper(targeted)
	if !strings.Contains(upper, "OFFSET") || !strings.Contains(upper, "FETCH") || strings.Contains(upper, "LIMIT") {
		t.Errorf("sqlserver dialect render should use OFFSET/FETCH without LIMIT, got %q", targeted)
	}
	generic, err := formatter.FormatASTChecked(tree, renderRWOpts("sqlserver", "nodialect"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToUpper(generic), "LIMIT") {
		t.Errorf("nodialect render should keep LIMIT, got %q", generic)
	}
}

// TestRenderScaleInputsRender guards BenchmarkRenderScale: every shape and
// size renders non-empty SQL that re-parses, and output grows with n.
func TestRenderScaleInputsRender(t *testing.T) {
	for _, shape := range benchcorpus.ScaleShapes {
		prev := 0
		for _, n := range benchcorpus.ScaleSizes {
			tree := mustParseAST(t, benchcorpus.ScaleSQL(shape, n))
			out, err := formatter.FormatASTChecked(tree, ast.CompactStyle())
			ast.ReleaseAST(tree)
			if err != nil {
				t.Fatalf("%s/%d: %v", shape, n, err)
			}
			if len(out) <= prev {
				t.Errorf("%s/%d: output length %d did not grow past %d", shape, n, len(out), prev)
			}
			prev = len(out)
			again, err := gosqlx.Parse(out)
			if err != nil {
				t.Fatalf("%s/%d: rendered SQL does not re-parse: %v", shape, n, err)
			}
			ast.ReleaseAST(again)
		}
	}
}
