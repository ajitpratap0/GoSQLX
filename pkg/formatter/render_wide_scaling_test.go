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
	"runtime"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/internal/scaletest"
	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func renderWideModes() []struct {
	name string
	opts ast.FormatOptions
} {
	compact := ast.CompactStyle()
	lower, semicolon, postgres := compact, compact, compact
	lower.KeywordCase = ast.KeywordLower
	semicolon.AddSemicolon = true
	postgres.Dialect = "postgresql"
	return []struct {
		name string
		opts ast.FormatOptions
	}{
		{"compact", compact},
		{"lower", lower},
		{"readable", ast.ReadableStyle()},
		{"semicolon", semicolon},
		{"postgresql", postgres},
	}
}

// Build the oracle independently of the renderer and the corpus generator.
func renderWideWant(n int, opts ast.FormatOptions) string {
	selectKW, asKW, fromKW, whereKW := "SELECT", "AS", "FROM", "WHERE"
	if opts.KeywordCase == ast.KeywordLower {
		selectKW, asKW, fromKW, whereKW = "select", "as", "from", "where"
	}
	var want strings.Builder
	want.WriteString(selectKW + " ")
	for i := 0; i < n; i++ {
		if i > 0 {
			want.WriteString(", ")
		}
		fmt.Fprintf(&want, "t.col_%d + %d %s c%d", i, i, asKW, i)
	}
	sep := " "
	if opts.NewlinePerClause {
		sep = "\n"
	}
	want.WriteString(sep + fromKW + " t" + sep + whereKW + " t.a = 1")
	if opts.AddSemicolon {
		want.WriteByte(';')
	}
	return want.String()
}

func checkRenderWideOutput(t *testing.T, tree *ast.AST, opts ast.FormatOptions, want string) {
	t.Helper()
	got, err := formatter.FormatASTChecked(tree, opts)
	if err != nil {
		t.Fatalf("FormatASTChecked: %v", err)
	}
	if got != want {
		offset := 0
		for offset < len(got) && offset < len(want) && got[offset] == want[offset] {
			offset++
		}
		t.Fatalf("first differing byte offset %d (got length %d, want %d): got %q; want %q", offset, len(got), len(want), got[offset:], want[offset:])
	}
}

func TestRenderWideExactOutput(t *testing.T) {
	for _, n := range []int{3, 100, 1000} {
		t.Run(fmt.Sprintf("n%d", n), func(t *testing.T) {
			tree := mustParseAST(t, benchcorpus.ScaleSQL(benchcorpus.ScaleWide, n))
			defer ast.ReleaseAST(tree)
			for _, mode := range renderWideModes() {
				t.Run(mode.name, func(t *testing.T) {
					want := renderWideWant(n, mode.opts)
					// Literal anchors pin visitor whitespace and dialect output separately
					// from the loop used for the larger widths.
					if n == 3 {
						switch mode.name {
						case "readable":
							want = "SELECT t.col_0 + 0 AS c0, t.col_1 + 1 AS c1, t.col_2 + 2 AS c2\nFROM t\nWHERE t.a = 1;"
						case "postgresql":
							want = "SELECT t.col_0 + 0 AS c0, t.col_1 + 1 AS c1, t.col_2 + 2 AS c2 FROM t WHERE t.a = 1"
						}
					}
					checkRenderWideOutput(t, tree, mode.opts, want)
				})
			}
		})
	}
}

// Tenfold width growth should cost about 10x in time and allocated bytes.
// A 20x bound leaves headroom while rejecting repeated prefix copies/scans
// (quadratic work grows about 100x). Parsing stays outside measurements.
func TestRenderWideLinearGrowth(t *testing.T) {
	small := mustParseAST(t, benchcorpus.ScaleSQL(benchcorpus.ScaleWide, 100))
	defer ast.ReleaseAST(small)
	large := mustParseAST(t, benchcorpus.ScaleSQL(benchcorpus.ScaleWide, 1000))
	defer ast.ReleaseAST(large)
	for _, mode := range renderWideModes() {
		t.Run(mode.name, func(t *testing.T) {
			render := func(tree *ast.AST) func() {
				return func() {
					out, err := formatter.FormatASTChecked(tree, mode.opts)
					if err != nil {
						t.Fatalf("FormatASTChecked: %v", err)
					}
					runtime.KeepAlive(out)
				}
			}
			smallOut, err := formatter.FormatASTChecked(small, mode.opts)
			if err != nil {
				t.Fatal(err)
			}
			largeOut, err := formatter.FormatASTChecked(large, mode.opts)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("output bytes n=100: %d; n=1000: %d", len(smallOut), len(largeOut))
			scaletest.AssertLinearGrowth(t, mode.name, 20, render(small), render(large))
			// Bytes are bounded per output byte instead of small-vs-large: a
			// pool miss under -race makes the small/large ratio noisy, while
			// bytes allocated per output byte stays ~3x when linear and
			// grows with n (hundreds of x at n=1000) for a quadratic copy.
			const runs = 5
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			for i := 0; i < runs; i++ {
				render(large)()
			}
			runtime.ReadMemStats(&after)
			perRun := float64(after.TotalAlloc-before.TotalAlloc) / runs
			if limit := 16 * float64(len(largeOut)); perRun > limit {
				t.Errorf("%s: allocated %.0f bytes per render for %d output bytes, want at most %.0f (super-linear growth)", mode.name, perRun, len(largeOut), limit)
			}
		})
	}
}
