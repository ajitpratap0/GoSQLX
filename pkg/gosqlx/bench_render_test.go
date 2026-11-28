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

package gosqlx_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/highlight"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

var renderMatrixSink string

// rwDialects lists the dialects with a real-world corpus, in
// keywords.AllDialects order. generic and the dialects nobody wrote a corpus
// for are not part of the RW matrix.
func rwDialects() []string {
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

// rwValid returns the real-world statements of dialect that validate in that
// dialect, in corpus order. Filtering happens once, outside any timer, so the
// benchmark loops never time an error path.
func rwValid(tb testing.TB, dialect string) []benchcorpus.Statement {
	tb.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		tb.Fatalf("load benchmark corpus: %v", err)
	}
	var out []benchcorpus.Statement
	for _, st := range set.RealWorld(dialect) {
		if parser.ValidateWithDialect(st.SQL, keywords.SQLDialect(dialect)) == nil {
			out = append(out, st)
		}
	}
	return out
}

// BenchmarkFormatWithDialectRW measures gosqlx.FormatWithDialect (tokenize,
// parse, render in the dialect) on one real-world statement per operation,
// cycling through the dialect's corpus.
func BenchmarkFormatWithDialectRW(b *testing.B) {
	opts := gosqlx.DefaultFormatOptions()
	for _, dialect := range rwDialects() {
		d := keywords.SQLDialect(dialect)
		var sqls []string
		for _, st := range rwValid(b, dialect) {
			// Comments that cannot be placed make Format refuse by design.
			if _, err := gosqlx.FormatWithDialect(st.SQL, opts, d); err == nil {
				sqls = append(sqls, st.SQL)
			}
		}
		if len(sqls) == 0 {
			b.Fatalf("%s: no formattable real-world statements", dialect)
		}
		b.Run(dialect, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				out, err := gosqlx.FormatWithDialect(sqls[i%len(sqls)], opts, d)
				if err != nil {
					b.Fatal(err)
				}
				renderMatrixSink = out
			}
		})
	}
}

// BenchmarkValidateRW measures parser.ValidateWithDialect per dialect and size
// bucket. Small and medium buckets cycle through corpus statements; the large
// bucket is one script of at least 64 KB built from the same statements.
func BenchmarkValidateRW(b *testing.B) {
	for _, dialect := range rwDialects() {
		stmts := rwValid(b, dialect)
		d := keywords.SQLDialect(dialect)
		b.Run(dialect, func(b *testing.B) {
			for _, bucket := range benchcorpus.Buckets {
				var inputs []benchcorpus.Statement
				if bucket == benchcorpus.Large {
					inputs = []benchcorpus.Statement{benchcorpus.Script(stmts, benchcorpus.LargeMin)}
				} else {
					inputs = benchcorpus.InBucket(stmts, bucket)
				}
				if len(inputs) == 0 || inputs[0].SQL == "" {
					continue // this dialect has no statement of that size
				}
				b.Run(bucket.String(), func(b *testing.B) {
					b.ReportAllocs()
					for i := 0; i < b.N; i++ {
						if err := parser.ValidateWithDialect(inputs[i%len(inputs)].SQL, d); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

// BenchmarkHighlight measures gosqlx.Highlight (tokenize plus span
// classification) over the portable queries.
func BenchmarkHighlight(b *testing.B) {
	set, err := benchcorpus.Default()
	if err != nil {
		b.Fatal(err)
	}
	for _, q := range set.Portable() {
		b.Run(q.ID, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if len(gosqlx.Highlight(q.SQL)) == 0 {
					b.Fatal("no spans")
				}
			}
		})
	}
}

// TestRWMatrixCoversEightDialects pins the dialect set of the RW benchmarks.
func TestRWMatrixCoversEightDialects(t *testing.T) {
	got := rwDialects()
	if len(got) != 8 {
		t.Fatalf("rwDialects = %v, want 8 dialects", got)
	}
	for _, d := range got {
		if len(rwValid(t, d)) == 0 {
			t.Errorf("%s: no valid real-world statements", d)
		}
	}
}

// TestValidateRWBucketsAreSized guards the bucket split BenchmarkValidateRW
// relies on: every small input is under 256 B, every medium input is between
// 256 B and 64 KB, and the large script reaches 64 KB and still validates.
func TestValidateRWBucketsAreSized(t *testing.T) {
	for _, dialect := range rwDialects() {
		stmts := rwValid(t, dialect)
		for _, st := range benchcorpus.InBucket(stmts, benchcorpus.Small) {
			if len(st.SQL) >= benchcorpus.SmallLimit {
				t.Errorf("%s: small statement %s is %d B", dialect, st.Key(), len(st.SQL))
			}
		}
		for _, st := range benchcorpus.InBucket(stmts, benchcorpus.Medium) {
			if n := len(st.SQL); n < benchcorpus.SmallLimit || n >= benchcorpus.LargeMin {
				t.Errorf("%s: medium statement %s is %d B", dialect, st.Key(), n)
			}
		}
		script := benchcorpus.Script(stmts, benchcorpus.LargeMin)
		if len(script.SQL) < benchcorpus.LargeMin {
			t.Errorf("%s: large script is %d B, want >= %d", dialect, len(script.SQL), benchcorpus.LargeMin)
		}
		if err := parser.ValidateWithDialect(script.SQL, keywords.SQLDialect(dialect)); err != nil {
			t.Errorf("%s: large script does not validate: %v", dialect, err)
		}
	}
}

// TestHighlightSpansAreOrderedAndInBounds pins what BenchmarkHighlight times:
// for every portable query the spans are non-empty, ascending, non-overlapping
// and inside the input.
func TestHighlightSpansAreOrderedAndInBounds(t *testing.T) {
	set, err := benchcorpus.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range set.Portable() {
		spans := gosqlx.Highlight(q.SQL)
		if len(spans) == 0 {
			t.Errorf("%s: no spans", q.ID)
		}
		prevEnd := 0
		for _, sp := range spans {
			if sp.Start < prevEnd || sp.End <= sp.Start || sp.End > len(q.SQL) {
				t.Errorf("%s: bad span %+v after end %d (len %d)", q.ID, sp, prevEnd, len(q.SQL))
			}
			prevEnd = sp.End
		}
	}
}

// TestHighlightClassifiesKeywords checks that Highlight actually separates
// keywords from identifiers, so the benchmark exercises the classifier.
func TestHighlightClassifiesKeywords(t *testing.T) {
	const sql = "SELECT id FROM users"
	cats := map[string]highlight.Category{}
	for _, sp := range gosqlx.Highlight(sql) {
		cats[sp.Text(sql)] = sp.Category
	}
	if cats["SELECT"] == cats["users"] {
		t.Errorf("keyword and identifier share category %v: %v", cats["SELECT"], cats)
	}
}
