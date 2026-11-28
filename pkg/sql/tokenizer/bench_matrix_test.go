// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package tokenizer_test

// Tokenizer benchmark matrix (perf plan section 2.2, task W0-03).
//
//	BenchmarkTokenize/{scratch,public}/<q>      11 portable queries
//	BenchmarkTokenizeRW/<dialect>/<bucket>      8 real-world dialects x small/medium/large
//	BenchmarkTokenizeShape/<shape>              numeric, comments, escapes, nonascii
//	BenchmarkTokenizeLarge/{1MB,10MB}           scratch path on a scripted corpus
//
// "scratch" is the path gosqlx.Parse uses (tokscratch: tokens are built in a
// buffer owned by the pooled tokenizer). "public" is TokenizeString, which
// hands the caller an owned slice. Every benchmark takes and returns a pooled
// tokenizer per operation, as the entry points do.
//
// One RW operation is one pass over the bucket's statements; the ns/stmt
// metric divides that out. Inputs come from internal/benchcorpus so the
// parser and gosqlx matrices see byte-identical statements.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/internal/tokscratch"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// maxBucketStatements caps how many statements one RW operation covers, so
// the matrix stays fast. The first N in corpus order are taken, so the cap is
// deterministic.
const maxBucketStatements = 64

type tokenizeFunc func(tkz *tokenizer.Tokenizer, sql string) ([]models.TokenWithSpan, error)

var (
	tokenizeScratch tokenizeFunc = func(tkz *tokenizer.Tokenizer, sql string) ([]models.TokenWithSpan, error) {
		return tokscratch.String(tkz, sql)
	}
	tokenizePublic tokenizeFunc = func(tkz *tokenizer.Tokenizer, sql string) ([]models.TokenWithSpan, error) {
		return tkz.TokenizeString(sql)
	}
)

var tokSink int

func loadCorpus(tb testing.TB) *benchcorpus.Set {
	tb.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		tb.Fatalf("load benchmark corpus: %v", err)
	}
	return set
}

// rwCell is one RW/<dialect>/<bucket> input.
type rwCell struct {
	dialect string
	bucket  benchcorpus.Bucket
	sqls    []string
}

func (c rwCell) name() string { return c.dialect + "/" + c.bucket.String() }

func (c rwCell) bytes() int {
	n := 0
	for _, s := range c.sqls {
		n += len(s)
	}
	return n
}

// rwDialects lists the dialects that have a real-world corpus, in
// benchcorpus order.
func rwDialects(set *benchcorpus.Set) []string {
	var out []string
	for _, d := range benchcorpus.Dialects() {
		if len(set.RealWorld(d)) > 0 {
			out = append(out, d)
		}
	}
	return out
}

// rwCells builds the dialect x bucket grid. No corpus statement reaches the
// large bucket, so that cell is one scripted statement of at least LargeMin
// bytes (benchcorpus.Script).
func rwCells(set *benchcorpus.Set) []rwCell {
	var cells []rwCell
	for _, d := range rwDialects(set) {
		stmts := set.RealWorld(d)
		for _, b := range benchcorpus.Buckets {
			var sqls []string
			if b == benchcorpus.Large {
				sqls = []string{benchcorpus.Script(benchcorpus.InBucket(stmts, benchcorpus.Small), benchcorpus.LargeMin).SQL}
			} else {
				for _, st := range benchcorpus.InBucket(stmts, b) {
					if len(sqls) == maxBucketStatements {
						break
					}
					sqls = append(sqls, st.SQL)
				}
			}
			cells = append(cells, rwCell{dialect: d, bucket: b, sqls: sqls})
		}
	}
	return cells
}

// shapeInputs returns the synthetic stress inputs, each a few KB, built to
// hit one tokenizer code path hard.
func shapeInputs() []struct{ name, sql string } {
	var numeric, comments, escapes, nonascii strings.Builder
	numeric.WriteString("SELECT ")
	for i := 0; i < 200; i++ {
		if i > 0 {
			numeric.WriteString(", ")
		}
		fmt.Fprintf(&numeric, "%d, %d.%d, 0x%X, %de-%d, .%d", i, i, i*7, i*13+255, i+1, i%9, i)
	}
	numeric.WriteString(" FROM t")

	for i := 0; i < 100; i++ {
		fmt.Fprintf(&comments, "-- line comment %d with some text\nSELECT %d /* block %d */ FROM t%d; /* trailing\n multi-line */\n", i, i, i, i)
	}

	escapes.WriteString("SELECT ")
	for i := 0; i < 150; i++ {
		if i > 0 {
			escapes.WriteString(", ")
		}
		fmt.Fprintf(&escapes, `'it''s %d', "quo""ted%d", E'tab\\t%d', $$dollar %d$$`, i, i, i, i)
	}
	escapes.WriteString(" FROM t")

	nonascii.WriteString("SELECT ")
	for i := 0; i < 150; i++ {
		if i > 0 {
			nonascii.WriteString(", ")
		}
		fmt.Fprintf(&nonascii, "名前%d, été_%d, '你好 %d', \"данные%d\"", i, i, i, i)
	}
	nonascii.WriteString(" FROM 表")

	return []struct{ name, sql string }{
		{"numeric", numeric.String()},
		{"comments", comments.String()},
		{"escapes", escapes.String()},
		{"nonascii", nonascii.String()},
	}
}

// largeInput returns a deterministic script of at least n bytes made of
// INSERT rows that each carry a ~400-byte text literal. The tokenizer rejects
// input above 1,000,000 tokens and 10 MiB (MaxInputSize), and the corpus
// statements are token-dense (about 7 bytes per token), so a 10 MB corpus
// script is refused; text-heavy rows keep it at about 22 bytes per token.
// The "10MB" cell asks for 10 MiB minus a margin and lands a few hundred
// bytes under the byte limit.
func largeInput(n int) string {
	text := strings.Repeat("lorem ipsum dolor sit amet, ", 14)
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, "INSERT INTO docs (id, score, body) VALUES (%d, %d.5, '%s');\n", i, i%1000, text)
	}
	return b.String()
}

const largeMargin = 4096

func runTokenize(b *testing.B, fn tokenizeFunc, dialect keywords.SQLDialect, sqls ...string) {
	b.Helper()
	total := 0
	for _, s := range sqls {
		total += len(s)
	}
	b.ReportAllocs()
	b.SetBytes(int64(total))
	for b.Loop() {
		for _, sql := range sqls {
			tkz := tokenizer.GetTokenizer()
			if dialect != "" {
				tkz.SetDialect(dialect)
			}
			toks, err := fn(tkz, sql)
			if err != nil {
				tokenizer.PutTokenizer(tkz)
				b.Fatal(err)
			}
			tokSink += len(toks)
			tokenizer.PutTokenizer(tkz)
		}
	}
	if len(sqls) > 1 {
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*len(sqls)), "ns/stmt")
	}
}

func BenchmarkTokenize(b *testing.B) {
	set := loadCorpus(b)
	for _, path := range []struct {
		name string
		fn   tokenizeFunc
	}{{"scratch", tokenizeScratch}, {"public", tokenizePublic}} {
		b.Run(path.name, func(b *testing.B) {
			for _, q := range set.Portable() {
				b.Run(q.ID, func(b *testing.B) { runTokenize(b, path.fn, "", q.SQL) })
			}
		})
	}
}

func BenchmarkTokenizeRW(b *testing.B) {
	for _, c := range rwCells(loadCorpus(b)) {
		b.Run(c.name(), func(b *testing.B) {
			runTokenize(b, tokenizeScratch, keywords.SQLDialect(c.dialect), c.sqls...)
		})
	}
}

func BenchmarkTokenizeShape(b *testing.B) {
	for _, s := range shapeInputs() {
		b.Run(s.name, func(b *testing.B) { runTokenize(b, tokenizeScratch, "", s.sql) })
	}
}

func BenchmarkTokenizeLarge(b *testing.B) {
	for _, l := range []struct {
		name string
		n    int
	}{{"1MB", 1 << 20}, {"10MB", 10<<20 - largeMargin}} {
		sql := largeInput(l.n)
		b.Run(l.name, func(b *testing.B) { runTokenize(b, tokenizeScratch, "", sql) })
	}
}

// The tests below keep the matrix honest: a benchmark that silently measures
// an empty or failing input is worse than none.

func TestBenchMatrixRWGridIsComplete(t *testing.T) {
	set := loadCorpus(t)
	dialects := rwDialects(set)
	if len(dialects) != 8 {
		t.Fatalf("real-world dialects = %v, want 8", dialects)
	}
	cells := rwCells(set)
	if want := len(dialects) * len(benchcorpus.Buckets); len(cells) != want {
		t.Fatalf("got %d cells, want %d", len(cells), want)
	}
	for _, c := range cells {
		if len(c.sqls) == 0 {
			t.Errorf("%s: no statements", c.name())
			continue
		}
		if c.bucket == benchcorpus.Large && c.bytes() < benchcorpus.LargeMin {
			t.Errorf("%s: %d bytes, want >= %d", c.name(), c.bytes(), benchcorpus.LargeMin)
		}
		for _, sql := range c.sqls {
			tkz := tokenizer.GetTokenizer()
			tkz.SetDialect(keywords.SQLDialect(c.dialect))
			toks, err := tokenizeScratch(tkz, sql)
			n := len(toks)
			tokenizer.PutTokenizer(tkz)
			if err != nil || n == 0 {
				t.Fatalf("%s: tokenize %d tokens, err %v", c.name(), n, err)
			}
		}
	}
}

func TestBenchMatrixScratchEqualsPublic(t *testing.T) {
	set := loadCorpus(t)
	if len(set.Portable()) != 11 {
		t.Fatalf("portable queries = %d, want 11", len(set.Portable()))
	}
	for _, q := range set.Portable() {
		pub := tokenizer.GetTokenizer()
		want, err := tokenizePublic(pub, q.SQL)
		if err != nil {
			t.Fatalf("%s public: %v", q.ID, err)
		}
		want = append([]models.TokenWithSpan(nil), want...)
		tokenizer.PutTokenizer(pub)

		scr := tokenizer.GetTokenizer()
		got, err := tokenizeScratch(scr, q.SQL)
		if err != nil {
			t.Fatalf("%s scratch: %v", q.ID, err)
		}
		if len(got) != len(want) {
			t.Fatalf("%s: scratch %d tokens, public %d", q.ID, len(got), len(want))
		}
		for i := range want {
			g, w := got[i].Token, want[i].Token
			if g.Type != w.Type || g.Value != w.Value || g.Long != w.Long || g.Quote != w.Quote || got[i].Start != want[i].Start || got[i].End != want[i].End {
				t.Fatalf("%s token %d: scratch %+v, public %+v", q.ID, i, got[i], want[i])
			}
		}
		tokenizer.PutTokenizer(scr)
	}
}

func TestBenchMatrixShapesExerciseTheirPath(t *testing.T) {
	for _, s := range shapeInputs() {
		tkz := tokenizer.GetTokenizer()
		toks, err := tokenizePublic(tkz, s.sql)
		tokenizer.PutTokenizer(tkz)
		if err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		if len(toks) < 300 {
			t.Errorf("%s: only %d tokens, shape is too small to measure", s.name, len(toks))
		}
		switch s.name {
		case "comments":
			selects := 0
			for _, tk := range toks {
				if strings.EqualFold(tk.Token.Value, "SELECT") {
					selects++
				}
			}
			if selects != 100 {
				t.Errorf("comments: %d SELECT tokens, want 100 (comments must not swallow statements)", selects)
			}
		case "nonascii":
			found := false
			for _, tk := range toks {
				if strings.ContainsFunc(tk.Token.Value, func(r rune) bool { return r > 127 }) {
					found = true
					break
				}
			}
			if !found {
				t.Error("nonascii: no token carries a non-ASCII rune")
			}
		}
	}
}

func TestBenchMatrixLargeInputsReachTheirSize(t *testing.T) {
	for _, n := range []int{1 << 20, 10<<20 - largeMargin} {
		sql := largeInput(n)
		if len(sql) < n {
			t.Errorf("largeInput(%d) = %d bytes", n, len(sql))
		}
		tkz := tokenizer.GetTokenizer()
		toks, err := tokenizeScratch(tkz, sql)
		got := len(toks)
		tokenizer.PutTokenizer(tkz)
		if err != nil || got == 0 {
			t.Errorf("tokenize %d-byte input: %d tokens, err %v", len(sql), got, err)
		}
	}
}
