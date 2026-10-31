// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package gosqlx_test

// Parse end-to-end benchmark matrix (perf plan section 2.2, task W0-03).
//
//	BenchmarkParseE2E/<q>                          Parse + ReleaseAST, 11 portable queries
//	BenchmarkParseRW/<dialect>/<bucket>            ParseWithDialect + ReleaseAST, 8 dialects x small/medium/large
//	BenchmarkParseTPC/{tpch,tpcds,orm}             Parse + ReleaseAST over a whole generic corpus
//	BenchmarkParseError/<case>/<api>               failing input, the LSP-while-typing workload
//
// One ParseRW or ParseTPC operation is one pass over the cell's statements;
// the ns/stmt metric divides that out. The large bucket is one scripted
// statement of at least 64 KB, since no corpus statement is that big. All
// inputs come from internal/benchcorpus, which drops known failures, so every
// benchmark here parses successfully except ParseError.
//
// The stage split of the same work lives in pkg/sql/parser (ParseStage) and
// the tokenizer share in pkg/sql/tokenizer (Tokenize*).

import (
	"errors"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// mxMaxBucketStatements caps one RW or TPC operation, deterministically (the
// first N in corpus order), to keep the matrix fast.
const mxMaxBucketStatements = 64

func mxCorpus(tb testing.TB) *benchcorpus.Set {
	tb.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		tb.Fatalf("load benchmark corpus: %v", err)
	}
	return set
}

type mxCell struct {
	name    string
	dialect keywords.SQLDialect // "" parses with gosqlx.Parse
	sqls    []string
}

func (c mxCell) bytes() int {
	n := 0
	for _, s := range c.sqls {
		n += len(s)
	}
	return n
}

func (c mxCell) parse(sql string) (*ast.AST, error) {
	if c.dialect == "" {
		return gosqlx.Parse(sql)
	}
	return gosqlx.ParseWithDialect(sql, c.dialect)
}

// mxRWCells builds the dialect x bucket grid for the 8 dialects that have a
// real-world corpus.
func mxRWCells(set *benchcorpus.Set) []mxCell {
	var cells []mxCell
	for _, d := range benchcorpus.Dialects() {
		stmts := set.RealWorld(d)
		if len(stmts) == 0 {
			continue
		}
		for _, bucket := range benchcorpus.Buckets {
			var sqls []string
			if bucket == benchcorpus.Large {
				sqls = []string{benchcorpus.Script(benchcorpus.InBucket(stmts, benchcorpus.Small), benchcorpus.LargeMin).SQL}
			} else {
				for _, st := range benchcorpus.InBucket(stmts, bucket) {
					if len(sqls) == mxMaxBucketStatements {
						break
					}
					sqls = append(sqls, st.SQL)
				}
			}
			cells = append(cells, mxCell{name: d + "/" + bucket.String(), dialect: keywords.SQLDialect(d), sqls: sqls})
		}
	}
	return cells
}

var mxTPCCorpora = []string{"tpch", "tpcds", "orm"}

func mxTPCCells(set *benchcorpus.Set) []mxCell {
	var cells []mxCell
	for _, name := range mxTPCCorpora {
		var sqls []string
		for _, st := range set.ByCorpus("generic/" + name) {
			sqls = append(sqls, st.SQL)
		}
		cells = append(cells, mxCell{name: name, sqls: sqls})
	}
	return cells
}

func mxRunPass(b *testing.B, c mxCell) {
	b.Helper()
	b.ReportAllocs()
	b.SetBytes(int64(c.bytes()))
	for b.Loop() {
		for _, sql := range c.sqls {
			tree, err := c.parse(sql)
			if err != nil {
				b.Fatal(err)
			}
			ast.ReleaseAST(tree)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*len(c.sqls)), "ns/stmt")
}

func BenchmarkParseE2E(b *testing.B) {
	for _, q := range mxCorpus(b).Portable() {
		b.Run(q.ID, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(q.SQL)))
			for b.Loop() {
				tree, err := gosqlx.Parse(q.SQL)
				if err != nil {
					b.Fatal(err)
				}
				ast.ReleaseAST(tree)
			}
		})
	}
}

func BenchmarkParseRW(b *testing.B) {
	for _, c := range mxRWCells(mxCorpus(b)) {
		b.Run(c.name, func(b *testing.B) { mxRunPass(b, c) })
	}
}

func BenchmarkParseTPC(b *testing.B) {
	for _, c := range mxTPCCells(mxCorpus(b)) {
		b.Run(c.name, func(b *testing.B) { mxRunPass(b, c) })
	}
}

// mxErrorCase is an input that fails at a known stage.
type mxErrorCase struct {
	name string
	sql  string
	// tokenize is true when the generic Parse fails in the tokenizer
	// (ErrTokenize) and false when it fails in the parser (ErrSyntax).
	tokenize bool
}

func mxErrorCases() []mxErrorCase {
	// A long valid prefix: a wide select list that parses fine before the
	// error at the very end, so the failure is found after the most work.
	var long strings.Builder
	long.WriteString("SELECT ")
	for i := 0; i < 200; i++ {
		if i > 0 {
			long.WriteString(", ")
		}
		long.WriteString("t.col_")
		long.WriteString(strings.Repeat("x", i%7+1))
	}
	long.WriteString(" FROM t WHERE a = 1 AND")

	return []mxErrorCase{
		{"syntax_mid", "SELECT a, , b FROM users WHERE id = 1 ORDER BY a", false},
		{"syntax_end", "SELECT a, b FROM users WHERE id = 1 AND", false},
		{"tokenize", "SELECT a FROM users WHERE name = 'unterminated", true},
		{"long_prefix", long.String(), false},
	}
}

func BenchmarkParseError(b *testing.B) {
	for _, ec := range mxErrorCases() {
		b.Run(ec.name, func(b *testing.B) {
			b.Run("parse", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(ec.sql)))
				for b.Loop() {
					if _, err := gosqlx.Parse(ec.sql); err == nil {
						b.Fatal("input unexpectedly parsed")
					}
				}
			})
			b.Run("validate", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(ec.sql)))
				for b.Loop() {
					if err := gosqlx.Validate(ec.sql); err == nil {
						b.Fatal("input unexpectedly validated")
					}
				}
			})
			for _, d := range []keywords.SQLDialect{"postgresql", "mysql"} {
				b.Run(string(d), func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(len(ec.sql)))
					for b.Loop() {
						if _, err := gosqlx.ParseWithDialect(ec.sql, d); err == nil {
							b.Fatal("input unexpectedly parsed")
						}
					}
				})
			}
		})
	}
}

// The tests below keep the matrix honest: a benchmark that measures an empty
// or wrongly-succeeding input is worse than none.

func TestBenchMatrixParseCellsParse(t *testing.T) {
	set := mxCorpus(t)
	if n := len(set.Portable()); n != 11 {
		t.Fatalf("portable queries = %d, want 11", n)
	}
	cells := append(mxRWCells(set), mxTPCCells(set)...)
	dialects := map[string]bool{}
	for _, c := range cells {
		if len(c.sqls) == 0 {
			t.Errorf("%s: no statements", c.name)
			continue
		}
		if d, _, ok := strings.Cut(c.name, "/"); ok && c.dialect != "" {
			dialects[d] = true
		}
		for i, sql := range c.sqls {
			tree, err := c.parse(sql)
			if err != nil {
				t.Errorf("%s statement %d does not parse: %v", c.name, i, err)
				break
			}
			if len(tree.Statements) == 0 {
				t.Errorf("%s statement %d parsed to zero statements", c.name, i)
			}
			ast.ReleaseAST(tree)
		}
	}
	if len(dialects) != 8 {
		t.Errorf("RW grid covers %d dialects, want 8: %v", len(dialects), dialects)
	}
	if want := 8 * len(benchcorpus.Buckets); len(mxRWCells(set)) != want {
		t.Errorf("RW cells = %d, want %d", len(mxRWCells(set)), want)
	}
	if len(mxTPCCells(set)) != len(mxTPCCorpora) {
		t.Errorf("TPC cells = %d, want %d", len(mxTPCCells(set)), len(mxTPCCorpora))
	}
	for _, c := range mxRWCells(set) {
		if strings.HasSuffix(c.name, "/large") && c.bytes() < benchcorpus.LargeMin {
			t.Errorf("%s: %d bytes, want >= %d", c.name, c.bytes(), benchcorpus.LargeMin)
		}
	}
}

func TestBenchMatrixErrorCasesFailInTheirStage(t *testing.T) {
	for _, ec := range mxErrorCases() {
		_, err := gosqlx.Parse(ec.sql)
		if err == nil {
			t.Errorf("%s: Parse succeeded", ec.name)
			continue
		}
		if got := errors.Is(err, gosqlx.ErrTokenize); got != ec.tokenize {
			t.Errorf("%s: tokenizer failure = %v, want %v (err: %v)", ec.name, got, ec.tokenize, err)
		}
		if !ec.tokenize && !errors.Is(err, gosqlx.ErrSyntax) {
			t.Errorf("%s: want a syntax error, got %v", ec.name, err)
		}
		if gosqlx.Validate(ec.sql) == nil {
			t.Errorf("%s: Validate accepted the input", ec.name)
		}
		for _, d := range []keywords.SQLDialect{"postgresql", "mysql"} {
			if _, err := gosqlx.ParseWithDialect(ec.sql, d); err == nil {
				t.Errorf("%s: ParseWithDialect(%s) succeeded", ec.name, d)
			}
		}
	}
}

func TestBenchMatrixLongPrefixIsLongAndFailsLate(t *testing.T) {
	var long mxErrorCase
	for _, ec := range mxErrorCases() {
		if ec.name == "long_prefix" {
			long = ec
		}
	}
	if len(long.sql) < 2000 {
		t.Fatalf("long_prefix is only %d bytes", len(long.sql))
	}
	// The error must come from the tail, not the head: the same text without
	// its dangling AND is valid.
	valid := strings.TrimSuffix(long.sql, " AND")
	tree, err := gosqlx.Parse(valid)
	if err != nil {
		t.Fatalf("long_prefix minus the trailing AND must parse: %v", err)
	}
	ast.ReleaseAST(tree)
}
