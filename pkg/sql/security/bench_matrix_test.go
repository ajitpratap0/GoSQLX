// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package security_test

// Security benchmark matrix (PLAN.md 2.2, W0-06).
//
//	BenchmarkScanSQLRW/<dialect>         Scanner.ScanSQL over the dialect's real-world statements
//	BenchmarkScanSQLParams/{pg_dollar,qmark,at}   five parameterized statements, scanned one by one (finding-free)
//	BenchmarkScanSQLLarge/{30KB,1MB}     one script of that size (PostgreSQL real-world statements)
//	BenchmarkScanASTRW/<dialect>         Scanner.Scan over pre-parsed trees of the same statements
//
// One op of the RW benchmarks is one pass over the whole statement set; the
// ns/stmt metric divides by the statement count. The package is security_test
// (external) because internal/benchcorpus imports pkg/gosqlx.

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/security"
)

func rwDialects(tb testing.TB) []string {
	tb.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		tb.Fatalf("benchcorpus.Default: %v", err)
	}
	var out []string
	for _, d := range benchcorpus.Dialects() {
		if len(set.RealWorld(d)) > 0 {
			out = append(out, d)
		}
	}
	return out
}

// rwSQL returns the dialect's real-world statements below the Large bucket.
func rwSQL(tb testing.TB, dialect string) []string {
	tb.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		tb.Fatalf("benchcorpus.Default: %v", err)
	}
	var out []string
	for _, st := range set.RealWorld(dialect) {
		if st.Bucket != benchcorpus.Large {
			out = append(out, st.SQL)
		}
	}
	return out
}

func totalBytes(stmts []string) int64 {
	var n int64
	for _, s := range stmts {
		n += int64(len(s))
	}
	return n
}

// largeScript builds a script of at least minBytes from the PostgreSQL
// real-world statements, deterministically.
func largeScript(tb testing.TB, minBytes int) string {
	tb.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		tb.Fatalf("benchcorpus.Default: %v", err)
	}
	return benchcorpus.Script(set.RealWorld("postgresql"), minBytes).SQL
}

// paramStyles are parameterized statements in the three placeholder styles
// callers bind: PostgreSQL $n, positional ?, and SQL Server/named @name. None
// is an injection, so a scan of them reports no findings.
var paramStyles = []struct {
	name    string
	dialect keywords.SQLDialect
	stmts   []string
}{
	{"pg_dollar", keywords.DialectPostgreSQL, []string{
		"SELECT id, name FROM users WHERE id = $1 AND status = $2",
		"INSERT INTO orders (user_id, total, created_at) VALUES ($1, $2, $3)",
		"UPDATE accounts SET status = $1 WHERE id = $2 AND balance >= $3",
		"SELECT o.id, o.total FROM orders o JOIN users u ON u.id = o.user_id WHERE u.email = $1 ORDER BY o.created_at DESC LIMIT $2",
		"DELETE FROM sessions WHERE token = $1 AND expires_at < $2",
	}},
	{"qmark", keywords.DialectMySQL, []string{
		"SELECT id, name FROM users WHERE id = ? AND status = ?",
		"INSERT INTO orders (user_id, total, created_at) VALUES (?, ?, ?)",
		"UPDATE accounts SET status = ? WHERE id = ? AND balance >= ?",
		"SELECT o.id, o.total FROM orders o JOIN users u ON u.id = o.user_id WHERE u.email = ? ORDER BY o.created_at DESC LIMIT ?",
		"DELETE FROM sessions WHERE token = ? AND expires_at < ?",
	}},
	{"at", keywords.DialectSQLServer, []string{
		"SELECT id, name FROM users WHERE id = @p1 AND status = @p2",
		"INSERT INTO orders (user_id, total, created_at) VALUES (@p1, @p2, @p3)",
		"UPDATE accounts SET status = @status WHERE id = @id AND balance >= @amount",
		"SELECT o.id, o.total FROM orders o JOIN users u ON u.id = o.user_id WHERE u.email = @email ORDER BY o.created_at DESC",
		"DELETE FROM sessions WHERE token = @token AND expires_at < @now",
	}},
}

func BenchmarkScanSQLRW(b *testing.B) {
	sc := security.NewScanner()
	for _, d := range rwDialects(b) {
		stmts := rwSQL(b, d)
		b.Run(d, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(totalBytes(stmts))
			for i := 0; i < b.N; i++ {
				for _, s := range stmts {
					_ = sc.ScanSQL(s)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(stmts)), "ns/stmt")
		})
	}
}

func BenchmarkScanSQLParams(b *testing.B) {
	sc := security.NewScanner()
	for _, ps := range paramStyles {
		b.Run(ps.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(totalBytes(ps.stmts))
			for i := 0; i < b.N; i++ {
				for _, st := range ps.stmts {
					_ = sc.ScanSQL(st)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(ps.stmts)), "ns/stmt")
		})
	}
}

func BenchmarkScanSQLLarge(b *testing.B) {
	sc := security.NewScanner()
	for _, tc := range []struct {
		name  string
		bytes int
	}{{"30KB", 30 << 10}, {"1MB", 1 << 20}} {
		sql := largeScript(b, tc.bytes)
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(sql)))
			for i := 0; i < b.N; i++ {
				_ = sc.ScanSQL(sql)
			}
		})
	}
}

// parseTrees parses each statement with the dialect and keeps the trees that
// parse. The caller releases them.
func parseTrees(tb testing.TB, stmts []string, dialect string) []*ast.AST {
	tb.Helper()
	var trees []*ast.AST
	for _, s := range stmts {
		tree, err := gosqlx.ParseWithDialect(s, keywords.SQLDialect(dialect))
		if err == nil && tree != nil {
			trees = append(trees, tree)
		}
	}
	return trees
}

func BenchmarkScanASTRW(b *testing.B) {
	sc := security.NewScanner()
	// The trees are shared by every run of every sub-benchmark (testing runs
	// the sub-benchmark function once per N), so they are released exactly
	// once, from this top-level benchmark's cleanup. Releasing from a cleanup
	// registered inside b.Run would empty the trees after the N=1 probe and
	// put them into the pool repeatedly.
	var all []*ast.AST
	b.Cleanup(func() {
		for _, t := range all {
			ast.ReleaseAST(t)
		}
	})
	for _, d := range rwDialects(b) {
		trees := parseTrees(b, rwSQL(b, d), d)
		all = append(all, trees...)
		b.Run(d, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for _, t := range trees {
					_ = sc.Scan(t)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(trees)), "ns/stmt")
			// Fail if the inputs were emptied while timing.
			for _, t := range trees {
				if len(t.Statements) == 0 {
					b.Fatal("benchmark input AST was released or emptied during the run")
				}
			}
		})
	}
}

// TestParameterizedBenchInputsAreClean pins what BenchmarkScanSQLParams
// measures: the scan of bound-parameter statements finds nothing, and the
// statements parse in their dialect so the same inputs serve an AST scan.
func TestParameterizedBenchInputsAreClean(t *testing.T) {
	sc := security.NewScanner()
	for _, ps := range paramStyles {
		t.Run(ps.name, func(t *testing.T) {
			for _, s := range ps.stmts {
				if res := sc.ScanSQL(s); res.TotalCount != 0 {
					t.Errorf("ScanSQL found %d findings in %q: %+v", res.TotalCount, s, res.Findings)
				}
				tree, err := gosqlx.ParseWithDialect(s, ps.dialect)
				if err != nil {
					t.Errorf("%q does not parse as %s: %v", s, ps.dialect, err)
					continue
				}
				if res := sc.Scan(tree); res.TotalCount != 0 {
					t.Errorf("Scan found %d findings in %q", res.TotalCount, s)
				}
				ast.ReleaseAST(tree)
			}
		})
	}
}

// TestLargeScriptSizes pins the two ScanSQLLarge inputs: at least the named
// size, below security.MaxScanInputSize so the scanner does not
// short-circuit, and identical across two builds.
func TestLargeScriptSizes(t *testing.T) {
	for _, min := range []int{30 << 10, 1 << 20} {
		s := largeScript(t, min)
		if len(s) < min || len(s) > min+64<<10 {
			t.Errorf("script for %d bytes is %d bytes", min, len(s))
		}
		if s != largeScript(t, min) {
			t.Errorf("script for %d bytes is not deterministic", min)
		}
		if len(s) >= security.MaxScanInputSize {
			t.Errorf("script for %d bytes reaches the scanner input limit", min)
		}
	}
}

// TestRWScansAreDeterministicAndConsistent checks that scanning the same
// statements twice yields the same finding counts, for the SQL scan and for
// the AST scan, on every dialect. A benchmark that scans different work per
// iteration would not be comparable between commits.
func TestRWScansAreDeterministicAndConsistent(t *testing.T) {
	sc := security.NewScanner()
	for _, d := range rwDialects(t) {
		stmts := rwSQL(t, d)
		if len(stmts) == 0 {
			t.Fatalf("%s: no statements", d)
		}
		sum := func() (sqlN, astN int) {
			for _, s := range stmts {
				sqlN += sc.ScanSQL(s).TotalCount
			}
			trees := parseTrees(t, stmts, d)
			if len(trees)*2 < len(stmts) {
				t.Errorf("%s: only %d of %d statements parse", d, len(trees), len(stmts))
			}
			for _, tr := range trees {
				astN += sc.Scan(tr).TotalCount
				ast.ReleaseAST(tr)
			}
			return sqlN, astN
		}
		s1, a1 := sum()
		s2, a2 := sum()
		if s1 != s2 || a1 != a2 {
			t.Errorf("%s: counts differ between runs: sql %d/%d ast %d/%d", d, s1, s2, a1, a2)
		}
	}
}
