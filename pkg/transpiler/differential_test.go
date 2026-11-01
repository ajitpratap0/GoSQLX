// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package transpiler

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// Generator vocabulary: operators and atoms chosen to hit every byte class the
// source prefilters key on (|, quotes, non-ASCII, type delimiters, backslashes).
var vbin = []string{"+", "-", "*", "/", "%", "^", "|", "&", "#", "||", "<<", ">>", "->", "->>", "#>", "#>>", "@>", "<@", "?", "?|", "?&", "<=>", "=", "<>", "!=", "<", "<=", ">", ">=", "AND", "OR", "XOR", "DIV", "MOD", "IS DISTINCT FROM", "LIKE", "ILIKE", "~", "~*", "!~", "&&", "@@", "<->", "=>", ":=", "IN"}
var vun = []string{"-", "+", "NOT ", "~", "@", "|/", "||/", "!!", "PRIOR ", "BINARY ", "CONNECT_BY_ROOT ", "!"}
var vatoms = []string{"a", "b", "t.c", "1", "2.5", "'x'", "'a\\nb'", "'\\x1a'", "'\\0'", "'\\Z'", "E'a\\\\b'", "N'x'", "X'41'", "$5", "$5.00", "{'k': 1}", "U&'d\\0041'", "NULL", "?", "$1", ":p", "q'[a]'", "_utf8mb4'a'", "'a\x00b'", "'a\x1ab'", "$$a\\b$$", "`q`", "\"q\"", "[q]"}

func vexpr(r *rand.Rand, d int) string {
	if d <= 0 || r.Intn(4) == 0 {
		return vatoms[r.Intn(len(vatoms))]
	}
	switch r.Intn(9) {
	case 0, 1, 2, 3:
		return vexpr(r, d-1) + " " + vbin[r.Intn(len(vbin))] + " " + vexpr(r, d-1)
	case 4:
		return vun[r.Intn(len(vun))] + vexpr(r, d-1)
	case 5:
		return "(" + vexpr(r, d-1) + ")"
	case 6:
		return "f(" + vexpr(r, d-1) + ", " + vexpr(r, d-1) + ")"
	case 7:
		return "CASE WHEN " + vexpr(r, d-1) + " THEN " + vexpr(r, d-1) + " ELSE " + vexpr(r, d-1) + " END"
	default:
		return "CAST(" + vexpr(r, d-1) + " AS INT)"
	}
}

func vstmt(r *rand.Rand) string {
	var sb strings.Builder
	switch r.Intn(10) {
	case 0:
		sb.WriteString("SELECT TOP 5 ")
	case 1:
		sb.WriteString("SELECT DISTINCT ")
	default:
		sb.WriteString("SELECT ")
	}
	sb.WriteString(vexpr(r, 4))
	sb.WriteString(" FROM t")
	if r.Intn(2) == 0 {
		sb.WriteString(" WHERE " + vexpr(r, 3))
	}
	switch r.Intn(10) {
	case 0:
		sb.WriteString(" ORDER BY 1 LIMIT 5 WITH TIES")
	case 1:
		sb.WriteString(" ORDER BY 1 FETCH FIRST 5 ROWS WITH TIES")
	case 2:
		sb.WriteString(" ORDER BY 1 LIMIT 5 OFFSET 2")
	case 3:
		sb.WriteString(" UNION SELECT 1 FROM u ORDER BY 1 LIMIT 3")
	case 4:
		sb.WriteString(" ORDER BY 1 OFFSET 2 ROWS FETCH NEXT 5 ROWS ONLY")
	}
	if r.Intn(8) == 0 {
		sb.WriteString("; INSERT INTO t VALUES (" + vexpr(r, 2) + ")")
	}
	return sb.String()
}

func vfixed(depths []int) []string {
	out := []string{
		"SELECT 'a\\x1a'", "SELECT '\\u001a'", "SELECT '\\032'", "SELECT 'x\\0y'", "SELECT 'x\\Zy'",
		"SELECT * FROM t LIMIT 5 WITH TIES", "SELECT topic FROM t", "SELECT a FROM stopwatch", "SELECT ties FROM t",
		"UPDATE TOP (5) t SET a = 1", "DELETE TOP (5) FROM t", "INSERT TOP (5) INTO t SELECT 1",
		"SELECT a FROM t UNION ALL SELECT b FROM u ORDER BY 1 LIMIT 5",
		"(SELECT a FROM t ORDER BY a LIMIT 1) UNION (SELECT b FROM u ORDER BY b LIMIT 2) ORDER BY 1 LIMIT 3",
		"SELECT a FROM t WHERE a < b AND b <= c AND c >= d AND d <> e",
		// Byte classes the DDL and non-ASCII prefilters key on. The quoted and
		// bracketed type-delimiter fixtures below do not distinguish the DDL
		// prefilter for " and [: formatter.FormatASTChecked restyles data types
		// itself, so those two branches are equivalent mutants (only the backtick
		// case with ClickHouse reaches the prefilter). The white-box tests
		// TestScanSourceStringOpeners and TestScanSourceTypeDelimiters pin them.
		"SELECT ‘a’", "SELECT «a»", "SELECT ‘a\\nb’", "SELECT «a\\tb»", "SELECT „a“ FROM t", "SELECT \u201cx\u201d FROM t", "SELECT émoji FROM t WHERE a = 'é'",
		`CREATE TABLE t (v "custom")`, "CREATE TABLE t (v `custom`)", "CREATE TABLE t (v [custom])", "CREATE TABLE t (v INT[])",
		"CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY, flag TINYINT(1))", `CREATE TABLE "my tbl" ("my col" INT)`,
		"CREATE TABLE `my tbl` (`my col` INT)", "CREATE TABLE [my tbl] ([my col] INT)", "SELECT `a b`, \"c d\", [e f] FROM `g h`",
		`SELECT "a\nb" FROM t`, `SELECT "a\\b", "it's" FROM t`, `SELECT "x" FROM t WHERE "y" = "z"`, `SELECT a AS "my col" FROM t`,
		"SELECT [a] FROM [t] WHERE [b] = 1", "SELECT a[1] FROM t", "SELECT ARRAY[1,2][1] FROM t", "SELECT x::INT[] FROM t", "SELECT CAST(x AS [custom]) FROM t",
		"SELECT é FROM ü", "SELECT a AS é FROM t", "SELECT ‘it’s’", "CREATE TABLE té (cé INT)", "SELECT 1 AS \u2018x\u2019",
		"SELECT 1 FROM t WHERE x = 1 /* ^ | */", "SELECT 1 -- ^\n", "SELECT ¬ FROM t",
	}
	for _, n := range depths {
		out = append(out,
			"SELECT "+strings.Repeat("(", n)+"1"+strings.Repeat(")", n)+" FROM t",
			"SELECT "+strings.Repeat("f(", n)+"1"+strings.Repeat(")", n)+" FROM t",
			"SELECT "+strings.Repeat("NOT ", n)+"1 FROM t",
			"SELECT "+strings.Repeat("- ", n)+"1 FROM t",
			"SELECT "+strings.Repeat("+ ", n)+"1 FROM t",
			"SELECT "+strings.Repeat("PRIOR ", n)+"1 FROM t",
			"SELECT "+strings.Repeat("BINARY ", n)+"1 FROM t",
			"SELECT "+strings.Repeat("CONNECT_BY_ROOT ", n)+"1 FROM t",
			"SELECT 1"+strings.Repeat(" + (1", n)+strings.Repeat(")", n)+" FROM t",
			"SELECT 1"+strings.Repeat(" * 2 + 3 - (4 / 5)", n/4)+" FROM t",
			"SELECT 1"+strings.Repeat(" OR a", n)+" FROM t",
		)
	}
	return out
}

// TestTranspileDifferential compares the prefiltered pipeline with the
// unfiltered one over every ordered dialect pair for fixed edge cases and a
// seeded random corpus. Prefilters must be pure optimisations: any diff in
// output or error text is a bug in a prefilter or in a rule it skips.
func TestTranspileDifferential(t *testing.T) {
	dialects := prefilterDialects()
	r := rand.New(rand.NewSource(42))
	var sqls []string
	// The deep-nesting fixtures (depths straddling the 512 recursion ceiling)
	// over 81 pairs dominate the cost, not the random corpus. Under -race or
	// -short keep one depth just below and one above the ceiling.
	depths := []int{510, 511, 512, 513, 514, 520, 600, 1100}
	n := 6000
	if raceDetector || testing.Short() {
		depths = []int{511, 513}
		n = 200
	}
	sqls = append(sqls, vfixed(depths)...)
	for i := 0; i < n; i++ {
		sqls = append(sqls, vstmt(r))
	}
	bad := 0
	cnt := 0
	valid := 0
	for _, sql := range sqls {
		for _, from := range dialects {
			if _, perr := parser.ParseWithDialect(sql, from); perr != nil {
				continue
			}
			valid++
			for _, to := range dialects {
				cnt++
				got, gotErr := transpile(sql, from, to, true)
				want, wantErr := transpile(sql, from, to, false)
				if got != want || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
					bad++
					if bad <= 15 {
						sh := sql
						if len(sh) > 160 {
							sh = sh[:160] + "..."
						}
						t.Errorf("DIFF %s->%s %q\n  filtered=(%q, %v)\n  unfilter=(%q, %v)", from, to, sh, truncForLog(got), gotErr, truncForLog(want), wantErr)
					}
				}
			}
		}
	}
	t.Logf("compared %d transpile pairs (%d parse-ok source/dialect combos), %d diffs", cnt, valid, bad)
	if bad > 0 {
		t.Fail()
	}
}

func truncForLog(s string) string {
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}
