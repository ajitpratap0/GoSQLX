// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package transpiler

import (
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

func TestOpsSkipIsSafe(t *testing.T) {
	dialects := prefilterDialects()
	if testing.Short() {
		dialects = []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectSQLServer}
	}
	stmts := []string{"SELECT a + 1 FROM t WHERE b <> 2 AND c <= 3", "SELECT a FROM t LIMIT 5", "UPDATE t SET a = a - 1 WHERE id = 7"}
	err := filepath.WalkDir("../../testdata/realworld", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".sql" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, c := range strings.Split(string(data), ";") {
			if strings.TrimSpace(c) != "" && (!testing.Short() || i < 2) {
				stmts = append(stmts, c)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	n := 2000
	if testing.Short() || raceDetector {
		n = 200
	}
	r := rand.New(rand.NewSource(7))
	for i := 0; i < n; i++ {
		stmts = append(stmts, vstmt(r))
	}
	skipped := 0
	for _, sql := range stmts {
		if scanSource(sql).ops {
			continue
		}
		for _, from := range dialects {
			for i, to := range dialects {
				tree, err := parser.ParseWithDialect(sql, from)
				if err != nil {
					continue
				}
				if i == 0 {
					skipped++
				}
				before := fmtTree(t, tree, to)
				for _, stmt := range tree.Statements {
					if err := retargetOperators(stmt, from, to); err != nil {
						ast.ReleaseAST(tree)
						t.Fatalf("%s -> %s %q: %v", from, to, sql, err)
					}
				}
				after := fmtTree(t, tree, to)
				ast.ReleaseAST(tree)
				if after != before {
					t.Fatalf("%s -> %s %q: %q -> %q", from, to, sql, before, after)
				}
			}
		}
	}
	if skipped < 50 {
		t.Fatalf("only %d parseable statements exercised", skipped)
	}
	t.Logf("skipped %d parseable statements", skipped)
}

func fmtTree(t *testing.T, tree *ast.AST, to keywords.SQLDialect) string {
	t.Helper()
	style := ast.CompactStyle()
	style.Dialect = string(to)
	out, err := formatter.FormatASTChecked(tree, style)
	if err != nil {
		return "ERR:" + err.Error()
	}
	return out
}

func TestScanSourceOps(t *testing.T) {
	yes := []string{"a ^ b", "a | b", "a & b", "a # b", "~a", "@ a", "a ? b", "a != b", "$1", "{'k': 1}", "a << b", "a >> b", "a <-> b", "x<-1", "a <=> b", "a -> b", "a ->> b", "f(x => 1)", "a := 1", `U&'d\0061t'`, `u&'x'`}
	no := []string{"1", "a + b - c * d / e % f", "a = 1", "a <> 2", "a < 3", "a > 4", "a <= 5", "a >= 6", "x < -1", "-1", "NOT a", "a OR b AND c", "a::INT", "b[1]", "a IN (1, 2)", "a BETWEEN 1 AND 2", "a LIKE 'x%'", "a IS NULL", "CAST(a AS INT)", "COUNT(*)", "1 -- c", "1 /* c */", "'it''s'", `"q"`, "`q`", "[q]", "u.id FROM users u", "* FROM a JOIN b USING (id)", "a FROM t ORDER BY 1 LIMIT 5", "é", "a <", "a -", "a =", "a :", "U"}
	for _, s := range yes {
		for _, prefix := range []string{"", "SELECT "} {
			if !scanSource(prefix + s).ops {
				t.Errorf("%q: want ops", prefix+s)
			}
		}
	}
	for _, s := range []string{"a ^", "a |", "a &", "a #", "a ~", "a @", "a ?", "a !", "a {", "a $", "a <<", "a <-", "a >>", "a ->", "a =>", "a :=", "U&", "u&"} {
		if !scanSource(s).ops {
			t.Errorf("%q: want ops", s)
		}
	}
	if scanSource("").ops {
		t.Error("empty source has ops")
	}
	for _, s := range no {
		if scanSource("SELECT " + s).ops {
			t.Errorf("%q: unexpected ops", s)
		}
	}
}

func TestOpsPrefilterRequiredConstructs(t *testing.T) {
	pg, my, or, sf, ss, ch, sq := keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectOracle, keywords.DialectSnowflake, keywords.DialectSQLServer, keywords.DialectClickHouse, keywords.DialectSQLite
	cases := []struct {
		sql               string
		from, to          keywords.SQLDialect
		contains, errText string
	}{
		{"SELECT a ^ b FROM t", pg, my, "POWER(a, b)", ""}, {"SELECT a ^ b FROM t", my, pg, "a # b", ""}, {"SELECT a ^ b FROM t", my, or, "", "the bitwise XOR operator ^ has no equivalent in oracle"},
		{"SELECT a | b FROM t", pg, sf, "BITOR(a, b)", ""}, {"SELECT a | b FROM t", pg, or, "", "the PostgreSQL operator | has no equivalent in oracle"}, {"SELECT a & b FROM t", pg, or, "BITAND(a, b)", ""},
		{"SELECT a # b FROM t", pg, my, "a ^ b", ""}, {"SELECT a # b FROM t", pg, or, "", "the PostgreSQL bitwise XOR operator # has no equivalent in oracle"},
		{"SELECT a << 1 FROM t", pg, ss, "LEFT_SHIFT(a, 1)", ""}, {"SELECT a >> 1 FROM t", pg, ch, "bitShiftRight(a, 1)", ""}, {"SELECT ~a FROM t", pg, sf, "BITNOT(a)", ""}, {"SELECT ~a FROM t", pg, or, "", "the bitwise NOT operator ~ has no equivalent in oracle"},
		{"SELECT @ a FROM t", pg, my, "ABS(a)", ""}, {"SELECT |/ a FROM t", pg, my, "SQRT(a)", ""}, {"SELECT ||/ a FROM t", pg, my, "", "the PostgreSQL cube root operator ||/ has no equivalent in mysql"}, {"SELECT !! 5 FROM t", pg, my, "", "the PostgreSQL factorial operator !! has no equivalent in mysql"},
		{"SELECT a ? 'k' FROM t", pg, my, "", "the PostgreSQL operator ? has no equivalent in mysql"}, {"SELECT a ?| b FROM t", pg, sq, "", "the PostgreSQL operator ?| has no equivalent in sqlite"}, {"SELECT a @> b FROM t", pg, my, "", "the PostgreSQL operator @> has no equivalent in mysql"}, {"SELECT a <-> b FROM t", pg, my, "", "the PostgreSQL operator <-> has no equivalent in mysql"}, {"SELECT a ~* b FROM t", pg, my, "", "the PostgreSQL operator ~* has no equivalent in mysql"}, {"SELECT a !~ b FROM t", pg, my, "", "the PostgreSQL operator !~ has no equivalent in mysql"},
		{"SELECT j -> 'k' FROM t", pg, ch, "", "the JSON operator -> has no equivalent in clickhouse"}, {"SELECT j ->> 'k' FROM t", pg, sf, "", "the JSON operator ->> has no equivalent in snowflake"}, {"SELECT arrayMap(x -> x * 2, [1, 2]) FROM t", ch, pg, "", "the lambda operator -> has no equivalent in postgresql"}, {"SELECT a || b FROM t", pg, my, "CONCAT(a, b)", ""},
		{"SELECT $5.00 FROM t", ss, pg, "", "the SQL Server money literal $5.00 has no equivalent in postgresql"}, {"SELECT $5 FROM t", ss, pg, "", "the SQL Server money literal $5 has no equivalent in postgresql"}, {"SELECT {'k': 1} FROM t", sf, pg, "", "the Snowflake object constant {...} has no equivalent in postgresql"}, {`SELECT U&'d\0061t' FROM t`, pg, my, "", "the PostgreSQL Unicode escape syntax U& has no equivalent in mysql"}, {`SELECT u&'d\0061t' FROM t`, pg, my, "", "the PostgreSQL Unicode escape syntax U& has no equivalent in mysql"},
	}
	for _, tc := range cases {
		t.Run(tc.sql+"/"+string(tc.from)+"_"+string(tc.to), func(t *testing.T) {
			if !scanSource(tc.sql).ops {
				t.Errorf("source not classified as ops")
			}
			out, err := Transpile(tc.sql, tc.from, tc.to)
			if tc.errText != "" {
				if err == nil || err.Error() != "rewrite: "+tc.errText {
					t.Errorf("error = %v, want rewrite: %s", err, tc.errText)
				}
			} else if err != nil || !strings.Contains(out, tc.contains) {
				t.Errorf("output = %q, error = %v; want %q", out, err, tc.contains)
			}
			if testing.Short() {
				checkPrefilterEquivalent(t, tc.sql, tc.from, tc.to)
			} else {
				for _, from := range prefilterDialects() {
					for _, to := range prefilterDialects() {
						checkPrefilterEquivalent(t, tc.sql, from, to)
					}
				}
			}
		})
	}
}
