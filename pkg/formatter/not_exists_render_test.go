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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// notExistsParse parses sql with the given dialect ("" selects gosqlx.Parse).
func notExistsParse(sql string, dialect keywords.SQLDialect) (*ast.AST, error) {
	if dialect == "" {
		return gosqlx.Parse(sql)
	}
	return gosqlx.ParseWithDialect(sql, dialect)
}

// TestNotExists_RoundTrip_Issue601 verifies that NOT EXISTS (subquery) renders
// as a prefix NOT (not the invalid "NOT (EXISTS (...) NOT )") through
// AST.SQL(), FormatAST (compact and readable) and survives a re-parse.
func TestNotExists_RoundTrip_Issue601(t *testing.T) {
	cases := []struct {
		name  string
		sql   string
		shape bool // also assert the AST shape of a top-level WHERE NOT EXISTS
	}{
		{"where", "SELECT * FROM t WHERE NOT EXISTS (SELECT 1 FROM u)", true},
		{"and_after", "SELECT * FROM t WHERE NOT EXISTS (SELECT 1 FROM u) AND a = 1", false},
		{"and_before_correlated", "SELECT * FROM t WHERE a = 1 AND NOT EXISTS (SELECT 1 FROM u WHERE u.x = t.x)", false},
		{"or", "SELECT * FROM t WHERE a = 1 OR NOT EXISTS (SELECT 1 FROM u)", false},
		{"nested", "SELECT * FROM t WHERE NOT EXISTS (SELECT 1 FROM u WHERE NOT EXISTS (SELECT 1 FROM v WHERE v.y = u.y))", true},
		{"case_when", "SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM u) THEN 1 ELSE 0 END AS flag FROM t", false},
		{"parenthesized", "SELECT * FROM t WHERE (NOT EXISTS (SELECT 1 FROM u)) OR b = 2", false},
		{"having", "SELECT dept FROM emp GROUP BY dept HAVING NOT EXISTS (SELECT 1 FROM u)", false},
		{"update", "UPDATE t SET a = 1 WHERE NOT EXISTS (SELECT 1 FROM u WHERE u.id = t.id)", false},
		{"delete", "DELETE FROM t WHERE NOT EXISTS (SELECT 1 FROM u WHERE u.id = t.id)", false},
	}
	dialects := []struct {
		name string
		d    keywords.SQLDialect
	}{
		{"default", ""},
		{"postgresql", keywords.DialectPostgreSQL},
		{"mysql", keywords.DialectMySQL},
		{"sqlserver", keywords.DialectSQLServer},
		{"sqlite", keywords.DialectSQLite},
		{"oracle", keywords.DialectOracle},
		{"snowflake", keywords.DialectSnowflake},
		{"clickhouse", keywords.DialectClickHouse},
		{"mariadb", keywords.DialectMariaDB},
	}

	for _, tc := range cases {
		for _, dl := range dialects {
			t.Run(tc.name+"/"+dl.name, func(t *testing.T) {
				tree, err := notExistsParse(tc.sql, dl.d)
				if err != nil {
					t.Fatalf("parse %q: %v", tc.sql, err)
				}
				defer ast.ReleaseAST(tree)

				// The input is already in canonical form, so SQL() must
				// reproduce it exactly.
				want := tc.sql
				got := tree.SQL()
				if got != want {
					t.Fatalf("tree.SQL() mismatch\n got: %s\nwant: %s", got, want)
				}
				assertNoBrokenNotExists(t, "tree.SQL()", got)

				compact := formatter.FormatAST(tree, ast.CompactStyle())
				if compact != want {
					t.Errorf("FormatAST(compact) mismatch\n got: %s\nwant: %s", compact, want)
				}
				assertNoBrokenNotExists(t, "FormatAST(compact)", compact)

				// Idempotent round trip through SQL().
				tree2, err := notExistsParse(got, dl.d)
				if err != nil {
					t.Fatalf("re-parse of tree.SQL() %q: %v", got, err)
				}
				defer ast.ReleaseAST(tree2)
				if got2 := tree2.SQL(); got2 != want {
					t.Errorf("re-parsed SQL() mismatch\n got: %s\nwant: %s", got2, want)
				}
				if tc.shape {
					assertNotExistsShape(t, tree2)
				}

				// Readable formatter output must also re-parse to the same SQL.
				readable := formatter.FormatAST(tree, ast.ReadableStyle())
				assertNoBrokenNotExists(t, "FormatAST(readable)", readable)
				tree3, err := notExistsParse(readable, dl.d)
				if err != nil {
					t.Fatalf("re-parse of readable output %q: %v", readable, err)
				}
				defer ast.ReleaseAST(tree3)
				if got3 := tree3.SQL(); got3 != want {
					t.Errorf("readable re-parse SQL() mismatch\n got: %s\nwant: %s", got3, want)
				}
			})
		}
	}
}

func assertNoBrokenNotExists(t *testing.T, label, s string) {
	t.Helper()
	if strings.Contains(s, "NOT (EXISTS") || strings.Contains(s, ") NOT )") {
		t.Errorf("%s contains the invalid NOT EXISTS rendering: %s", label, s)
	}
}

// assertNotExistsShape checks that the first statement's WHERE is the parser's
// NOT EXISTS shape: BinaryExpression{Operator: NOT, Not: true, Right: nil,
// Left: *ExistsExpression}.
func assertNotExistsShape(t *testing.T, tree *ast.AST) {
	t.Helper()
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
	}
	bin, ok := sel.Where.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected WHERE *ast.BinaryExpression, got %T", sel.Where)
	}
	if !strings.EqualFold(bin.Operator, "NOT") || !bin.Not || bin.Right != nil {
		t.Errorf("unexpected shape: Operator=%q Not=%v Right=%v", bin.Operator, bin.Not, bin.Right)
	}
	if _, ok := bin.Left.(*ast.ExistsExpression); !ok {
		t.Errorf("expected Left *ast.ExistsExpression, got %T", bin.Left)
	}
}

func TestNotExists_FormatString_Issue601(t *testing.T) {
	inputs := []string{
		"SELECT * FROM t WHERE NOT EXISTS (SELECT 1 FROM u)",
		"SELECT * FROM t WHERE NOT EXISTS (SELECT 1 FROM u) AND a = 1",
	}
	for _, in := range inputs {
		out, err := formatter.FormatString(in)
		if err != nil {
			t.Fatalf("FormatString(%q): %v", in, err)
		}
		if !strings.Contains(out, "NOT EXISTS (SELECT 1 FROM u)") {
			t.Errorf("FormatString(%q) lost NOT EXISTS: %q", in, out)
		}
		assertNoBrokenNotExists(t, "FormatString", out)
		tree, err := gosqlx.Parse(out)
		if err != nil {
			t.Fatalf("formatted output %q does not re-parse: %v", out, err)
		}
		ast.ReleaseAST(tree)
	}
}
