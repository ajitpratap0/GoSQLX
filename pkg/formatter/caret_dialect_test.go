// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestCaretTargetDialect(t *testing.T) {
	tests := []struct {
		source, target keywords.SQLDialect
		in, contains   string
		wantError      bool
	}{
		{"postgresql", "mysql", "SELECT a ^ (b + c) * d", "POWER(a, (b + c)) * d", false},
		{"postgresql", "sqlserver", "SELECT a ^ b", "POWER(a, b)", false},
		{"postgresql", "oracle", "SELECT a ^ b", "POWER(a, b)", false},
		{"postgresql", "sqlite", "SELECT a ^ b", "POWER(a, b)", false},
		{"generic", "postgresql", "SELECT a -> b ^ 2", "(a -> b) ^ 2", false},
		{"generic", "postgresql", "SELECT a ^ b -> c", "a ^ (b -> c)", false},
		{"mysql", "postgresql", "SELECT a * b ^ c", "a * (b # c)", false},
		{"mysql", "sqlserver", "SELECT a * b ^ c", "a * (b ^ c)", false},
		{"sqlserver", "mysql", "SELECT a + b ^ c", "(a + b) ^ c", false},
		{"sqlserver", "snowflake", "SELECT a ^ b", "BITXOR(a, b)", false},
		{"mysql", "clickhouse", "SELECT a ^ b", "bitXor(a, b)", false},
		{"mysql", "sqlite", "SELECT a ^ b", "", true},
		{"mysql", "generic", "SELECT a ^ b", "", true},
		{"postgresql", "mysql", `SELECT U&'d\0061t'`, "", true},
		// PostgreSQL # (XOR), ~, shifts, || and PostgreSQL-only operators.
		{"postgresql", "mysql", "SELECT a # b FROM t", "SELECT a ^ b FROM t", false},
		{"postgresql", "mysql", "SELECT a # b * c", "a ^ (b * c)", false},
		{"postgresql", "mariadb", "SELECT a * (b # c)", "a * (b ^ c)", false},
		{"postgresql", "sqlserver", "SELECT a # b + c", "a ^ (b + c)", false},
		{"postgresql", "snowflake", "SELECT a # b, ~a, a << 2, a | b", "BITXOR(a, b), BITNOT(a), BITSHIFTLEFT(a, 2), BITOR(a, b)", false},
		{"postgresql", "clickhouse", "SELECT a # b, ~a, a >> 2, a & b", "bitXor(a, b), bitNot(a), bitShiftRight(a, 2), bitAnd(a, b)", false},
		{"postgresql", "sqlserver", "SELECT a << 2", "LEFT_SHIFT(a, 2)", false},
		{"postgresql", "oracle", "SELECT a & b FROM t", "BITAND(a, b)", false},
		{"postgresql", "mysql", "SELECT a || b || c", "CONCAT(a, b, c)", false},
		{"postgresql", "oracle", "SELECT a # b FROM t", "", true},
		{"postgresql", "oracle", "SELECT ~a FROM t", "", true},
		{"postgresql", "oracle", "SELECT a << 2 FROM t", "", true},
		{"postgresql", "sqlite", "SELECT a # b", "", true},
		{"postgresql", "mysql", "SELECT a @> b", "", true},
		{"postgresql", "snowflake", "SELECT a ~ 'x'", "", true},
	}
	for _, tt := range tests {
		t.Run(string(tt.source)+"/"+string(tt.target)+"/"+tt.in, func(t *testing.T) {
			a, err := gosqlx.ParseWithDialect(tt.in, tt.source)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(a)
			before := a.SQL()
			opts := ast.CompactStyle()
			opts.Dialect = string(tt.target)
			got, err := formatter.FormatASTChecked(a, opts)
			if (err != nil) != tt.wantError {
				t.Fatalf("output=%q error=%v", got, err)
			}
			if tt.wantError {
				if legacy := formatter.FormatAST(a, opts); legacy != "" {
					t.Errorf("unchecked returned unsafe SQL %q", legacy)
				}
				if trans, err := gosqlx.Transpile(tt.in, tt.source, tt.target); err == nil {
					t.Errorf("transpiler returned %q, want error", trans)
				}
				return
			}
			if !strings.Contains(got, tt.contains) {
				t.Errorf("got %q want fragment %q", got, tt.contains)
			}
			again, err := gosqlx.ParseWithDialect(got, tt.target)
			if err != nil {
				t.Fatalf("target reparse %q: %v", got, err)
			}
			defer ast.ReleaseAST(again)
			if a.SQL() != before {
				t.Errorf("source mutated: %q -> %q", before, a.SQL())
			}
			trans, err := gosqlx.Transpile(tt.in, tt.source, tt.target)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(trans, tt.contains) {
				t.Errorf("transpiler disagrees: %q", trans)
			}
		})
	}
}

func TestFormatQuotedTypesForTarget(t *testing.T) {
	for _, in := range []string{`SELECT CAST(x AS "MyType"), x::"char"`, `CREATE TABLE t (a "MyDomain")`} {
		a, err := gosqlx.ParseWithDialect(in, keywords.DialectPostgreSQL)
		if err != nil {
			t.Fatal(err)
		}
		defer ast.ReleaseAST(a)
		before := a.SQL()
		opts := ast.CompactStyle()
		opts.Dialect = "mysql"
		out, err := formatter.FormatASTChecked(a, opts)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, `"My`) || !strings.Contains(out, "`") {
			t.Fatalf("target type quotes lost: %s", out)
		}
		b, err := gosqlx.ParseWithDialect(out, keywords.DialectMySQL)
		if err != nil {
			t.Fatal(err)
		}
		defer ast.ReleaseAST(b)
		if a.SQL() != before {
			t.Fatal("source mutated")
		}
	}
}

func TestFormatTargetDoesNotMutateMapExpressions(t *testing.T) {
	a, err := gosqlx.ParseWithDialect(`SELECT * FROM t AT (TIMESTAMP => CAST('x' AS "MyType"))`, keywords.DialectSnowflake)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(a)
	before := a.SQL()
	opts := ast.CompactStyle()
	opts.Dialect = "mysql"
	if _, err := formatter.FormatASTChecked(a, opts); err != nil {
		t.Fatal(err)
	}
	if got := a.SQL(); got != before {
		t.Fatalf("source mutated: %q -> %q", before, got)
	}
}
