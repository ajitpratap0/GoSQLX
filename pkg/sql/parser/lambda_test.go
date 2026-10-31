// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// firstArrow returns the first -> BinaryExpression in the first argument of
// the first function call in the first SELECT column.
func firstArrow(t *testing.T, sql string, d keywords.SQLDialect) *ast.BinaryExpression {
	t.Helper()
	tree, err := parser.ParseWithDialect(sql, d)
	if err != nil {
		t.Fatalf("%s %q: %v", d, sql, err)
	}
	t.Cleanup(func() { ast.ReleaseAST(tree) })
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("%s %q: statement %T", d, sql, tree.Statements[0])
	}
	call, ok := sel.Columns[0].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("%s %q: column %T", d, sql, sel.Columns[0])
	}
	for _, arg := range call.Arguments {
		if b, ok := arg.(*ast.BinaryExpression); ok && b.Operator == "->" {
			return b
		}
	}
	t.Fatalf("%s %q: no -> argument in %#v", d, sql, call.Arguments)
	return nil
}

// In ClickHouse and Snowflake -> is the lambda operator: its body is a whole
// expression, so x -> x * 2 is x -> (x * 2) and never (x -> x) * 2 (#897).
func TestLambdaBodyIsWholeExpression(t *testing.T) {
	tests := []struct {
		sql    string
		bodyOp string // operator at the root of the lambda body
	}{
		{"SELECT arrayMap(x -> x * 2, arr) FROM t", "*"},
		{"SELECT arrayMap(x -> x + 1 - y, arr) FROM t", "-"},
		{"SELECT arrayFilter(x -> x > 1 AND x < 5, arr) FROM t", "AND"},
		{"SELECT arrayFilter(x -> x > 1 OR x IS NULL, arr) FROM t", "OR"},
		{"SELECT arrayExists(x -> x LIKE 'err%', tags) FROM t", "LIKE"},
		{"SELECT arrayMap((x, y) -> x + y, a, b) FROM t", "+"},
		{"SELECT arrayFold((acc, x) -> acc + x, arr, 0) FROM t", "+"},
	}
	for _, d := range []keywords.SQLDialect{keywords.DialectClickHouse, keywords.DialectSnowflake} {
		for _, tc := range tests {
			lambda := firstArrow(t, tc.sql, d)
			if !lambda.Lambda {
				t.Errorf("%s %q: -> not marked as a lambda", d, tc.sql)
			}
			body, ok := lambda.Right.(*ast.BinaryExpression)
			if !ok || body.Operator != tc.bodyOp {
				t.Errorf("%s %q: lambda body = %#v, want a %s expression", d, tc.sql, lambda.Right, tc.bodyOp)
			}
		}
	}
}

// Nested lambdas and lambdas whose body is IN keep the full body too.
func TestLambdaBodyNonBinary(t *testing.T) {
	for _, d := range []keywords.SQLDialect{keywords.DialectClickHouse, keywords.DialectSnowflake} {
		lambda := firstArrow(t, "SELECT arrayFilter(x -> x IN (1, 2), arr) FROM t", d)
		if _, ok := lambda.Right.(*ast.InExpression); !ok {
			t.Errorf("%s: IN body = %T", d, lambda.Right)
		}
		outer := firstArrow(t, "SELECT arrayMap(x -> arrayMap(y -> y * x, arr), arr) FROM t", d)
		inner, ok := outer.Right.(*ast.FunctionCall)
		if !ok || len(inner.Arguments) != 2 {
			t.Fatalf("%s: nested body = %#v", d, outer.Right)
		}
		b, ok := inner.Arguments[0].(*ast.BinaryExpression)
		if !ok || !b.Lambda {
			t.Fatalf("%s: inner lambda = %#v", d, inner.Arguments[0])
		}
		if body, ok := b.Right.(*ast.BinaryExpression); !ok || body.Operator != "*" {
			t.Errorf("%s: inner lambda body = %#v", d, b.Right)
		}
	}
}

// Where -> is JSON field access it keeps its tight binding and is not a
// lambda.
func TestJSONArrowIsNotLambda(t *testing.T) {
	for _, d := range []keywords.SQLDialect{keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectSQLite, keywords.DialectPostgreSQL} {
		tree, err := parser.ParseWithDialect("SELECT data -> 'a' FROM t", d)
		if err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		sel, ok := tree.Statements[0].(*ast.SelectStatement)
		if !ok {
			t.Fatalf("%s: statement %T", d, tree.Statements[0])
		}
		b, ok := sel.Columns[0].(*ast.BinaryExpression)
		if !ok || b.Operator != "->" || b.Lambda {
			t.Errorf("%s: column = %#v, want JSON ->", d, sel.Columns[0])
		}
		ast.ReleaseAST(tree)
	}
}

// Formatting a parsed lambda for its own dialect, or for the other lambda
// dialect, reproduces the source.
func TestLambdaFormatRoundTrip(t *testing.T) {
	inputs := []string{
		"SELECT arrayMap(x -> x * 2, [1, 2, 3])",
		"SELECT arrayFilter(x -> x > 1 AND x < 5, arr) FROM t",
		"SELECT arrayMap((x, y) -> x + y, a, b) FROM t",
		"SELECT arrayExists(x -> x LIKE 'err%', tags) FROM t",
		"SELECT arrayFilter(x -> x IN (SELECT id FROM t), arr) FROM s",
		"SELECT arrayMap(x -> arrayMap(y -> y * x, [1, 2]), [1, 2])",
		"SELECT arraySort(x -> -x, arr) FROM t",
	}
	lambdaDialects := []keywords.SQLDialect{keywords.DialectClickHouse, keywords.DialectSnowflake}
	for _, from := range lambdaDialects {
		for _, sql := range inputs {
			tree, err := parser.ParseWithDialect(sql, from)
			if err != nil {
				t.Fatalf("%s %q: %v", from, sql, err)
			}
			for _, to := range lambdaDialects {
				style := ast.CompactStyle()
				style.Dialect = string(to)
				got, err := formatter.FormatASTChecked(tree, style)
				if err != nil || got != sql {
					t.Errorf("%s -> %s format %q: got %q, %v", from, to, sql, got, err)
				}
			}
			ast.ReleaseAST(tree)
		}
	}
}
