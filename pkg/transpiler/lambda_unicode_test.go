// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package transpiler

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

var lambdaDialects = []keywords.SQLDialect{keywords.DialectClickHouse, keywords.DialectSnowflake}

// Lambda statements already in the formatter's canonical spelling.
var lambdaStatements = []string{
	"SELECT arrayMap(x -> x * 2, [1, 2, 3])",
	"SELECT arrayFilter(x -> x > 1 AND x < 5, arr) FROM t",
	"SELECT arrayFilter(x -> x > 1 OR x IS NULL, arr) FROM t",
	"SELECT arrayMap((x, y) -> x + y, a, b) FROM t",
	"SELECT arrayFold((acc, x) -> acc + x, [1, 2, 3], toUInt64(0))",
	"SELECT arrayExists(x -> x LIKE 'err%', tags) FROM t",
	"SELECT arrayFilter(x -> x IN (SELECT id FROM t), arr) FROM s",
	"SELECT arrayMap(x -> arrayMap(y -> y * x, [1, 2]), [1, 2])",
	"SELECT arraySort(x -> -x, arr) FROM t",
	"SELECT TRANSFORM(arr, a -> a * 2) FROM t",
	"SELECT REDUCE(arr, 0, (acc, val) -> acc + val) FROM t",
}

// Transpiling a lambda within and between ClickHouse and Snowflake must not
// change it: x -> x * 2 used to come out as (x -> x) * 2 (#897).
func TestTranspileLambdaUnchanged(t *testing.T) {
	for _, from := range lambdaDialects {
		for _, to := range lambdaDialects {
			for _, sql := range lambdaStatements {
				got, err := Transpile(sql, from, to)
				if err != nil || got != sql {
					t.Errorf("%s -> %s %q: got %q, %v", from, to, sql, got, err)
				}
			}
		}
	}
}

// Where -> is the JSON operator, the transpiled lambda keeps its body
// grouped as the target parses it.
func TestTranspileLambdaKeepsBodyGrouping(t *testing.T) {
	for _, tc := range []struct {
		to   keywords.SQLDialect
		sql  string
		want string
	}{
		{keywords.DialectMySQL, "SELECT arrayMap(x -> x * 2, arr) FROM t", "SELECT arrayMap(x -> (x * 2), arr) FROM t"},
		{keywords.DialectSQLite, "SELECT arrayMap(x -> x * 2, arr) FROM t", "SELECT arrayMap(x -> (x * 2), arr) FROM t"},
		{keywords.DialectPostgreSQL, "SELECT arrayMap(x -> x * 2, arr) FROM t", "SELECT arrayMap(x -> x * 2, arr) FROM t"},
		{keywords.DialectPostgreSQL, "SELECT arrayFilter(x -> x > 1, arr) FROM t", "SELECT arrayFilter(x -> (x > 1), arr) FROM t"},
	} {
		for _, from := range lambdaDialects {
			got, err := Transpile(tc.sql, from, tc.to)
			if err != nil || got != tc.want {
				t.Errorf("%s -> %s %q: got %q, %v; want %q", from, tc.to, tc.sql, got, err, tc.want)
			}
		}
	}
	// Re-parsing the output in each dialect that has a JSON -> must give
	// the -> the whole body as its right operand.
	jsonDialects := []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectSQLite}
	bodies := map[string]string{
		"SELECT arrayMap(x -> x * 2, arr) FROM t":                  "*",
		"SELECT arrayMap((x, y) -> x + y, a, b) FROM t":            "+",
		"SELECT arrayFilter(x -> x > 1 AND x < 5, arr) FROM t":     "AND",
		"SELECT arrayFilter(x -> x > 1 OR x IS NULL, arr) FROM t":  "OR",
		"SELECT arrayExists(x -> x LIKE 'err%', tags) FROM t":      "LIKE",
		"SELECT arrayMap(x -> x - 1 + y, arr) FROM t":              "+",
		"SELECT arrayMap(x -> x = 1, arr) FROM t":                  "=",
		"SELECT arrayMap(x -> x || 'a', arr) FROM t":               "||",
		"SELECT arrayFilter(x -> NOT x > 1 AND x < 5, arr) FROM t": "AND",
	}
	for _, from := range lambdaDialects {
		for _, to := range jsonDialects {
			for sql, op := range bodies {
				out, err := Transpile(sql, from, to)
				if err != nil {
					t.Errorf("%s -> %s %q: %v", from, to, sql, err)
					continue
				}
				got := arrowBodyOperator(t, out, to)
				if op == "||" && (to == keywords.DialectMySQL || to == keywords.DialectMariaDB) {
					op = "CONCAT()" // || is OR there; the transpiler writes CONCAT
				}
				if got != op {
					t.Errorf("%s -> %s %q: output %q parses with -> body %q, want %q", from, to, sql, out, got, op)
				}
			}
		}
	}
}

// arrowBodyOperator parses sql in d and returns the operator at the root of
// the right operand of the first -> argument of the first column's call.
func arrowBodyOperator(t *testing.T, sql string, d keywords.SQLDialect) string {
	t.Helper()
	tree, err := parser.ParseWithDialect(sql, d)
	if err != nil {
		t.Fatalf("%s re-parse %q: %v", d, sql, err)
	}
	defer ast.ReleaseAST(tree)
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("%s re-parse %q: statement %T", d, sql, tree.Statements[0])
	}
	call, ok := sel.Columns[0].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("%s re-parse %q: column %T", d, sql, sel.Columns[0])
	}
	for _, arg := range call.Arguments {
		arrow, ok := arg.(*ast.BinaryExpression)
		if !ok || arrow.Operator != "->" {
			continue
		}
		body := arrow.Right
		for {
			p, ok := body.(*ast.ParenthesizedExpression)
			if !ok {
				break
			}
			body = p.Expr
		}
		switch b := body.(type) {
		case *ast.BinaryExpression:
			return b.Operator
		case *ast.FunctionCall:
			return b.Name + "()"
		}
		return "<none>"
	}
	t.Fatalf("%s re-parse %q: no -> argument", d, sql)
	return ""
}

// Oracle, Snowflake and ClickHouse have no U& literals and no & operator:
// U&'...' is an error there instead of becoming BITAND(U, '...') (#898).
func TestTranspileUnicodeAmpersandRejected(t *testing.T) {
	for _, from := range []keywords.SQLDialect{keywords.DialectOracle, keywords.DialectSnowflake, keywords.DialectClickHouse} {
		for _, to := range prefilterDialects() {
			for _, sql := range []string{`SELECT U&'d\0061t'`, `SELECT u&'x' FROM t`, `SELECT U&"d\0061t" FROM t`, `SELECT U&'x' UESCAPE '!'`} {
				got, err := Transpile(sql, from, to)
				if err == nil || !strings.Contains(err.Error(), "U& Unicode escape literals in "+string(from)) {
					t.Errorf("%s -> %s %q: got %q, %v; want a U& error", from, to, sql, got, err)
				}
			}
		}
	}
}

// Where & exists, U&'x' is U & 'x' and keeps that meaning; PostgreSQL keeps
// its U& literal.
func TestTranspileUnicodeAmpersandElsewhere(t *testing.T) {
	for _, tc := range []struct {
		from, to keywords.SQLDialect
		sql      string
		want     string
	}{
		{keywords.DialectMySQL, keywords.DialectMySQL, `SELECT U&'x'`, `SELECT U & 'x'`},
		{keywords.DialectMariaDB, keywords.DialectMariaDB, `SELECT U&'x'`, `SELECT U & 'x'`},
		{keywords.DialectSQLServer, keywords.DialectSQLServer, `SELECT U&'x'`, `SELECT U & 'x'`},
		{keywords.DialectSQLite, keywords.DialectSQLite, `SELECT U&'x'`, `SELECT U & 'x'`},
		{keywords.DialectMySQL, keywords.DialectOracle, `SELECT U&'x'`, `SELECT BITAND(U, 'x')`},
		{keywords.DialectMySQL, keywords.DialectClickHouse, `SELECT U&'x'`, `SELECT bitAnd(U, 'x')`},
		{keywords.DialectPostgreSQL, keywords.DialectPostgreSQL, `SELECT U&'d\0061t'`, `SELECT U&'d\0061t'`},
		// Spaced, & stays an operator in the dialects without U& literals.
		{keywords.DialectOracle, keywords.DialectOracle, `SELECT U & 'x'`, `SELECT BITAND(U, 'x')`},
	} {
		got, err := Transpile(tc.sql, tc.from, tc.to)
		if err != nil || got != tc.want {
			t.Errorf("%s -> %s %q: got %q, %v; want %q", tc.from, tc.to, tc.sql, got, err, tc.want)
		}
	}
}
