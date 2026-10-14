// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package parser_test

import (
	"errors"
	"strings"
	"testing"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestClickHouseParametricAggregates verifies that ClickHouse parametric
// aggregates of the form `funcName(params)(args)` parse. Regression for #482.
func TestClickHouseParametricAggregates(t *testing.T) {
	queries := map[string]string{
		"quantile_tdigest": `SELECT quantileTDigest(0.95)(value) FROM events`,
		"top_k":            `SELECT topK(10)(name) FROM users`,
		"quantiles":        `SELECT quantiles(0.5, 0.9, 0.99)(latency_ms) FROM requests`,
		"with_group_by":    `SELECT category, quantileTDigest(0.99)(price) FROM products GROUP BY category`,
	}
	for name, q := range queries {
		q := q
		t.Run(name, func(t *testing.T) {
			if _, err := gosqlx.ParseWithDialect(q, keywords.DialectClickHouse); err != nil {
				t.Fatalf("parse failed: %v", err)
			}
		})
	}
}

// TestClickHouseParametricAggregates_ASTShape verifies that the Parameters
// field is populated and reachable via the visitor pattern.
func TestClickHouseParametricAggregates_ASTShape(t *testing.T) {
	q := `SELECT quantileTDigest(0.95)(value) FROM events`
	tree, err := gosqlx.ParseWithDialect(q, keywords.DialectClickHouse)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	// Walk the tree until we find a FunctionCall node and verify both
	// Parameters and Arguments are populated, and Children() exposes both.
	var found bool
	var visit func(n ast.Node)
	visit = func(n ast.Node) {
		if n == nil || found {
			return
		}
		if fc, ok := n.(*ast.FunctionCall); ok && fc.Name == "quantileTDigest" {
			if len(fc.Parameters) != 1 {
				t.Fatalf("Parameters: want 1, got %d", len(fc.Parameters))
			}
			if len(fc.Arguments) != 1 {
				t.Fatalf("Arguments: want 1, got %d", len(fc.Arguments))
			}
			// Children() must include both the argument and the parameter.
			if len(fc.Children()) < 2 {
				t.Fatalf("Children(): want >=2 (args + params), got %d", len(fc.Children()))
			}
			found = true
			return
		}
		for _, c := range n.Children() {
			visit(c)
		}
	}
	for _, stmt := range tree.Statements {
		visit(stmt)
	}
	if !found {
		t.Fatal("did not find quantileTDigest FunctionCall in AST")
	}
}

// TestClickHouseParametricAggregates_Render is a regression for the renderer:
// FunctionCall.SQL() must emit ClickHouse parametric aggregates as
// `funcName(params)(args)`, preserving the params group. Previously the
// Parameters group was silently dropped, yielding `funcName(args)`.
func TestClickHouseParametricAggregates_Render(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{"quantile_tdigest", `SELECT quantileTDigest(0.95)(value) FROM events`},
		{"top_k", `SELECT topK(10)(name) FROM users`},
		{"quantiles_multi", `SELECT quantiles(0.5, 0.9, 0.99)(latency_ms) FROM requests`},
		{"with_group_by", `SELECT category, quantileTDigest(0.99)(price) FROM products GROUP BY category`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tt.sql, keywords.DialectClickHouse)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			if got := tree.SQL(); got != tt.sql {
				t.Errorf("SQL() = %q, want %q", got, tt.sql)
			}
		})
	}
}

// firstColumn605 parses sql in dialect and returns the parsed tree's SQL() and
// the first SELECT column expression.
func firstColumn605(t *testing.T, sql string, dialect keywords.SQLDialect) (string, ast.Expression) {
	t.Helper()
	tree, err := gosqlx.ParseWithDialect(sql, dialect)
	if err != nil {
		t.Fatalf("ParseWithDialect(%q, %s) failed: %v", sql, dialect, err)
	}
	if len(tree.Statements) == 0 {
		t.Fatalf("no statements parsed from %q", sql)
	}
	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
	}
	if len(stmt.Columns) == 0 {
		t.Fatalf("no columns parsed from %q", sql)
	}
	col := stmt.Columns[0]
	if ae, ok := col.(*ast.AliasedExpression); ok {
		col = ae.Expr
	}
	return tree.SQL(), col
}

// assertReparses605 checks that out parses in dialect and renders to itself.
func assertReparses605(t *testing.T, out string, dialect keywords.SQLDialect) {
	t.Helper()
	tree, err := gosqlx.ParseWithDialect(out, dialect)
	if err != nil {
		t.Fatalf("re-parse of %q failed: %v", out, err)
	}
	if got := tree.SQL(); got != out {
		t.Fatalf("round trip mismatch\n got: %q\nwant: %q", got, out)
	}
}

// TestClickHouseParametric_DistinctInArgs_605: DISTINCT in the argument group
// of a ClickHouse parametric aggregate is accepted and kept with that group.
func TestClickHouseParametric_DistinctInArgs_605(t *testing.T) {
	t.Run("parametric", func(t *testing.T) {
		const sql = "SELECT quantile(0.5)(DISTINCT x) FROM t"
		out, col := firstColumn605(t, sql, keywords.DialectClickHouse)
		fc, ok := col.(*ast.FunctionCall)
		if !ok {
			t.Fatalf("expected *ast.FunctionCall, got %T", col)
		}
		if fc.Name != "quantile" || len(fc.Parameters) != 1 || len(fc.Arguments) != 1 || !fc.Distinct || len(fc.OrderBy) != 0 {
			t.Fatalf("unexpected FunctionCall shape: name=%q params=%d args=%d distinct=%v orderBy=%d",
				fc.Name, len(fc.Parameters), len(fc.Arguments), fc.Distinct, len(fc.OrderBy))
		}
		if out != sql {
			t.Fatalf("SQL() = %q, want %q", out, sql)
		}
		assertReparses605(t, out, keywords.DialectClickHouse)
	})
	t.Run("single_group_control", func(t *testing.T) {
		const sql = "SELECT uniqExact(DISTINCT x) FROM t"
		out, _ := firstColumn605(t, sql, keywords.DialectClickHouse)
		if out != sql {
			t.Fatalf("SQL() = %q, want %q", out, sql)
		}
		assertReparses605(t, out, keywords.DialectClickHouse)
	})
}

// TestClickHouseParametric_RejectsModifiersInParams_605: DISTINCT / ORDER BY
// in the parameter group, and a third paren group, are rejected with E2004
// instead of being silently moved to the argument group.
func TestClickHouseParametric_RejectsModifiersInParams_605(t *testing.T) {
	cases := []struct {
		sql    string
		substr string
		column int // 0 = do not check
	}{
		{"SELECT uniqExact(DISTINCT x)(y) FROM t", "DISTINCT is not allowed in the parameter list", 18},
		{"SELECT groupArray(DISTINCT 3)(x) FROM t", "DISTINCT is not allowed in the parameter list", 19},
		{"SELECT groupArray(x ORDER BY y)(z) FROM t", "ORDER BY is not allowed in the parameter list", 0},
		{"SELECT f(1)(2)(3) FROM t", "at most two parenthesized", 15},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.sql, func(t *testing.T) {
			_, err := gosqlx.ParseWithDialect(tc.sql, keywords.DialectClickHouse)
			if err == nil {
				t.Fatalf("expected an error for %q", tc.sql)
			}
			msg := err.Error()
			if !strings.Contains(msg, "E2004") || !strings.Contains(msg, tc.substr) {
				t.Fatalf("error %q: want E2004 containing %q", msg, tc.substr)
			}
			if tc.column == 0 {
				return
			}
			var gerr *goerrors.Error
			if !errors.As(err, &gerr) {
				t.Fatalf("expected *errors.Error in chain, got %T", err)
			}
			if gerr.Location.Line != 1 || gerr.Location.Column != tc.column {
				t.Fatalf("error location = %d:%d, want 1:%d", gerr.Location.Line, gerr.Location.Column, tc.column)
			}
		})
	}
}

// TestFunctionCallSubscript_605: a [...] subscript or slice directly after a
// function call applies to the call result and round-trips.
func TestFunctionCallSubscript_605(t *testing.T) {
	cases := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    string
		slice   bool
		params  int
	}{
		{"ch_parametric", keywords.DialectClickHouse, "SELECT quantiles(0.5,0.9)(x)[1] FROM t", "SELECT quantiles(0.5, 0.9)(x)[1] FROM t", false, 2},
		{"ch_simple", keywords.DialectClickHouse, "SELECT groupArray(x)[1] FROM t", "SELECT groupArray(x)[1] FROM t", false, 0},
		{"ch_nested", keywords.DialectClickHouse, "SELECT groupArray(x)[1][2] FROM t", "SELECT groupArray(x)[1][2] FROM t", false, 0},
		{"ch_slice", keywords.DialectClickHouse, "SELECT groupArray(x)[1:2] FROM t", "SELECT groupArray(x)[1:2] FROM t", true, 0},
		{"ch_alias", keywords.DialectClickHouse, "SELECT groupArray(x)[1] AS g FROM t", "SELECT groupArray(x)[1] AS g FROM t", false, 0},
		{"pg_array_agg", keywords.DialectPostgreSQL, "SELECT array_agg(x)[1] FROM t", "SELECT array_agg(x)[1] FROM t", false, 0},
		{"generic", keywords.DialectGeneric, "SELECT f(x)[1] FROM t", "SELECT f(x)[1] FROM t", false, 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			out, col := firstColumn605(t, tc.sql, tc.dialect)
			var array ast.Expression
			if tc.slice {
				se, ok := col.(*ast.ArraySliceExpression)
				if !ok {
					t.Fatalf("expected *ast.ArraySliceExpression, got %T", col)
				}
				array = se.Array
			} else {
				se, ok := col.(*ast.ArraySubscriptExpression)
				if !ok {
					t.Fatalf("expected *ast.ArraySubscriptExpression, got %T", col)
				}
				array = se.Array
				// Nested subscripts wrap another subscript; walk to the call.
				for {
					inner, ok := array.(*ast.ArraySubscriptExpression)
					if !ok {
						break
					}
					array = inner.Array
				}
			}
			fc, ok := array.(*ast.FunctionCall)
			if !ok {
				t.Fatalf("expected subscripted *ast.FunctionCall, got %T", array)
			}
			if len(fc.Parameters) != tc.params || len(fc.Arguments) != 1 {
				t.Fatalf("FunctionCall params=%d args=%d, want params=%d args=1", len(fc.Parameters), len(fc.Arguments), tc.params)
			}
			if out != tc.want {
				t.Fatalf("SQL() = %q, want %q", out, tc.want)
			}
			assertReparses605(t, out, tc.dialect)
		})
	}

	t.Run("pg_parenthesized_call_output_reparses", func(t *testing.T) {
		out, _ := firstColumn605(t, "SELECT (array_agg(x))[1] FROM t", keywords.DialectPostgreSQL)
		if _, err := gosqlx.ParseWithDialect(out, keywords.DialectPostgreSQL); err != nil {
			t.Fatalf("re-parse of %q failed: %v", out, err)
		}
	})

	t.Run("sqlserver_bracket_alias_unchanged", func(t *testing.T) {
		out, _ := firstColumn605(t, "SELECT count(*) [cnt] FROM t", keywords.DialectSQLServer)
		if want := "SELECT count(*) AS cnt FROM t"; out != want {
			t.Fatalf("SQL() = %q, want %q", out, want)
		}
	})
}

// TestFunctionCallSubscript_605_SQLiteBracketAlias: in SQLite, [name] after a
// call is a bracket-quoted alias, not a subscript, so it must never be read
// as count(*)[cnt] (which drops the alias and does not re-parse in SQLite).
func TestFunctionCallSubscript_605_SQLiteBracketAlias(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect("SELECT count(*) [cnt] FROM t", keywords.DialectSQLite)
	if err != nil {
		return // rejected, as before #605: acceptable
	}
	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
	}
	col := stmt.Columns[0]
	if ae, ok := col.(*ast.AliasedExpression); ok {
		col = ae.Expr
	}
	if _, ok := col.(*ast.ArraySubscriptExpression); ok {
		t.Fatalf("SQLite [cnt] after a call parsed as a subscript: %s", tree.SQL())
	}
}
