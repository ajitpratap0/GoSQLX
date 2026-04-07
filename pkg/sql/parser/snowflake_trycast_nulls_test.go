// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestTryCast verifies that TRY_CAST(expr AS type) parses in Snowflake
// (and is identical in shape to CAST). Regression for #483.
func TestTryCast(t *testing.T) {
	queries := []string{
		`SELECT TRY_CAST(value AS INT) FROM events`,
		`SELECT TRY_CAST(price AS DECIMAL(10, 2)) FROM products`,
		`SELECT TRY_CAST(name AS VARCHAR(100)) FROM users`,
		`SELECT TRY_CAST(json_col AS VARIANT) FROM events`,
	}
	for _, q := range queries {
		t.Run(q, func(t *testing.T) {
			if _, err := gosqlx.ParseWithDialect(q, keywords.DialectSnowflake); err != nil {
				t.Fatalf("Snowflake TRY_CAST parse failed: %v", err)
			}
		})
	}
}

// TestWindowNullTreatment verifies IGNORE NULLS / RESPECT NULLS on window
// functions parses for Snowflake. Regression for #483.
func TestWindowNullTreatment(t *testing.T) {
	queries := map[string]string{
		"lag_ignore_nulls":   `SELECT LAG(price) IGNORE NULLS OVER (ORDER BY ts) FROM ticks`,
		"lead_respect_nulls": `SELECT LEAD(price) RESPECT NULLS OVER (PARTITION BY symbol ORDER BY ts) FROM ticks`,
		"first_value_ignore": `SELECT FIRST_VALUE(price) IGNORE NULLS OVER (PARTITION BY symbol ORDER BY ts) FROM ticks`,
		"last_value_respect": `SELECT LAST_VALUE(price) RESPECT NULLS OVER (PARTITION BY symbol ORDER BY ts) FROM ticks`,
	}
	for name, q := range queries {
		q := q
		t.Run(name, func(t *testing.T) {
			if _, err := gosqlx.ParseWithDialect(q, keywords.DialectSnowflake); err != nil {
				t.Fatalf("parse failed: %v", err)
			}
		})
	}
}

// TestTryCastASTShape verifies that a TRY_CAST expression has Try=true and
// TokenLiteral() returns "TRY_CAST", while a plain CAST returns "CAST".
func TestTryCastASTShape(t *testing.T) {
	tcs := map[string]struct {
		query   string
		wantTry bool
		wantLit string
	}{
		"try_cast": {`SELECT TRY_CAST(value AS INT) FROM events`, true, "TRY_CAST"},
		"cast":     {`SELECT CAST(value AS INT) FROM events`, false, "CAST"},
	}
	for name, tc := range tcs {
		tc := tc
		t.Run(name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.query, keywords.DialectSnowflake)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			var found bool
			var visit func(n ast.Node)
			visit = func(n ast.Node) {
				if n == nil || found {
					return
				}
				if c, ok := n.(*ast.CastExpression); ok {
					if c.Try != tc.wantTry {
						t.Fatalf("Try: want %v, got %v", tc.wantTry, c.Try)
					}
					if c.TokenLiteral() != tc.wantLit {
						t.Fatalf("TokenLiteral: want %q, got %q", tc.wantLit, c.TokenLiteral())
					}
					found = true
					return
				}
				for _, ch := range n.Children() {
					visit(ch)
				}
			}
			for _, stmt := range tree.Statements {
				visit(stmt)
			}
			if !found {
				t.Fatal("CastExpression not found in AST")
			}
		})
	}
}
