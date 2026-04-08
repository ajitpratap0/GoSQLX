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
