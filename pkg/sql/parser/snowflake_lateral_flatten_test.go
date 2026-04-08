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

// TestSnowflakeFromTableFunctions verifies function-call style table refs
// (LATERAL FLATTEN, TABLE(...), IDENTIFIER(...), GENERATOR(...)) parse in
// the Snowflake dialect. Regression for #483.
func TestSnowflakeFromTableFunctions(t *testing.T) {
	queries := map[string]string{
		"lateral_flatten_named": `SELECT value FROM LATERAL FLATTEN(input => array_col)`,

		"lateral_flatten_with_alias": `SELECT f.value
FROM events, LATERAL FLATTEN(input => events.tags) f`,

		"table_of_udf": `SELECT * FROM TABLE(my_func(1, 2))`,

		"identifier_wrapped": `SELECT * FROM IDENTIFIER('my_table')`,

		"generator_named_args": `SELECT seq4()
FROM TABLE(GENERATOR(rowcount => 100))`,
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

// TestNamedArgumentASTShape verifies the NamedArgument AST node is produced
// for `name => expr` and is reachable via the visitor pattern.
func TestNamedArgumentASTShape(t *testing.T) {
	q := `SELECT * FROM LATERAL FLATTEN(input => tags)`
	tree, err := gosqlx.ParseWithDialect(q, keywords.DialectSnowflake)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	var found bool
	var visit func(n ast.Node)
	visit = func(n ast.Node) {
		if n == nil || found {
			return
		}
		if na, ok := n.(*ast.NamedArgument); ok {
			if na.Name != "input" {
				t.Fatalf("NamedArgument.Name: want %q, got %q", "input", na.Name)
			}
			if na.Value == nil {
				t.Fatal("NamedArgument.Value nil")
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
		t.Fatal("NamedArgument not found in AST")
	}
}
