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

// TestSnowflakeTimeTravel verifies AT / BEFORE / CHANGES clauses on a table
// reference in the Snowflake dialect. Regression for #483.
func TestSnowflakeTimeTravel(t *testing.T) {
	queries := map[string]string{
		"at_timestamp_cast": `SELECT * FROM users AT (TIMESTAMP => '2024-01-01'::TIMESTAMP)`,
		"at_offset":         `SELECT * FROM users AT (OFFSET => -300)`,
		"at_statement":      `SELECT * FROM users AT (STATEMENT => '8e5d0ca9-005e-44e6-b858-a8f5b37c5726')`,
		"before_statement":  `SELECT * FROM users BEFORE (STATEMENT => '8e5d0ca9-005e-44e6-b858-a8f5b37c5726')`,
		"changes_default":   `SELECT * FROM users CHANGES (INFORMATION => DEFAULT)`,
		"changes_and_at":    `SELECT * FROM users CHANGES (INFORMATION => DEFAULT) AT (TIMESTAMP => '2024-01-01'::TIMESTAMP)`,
		"at_with_alias":     `SELECT t.id FROM users AT (TIMESTAMP => '2024-01-01'::TIMESTAMP) t WHERE t.id = 1`,
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

// TestSnowflakeTimeTravelASTShape verifies the TimeTravel clause is populated
// on the TableReference and reachable via Children().
func TestSnowflakeTimeTravelASTShape(t *testing.T) {
	q := `SELECT * FROM users AT (TIMESTAMP => '2024-01-01'::TIMESTAMP)`
	tree, err := gosqlx.ParseWithDialect(q, keywords.DialectSnowflake)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	ss, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("want *ast.SelectStatement, got %T", tree.Statements[0])
	}
	if len(ss.Joins) > 0 || ss.TableName == "" && len(ss.Joins) == 0 {
		// The parser may place the table ref in different shapes; walk the
		// tree to find the TimeTravelClause instead.
	}
	var found bool
	var visit func(n ast.Node)
	visit = func(n ast.Node) {
		if n == nil || found {
			return
		}
		if tt, ok := n.(*ast.TimeTravelClause); ok {
			if tt.Kind != "AT" {
				t.Fatalf("Kind: want AT, got %q", tt.Kind)
			}
			if _, ok := tt.Named["TIMESTAMP"]; !ok {
				t.Fatalf("Named[TIMESTAMP] missing; have: %v", tt.Named)
			}
			found = true
			return
		}
		for _, c := range n.Children() {
			visit(c)
		}
	}
	visit(ss)
	if !found {
		t.Fatal("TimeTravelClause not found in AST")
	}
}
