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

// TestMinusAsExceptSynonym verifies MINUS is accepted as a set operator
// (synonym for EXCEPT) in Snowflake and Oracle dialects, and that it is
// normalized to "EXCEPT" on the AST. Regression for #483.
func TestMinusAsExceptSynonym(t *testing.T) {
	dialects := []keywords.SQLDialect{
		keywords.DialectSnowflake,
		keywords.DialectOracle,
	}
	q := `SELECT id FROM a MINUS SELECT id FROM b`
	for _, d := range dialects {
		d := d
		t.Run(string(d), func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(q, d)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			if len(tree.Statements) != 1 {
				t.Fatalf("want 1 statement, got %d", len(tree.Statements))
			}
			so, ok := tree.Statements[0].(*ast.SetOperation)
			if !ok {
				t.Fatalf("want *ast.SetOperation, got %T", tree.Statements[0])
			}
			if so.Operator != "EXCEPT" {
				t.Fatalf("Operator: want %q, got %q", "EXCEPT", so.Operator)
			}
		})
	}
}

// TestMinusNotSetOpInOtherDialects verifies that MINUS is still treated as
// a table alias (not a set operator) in dialects that do not support it.
// This protects against accidental hijacking in e.g. MySQL/PostgreSQL.
func TestMinusNotSetOpInOtherDialects(t *testing.T) {
	q := `SELECT id FROM a MINUS SELECT id FROM b`
	// In dialects without MINUS-as-EXCEPT, the MINUS identifier is consumed
	// as a table alias ("a AS MINUS") and "SELECT ..." starts a new statement.
	// We expect either success with 2 statements, or at minimum no panic.
	tree, err := gosqlx.ParseWithDialect(q, keywords.DialectPostgreSQL)
	if err != nil {
		return // error is acceptable; we only verify no hijacking
	}
	if len(tree.Statements) == 1 {
		if _, isSetOp := tree.Statements[0].(*ast.SetOperation); isSetOp {
			t.Fatal("PostgreSQL should not parse MINUS as a set operator")
		}
	}
}
