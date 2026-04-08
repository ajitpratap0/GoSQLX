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

// TestSnowflakeVariantPath verifies the Snowflake VARIANT colon-path
// expression (`col:field.sub[0]::string`) parses correctly. This is the
// biggest Snowflake gap from the QA sweep (#483) — required for any
// semi-structured / JSON workload.
func TestSnowflakeVariantPath(t *testing.T) {
	queries := map[string]string{
		"bare":             `SELECT col:field FROM t`,
		"nested":           `SELECT col:field.sub FROM t`,
		"with_cast":        `SELECT col:field.sub::string FROM t`,
		"bracket":          `SELECT col:items[0] FROM t`,
		"bracket_then_dot": `SELECT col:items[0].name FROM t`,
		"parse_json_chain": `SELECT PARSE_JSON(raw):a::int FROM t`,
		"quoted_key":       `SELECT col:"weird key" FROM t`,
		"in_where":         `SELECT id FROM t WHERE payload:status::string = 'active'`,
		"multi_segment":    `SELECT col:a.b.c.d::int AS x FROM t`,
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

// TestVariantPathASTShape asserts the VariantPath node is produced with the
// expected Root and Segments, and that the trailing :: cast wraps it.
func TestVariantPathASTShape(t *testing.T) {
	q := `SELECT col:field.sub[0]::string FROM t`
	tree, err := gosqlx.ParseWithDialect(q, keywords.DialectSnowflake)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	var vp *ast.VariantPath
	var cast *ast.CastExpression
	var visit func(n ast.Node)
	visit = func(n ast.Node) {
		if n == nil {
			return
		}
		switch x := n.(type) {
		case *ast.VariantPath:
			if vp == nil {
				vp = x
			}
		case *ast.CastExpression:
			if cast == nil {
				cast = x
			}
		}
		for _, c := range n.Children() {
			visit(c)
		}
	}
	for _, s := range tree.Statements {
		visit(s)
	}
	if vp == nil {
		t.Fatal("VariantPath not found")
	}
	if vp.Root == nil {
		t.Fatal("VariantPath.Root nil")
	}
	if len(vp.Segments) != 3 {
		t.Fatalf("Segments: want 3 (field, sub, [0]), got %d", len(vp.Segments))
	}
	if vp.Segments[0].Name != "field" {
		t.Fatalf("Segments[0].Name: want %q, got %q", "field", vp.Segments[0].Name)
	}
	if vp.Segments[1].Name != "sub" {
		t.Fatalf("Segments[1].Name: want %q, got %q", "sub", vp.Segments[1].Name)
	}
	if vp.Segments[2].Index == nil {
		t.Fatal("Segments[2].Index (bracket subscript) missing")
	}
	if cast == nil || cast.Type != "string" {
		t.Fatalf("Cast: want CastExpression with Type=string, got %+v", cast)
	}
}
