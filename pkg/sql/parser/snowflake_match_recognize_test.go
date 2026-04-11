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

// TestSnowflakeMatchRecognize verifies the SQL:2016 MATCH_RECOGNIZE clause
// parses for the Snowflake dialect. This was the last remaining Snowflake QA
// failure. Regression for #483.
func TestSnowflakeMatchRecognize(t *testing.T) {
	queries := map[string]string{
		"basic_up_down": `SELECT * FROM stock_price MATCH_RECOGNIZE (
			PARTITION BY symbol
			ORDER BY ts
			MEASURES MATCH_NUMBER() AS m
			ALL ROWS PER MATCH
			PATTERN (UP+ DOWN+)
			DEFINE UP AS price > PREV(price), DOWN AS price < PREV(price)
		)`,

		"one_row_per_match": `SELECT * FROM events MATCH_RECOGNIZE (
			ORDER BY ts
			MEASURES FIRST(ts) AS start_ts, LAST(ts) AS end_ts
			ONE ROW PER MATCH
			PATTERN (A B+ C)
			DEFINE A AS status = 'start', B AS status = 'running', C AS status = 'done'
		)`,

		"with_alias": `SELECT mr.* FROM events MATCH_RECOGNIZE (
			ORDER BY ts
			PATTERN (A+ B)
			DEFINE A AS val > 0, B AS val <= 0
		) AS mr`,

		"pattern_alternation": `SELECT * FROM t MATCH_RECOGNIZE (
			ORDER BY ts
			PATTERN ((A | B) C+)
			DEFINE A AS x = 1, B AS x = 2, C AS x = 3
		)`,

		"measures_only": `SELECT * FROM t MATCH_RECOGNIZE (
			ORDER BY id
			MEASURES COUNT(*) AS cnt
			ALL ROWS PER MATCH
			PATTERN (X+)
			DEFINE X AS val > 10
		)`,

		"partition_and_order": `SELECT * FROM t MATCH_RECOGNIZE (
			PARTITION BY region, category
			ORDER BY ts DESC
			PATTERN (A B)
			DEFINE A AS revenue > 100, B AS revenue < 50
		)`,
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

// TestMatchRecognizeASTShape verifies the MatchRecognizeClause AST node is
// populated and reachable via Children() traversal.
func TestMatchRecognizeASTShape(t *testing.T) {
	q := `SELECT * FROM stock_price MATCH_RECOGNIZE (
		PARTITION BY symbol
		ORDER BY ts
		MEASURES MATCH_NUMBER() AS m
		ALL ROWS PER MATCH
		PATTERN (UP+ DOWN+)
		DEFINE UP AS price > PREV(price), DOWN AS price < PREV(price)
	)`
	tree, err := gosqlx.ParseWithDialect(q, keywords.DialectSnowflake)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	var mr *ast.MatchRecognizeClause
	var visit func(n ast.Node)
	visit = func(n ast.Node) {
		if n == nil || mr != nil {
			return
		}
		if m, ok := n.(*ast.MatchRecognizeClause); ok {
			mr = m
			return
		}
		for _, c := range n.Children() {
			visit(c)
		}
	}
	for _, s := range tree.Statements {
		visit(s)
	}
	if mr == nil {
		t.Fatal("MatchRecognizeClause not found in AST")
	}
	if len(mr.PartitionBy) != 1 {
		t.Fatalf("PartitionBy: want 1, got %d", len(mr.PartitionBy))
	}
	if len(mr.OrderBy) != 1 {
		t.Fatalf("OrderBy: want 1, got %d", len(mr.OrderBy))
	}
	if len(mr.Measures) != 1 || mr.Measures[0].Alias != "m" {
		t.Fatalf("Measures: want [{alias:m}], got %+v", mr.Measures)
	}
	if mr.RowsPerMatch != "ALL ROWS PER MATCH" {
		t.Fatalf("RowsPerMatch: want %q, got %q", "ALL ROWS PER MATCH", mr.RowsPerMatch)
	}
	if mr.Pattern == "" {
		t.Fatal("Pattern is empty")
	}
	if len(mr.Definitions) != 2 {
		t.Fatalf("Definitions: want 2 (UP, DOWN), got %d", len(mr.Definitions))
	}
	if mr.Definitions[0].Name != "UP" {
		t.Fatalf("Definitions[0].Name: want UP, got %s", mr.Definitions[0].Name)
	}
	// Verify Children() includes the sub-expressions
	children := mr.Children()
	if len(children) < 4 {
		t.Fatalf("Children(): want >=4 (partition+order+measure+2 defs), got %d", len(children))
	}
}
