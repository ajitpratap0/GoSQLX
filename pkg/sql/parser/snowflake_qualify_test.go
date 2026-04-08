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

// TestSnowflakeQualify verifies the Snowflake QUALIFY clause parses between
// HAVING and ORDER BY. Regression for #483.
func TestSnowflakeQualify(t *testing.T) {
	queries := map[string]string{
		"simple": `SELECT id, name, ROW_NUMBER() OVER (ORDER BY id) AS rn
FROM users
QUALIFY rn = 1`,

		"with_where": `SELECT id, name
FROM users
WHERE active = true
QUALIFY ROW_NUMBER() OVER (PARTITION BY dept ORDER BY id) = 1`,

		"with_group_having": `SELECT dept, COUNT(*) AS n
FROM users
GROUP BY dept
HAVING COUNT(*) > 5
QUALIFY RANK() OVER (ORDER BY n DESC) <= 10`,

		"with_order_by": `SELECT id, RANK() OVER (ORDER BY score) AS r
FROM leaderboard
QUALIFY r <= 10
ORDER BY id`,
	}
	for name, q := range queries {
		q := q
		t.Run(name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(q, keywords.DialectSnowflake)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			if len(tree.Statements) == 0 {
				t.Fatal("no statements parsed")
			}
			ss, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
			}
			if ss.Qualify == nil {
				t.Fatal("Qualify clause missing from AST")
			}
		})
	}
}
