// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestClickHouseOrderByWithFill verifies ClickHouse's `ORDER BY expr WITH
// FILL [FROM..] [TO..] [STEP..]` modifier parses. Previously the WITH token
// after ORDER BY items was mis-routed to the WITH-CTE parser. Regression
// for #482.
func TestClickHouseOrderByWithFill(t *testing.T) {
	queries := map[string]string{
		"bare":          `SELECT id FROM t ORDER BY id WITH FILL`,
		"step_only":     `SELECT id FROM t ORDER BY id WITH FILL STEP 1`,
		"from_to_step":  `SELECT day, count() FROM events GROUP BY day ORDER BY day WITH FILL FROM '2024-01-01' TO '2024-12-31' STEP INTERVAL 1 DAY`,
		"multiple_cols": `SELECT a, b FROM t ORDER BY a WITH FILL STEP 1, b`,
		"with_desc":     `SELECT id FROM t ORDER BY id DESC WITH FILL STEP 1`,
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
