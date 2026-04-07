// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestClickHouseArrayLiteral verifies that the bare-bracket array literal
// `[1, 2, 3]` parses in the ClickHouse dialect. ClickHouse supports this as
// a shorthand for `array(1, 2, 3)`. Regression for #482.
func TestClickHouseArrayLiteral(t *testing.T) {
	queries := map[string]string{
		"int_literal":    `SELECT [1, 2, 3] AS nums`,
		"string_literal": `SELECT ['a', 'b', 'c'] AS words`,
		"empty":          `SELECT [] AS empty`,
		"nested":         `SELECT [[1, 2], [3, 4]] AS matrix`,
		"in_function":    `SELECT arrayJoin([10, 20, 30]) AS x`,
		"mixed_with_col": `SELECT id, [status, type] AS labels FROM events`,
	}
	for name, q := range queries {
		q := q
		t.Run(name, func(t *testing.T) {
			if _, err := gosqlx.ParseWithDialect(q, keywords.DialectClickHouse); err != nil {
				t.Fatalf("ParseWithDialect failed: %v", err)
			}
		})
	}
}
