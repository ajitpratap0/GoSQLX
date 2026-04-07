// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
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
