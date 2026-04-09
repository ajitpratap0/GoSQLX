// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestSnowflakeSample verifies Snowflake SAMPLE / TABLESAMPLE clause on
// table references. Regression for #483.
func TestSnowflakeSample(t *testing.T) {
	queries := map[string]string{
		"sample_pct":         `SELECT * FROM users SAMPLE (10)`,
		"tablesample_rows":   `SELECT * FROM users TABLESAMPLE (100 ROWS)`,
		"sample_bernoulli":   `SELECT * FROM users SAMPLE BERNOULLI (5)`,
		"tablesample_system": `SELECT * FROM users TABLESAMPLE SYSTEM (1)`,
		"sample_block":       `SELECT * FROM users SAMPLE BLOCK (10)`,
		"sample_with_where":  `SELECT * FROM users SAMPLE (50) WHERE id > 100`,
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
