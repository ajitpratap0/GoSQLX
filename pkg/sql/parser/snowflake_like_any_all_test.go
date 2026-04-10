// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestSnowflakeLikeAnyAll verifies LIKE ANY/ALL and ILIKE ANY/ALL parse in
// the Snowflake dialect. Regression for #483.
func TestSnowflakeLikeAnyAll(t *testing.T) {
	queries := map[string]string{
		"like_any":      `SELECT * FROM users WHERE name LIKE ANY ('%alice%', '%bob%')`,
		"like_all":      `SELECT * FROM users WHERE name LIKE ALL ('%a%', '%b%')`,
		"ilike_any":     `SELECT * FROM events WHERE msg ILIKE ANY ('%error%', '%warn%')`,
		"not_like_any":  `SELECT * FROM users WHERE name NOT LIKE ANY ('%test%', '%demo%')`,
		"not_ilike_all": `SELECT * FROM users WHERE name NOT ILIKE ALL ('%a%', '%b%')`,
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
