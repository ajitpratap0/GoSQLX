// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestSnowflakeUseAndDescribe verifies Snowflake session-context statements
// (USE WAREHOUSE/DATABASE/SCHEMA/ROLE) and DESCRIBE/DESC with object-kind
// prefixes. Regression for #483.
func TestSnowflakeUseAndDescribe(t *testing.T) {
	queries := []string{
		`USE WAREHOUSE compute_wh`,
		`USE DATABASE my_db`,
		`USE SCHEMA analytics`,
		`USE ROLE analyst`,
		`USE my_db`,
		`USE my_db.public`,
		`DESCRIBE TABLE users`,
		`DESCRIBE VIEW user_summary`,
		`DESCRIBE STAGE my_stage`,
		`DESC TABLE users`,
		`DESC users`,
	}
	for _, q := range queries {
		q := q
		t.Run(q, func(t *testing.T) {
			if _, err := gosqlx.ParseWithDialect(q, keywords.DialectSnowflake); err != nil {
				t.Fatalf("parse failed: %v", err)
			}
		})
	}
}
