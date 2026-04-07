// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package parser_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestSnowflakeILIKE verifies that ILIKE is accepted in the Snowflake dialect.
// Snowflake natively supports ILIKE; the parser previously rejected it with a
// "PostgreSQL-specific" error. Regression for #483.
func TestSnowflakeILIKE(t *testing.T) {
	queries := []string{
		`SELECT * FROM users WHERE name ILIKE 'alice%'`,
		`SELECT * FROM users WHERE name NOT ILIKE 'alice%'`,
	}
	for _, q := range queries {
		t.Run(q, func(t *testing.T) {
			if _, err := gosqlx.ParseWithDialect(q, keywords.DialectSnowflake); err != nil {
				t.Fatalf("ParseWithDialect(Snowflake) failed: %v", err)
			}
		})
	}
}

// TestClickHouseILIKE verifies ILIKE is accepted in the ClickHouse dialect.
func TestClickHouseILIKE(t *testing.T) {
	q := `SELECT * FROM events WHERE message ILIKE '%error%'`
	if _, err := gosqlx.ParseWithDialect(q, keywords.DialectClickHouse); err != nil {
		t.Fatalf("ParseWithDialect(ClickHouse) failed: %v", err)
	}
}

// TestMySQLILIKERejected verifies ILIKE is still rejected in dialects that
// do not natively support it.
func TestMySQLILIKERejected(t *testing.T) {
	q := `SELECT * FROM users WHERE name ILIKE 'alice%'`
	_, err := gosqlx.ParseWithDialect(q, keywords.DialectMySQL)
	if err == nil {
		t.Fatal("expected MySQL ILIKE to be rejected")
	}
	if !strings.Contains(err.Error(), "ILIKE is not supported") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestSnowflakePivot verifies PIVOT is parsed in the Snowflake dialect, where
// it was previously gated to SQL Server / Oracle only. Regression for #483.
func TestSnowflakePivot(t *testing.T) {
	q := `SELECT *
FROM monthly_sales
  PIVOT (SUM(amount) FOR month IN ('JAN', 'FEB', 'MAR'))
  AS p`
	if _, err := gosqlx.ParseWithDialect(q, keywords.DialectSnowflake); err != nil {
		t.Fatalf("Snowflake PIVOT parse failed: %v", err)
	}
}

// TestSnowflakeUnpivot verifies UNPIVOT is parsed in the Snowflake dialect.
func TestSnowflakeUnpivot(t *testing.T) {
	q := `SELECT *
FROM monthly_sales
  UNPIVOT (amount FOR month IN (jan, feb, mar))
  AS u`
	if _, err := gosqlx.ParseWithDialect(q, keywords.DialectSnowflake); err != nil {
		t.Fatalf("Snowflake UNPIVOT parse failed: %v", err)
	}
}
