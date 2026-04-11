// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestClickHouseWithTotals verifies GROUP BY ... WITH TOTALS parses.
func TestClickHouseWithTotals(t *testing.T) {
	queries := []string{
		`SELECT status, count() FROM events GROUP BY status WITH TOTALS`,
		`SELECT status, count() FROM events GROUP BY status WITH TOTALS ORDER BY status`,
	}
	for _, q := range queries {
		t.Run(q[:40], func(t *testing.T) {
			if _, err := gosqlx.ParseWithDialect(q, keywords.DialectClickHouse); err != nil {
				t.Fatalf("parse failed: %v", err)
			}
		})
	}
}

// TestClickHouseLimitBy verifies LIMIT N [OFFSET M] BY expr parses.
func TestClickHouseLimitBy(t *testing.T) {
	queries := []string{
		`SELECT user_id, event FROM events ORDER BY ts LIMIT 3 BY user_id`,
		`SELECT user_id, event FROM events ORDER BY ts LIMIT 3 OFFSET 1 BY user_id`,
		`SELECT user_id, event, ts FROM events ORDER BY ts LIMIT 5 BY user_id, event`,
	}
	for _, q := range queries {
		t.Run(q[:40], func(t *testing.T) {
			if _, err := gosqlx.ParseWithDialect(q, keywords.DialectClickHouse); err != nil {
				t.Fatalf("parse failed: %v", err)
			}
		})
	}
}

// TestClickHouseAnyJoin verifies the ANY/ALL join strictness prefix parses.
func TestClickHouseAnyJoin(t *testing.T) {
	queries := map[string]string{
		"any_left":  `SELECT * FROM a ANY LEFT JOIN b ON a.id = b.id`,
		"any_inner": `SELECT * FROM a ANY INNER JOIN b ON a.id = b.id`,
		"all_inner": `SELECT * FROM a ALL INNER JOIN b ON a.id = b.id`,
		"asof":      `SELECT * FROM a ASOF JOIN b ON a.id = b.id AND a.ts >= b.ts`,
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

// TestClickHouseDefaultAsIdentifier verifies DEFAULT can be used as a column
// name and DATABASES as a qualified table name in ClickHouse.
func TestClickHouseDefaultAsIdentifier(t *testing.T) {
	queries := []string{
		`SELECT default FROM t`,
		`SELECT database, default FROM system.databases`,
	}
	for _, q := range queries {
		t.Run(q, func(t *testing.T) {
			if _, err := gosqlx.ParseWithDialect(q, keywords.DialectClickHouse); err != nil {
				t.Fatalf("parse failed: %v", err)
			}
		})
	}
}
