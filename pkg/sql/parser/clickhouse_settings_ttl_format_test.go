// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestClickHouseSettingsTTLFormat verifies ClickHouse tail clauses parse for
// both CREATE TABLE and SELECT/INSERT. Regression for #482.
func TestClickHouseSettingsTTLFormat(t *testing.T) {
	queries := map[string]string{
		"create_table_with_settings": `CREATE TABLE events (
			id UInt64,
			ts DateTime
		) ENGINE = MergeTree()
		ORDER BY ts
		SETTINGS index_granularity = 8192, storage_policy = 'default'`,

		"create_table_with_ttl": `CREATE TABLE logs (
			event_date Date,
			message String
		) ENGINE = MergeTree()
		ORDER BY event_date
		TTL event_date + INTERVAL 90 DAY`,

		"create_table_ttl_then_settings": `CREATE TABLE logs (
			event_date Date,
			message String
		) ENGINE = MergeTree()
		ORDER BY event_date
		TTL event_date + INTERVAL 90 DAY
		SETTINGS index_granularity = 8192`,

		"select_with_settings": `SELECT * FROM events
		WHERE id > 100
		SETTINGS max_threads = 4, distributed_aggregation_memory_efficient = 1`,

		"insert_format_values": `INSERT INTO events (id, name) VALUES (1, 'a') FORMAT Values`,

		"insert_format_json_each_row": `INSERT INTO events FORMAT JSONEachRow`,
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
