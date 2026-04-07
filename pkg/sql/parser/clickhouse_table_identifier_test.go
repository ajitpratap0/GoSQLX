// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestClickHouseTableAsIdentifier verifies that the ClickHouse dialect accepts
// `table` as a column identifier in SELECT lists, function arguments, and
// GROUP BY clauses. ClickHouse system tables (system.replicas, system.tables,
// system.parts) all expose a `table` column, so this is a common real-world
// pattern. Regression test for issue #480.
func TestClickHouseTableAsIdentifier(t *testing.T) {
	queries := map[string]string{
		"replicas_with_table_column": `SELECT
    database,
    table,
    is_leader,
    is_readonly,
    is_session_expired,
    parts_to_check,
    queue_size,
    inserts_in_queue,
    merges_in_queue,
    absolute_delay,
    last_queue_update,
    zookeeper_path
FROM system.replicas
ORDER BY absolute_delay DESC`,

		"tables_with_bytes_on_disk": `SELECT
    database,
    table,
    engine,
    formatReadableSize(bytes_on_disk) AS size,
    parts,
    active_parts
FROM system.tables
WHERE engine LIKE '%MergeTree%'
  AND is_temporary = 0
ORDER BY bytes_on_disk DESC
LIMIT 10`,

		"tables_with_total_bytes": `SELECT
    database,
    table,
    engine,
    formatReadableSize(total_bytes) AS size,
    parts,
    active_parts
FROM system.tables
WHERE engine LIKE '%MergeTree%'
  AND is_temporary = 0
ORDER BY total_bytes DESC
LIMIT 10`,

		"parts_with_concat_table": `SELECT
    concat(database, '.' ,table) AS table_name,
    count() AS part_count,
    max(partition) AS latest_partition,
    formatReadableSize(sum(bytes_on_disk)) AS total_size
FROM system.parts
WHERE active = 1
  AND database NOT IN ('system')
GROUP BY database, table
ORDER BY part_count DESC
LIMIT 10`,

		"parts_having_count": `SELECT
    database,
    table,
    count() AS parts,
    formatReadableSize(sum(bytes_on_disk)) AS size
FROM system.parts
WHERE active = 1
  AND database NOT IN ('system')
GROUP BY database, table
HAVING parts > 300
ORDER BY parts DESC`,
	}

	for name, query := range queries {
		query := query
		t.Run(name, func(t *testing.T) {
			parsed, err := gosqlx.ParseWithDialect(query, keywords.DialectClickHouse)
			if err != nil {
				t.Fatalf("ParseWithDialect failed: %v", err)
			}
			if parsed == nil {
				t.Fatal("expected non-nil AST")
			}
		})
	}
}
