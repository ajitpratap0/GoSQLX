// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestClickHouseNestedColumnTypes verifies CREATE TABLE column definitions
// with nested/parameterised types parse for the ClickHouse dialect. Regression
// for #482.
func TestClickHouseNestedColumnTypes(t *testing.T) {
	queries := map[string]string{
		"array_string": `CREATE TABLE t (
			tags Array(String)
		) ENGINE = MergeTree() ORDER BY tags`,

		"nullable_int": `CREATE TABLE t (
			id Nullable(Int32)
		) ENGINE = MergeTree() ORDER BY id`,

		"array_nullable": `CREATE TABLE t (
			tags Array(Nullable(String))
		) ENGINE = MergeTree() ORDER BY tags`,

		"map_string_array": `CREATE TABLE t (
			counts Map(String, Array(UInt32))
		) ENGINE = MergeTree() ORDER BY counts`,

		"low_cardinality": `CREATE TABLE t (
			country LowCardinality(String)
		) ENGINE = MergeTree() ORDER BY country`,

		"fixed_string": `CREATE TABLE t (
			hash FixedString(32)
		) ENGINE = MergeTree() ORDER BY hash`,

		"datetime64_with_tz": `CREATE TABLE t (
			ts DateTime64(3, 'UTC')
		) ENGINE = MergeTree() ORDER BY ts`,

		"decimal_precision_scale": `CREATE TABLE t (
			price Decimal(38, 18)
		) ENGINE = MergeTree() ORDER BY price`,

		"replicated_engine": `CREATE TABLE t (
			id UInt64
		) ENGINE = ReplicatedMergeTree('/clickhouse/tables/t', '{replica}') ORDER BY id`,

		"distributed_engine": `CREATE TABLE t (
			id UInt64
		) ENGINE = Distributed('cluster', 'db', 'local_t', id)`,
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
