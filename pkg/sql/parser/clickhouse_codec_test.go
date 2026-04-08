// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestClickHouseCODEC verifies the ClickHouse CODEC(...) column option
// parses in CREATE TABLE. Regression for #482.
func TestClickHouseCODEC(t *testing.T) {
	queries := map[string]string{
		"single_codec": `CREATE TABLE t (
			id UInt64,
			payload String CODEC(ZSTD(3))
		) ENGINE = MergeTree() ORDER BY id`,

		"chained_codec": `CREATE TABLE t (
			id UInt64,
			ts DateTime CODEC(Delta, LZ4)
		) ENGINE = MergeTree() ORDER BY id`,

		"delta_with_width": `CREATE TABLE t (
			id UInt64 CODEC(Delta(8), ZSTD)
		) ENGINE = MergeTree() ORDER BY id`,
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
