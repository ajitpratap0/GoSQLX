// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestClickHouseParametricAggregates verifies that ClickHouse parametric
// aggregates of the form `funcName(params)(args)` parse. Regression for #482.
func TestClickHouseParametricAggregates(t *testing.T) {
	queries := map[string]string{
		"quantile_tdigest": `SELECT quantileTDigest(0.95)(value) FROM events`,
		"top_k":            `SELECT topK(10)(name) FROM users`,
		"quantiles":        `SELECT quantiles(0.5, 0.9, 0.99)(latency_ms) FROM requests`,
		"with_group_by":    `SELECT category, quantileTDigest(0.99)(price) FROM products GROUP BY category`,
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
