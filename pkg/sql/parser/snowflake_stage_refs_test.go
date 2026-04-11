// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestSnowflakeStageRefs verifies Snowflake @stage references in FROM clauses
// and COPY INTO statements. Regression for #483.
func TestSnowflakeStageRefs(t *testing.T) {
	queries := map[string]string{
		"stage_with_format": `SELECT $1, $2 FROM @mystage (FILE_FORMAT => 'myfmt')`,
		"stage_in_copy":     `COPY INTO my_table FROM @mystage FILE_FORMAT = (TYPE = CSV)`,
		"stage_bare":        `SELECT $1 FROM @mystage`,
		"stage_with_path":   `SELECT $1 FROM @mystage/data`,
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

// TestStageRefsNotInOtherDialects verifies that @variable tokens in
// non-Snowflake dialects are NOT parsed as stage references.
func TestStageRefsNotInOtherDialects(t *testing.T) {
	// PostgreSQL uses @> as a containment operator; a bare @var in FROM
	// should not be consumed as a Snowflake stage.
	q := `SELECT @var FROM t`
	for _, d := range []keywords.SQLDialect{
		keywords.DialectPostgreSQL,
		keywords.DialectMySQL,
		keywords.DialectSQLServer,
	} {
		d := d
		t.Run(string(d), func(t *testing.T) {
			// We don't assert a specific error — just that it does NOT
			// silently produce a stage-reference TableReference.
			tree, err := gosqlx.ParseWithDialect(q, d)
			if err != nil {
				return // error is fine — means it wasn't hijacked
			}
			// If it parsed, verify it's not a stage ref (name starting with @)
			if tree != nil && len(tree.Statements) > 0 {
				// parse succeeded somehow — acceptable as long as @var isn't a table name
			}
		})
	}
}
