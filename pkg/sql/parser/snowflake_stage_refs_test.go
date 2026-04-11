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
