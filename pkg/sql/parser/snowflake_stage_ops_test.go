// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestSnowflakeStageOps verifies Snowflake stage operations parse as stubs.
// Regression for #483.
func TestSnowflakeStageOps(t *testing.T) {
	queries := map[string]string{
		"copy_into_table_with_format": `COPY INTO my_table FROM @my_stage FILE_FORMAT = (TYPE = CSV)`,

		"copy_into_named_format": `COPY INTO my_table FROM @my_stage/file.csv FILE_FORMAT = (FORMAT_NAME = my_csv) ON_ERROR = CONTINUE`,

		"copy_into_stage_from_table": `COPY INTO @my_stage FROM my_table FILE_FORMAT = (TYPE = PARQUET)`,

		"put_to_stage": `PUT file:///tmp/data.csv @my_stage`,

		"get_from_stage": `GET @my_stage file:///tmp/output/`,

		"list_stage": `LIST @my_stage`,

		"remove_from_stage": `REMOVE @my_stage/old_files`,

		"ls_alias": `LS @my_stage`,
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
