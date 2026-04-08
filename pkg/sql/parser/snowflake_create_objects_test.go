// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestSnowflakeCreateObjects verifies Snowflake CREATE statements for object
// types beyond TABLE/VIEW/INDEX parse. These are currently consumed as
// stub statements (body is not modeled on the AST). Regression for #483.
func TestSnowflakeCreateObjects(t *testing.T) {
	queries := map[string]string{
		"create_stage": `CREATE STAGE my_stage URL='s3://bucket/path' CREDENTIALS=(AWS_KEY_ID='abc' AWS_SECRET_KEY='xyz')`,

		"create_file_format": `CREATE FILE FORMAT my_csv TYPE = CSV FIELD_DELIMITER = ','`,

		"create_stream": `CREATE STREAM my_stream ON TABLE events`,

		"create_task": `CREATE TASK daily_refresh WAREHOUSE = compute_wh SCHEDULE = 'USING CRON 0 0 * * * UTC' AS INSERT INTO t SELECT 1`,

		"create_or_replace_pipe": `CREATE OR REPLACE PIPE my_pipe AUTO_INGEST = TRUE AS COPY INTO t FROM @my_stage`,

		"create_warehouse": `CREATE WAREHOUSE my_wh WITH WAREHOUSE_SIZE = 'SMALL'`,

		"create_database": `CREATE DATABASE my_db`,

		"create_schema_qualified": `CREATE SCHEMA analytics.my_schema`,

		"create_role": `CREATE ROLE analyst`,

		"create_if_not_exists_stage": `CREATE STAGE IF NOT EXISTS my_stage URL='s3://bucket'`,
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
