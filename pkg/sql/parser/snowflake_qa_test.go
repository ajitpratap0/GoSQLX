// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
//go:build qa
// +build qa

// Package parser - Snowflake dialect QA corpus.
//
// This file is intentionally tagged `qa` so it does NOT run in the normal CI
// suite. It's a research-only harness for the QA report.
//
// Run with:
//
//	go test -tags qa -run TestSnowflakeQA -v ./pkg/sql/parser/
package parser_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

type sfCase struct {
	name string
	sql  string
}

func snowflakeCorpus() []sfCase {
	return []sfCase{
		// --- Basic / sanity ----------------------------------------------------
		{"select_basic", `SELECT 1`},
		{"select_from_table", `SELECT id, name FROM users`},
		{"select_qualified", `SELECT id FROM db.schema.users`},
		{"select_double_quoted_ident", `SELECT "Id", "Name" FROM "Users"`},
		{"select_reserved_ident_date", `SELECT date, type, value, status FROM events`},

		// --- QUALIFY -----------------------------------------------------------
		{"qualify_basic", `SELECT id, ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY ts) AS rn FROM events QUALIFY rn = 1`},
		{"qualify_with_where", `SELECT * FROM t WHERE x > 0 QUALIFY ROW_NUMBER() OVER (ORDER BY ts DESC) = 1`},
		{"qualify_with_groupby", `SELECT user_id, COUNT(*) c FROM e GROUP BY user_id QUALIFY RANK() OVER (ORDER BY c DESC) <= 10`},

		// --- MATCH_RECOGNIZE ---------------------------------------------------
		{"match_recognize_basic", `SELECT * FROM stock_price MATCH_RECOGNIZE (
			PARTITION BY symbol ORDER BY ts
			MEASURES MATCH_NUMBER() AS m
			ALL ROWS PER MATCH
			PATTERN (UP+ DOWN+)
			DEFINE UP AS price > PREV(price), DOWN AS price < PREV(price)
		)`},

		// --- PIVOT / UNPIVOT ---------------------------------------------------
		{"pivot_basic", `SELECT * FROM monthly_sales PIVOT (SUM(amount) FOR month IN ('JAN','FEB','MAR'))`},
		{"pivot_aliased", `SELECT * FROM monthly_sales PIVOT (SUM(amount) FOR month IN ('JAN','FEB')) AS p`},
		{"unpivot_basic", `SELECT * FROM quarterly_sales UNPIVOT (amount FOR quarter IN (q1, q2, q3, q4))`},

		// --- LATERAL FLATTEN ---------------------------------------------------
		{"lateral_flatten_basic", `SELECT t.id, f.value FROM t, LATERAL FLATTEN(input => t.arr) f`},
		{"lateral_flatten_path", `SELECT f.value:name::string FROM t, LATERAL FLATTEN(input => t.payload:items) f`},
		{"flatten_table_fn", `SELECT value FROM TABLE(FLATTEN(input => parse_json('[1,2,3]')))`},

		// --- Semi-structured (VARIANT/OBJECT/ARRAY paths) ---------------------
		{"variant_colon_path", `SELECT col:field FROM t`},
		{"variant_colon_dot", `SELECT col:field.sub FROM t`},
		{"variant_cast_short", `SELECT col:field::string FROM t`},
		{"variant_array_index", `SELECT col:items[0] FROM t`},
		{"variant_array_idx_path", `SELECT col:items[0].name::string FROM t`},
		{"variant_double_colon", `SELECT col::variant FROM t`},
		{"object_construct", `SELECT OBJECT_CONSTRUCT('a', 1, 'b', 2) FROM t`},
		{"object_construct_keep_null", `SELECT OBJECT_CONSTRUCT_KEEP_NULL('a', NULL) FROM t`},
		{"parse_json", `SELECT PARSE_JSON('{"a":1}'):a::int FROM t`},
		{"array_construct", `SELECT ARRAY_CONSTRUCT(1, 2, 3)`},
		{"get_path", `SELECT GET_PATH(col, 'a.b.c') FROM t`},

		// --- GROUPING SETS / CUBE / ROLLUP ------------------------------------
		{"grouping_sets", `SELECT a, b, SUM(x) FROM t GROUP BY GROUPING SETS ((a,b), (a), ())`},
		{"cube", `SELECT a, b, SUM(x) FROM t GROUP BY CUBE (a, b)`},
		{"rollup", `SELECT a, b, SUM(x) FROM t GROUP BY ROLLUP (a, b)`},

		// --- ILIKE / RLIKE ANY/ALL --------------------------------------------
		{"ilike_basic", `SELECT * FROM t WHERE name ILIKE '%foo%'`},
		{"ilike_any", `SELECT * FROM t WHERE name ILIKE ANY ('%foo%', '%bar%')`},
		{"like_all", `SELECT * FROM t WHERE name LIKE ALL ('%foo%', '%bar%')`},
		{"rlike", `SELECT * FROM t WHERE name RLIKE '^abc'`},

		// --- Window functions IGNORE/RESPECT NULLS ----------------------------
		{"lag_ignore_nulls", `SELECT LAG(x) IGNORE NULLS OVER (ORDER BY ts) FROM t`},
		{"first_value_respect_nulls", `SELECT FIRST_VALUE(x) RESPECT NULLS OVER (PARTITION BY g ORDER BY ts) FROM t`},
		{"window_frame_rows", `SELECT SUM(x) OVER (ORDER BY ts ROWS BETWEEN 3 PRECEDING AND CURRENT ROW) FROM t`},
		{"window_frame_range", `SELECT AVG(x) OVER (ORDER BY ts RANGE BETWEEN INTERVAL '7 days' PRECEDING AND CURRENT ROW) FROM t`},

		// --- Time travel -------------------------------------------------------
		{"at_timestamp", `SELECT * FROM t AT (TIMESTAMP => '2024-01-01'::timestamp)`},
		{"at_offset", `SELECT * FROM t AT (OFFSET => -60*5)`},
		{"before_statement", `SELECT * FROM t BEFORE (STATEMENT => '8e5d0ca9-1234')`},
		{"changes_clause", `SELECT * FROM t CHANGES (INFORMATION => DEFAULT) AT (TIMESTAMP => '2024-01-01'::timestamp)`},

		// --- MERGE -------------------------------------------------------------
		{"merge_basic", `MERGE INTO target t USING source s ON t.id = s.id
			WHEN MATCHED THEN UPDATE SET t.x = s.x
			WHEN NOT MATCHED THEN INSERT (id, x) VALUES (s.id, s.x)`},
		{"merge_delete", `MERGE INTO t USING s ON t.id=s.id WHEN MATCHED AND s.tombstone THEN DELETE`},

		// --- COPY INTO / stages ------------------------------------------------
		{"copy_into_table", `COPY INTO mytable FROM @mystage/path/ FILE_FORMAT = (TYPE = CSV)`},
		{"copy_into_location", `COPY INTO @mystage/out/ FROM (SELECT * FROM t) FILE_FORMAT = (TYPE = PARQUET)`},
		{"put_command", `PUT file:///tmp/data.csv @mystage`},
		{"get_command", `GET @mystage/data.csv file:///tmp/`},
		{"list_stage", `LIST @mystage`},

		// --- CREATE TABLE variants --------------------------------------------
		{"create_table_basic", `CREATE TABLE t (id INT, name STRING)`},
		{"create_table_cluster_by", `CREATE TABLE t (id INT, ts TIMESTAMP) CLUSTER BY (ts)`},
		{"create_table_copy_grants", `CREATE OR REPLACE TABLE t COPY GRANTS AS SELECT * FROM s`},
		{"create_stage", `CREATE STAGE mystage FILE_FORMAT = (TYPE = CSV)`},
		{"create_file_format", `CREATE FILE FORMAT myfmt TYPE = CSV FIELD_DELIMITER = ','`},

		// --- CREATE STREAM / TASK / PIPE --------------------------------------
		{"create_stream", `CREATE STREAM mystream ON TABLE mytable`},
		{"create_task", `CREATE TASK mytask WAREHOUSE = wh SCHEDULE = '5 MINUTE' AS INSERT INTO t SELECT 1`},
		{"create_pipe", `CREATE PIPE mypipe AS COPY INTO t FROM @mystage`},

		// --- Snowflake functions ----------------------------------------------
		{"try_cast", `SELECT TRY_CAST('abc' AS INT)`},
		{"iff", `SELECT IFF(x > 0, 'pos', 'neg') FROM t`},
		{"zeroifnull", `SELECT ZEROIFNULL(x) FROM t`},
		{"nullifzero", `SELECT NULLIFZERO(x) FROM t`},
		{"array_agg_within_group", `SELECT ARRAY_AGG(name) WITHIN GROUP (ORDER BY ts) FROM t`},
		{"listagg", `SELECT LISTAGG(name, ', ') WITHIN GROUP (ORDER BY name) FROM t`},
		{"date_trunc", `SELECT DATE_TRUNC('day', ts) FROM t`},
		{"dateadd", `SELECT DATEADD(day, 7, ts) FROM t`},
		{"datediff", `SELECT DATEDIFF(day, a, b) FROM t`},
		{"to_varchar_fmt", `SELECT TO_VARCHAR(ts, 'YYYY-MM-DD') FROM t`},
		{"generator_table", `SELECT seq4() FROM TABLE(GENERATOR(ROWCOUNT => 100))`},

		// --- Dollar-quoted strings --------------------------------------------
		{"dollar_quoted_simple", `SELECT $$hello world$$`},
		{"dollar_quoted_with_quotes", `SELECT $$it's "quoted"$$`},

		// --- Reserved-word collisions in identifiers --------------------------
		{"col_named_type", `SELECT type FROM events`},
		{"col_named_value", `SELECT value FROM kv`},
		{"col_named_status", `SELECT status FROM orders`},
		{"col_named_date", `SELECT date FROM logs`},

		// --- Misc / set ops / CTE ---------------------------------------------
		{"cte_basic", `WITH a AS (SELECT 1) SELECT * FROM a`},
		{"cte_recursive", `WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r WHERE n<10) SELECT * FROM r`},
		{"union_all", `SELECT 1 UNION ALL SELECT 2`},
		{"intersect", `SELECT 1 INTERSECT SELECT 1`},
		{"except", `SELECT 1 EXCEPT SELECT 2`},
		{"minus", `SELECT 1 MINUS SELECT 2`},

		// --- Sample / TABLESAMPLE ---------------------------------------------
		{"sample_pct", `SELECT * FROM t SAMPLE (10)`},
		{"tablesample_bernoulli", `SELECT * FROM t TABLESAMPLE BERNOULLI (10)`},

		// --- $1 positional / IDENTIFIER() -------------------------------------
		{"positional_col_$1", `SELECT $1, $2 FROM @mystage (FILE_FORMAT => 'myfmt')`},
		{"identifier_fn", `SELECT * FROM IDENTIFIER('mytable')`},

		// --- USE / SHOW / DESCRIBE --------------------------------------------
		{"use_warehouse", `USE WAREHOUSE my_wh`},
		{"use_database", `USE DATABASE my_db`},
		{"show_tables", `SHOW TABLES`},
		{"describe_table", `DESCRIBE TABLE t`},
	}
}

func TestSnowflakeQA(t *testing.T) {
	cases := snowflakeCorpus()
	var passed, failed int
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			_, err := gosqlx.ParseWithDialect(c.sql, keywords.DialectSnowflake)
			if err != nil {
				failed++
				// One-line summary so the report can grep PASS/FAIL.
				t.Logf("FAIL %-40s err=%s sql=%s", c.name, oneLine(err.Error()), oneLine(c.sql))
				t.Fail()
				return
			}
			passed++
			t.Logf("PASS %s", c.name)
		})
	}
	t.Logf("TOTAL=%d PASSED=%d FAILED=%d", len(cases), passed, failed)
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	return strings.TrimSpace(s)
}
