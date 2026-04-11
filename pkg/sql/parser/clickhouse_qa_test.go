//go:build qa

// ClickHouse dialect QA corpus. Run with:
//
//	go test -tags qa -run TestClickHouseQA -v ./pkg/sql/parser/
//
// This file is intentionally excluded from normal CI builds.
package parser_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

type qaCase struct {
	name string
	sql  string
}

func TestClickHouseQA(t *testing.T) {
	cases := []qaCase{
		// --- Basic SELECT
		{"select_basic", "SELECT 1"},
		{"select_star", "SELECT * FROM events"},
		{"select_qualified", "SELECT e.id, e.name FROM events e"},
		{"select_db_qual", "SELECT * FROM default.events"},

		// --- FINAL / SAMPLE / PREWHERE
		{"final", "SELECT * FROM events FINAL"},
		{"final_where", "SELECT id FROM events FINAL WHERE id > 0"},
		{"sample_decimal", "SELECT * FROM events SAMPLE 0.1"},
		{"sample_int", "SELECT * FROM events SAMPLE 10000"},
		{"sample_offset", "SELECT * FROM events SAMPLE 1/10 OFFSET 2/10"},
		{"prewhere", "SELECT id FROM events PREWHERE event_date = today()"},
		{"prewhere_where", "SELECT id FROM events PREWHERE event_date = today() WHERE user_id = 5"},
		{"final_sample_prewhere", "SELECT id FROM events FINAL SAMPLE 0.1 PREWHERE x = 1 WHERE y = 2"},

		// --- ARRAY JOIN
		{"array_join", "SELECT id, tag FROM events ARRAY JOIN tags AS tag"},
		{"left_array_join", "SELECT id, tag FROM events LEFT ARRAY JOIN tags AS tag"},
		{"array_join_multi", "SELECT id, t, v FROM x ARRAY JOIN tags AS t, vals AS v"},

		// --- LIMIT BY
		{"limit_by", "SELECT id, name FROM users ORDER BY name LIMIT 5 BY id"},
		{"limit_offset_by", "SELECT id FROM users ORDER BY id LIMIT 2, 5 BY id"},

		// --- GROUP BY rollups
		{"group_by_basic", "SELECT a, count() FROM t GROUP BY a"},
		{"group_by_rollup", "SELECT a, b, count() FROM t GROUP BY a, b WITH ROLLUP"},
		{"group_by_cube", "SELECT a, b, count() FROM t GROUP BY a, b WITH CUBE"},
		{"group_by_totals", "SELECT a, count() FROM t GROUP BY a WITH TOTALS"},

		// --- Window functions
		{"window_basic", "SELECT id, sum(x) OVER (PARTITION BY a ORDER BY b) FROM t"},
		{"window_named", "SELECT id, row_number() OVER w FROM t WINDOW w AS (PARTITION BY a ORDER BY b)"},
		{"window_frame", "SELECT id, sum(x) OVER (ORDER BY b ROWS BETWEEN 3 PRECEDING AND CURRENT ROW) FROM t"},

		// --- CTEs
		{"cte_basic", "WITH x AS (SELECT 1 AS a) SELECT a FROM x"},
		{"cte_multi", "WITH a AS (SELECT 1 AS x), b AS (SELECT 2 AS y) SELECT * FROM a, b"},
		{"cte_scalar", "WITH 5 AS five SELECT five + 1"},

		// --- JOIN variants
		{"any_join", "SELECT * FROM a ANY LEFT JOIN b ON a.id = b.id"},
		{"asof_join", "SELECT * FROM a ASOF JOIN b ON a.k = b.k AND a.t >= b.t"},
		{"global_join", "SELECT * FROM a GLOBAL INNER JOIN b ON a.id = b.id"},
		{"cross_join", "SELECT * FROM a CROSS JOIN b"},
		{"using_join", "SELECT * FROM a JOIN b USING (id)"},

		// --- DDL with engines
		{"create_mt", "CREATE TABLE t (id UInt64, name String) ENGINE = MergeTree() ORDER BY id"},
		{"create_mt_partition", "CREATE TABLE t (id UInt64, d Date) ENGINE = MergeTree() PARTITION BY toYYYYMM(d) ORDER BY id"},
		{"create_replacing", "CREATE TABLE t (id UInt64, v UInt64) ENGINE = ReplacingMergeTree(v) ORDER BY id"},
		{"create_summing", "CREATE TABLE t (k UInt64, v UInt64) ENGINE = SummingMergeTree() ORDER BY k"},
		{"create_distributed", "CREATE TABLE t AS local ENGINE = Distributed(cluster, db, local, rand())"},
		{"create_replicated", "CREATE TABLE t (id UInt64) ENGINE = ReplicatedMergeTree('/clickhouse/{shard}/t', '{replica}') ORDER BY id"},
		{"create_settings", "CREATE TABLE t (id UInt64) ENGINE = MergeTree() ORDER BY id SETTINGS index_granularity = 8192"},
		{"create_ttl", "CREATE TABLE t (id UInt64, d DateTime) ENGINE = MergeTree() ORDER BY id TTL d + INTERVAL 30 DAY"},
		{"create_codec", "CREATE TABLE t (id UInt64 CODEC(ZSTD(3))) ENGINE = MergeTree() ORDER BY id"},
		{"create_lowcard", "CREATE TABLE t (s LowCardinality(String)) ENGINE = MergeTree() ORDER BY tuple()"},
		{"create_nullable", "CREATE TABLE t (s Nullable(String)) ENGINE = MergeTree() ORDER BY tuple()"},
		{"create_fixedstring", "CREATE TABLE t (s FixedString(16)) ENGINE = MergeTree() ORDER BY tuple()"},
		{"create_array_col", "CREATE TABLE t (tags Array(String)) ENGINE = MergeTree() ORDER BY tuple()"},
		{"create_map_col", "CREATE TABLE t (m Map(String, UInt64)) ENGINE = MergeTree() ORDER BY tuple()"},
		{"create_tuple_col", "CREATE TABLE t (p Tuple(Float64, Float64)) ENGINE = MergeTree() ORDER BY tuple()"},
		{"create_datetime64", "CREATE TABLE t (ts DateTime64(3)) ENGINE = MergeTree() ORDER BY ts"},

		// --- Materialized View
		{"create_mv", "CREATE MATERIALIZED VIEW mv ENGINE = MergeTree() ORDER BY id AS SELECT id, count() FROM events GROUP BY id"},
		{"create_mv_to", "CREATE MATERIALIZED VIEW mv TO target AS SELECT id FROM events"},

		// --- INSERT
		{"insert_values", "INSERT INTO t (a, b) VALUES (1, 'x')"},
		{"insert_select", "INSERT INTO t SELECT * FROM s"},
		{"insert_format", "INSERT INTO t FORMAT JSONEachRow"},

		// --- system.* queries
		{"system_parts", "SELECT table, partition, rows FROM system.parts WHERE active"},
		{"system_columns", "SELECT database, table, name, type FROM system.columns"},
		{"system_tables", "SELECT database, name, engine FROM system.tables WHERE engine LIKE '%MergeTree%'"},
		{"system_processes", "SELECT query_id, user, query FROM system.processes"},
		{"system_settings", "SELECT name, value, changed FROM system.settings WHERE changed"},

		// --- Common ClickHouse functions
		{"fn_arrayJoin", "SELECT arrayJoin([1,2,3])"},
		{"fn_groupArray", "SELECT groupArray(id) FROM t"},
		{"fn_quantile", "SELECT quantileTDigest(0.99)(latency) FROM t"},
		{"fn_format_size", "SELECT formatReadableSize(1024)"},
		{"fn_toStartOfInterval", "SELECT toStartOfInterval(ts, INTERVAL 5 MINUTE) FROM t"},
		{"fn_dateDiff", "SELECT dateDiff('day', a, b) FROM t"},
		{"fn_toDate", "SELECT toDate(ts) FROM t"},
		{"fn_if", "SELECT if(x > 0, 'pos', 'neg') FROM t"},
		{"fn_multiIf", "SELECT multiIf(x = 1, 'a', x = 2, 'b', 'c') FROM t"},

		// --- Literals
		{"array_literal", "SELECT [1, 2, 3]"},
		{"tuple_literal", "SELECT (1, 'a', 3.14)"},
		{"map_literal", "SELECT map('a', 1, 'b', 2)"},
		{"array_subscript", "SELECT a[1] FROM t"},

		// --- Settings tail
		{"select_settings", "SELECT * FROM t SETTINGS max_threads = 4"},
		{"select_settings_multi", "SELECT * FROM t SETTINGS max_threads = 4, max_memory_usage = 1000000"},

		// --- Identifiers overlapping keywords (issue #480 area)
		{"id_table", "SELECT table FROM system.parts"},
		{"id_partition", "SELECT partition FROM system.parts"},
		{"id_key_value", "SELECT key, value FROM system.settings"},
		{"id_type_status", "SELECT type, status FROM system.replicas"},
		{"id_database_engine", "SELECT database, engine FROM system.tables"},
		{"id_name", "SELECT name FROM system.tables"},

		// --- Backtick identifiers
		{"backtick_id", "SELECT `event id`, `user-name` FROM events"},

		// --- Set ops
		{"union_all", "SELECT 1 UNION ALL SELECT 2"},
		{"intersect", "SELECT 1 INTERSECT SELECT 1"},

		// --- ORDER BY / WITH FILL
		{"order_with_fill", "SELECT n FROM t ORDER BY n WITH FILL FROM 0 TO 100 STEP 1"},
	}

	var failures []string
	pass, fail := 0, 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := gosqlx.ParseWithDialect(tc.sql, keywords.DialectClickHouse)
			if err != nil {
				fail++
				msg := fmt.Sprintf("FAIL %-30s | %s\n    SQL: %s\n    ERR: %v", tc.name, "", tc.sql, err)
				failures = append(failures, msg)
				t.Logf("%s", msg)
				return
			}
			pass++
		})
	}
	summary := fmt.Sprintf("\n=== ClickHouse QA Summary ===\nTotal: %d  Pass: %d  Fail: %d\n", len(cases), pass, fail)
	t.Log(summary)
	body := summary + "\n" + strings.Join(failures, "\n\n") + "\n"
	_ = os.WriteFile("/tmp/clickhouse-qa-raw.txt", []byte(body), 0644)
}
