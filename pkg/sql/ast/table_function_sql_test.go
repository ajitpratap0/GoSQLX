// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ast_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestTableFunctionSQL_Issue607 locks in that TableReference.SQL() keeps the
// call (name and arguments) of a table function in FROM instead of writing
// only its name: generate_series(1,10) AS g used to render as
// "generate_series g".
func TestTableFunctionSQL_Issue607(t *testing.T) {
	cases := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		{"pg generate_series alias", keywords.DialectPostgreSQL, "SELECT * FROM generate_series(1,10) AS g", "SELECT * FROM generate_series(1, 10) g"},
		{"pg generate_series no alias", keywords.DialectPostgreSQL, "SELECT * FROM generate_series(1,10)", "SELECT * FROM generate_series(1, 10)"},
		{"pg unnest array", keywords.DialectPostgreSQL, "SELECT * FROM unnest(ARRAY[1,2,3]) AS u", "SELECT * FROM unnest(ARRAY[1, 2, 3]) u"},
		{"pg lateral", keywords.DialectPostgreSQL, "SELECT * FROM t, LATERAL generate_series(1, t.n) AS g", "SELECT * FROM t, LATERAL generate_series(1, t.n) g"},
		{"pg qualified", keywords.DialectPostgreSQL, "SELECT * FROM pg_catalog.generate_series(1, 3) g", "SELECT * FROM pg_catalog.generate_series(1, 3) g"},
		{"pg json_each", keywords.DialectPostgreSQL, "SELECT * FROM json_each('{\"a\":1}') AS j", "SELECT * FROM json_each('{\"a\":1}') j"},
		{"pg in cte", keywords.DialectPostgreSQL, "WITH c AS (SELECT * FROM generate_series(1, 3) g) SELECT * FROM c", "WITH c AS (SELECT * FROM generate_series(1, 3) g) SELECT * FROM c"},
		{"pg in subquery", keywords.DialectPostgreSQL, "SELECT * FROM t WHERE id IN (SELECT g FROM generate_series(1, 3) g)", "SELECT * FROM t WHERE id IN (SELECT g FROM generate_series(1, 3) g)"},
		{"snowflake identifier", keywords.DialectSnowflake, "SELECT * FROM IDENTIFIER('t')", "SELECT * FROM IDENTIFIER('t')"},
		{"snowflake table()", keywords.DialectSnowflake, "SELECT * FROM TABLE(my_udtf(1, 2)) f", "SELECT * FROM TABLE(my_udtf(1, 2)) f"},
		{"bigquery unnest column", keywords.DialectBigQuery, "SELECT * FROM UNNEST(t.arr) AS x", "SELECT * FROM UNNEST(t.arr) x"},
		{"bigquery unnest array", keywords.DialectBigQuery, "SELECT * FROM UNNEST(ARRAY[1,2,3]) AS x", "SELECT * FROM UNNEST(ARRAY[1, 2, 3]) x"},
		{"clickhouse numbers alias", keywords.DialectClickHouse, "SELECT number FROM numbers(10) AS n", "SELECT number FROM numbers(10) n"},
		{"clickhouse remote", keywords.DialectClickHouse, "SELECT * FROM remote('host', db, tbl)", "SELECT * FROM remote('host', db, tbl)"},
		{"clickhouse url", keywords.DialectClickHouse, "SELECT * FROM url('http://x/y', CSV, 'a UInt8')", "SELECT * FROM url('http://x/y', CSV, 'a UInt8')"},
		{"clickhouse merge", keywords.DialectClickHouse, "SELECT * FROM merge('db', '^t') AS m", "SELECT * FROM merge('db', '^t') m"},
		{"clickhouse values", keywords.DialectClickHouse, "SELECT * FROM values('a Int8', 1, 2)", "SELECT * FROM values('a Int8', 1, 2)"},
		{"clickhouse null", keywords.DialectClickHouse, "SELECT * FROM null('a Int8')", "SELECT * FROM null('a Int8')"},
		{"clickhouse cluster", keywords.DialectClickHouse, "SELECT * FROM cluster('c', db.t)", "SELECT * FROM cluster('c', db.t)"},
		{"clickhouse file", keywords.DialectClickHouse, "SELECT * FROM file('data.csv', CSV)", "SELECT * FROM file('data.csv', CSV)"},
		{"clickhouse join", keywords.DialectClickHouse, "SELECT * FROM numbers(0, 10) n JOIN t ON n.number = t.id", "SELECT * FROM numbers(0, 10) n INNER JOIN t ON n.number = t.id"},
		{"clickhouse insert select", keywords.DialectClickHouse, "INSERT INTO t SELECT * FROM numbers(10)", "INSERT INTO t SELECT * FROM numbers(10)"},
		// Unchanged behaviour: plain tables (TableFunc == nil).
		{"pg plain table named like a function", keywords.DialectPostgreSQL, "SELECT * FROM generate_series", "SELECT * FROM generate_series"},
		{"pg plain aliased table", keywords.DialectPostgreSQL, "SELECT * FROM t AS x", "SELECT * FROM t x"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatalf("ParseWithDialect(%q) failed: %v", tc.sql, err)
			}
			if got := tree.SQL(); got != tc.want {
				t.Fatalf("SQL() mismatch\n got: %q\nwant: %q", got, tc.want)
			}

			// Byte-stable round trip.
			again, err := gosqlx.ParseWithDialect(tc.want, tc.dialect)
			if err != nil {
				t.Fatalf("re-parse of %q failed: %v", tc.want, err)
			}
			if got := again.SQL(); got != tc.want {
				t.Fatalf("round-trip SQL() mismatch\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}

// TestTableFunctionSQL_NamedArgs_Issue607 checks the Snowflake table functions
// with named arguments from the issue. The table reference must delegate to the
// FunctionCall writer so the call is no longer dropped. The exact "name => expr"
// text depends on named-argument rendering (#600): once TableFunc.SQL() contains
// "=>", the exact text from the issue is asserted too.
func TestTableFunctionSQL_NamedArgs_Issue607(t *testing.T) {
	cases := []struct {
		name      string
		sql       string
		fromIdx   int
		prefix    string
		suffix    string
		issueWant string
	}{
		{
			name:      "lateral flatten",
			sql:       "SELECT f.value FROM t, LATERAL FLATTEN(input => t.arr) f",
			fromIdx:   1,
			prefix:    "SELECT f.value FROM t, LATERAL ",
			suffix:    " f",
			issueWant: "SELECT f.value FROM t, LATERAL FLATTEN(input => t.arr) f",
		},
		{
			name:      "table(flatten)",
			sql:       "SELECT * FROM TABLE(FLATTEN(input => x)) f",
			fromIdx:   0,
			prefix:    "SELECT * FROM ",
			suffix:    " f",
			issueWant: "SELECT * FROM TABLE(FLATTEN(input => x)) f",
		},
		{
			name:      "table(generator)",
			sql:       "SELECT seq4() FROM TABLE(GENERATOR(ROWCOUNT => 10))",
			fromIdx:   0,
			prefix:    "SELECT seq4() FROM ",
			suffix:    "",
			issueWant: "SELECT seq4() FROM TABLE(GENERATOR(ROWCOUNT => 10))",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, keywords.DialectSnowflake)
			if err != nil {
				t.Fatalf("ParseWithDialect(%q) failed: %v", tc.sql, err)
			}
			if len(tree.Statements) != 1 {
				t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
			}
			sel, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
			}
			if tc.fromIdx >= len(sel.From) {
				t.Fatalf("FROM index %d out of range (%d refs)", tc.fromIdx, len(sel.From))
			}
			fn := sel.From[tc.fromIdx].TableFunc
			if fn == nil {
				t.Fatalf("expected TableFunc on From[%d]", tc.fromIdx)
			}

			got := tree.SQL()
			if want := tc.prefix + fn.SQL() + tc.suffix; got != want {
				t.Fatalf("SQL() mismatch\n got: %q\nwant: %q", got, want)
			}
			if strings.Contains(fn.SQL(), "=>") && got != tc.issueWant {
				t.Fatalf("SQL() mismatch with issue expectation\n got: %q\nwant: %q", got, tc.issueWant)
			}
			if _, err := gosqlx.ParseWithDialect(got, keywords.DialectSnowflake); err != nil {
				t.Fatalf("re-parse of %q failed: %v", got, err)
			}
		})
	}
}
