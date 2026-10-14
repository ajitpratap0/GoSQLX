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

package formatter_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestFormatAST_TableFunctions_Issue607 locks in that the library formatter
// keeps the call (name and arguments) of a table function in FROM:
// generate_series(1,10) AS g must not render as "generate_series g".
func TestFormatAST_TableFunctions_Issue607(t *testing.T) {
	cases := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    string // CompactStyle output
		call    string // call text that must survive in every style
	}{
		{"pg generate_series", keywords.DialectPostgreSQL, "SELECT * FROM generate_series(1,10) AS g", "SELECT * FROM generate_series(1, 10) g", "generate_series(1, 10)"},
		{"pg unnest", keywords.DialectPostgreSQL, "SELECT * FROM unnest(ARRAY[1,2,3]) AS u", "SELECT * FROM unnest(ARRAY[1, 2, 3]) u", "unnest(ARRAY[1, 2, 3])"},
		{"pg lateral", keywords.DialectPostgreSQL, "SELECT * FROM t, LATERAL generate_series(1, t.n) AS g", "SELECT * FROM t, LATERAL generate_series(1, t.n) g", "generate_series(1, t.n)"},
		{"pg qualified", keywords.DialectPostgreSQL, "SELECT * FROM pg_catalog.generate_series(1, 3) g", "SELECT * FROM pg_catalog.generate_series(1, 3) g", "pg_catalog.generate_series(1, 3)"},
		{"snowflake identifier", keywords.DialectSnowflake, "SELECT * FROM IDENTIFIER('t')", "SELECT * FROM IDENTIFIER('t')", "IDENTIFIER('t')"},
		{"snowflake table()", keywords.DialectSnowflake, "SELECT * FROM TABLE(my_udtf(1, 2)) f", "SELECT * FROM TABLE(my_udtf(1, 2)) f", "TABLE(my_udtf(1, 2))"},
		{"bigquery unnest", keywords.DialectBigQuery, "SELECT * FROM UNNEST(t.arr) AS x", "SELECT * FROM UNNEST(t.arr) x", "UNNEST(t.arr)"},
		{"clickhouse numbers", keywords.DialectClickHouse, "SELECT number FROM numbers(10) AS n", "SELECT number FROM numbers(10) n", "numbers(10)"},
		{"clickhouse remote", keywords.DialectClickHouse, "SELECT * FROM remote('host', db, tbl)", "SELECT * FROM remote('host', db, tbl)", "remote('host', db, tbl)"},
		{"clickhouse url", keywords.DialectClickHouse, "SELECT * FROM url('http://x/y', CSV, 'a UInt8')", "SELECT * FROM url('http://x/y', CSV, 'a UInt8')", "url('http://x/y', CSV, 'a UInt8')"},
		{"clickhouse merge", keywords.DialectClickHouse, "SELECT * FROM merge('db', '^t') AS m", "SELECT * FROM merge('db', '^t') m", "merge('db', '^t')"},
		{"clickhouse values", keywords.DialectClickHouse, "SELECT * FROM values('a Int8', 1, 2)", "SELECT * FROM values('a Int8', 1, 2)", "values('a Int8', 1, 2)"},
		{"clickhouse null", keywords.DialectClickHouse, "SELECT * FROM null('a Int8')", "SELECT * FROM null('a Int8')", "null('a Int8')"},
		{"clickhouse cluster", keywords.DialectClickHouse, "SELECT * FROM cluster('c', db.t)", "SELECT * FROM cluster('c', db.t)", "cluster('c', db.t)"},
		{"clickhouse file", keywords.DialectClickHouse, "SELECT * FROM file('data.csv', CSV)", "SELECT * FROM file('data.csv', CSV)", "file('data.csv', CSV)"},
		{"clickhouse join", keywords.DialectClickHouse, "SELECT * FROM numbers(0, 10) n JOIN t ON n.number = t.id", "SELECT * FROM numbers(0, 10) n INNER JOIN t ON n.number = t.id", "numbers(0, 10)"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatalf("ParseWithDialect(%q) failed: %v", tc.sql, err)
			}

			compact := formatter.FormatAST(tree, ast.CompactStyle())
			if compact != tc.want {
				t.Fatalf("FormatAST(CompactStyle) mismatch\n got: %q\nwant: %q", compact, tc.want)
			}

			readable := formatter.FormatAST(tree, ast.ReadableStyle())
			if !strings.Contains(readable, tc.call) {
				t.Fatalf("FormatAST(ReadableStyle) lost the table function call %q:\n%s", tc.call, readable)
			}

			again, err := gosqlx.ParseWithDialect(compact, tc.dialect)
			if err != nil {
				t.Fatalf("re-parse of %q failed: %v", compact, err)
			}
			if got := again.SQL(); !strings.Contains(got, tc.call) {
				t.Fatalf("re-parsed SQL() lost the call %q: %q", tc.call, got)
			}
			if got := formatter.FormatAST(again, ast.CompactStyle()); got != tc.want {
				t.Fatalf("round-trip FormatAST mismatch\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}

// TestFormatAST_TableFunctions_PublicAPI_Issue607 checks the issue's repro
// through the gosqlx.FormatAST convenience wrapper.
func TestFormatAST_TableFunctions_PublicAPI_Issue607(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect("SELECT * FROM generate_series(1,10) AS g", keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("ParseWithDialect failed: %v", err)
	}
	got := gosqlx.FormatAST(tree)
	if !strings.Contains(got, "FROM generate_series(1, 10) g") {
		t.Fatalf("gosqlx.FormatAST lost the table function arguments: %q", got)
	}
}

// TestFormatAST_TableFunctions_NamedArgs_Issue607 covers the Snowflake named
// argument case: the table reference must delegate to the FunctionCall
// writer. The exact "name => expr" text depends on #600; once the call renders
// "=>", the exact text from the issue is asserted too.
func TestFormatAST_TableFunctions_NamedArgs_Issue607(t *testing.T) {
	const sql = "SELECT f.value FROM t, LATERAL FLATTEN(input => t.arr) f"
	tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectSnowflake)
	if err != nil {
		t.Fatalf("ParseWithDialect(%q) failed: %v", sql, err)
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	if len(sel.From) < 2 || sel.From[1].TableFunc == nil {
		t.Fatalf("expected TableFunc on From[1]")
	}
	fn := sel.From[1].TableFunc.SQL()

	got := formatter.FormatAST(tree, ast.CompactStyle())
	if want := "SELECT f.value FROM t, LATERAL " + fn + " f"; got != want {
		t.Fatalf("FormatAST(CompactStyle) mismatch\n got: %q\nwant: %q", got, want)
	}
	if strings.Contains(fn, "=>") && got != sql {
		t.Fatalf("FormatAST mismatch with issue expectation\n got: %q\nwant: %q", got, sql)
	}
	if _, err := gosqlx.ParseWithDialect(got, keywords.DialectSnowflake); err != nil {
		t.Fatalf("re-parse of %q failed: %v", got, err)
	}
}
