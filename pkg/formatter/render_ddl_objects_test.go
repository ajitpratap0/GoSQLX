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
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestFormatDDLObjects checks the formatter output of the CREATE TABLE,
// CREATE INDEX, view, DROP and TRUNCATE extensions under the readable
// (newline-per-clause, upper-case) and lower-case compact styles, and that
// each output re-parses and formats idempotently.
func TestFormatDDLObjects(t *testing.T) {
	lower := ast.CompactStyle()
	lower.KeywordCase = ast.KeywordLower
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		opts    ast.FormatOptions
		want    string
	}{
		{"ctas readable", keywords.DialectPostgreSQL, "CREATE TABLE t AS SELECT a FROM u WHERE a > 1", ast.ReadableStyle(),
			"CREATE TABLE t AS\nSELECT a\nFROM u\nWHERE a > 1;"},
		{"ctas lower", keywords.DialectPostgreSQL, "CREATE TABLE t AS SELECT a FROM u WITH NO DATA", lower,
			"create table t as select a from u with no data"},
		{"clickhouse engine lower", keywords.DialectClickHouse,
			"CREATE TABLE e (a UInt8) ENGINE = MergeTree ORDER BY a SETTINGS index_granularity = 1", lower,
			"create table e (a UInt8) engine=MergeTree order by a settings index_granularity = 1"},
		{"columns readable with options", keywords.DialectMySQL,
			"CREATE TABLE t (id INT, PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4", ast.ReadableStyle(),
			"CREATE TABLE t (\n  id INT,\n  PRIMARY KEY (id)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"},
		{"period readable", keywords.DialectMariaDB,
			"CREATE TABLE p (s TIMESTAMP(6), e TIMESTAMP(6), PERIOD FOR SYSTEM_TIME (s, e)) WITH SYSTEM VERSIONING", ast.ReadableStyle(),
			"CREATE TABLE p (\n  s TIMESTAMP(6),\n  e TIMESTAMP(6),\n  PERIOD FOR SYSTEM_TIME (s, e)\n) WITH SYSTEM VERSIONING;"},
		{"index readable", keywords.DialectSQLServer,
			"CREATE NONCLUSTERED INDEX ix ON t (a) INCLUDE (b) WHERE a > 1 WITH (FILLFACTOR = 90)", ast.ReadableStyle(),
			"CREATE NONCLUSTERED INDEX ix ON t (a) INCLUDE (b)\nWHERE a > 1 WITH (FILLFACTOR = 90);"},
		{"view lower", keywords.DialectOracle, "CREATE OR REPLACE FORCE VIEW v AS SELECT a FROM t WITH READ ONLY", lower,
			"create or replace force view v as select a from t with read only"},
		{"mv readable", keywords.DialectClickHouse, "CREATE MATERIALIZED VIEW mv TO d AS SELECT a FROM s", ast.ReadableStyle(),
			"CREATE MATERIALIZED VIEW mv TO d AS\nSELECT a\nFROM s;"},
		{"drop lower", keywords.DialectMySQL, "DROP INDEX ix ON t", lower, "drop index ix on t"},
		{"truncate", keywords.DialectOracle, "TRUNCATE TABLE t DROP STORAGE", ast.ReadableStyle(), "TRUNCATE TABLE t DROP STORAGE;"},
		{"verbatim object", keywords.DialectPostgreSQL, "CREATE SCHEMA IF NOT EXISTS analytics", lower,
			"CREATE SCHEMA IF NOT EXISTS analytics"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tt.sql, tt.dialect)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			defer ast.ReleaseAST(tree)
			got := formatter.FormatAST(tree, tt.opts)
			if got != tt.want {
				t.Fatalf("format\n got: %q\nwant: %q", got, tt.want)
			}
			tree2, err := gosqlx.ParseWithDialect(got, tt.dialect)
			if err != nil {
				t.Fatalf("re-parse %q: %v", got, err)
			}
			defer ast.ReleaseAST(tree2)
			if again := formatter.FormatAST(tree2, tt.opts); again != got {
				t.Fatalf("not idempotent\nfirst:  %q\nsecond: %q", got, again)
			}
		})
	}
}
