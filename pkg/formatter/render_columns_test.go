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

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestFormat_ColumnDefinitionsKeepTheirMeaning formats CREATE TABLE statements
// that use dialect column attributes and table constraints, and checks that
// the formatter keeps every attribute (nothing is dropped), writes the dialect
// spelling the source used, and that the output parses again and formats to
// itself.
func TestFormat_ColumnDefinitionsKeepTheirMeaning(t *testing.T) {
	cases := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    []string // substrings the formatted text must contain
		notWant []string
	}{
		{"sqlite autoincrement", keywords.DialectSQLite,
			"CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)",
			[]string{"id INTEGER PRIMARY KEY AUTOINCREMENT"}, []string{"AUTO_INCREMENT"}},
		{"mysql auto_increment", keywords.DialectMySQL,
			"CREATE TABLE t (id INT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'pk', PRIMARY KEY (id))",
			[]string{"id INT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'pk'", "PRIMARY KEY (id)"}, []string{"AUTOINCREMENT"}},
		{"mysql attributes", keywords.DialectMySQL,
			"CREATE TABLE t (s VARCHAR(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin, ts DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, g INT AS (1 + 1) STORED, v INT INVISIBLE)",
			[]string{"CHARACTER SET utf8mb4 COLLATE utf8mb4_bin", "ON UPDATE CURRENT_TIMESTAMP", "AS (1 + 1) STORED", "INVISIBLE"}, nil},
		{"mysql indexes", keywords.DialectMySQL,
			"CREATE TABLE t (id INT, a TEXT, UNIQUE KEY uq (id), FULLTEXT KEY ft (a), KEY k (id), KEY f ((id + 1)))",
			[]string{"UNIQUE KEY uq (id)", "FULLTEXT KEY ft (a)", "KEY k (id)", "KEY f ((id + 1))"}, nil},
		{"postgres identity and types", keywords.DialectPostgreSQL,
			"CREATE TABLE t (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, tags text[], at timestamp with time zone, d double precision)",
			[]string{"GENERATED ALWAYS AS IDENTITY PRIMARY KEY", "tags text[]", "at timestamp with time zone", "d double precision"}, nil},
		{"postgres deferrable", keywords.DialectPostgreSQL,
			"CREATE TABLE t (a int REFERENCES u (id) DEFERRABLE INITIALLY DEFERRED, b int, UNIQUE (b) DEFERRABLE, LIKE v INCLUDING ALL)",
			[]string{"DEFERRABLE INITIALLY DEFERRED", "UNIQUE (b) DEFERRABLE", "LIKE v INCLUDING ALL"}, nil},
		{"sqlserver identity", keywords.DialectSQLServer,
			"CREATE TABLE t (id INT IDENTITY(1, 1) NOT NULL, CONSTRAINT pk PRIMARY KEY CLUSTERED (id))",
			[]string{"IDENTITY(1, 1) NOT NULL", "CONSTRAINT pk PRIMARY KEY CLUSTERED (id)"}, nil},
		{"snowflake autoincrement", keywords.DialectSnowflake,
			"CREATE TABLE t (id NUMBER AUTOINCREMENT START 1 INCREMENT 1)",
			[]string{"AUTOINCREMENT START 1 INCREMENT 1"}, []string{"AUTO_INCREMENT"}},
		{"sqlite typeless", keywords.DialectSQLite,
			"CREATE TABLE t (a, b NOT NULL, c COLLATE NOCASE)",
			[]string{"a,", "b NOT NULL", "c COLLATE NOCASE"}, nil},
		{"clickhouse clauses", keywords.DialectClickHouse,
			"CREATE TABLE t (a UInt8, b UInt8 MATERIALIZED a + 1, c UInt8 DEFAULT 1 CODEC(ZSTD), INDEX i a TYPE minmax GRANULARITY 1, CONSTRAINT k CHECK a > 0) ENGINE = MergeTree ORDER BY a",
			[]string{"b UInt8 MATERIALIZED a + 1", "c UInt8 DEFAULT 1 CODEC(ZSTD)", "INDEX i a TYPE minmax GRANULARITY 1", "CONSTRAINT k CHECK (a > 0)"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			defer ast.ReleaseAST(tree)
			out := gosqlx.FormatAST(tree)
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("formatted output lacks %q:\n%s", w, out)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(out, w) {
					t.Errorf("formatted output contains %q:\n%s", w, out)
				}
			}
			tree2, err := gosqlx.ParseWithDialect(out, tc.dialect)
			if err != nil {
				t.Fatalf("formatted output does not parse: %v\n%s", err, out)
			}
			defer ast.ReleaseAST(tree2)
			if again := gosqlx.FormatAST(tree2); again != out {
				t.Errorf("formatting is not idempotent:\n%s\n%s", out, again)
			}
		})
	}
}
