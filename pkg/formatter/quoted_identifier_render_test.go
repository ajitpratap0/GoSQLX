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

// TestQuotedIdentifier_FormatAST_Issue611 verifies that FormatAST keeps the
// quotes on reserved-word, spaced and case-sensitive identifiers in CTE
// names and column lists, view column lists, select lists and table names,
// so compact and readable output re-parse to the same SQL() in every dialect.
func TestQuotedIdentifier_FormatAST_Issue611(t *testing.T) {
	cases := []struct {
		name     string
		sql      string
		compact  string // "" means identical to sql
		readable string // "" skips the exact readable assertion
	}{
		{"cte_column_reserved", `WITH c ("select") AS (SELECT 1) SELECT * FROM c`, "",
			"WITH c (\"select\") AS (SELECT 1)\nSELECT *\nFROM c"},
		{"cte_column_space", `WITH c ("a b") AS (SELECT 1) SELECT * FROM c`, "",
			"WITH c (\"a b\") AS (SELECT 1)\nSELECT *\nFROM c"},
		{"view_column_reserved", `CREATE VIEW v ("select") AS SELECT 1`, "",
			"CREATE VIEW v (\"select\") AS\nSELECT 1"},
		{"select_reserved", `SELECT "select" FROM t`, "",
			"SELECT \"select\"\nFROM t"},
		{"select_space_case_table_space", `SELECT "a b", "Mixed" FROM "my table"`, "",
			"SELECT \"a b\", \"Mixed\"\nFROM \"my table\""},
		{"mview_column_reserved", `CREATE MATERIALIZED VIEW mv ("select") AS SELECT 1`, "",
			"CREATE MATERIALIZED VIEW mv (\"select\") AS\nSELECT 1"},
		{"cte_name_reserved", `WITH "select" AS (SELECT 1) SELECT * FROM "select"`, "",
			"WITH \"select\" AS (SELECT 1)\nSELECT *\nFROM \"select\""},
		{"join_reserved_table", `SELECT * FROM a JOIN "order" o ON a.id = o.id`,
			`SELECT * FROM a INNER JOIN "order" o ON a.id = o.id`,
			"SELECT *\nFROM a\nINNER JOIN \"order\" o ON a.id = o.id"},
	}
	dialects := []keywords.SQLDialect{
		keywords.DialectGeneric,
		keywords.DialectPostgreSQL,
		keywords.DialectMySQL,
		keywords.DialectMariaDB,
		keywords.DialectSQLServer,
		keywords.DialectOracle,
		keywords.DialectSQLite,
		keywords.DialectSnowflake,
		keywords.DialectClickHouse,
	}
	// Readable layout without the trailing semicolon: nested-statement
	// semicolons are a separate formatter issue (#602).
	readableOpts := ast.ReadableStyle()
	readableOpts.AddSemicolon = false

	for _, tc := range cases {
		for _, d := range dialects {
			t.Run(tc.name+"/"+string(d), func(t *testing.T) {
				tree, err := gosqlx.ParseWithDialect(tc.sql, d)
				if err != nil {
					t.Fatalf("parse %q: %v", tc.sql, err)
				}
				defer ast.ReleaseAST(tree)
				want := tree.SQL()

				compactWant := tc.compact
				if compactWant == "" {
					compactWant = tc.sql
				}
				compact := formatter.FormatAST(tree, ast.CompactStyle())
				if compact != compactWant {
					t.Errorf("FormatAST(compact) mismatch\n got: %s\nwant: %s", compact, compactWant)
				}

				readable := formatter.FormatAST(tree, readableOpts)
				if tc.readable != "" && readable != tc.readable {
					t.Errorf("FormatAST(readable) mismatch\n got: %q\nwant: %q", readable, tc.readable)
				}

				for label, out := range map[string]string{"compact": compact, "readable": readable} {
					tree2, err := gosqlx.ParseWithDialect(out, d)
					if err != nil {
						t.Errorf("%s output %q does not re-parse: %v", label, out, err)
						continue
					}
					if got := tree2.SQL(); got != want {
						t.Errorf("%s re-parse SQL() mismatch\n got: %s\nwant: %s", label, got, want)
					}
					ast.ReleaseAST(tree2)
				}
			})
		}
	}
}
