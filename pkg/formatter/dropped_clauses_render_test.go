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

// TestRender_Issue600_KeepsClauses locks in that tree.SQL() and pkg/formatter
// keep IGNORE/RESPECT NULLS, named function arguments, MySQL ON DUPLICATE KEY
// UPDATE, SQL Server INSERT ... OUTPUT and ClickHouse SELECT ... SETTINGS
// (issue #600). Each case must round-trip verbatim through SQL(), the compact
// formatter, and the readable formatter, and re-parse with the same dialect.
func TestRender_Issue600_KeepsClauses(t *testing.T) {
	cases := []struct {
		name        string
		dialect     keywords.SQLDialect // "" means gosqlx.Parse
		sql         string
		mustContain string // substring the readable output must contain
	}{
		{"ignore_nulls", "", "SELECT FIRST_VALUE(x) IGNORE NULLS OVER (ORDER BY y) FROM t", "IGNORE NULLS"},
		{"respect_nulls", "", "SELECT LAG(x, 1) RESPECT NULLS OVER (PARTITION BY g ORDER BY y) FROM t", "RESPECT NULLS"},
		{"ignore_nulls_snowflake", keywords.DialectSnowflake, "SELECT FIRST_VALUE(x) IGNORE NULLS OVER (ORDER BY y) FROM t", "IGNORE NULLS"},
		{"named_arg", "", "SELECT f(x => 1) FROM t", "x => 1"},
		{"named_args_postgres", keywords.DialectPostgreSQL, "SELECT f(x => 1, y => 'a') FROM t", "y => 'a'"},
		{"named_arg_nested", "", "SELECT f(x => g(y => 2)) FROM t", "x => g(y => 2)"},
		{"on_duplicate_key", keywords.DialectMySQL, "INSERT INTO t (a) VALUES (1) ON DUPLICATE KEY UPDATE a = 2", "ON DUPLICATE KEY UPDATE a = 2"},
		{"on_duplicate_key_multi", keywords.DialectMySQL, "INSERT INTO t (a, b) VALUES (1, 2) ON DUPLICATE KEY UPDATE a = VALUES(a), b = b + 1", "ON DUPLICATE KEY UPDATE a = VALUES(a), b = b + 1"},
		{"on_duplicate_key_select", keywords.DialectMySQL, "INSERT INTO t (a) SELECT a FROM u ON DUPLICATE KEY UPDATE a = 2", "ON DUPLICATE KEY UPDATE a = 2"},
		{"output", keywords.DialectSQLServer, "INSERT INTO t (a) OUTPUT INSERTED.id VALUES (1)", "\nOUTPUT INSERTED.id"},
		{"output_multi", keywords.DialectSQLServer, "INSERT INTO t (a) OUTPUT INSERTED.id, INSERTED.a VALUES (1)", "\nOUTPUT INSERTED.id, INSERTED.a"},
		{"output_star_select", keywords.DialectSQLServer, "INSERT INTO t (a) OUTPUT INSERTED.* SELECT a FROM u", "\nOUTPUT INSERTED.*"},
		{"settings", keywords.DialectClickHouse, "SELECT a FROM t SETTINGS max_threads = 4", "\nSETTINGS max_threads = 4"},
		{"settings_multi", keywords.DialectClickHouse, "SELECT * FROM events WHERE id > 100 SETTINGS max_threads = 4, distributed_aggregation_memory_efficient = 1", "\nSETTINGS max_threads = 4, distributed_aggregation_memory_efficient = 1"},
		{"settings_after_limit", keywords.DialectClickHouse, "SELECT a FROM t ORDER BY a LIMIT 10 SETTINGS max_threads = 4, join_algorithm = 'hash'", "\nSETTINGS max_threads = 4, join_algorithm = 'hash'"},
		{"settings_keyword_names", keywords.DialectClickHouse, "SELECT a FROM t SETTINGS limit = 10, final = 1", "\nSETTINGS limit = 10, final = 1"},
		{"settings_union", keywords.DialectClickHouse, "SELECT a FROM t UNION ALL SELECT b FROM u SETTINGS max_threads = 4", "\nSETTINGS max_threads = 4"},
		{"on_conflict_control", keywords.DialectPostgreSQL, "INSERT INTO t (a) VALUES (1) ON CONFLICT (a) DO UPDATE SET a = 2 RETURNING a", "RETURNING a"},
	}

	parse := func(t *testing.T, d keywords.SQLDialect, sql string) *ast.AST {
		t.Helper()
		var (
			tree *ast.AST
			err  error
		)
		if d == "" {
			tree, err = gosqlx.Parse(sql)
		} else {
			tree, err = gosqlx.ParseWithDialect(sql, d)
		}
		if err != nil {
			t.Fatalf("parse(%q, %q): %v", d, sql, err)
		}
		return tree
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tree := parse(t, tc.dialect, tc.sql)

			if got := tree.SQL(); got != tc.sql {
				t.Errorf("SQL() mismatch\n got: %s\nwant: %s", got, tc.sql)
			}

			compact := formatter.FormatAST(tree, ast.CompactStyle())
			if compact != tc.sql {
				t.Errorf("compact FormatAST mismatch\n got: %s\nwant: %s", compact, tc.sql)
			}

			readable := formatter.FormatAST(tree, ast.ReadableStyle())
			if !strings.Contains(readable, tc.mustContain) {
				t.Errorf("readable FormatAST lost clause %q:\n%s", tc.mustContain, readable)
			}

			for label, out := range map[string]string{"compact": compact, "readable": readable} {
				re := parse(t, tc.dialect, out)
				if got := re.SQL(); got != tc.sql {
					t.Errorf("%s output did not round-trip\n out: %s\n got: %s\nwant: %s", label, out, got, tc.sql)
				}
			}
		})
	}
}

// TestRender_Issue600_KeywordCase verifies that the clause keywords restored
// for #600 (SETTINGS, OUTPUT, ON DUPLICATE KEY UPDATE) honour
// FormatOptions.KeywordCase like every other clause keyword.
func TestRender_Issue600_KeywordCase(t *testing.T) {
	cases := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		lower   string
	}{
		{"settings", keywords.DialectClickHouse, "SELECT a FROM t SETTINGS max_threads = 4", "settings max_threads = 4"},
		{"output", keywords.DialectSQLServer, "INSERT INTO t (a) OUTPUT INSERTED.id VALUES (1)", "output INSERTED.id"},
		{"on_duplicate_key", keywords.DialectMySQL, "INSERT INTO t (a) VALUES (1) ON DUPLICATE KEY UPDATE a = 2", "on duplicate key update a = 2"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.sql, err)
			}
			for label, style := range map[string]ast.FormatOptions{
				"compact":  ast.CompactStyle(),
				"readable": ast.ReadableStyle(),
			} {
				style.KeywordCase = ast.KeywordLower
				out := formatter.FormatAST(tree, style)
				if !strings.Contains(out, tc.lower) {
					t.Errorf("%s lowercase output missing %q:\n%s", label, tc.lower, out)
				}
				if _, err := gosqlx.ParseWithDialect(out, tc.dialect); err != nil {
					t.Errorf("%s lowercase output does not re-parse: %v\n%s", label, err, out)
				}
			}
		})
	}
}
