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

package parser

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestParser_MaintenanceBoundaries(t *testing.T) {
	pg, rs, lite := keywords.DialectPostgreSQL, keywords.DialectRedshift, keywords.DialectSQLite
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{pg, "VACUUM t junk words here"}, {pg, "VACUUM (VERBOSE) t junk"},
		{pg, "VACUUM FULL t garbage"}, {pg, "ANALYZE t foo bar"},
		{pg, "ANALYZE VERBOSE t (a) extra"}, {pg, "LISTEN chan extra stuff"},
		{pg, "LISTEN a, b"}, {pg, "UNLISTEN chan junk"}, {pg, "NOTIFY chan, 'p' junk"},
		{pg, "VACUUM t junk; SELECT 1"}, {rs, "VACUUM FULL t TO 75 PERCENT junk"},
		{lite, "VACUUM junk more"}, {lite, "VACUUM main INTO 'f.db' junk"},
		{lite, "ANALYZE main.t junk"}, {lite, "ANALYZE main.t.extra"}, {"", "VACUUM t junk words"},
		{"", "VACUUM (VERBOSE) t BOOST"}, {"", "VACUUM FULL t INTO 'f.db'"},
	}
	for _, tc := range tests {
		t.Run(string(tc.dialect)+"/"+tc.sql, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, tc.dialect)
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
			if err == nil || !strings.Contains(err.Error(), "semicolon or end of statement") {
				t.Fatalf("got %v, want trailing-token error", err)
			}
		})
	}
}

func TestParser_MaintenanceForms(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		forms   []string
	}{
		{keywords.DialectPostgreSQL, []string{
			"VACUUM", "VACUUM FULL t", "VACUUM FULL FREEZE VERBOSE ANALYZE t", "VACUUM ANALYZE t",
			"VACUUM (VERBOSE, ANALYZE) users", "VACUUM (PARALLEL 4, INDEX_CLEANUP off) s.t (a, b), u",
			"VACUUM ONLY t", "VACUUM t, u", "VACUUM t (a, b)",
			"ANALYZE", "ANALYZE users", "ANALYZE VERBOSE t (a)", "ANALYZE (SKIP_LOCKED) t",
			"LISTEN channel", `LISTEN "My Chan"`, "UNLISTEN *", "UNLISTEN c", "NOTIFY channel", "NOTIFY channel, 'hello'",
			`NOTIFY channel, E'hello'`, "NOTIFY channel, $$hello$$", "VACUUM t; SELECT 1", "LISTEN c\nCOMMIT",
		}},
		{keywords.DialectRedshift, []string{
			"VACUUM", "VACUUM FULL t", "VACUUM SORT ONLY t", "VACUUM DELETE ONLY t TO 90 PERCENT",
			"VACUUM REINDEX t", "VACUUM RECLUSTER t", "VACUUM t TO 75 PERCENT BOOST",
			"ANALYZE", "ANALYZE t PREDICATE COLUMNS", "ANALYZE VERBOSE t (a, b)",
			"ANALYZE ALL COLUMNS", "ANALYZE COMPRESSION", "ANALYZE COMPRESSION t COMPROWS 1000",
		}},
		{keywords.DialectSQLite, []string{
			"VACUUM", "VACUUM main", "VACUUM INTO 'backup.db'", "VACUUM main INTO 'f.db'",
			"VACUUM main INTO ?", "VACUUM INTO backup", "ANALYZE", "ANALYZE main", "ANALYZE main.t",
		}},
		{keywords.DialectMySQL, []string{"ANALYZE TABLE t, u", "ANALYZE NO_WRITE_TO_BINLOG TABLE t UPDATE HISTOGRAM ON c WITH 10 BUCKETS"}},
		{keywords.DialectOracle, []string{"ANALYZE TABLE t COMPUTE STATISTICS", "ANALYZE TABLE t DELETE STATISTICS"}},
		{"", []string{"VACUUM (VERBOSE) t", "VACUUM SORT ONLY t", "VACUUM main INTO 'f.db'", "ANALYZE t, u", "ANALYZE COMPRESSION t COMPROWS 1000", "ANALYZE TABLE t", "LISTEN c"}},
	}
	for _, tc := range tests {
		for _, sql := range tc.forms {
			t.Run(string(tc.dialect)+"/"+sql, func(t *testing.T) {
				tree, err := ParseWithDialect(sql, tc.dialect)
				if err != nil {
					t.Fatal(err)
				}
				defer ast.ReleaseAST(tree)
				count := 1
				if strings.Contains(sql, ";") || strings.Contains(sql, "\n") {
					count = 2
				}
				if len(tree.Statements) != count {
					t.Fatalf("got %d statements, want %d", len(tree.Statements), count)
				}
				stmt, ok := tree.Statements[0].(*ast.UtilityStatement)
				if !ok {
					t.Fatalf("got %T, want UtilityStatement", tree.Statements[0])
				}
				if want := strings.Fields(sql)[0]; stmt.Kind != want {
					t.Errorf("Kind = %q, want %q", stmt.Kind, want)
				}
				if stmt.Text == "" {
					t.Error("empty statement text")
				}
			})
		}
	}
}

func TestParser_MaintenanceText(t *testing.T) {
	for _, sql := range []string{`vacuum (VERBOSE) "My Table" (a, b)`, `listen "My Chan"`, `notify c, 'hello'`} {
		t.Run(sql, func(t *testing.T) {
			tree, err := ParseWithDialect(sql+"; SELECT 1", keywords.DialectPostgreSQL)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			stmt, ok := tree.Statements[0].(*ast.UtilityStatement)
			if !ok {
				t.Fatalf("got %T, want UtilityStatement", tree.Statements[0])
			}
			if stmt.Text != sql {
				t.Errorf("Text = %q, want %q", stmt.Text, sql)
			}
		})
	}
}

func TestParser_MaintenanceIncomplete(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectPostgreSQL, "VACUUM (VERBOSE"},
		{keywords.DialectPostgreSQL, "VACUUM t (a"},
		{keywords.DialectPostgreSQL, "VACUUM ONLY"},
		{keywords.DialectPostgreSQL, "ANALYZE t,"},
		{keywords.DialectPostgreSQL, "LISTEN"},
		{keywords.DialectPostgreSQL, "NOTIFY c,"},
		{keywords.DialectPostgreSQL, "NOTIFY c, 1"},
		{keywords.DialectRedshift, "VACUUM SORT"},
		{keywords.DialectRedshift, "VACUUM t TO PERCENT"},
		{keywords.DialectRedshift, "VACUUM t TO 75"},
		{keywords.DialectRedshift, "ANALYZE t PREDICATE"},
		{keywords.DialectRedshift, "ANALYZE COMPRESSION t COMPROWS"},
		{keywords.DialectSQLite, "VACUUM INTO"},
	}
	for _, tc := range tests {
		t.Run(string(tc.dialect)+"/"+tc.sql, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, tc.dialect)
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
			if err == nil || !strings.Contains(err.Error(), "E2002 at line 1, column") {
				t.Fatalf("got %v, want positioned E2002", err)
			}
		})
	}
}
