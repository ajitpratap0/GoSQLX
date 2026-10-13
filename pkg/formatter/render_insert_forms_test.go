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
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// TestRenderInsertForms checks that FormatAST renders the #610 INSERT and
// UPDATE forms and that its output re-parses to the same statement.
func TestRenderInsertForms(t *testing.T) {
	tests := []struct {
		name     string
		dialect  keywords.SQLDialect
		sql      string
		contains []string
		excludes []string
		// compactOnly skips the readable style: it renders a nested query
		// source with its own ";" (#602), so RETURNING after it would not
		// re-parse until that is fixed.
		compactOnly bool
	}{
		{
			name: "default values", dialect: keywords.DialectPostgreSQL,
			sql:      "INSERT INTO t DEFAULT VALUES RETURNING id",
			contains: []string{"DEFAULT VALUES", "RETURNING id"},
		},
		{
			name: "default values sqlserver", dialect: keywords.DialectSQLServer,
			sql:      "INSERT INTO t DEFAULT VALUES",
			contains: []string{"DEFAULT VALUES"},
		},
		{
			name: "default values sqlite", dialect: keywords.DialectSQLite,
			sql:      "INSERT INTO t DEFAULT VALUES",
			contains: []string{"DEFAULT VALUES"},
		},
		{
			name: "mysql set", dialect: keywords.DialectMySQL,
			sql:      "INSERT INTO t SET a = 1, b = 2",
			contains: []string{"SET a = 1, b = 2"},
			excludes: []string{"(a, b)", "VALUES"},
		},
		{
			name: "mariadb set", dialect: keywords.DialectMariaDB,
			sql:      "INSERT INTO t SET a = 1, b = 'x'",
			contains: []string{"SET a = 1, b = 'x'"},
			excludes: []string{"(a, b)", "VALUES"},
		},
		{
			name: "returning after select source", dialect: keywords.DialectPostgreSQL,
			sql:         "INSERT INTO t SELECT * FROM s RETURNING id",
			contains:    []string{"RETURNING id"},
			compactOnly: true,
		},
		{
			name: "parenthesized source", dialect: keywords.DialectGeneric,
			sql:         "INSERT INTO t (SELECT * FROM s)",
			contains:    []string{"INSERT INTO t SELECT * FROM s"},
			excludes:    []string{"(SELECT"},
			compactOnly: true,
		},
		{
			name: "update from", dialect: keywords.DialectPostgreSQL,
			sql:      "UPDATE t SET a = s.b FROM s WHERE t.id = s.id",
			contains: []string{"FROM s"},
		},
	}

	styles := []struct {
		name string
		opts ast.FormatOptions
	}{
		{"compact", ast.CompactStyle()},
		{"readable", ast.ReadableStyle()},
	}

	for _, tt := range tests {
		for _, st := range styles {
			if tt.compactOnly && st.name != "compact" {
				continue
			}
			t.Run(tt.name+"/"+st.name, func(t *testing.T) {
				tree, err := parser.ParseWithDialect(tt.sql, tt.dialect)
				if err != nil {
					t.Fatalf("ParseWithDialect(%q, %q): %v", tt.sql, tt.dialect, err)
				}
				defer ast.ReleaseAST(tree)
				want := tree.SQL()

				out := formatter.FormatAST(tree, st.opts)
				flat := strings.Join(strings.Fields(out), " ")
				for _, c := range tt.contains {
					if !strings.Contains(flat, c) {
						t.Errorf("FormatAST = %q, want it to contain %q", out, c)
					}
				}
				for _, e := range tt.excludes {
					if strings.Contains(flat, e) {
						t.Errorf("FormatAST = %q, must not contain %q", out, e)
					}
				}

				tree2, err := parser.ParseWithDialect(out, tt.dialect)
				if err != nil {
					t.Fatalf("re-parse of FormatAST output %q: %v", out, err)
				}
				defer ast.ReleaseAST(tree2)
				if got := tree2.SQL(); got != want {
					t.Fatalf("round-trip SQL() = %q, want %q", got, want)
				}
			})
		}
	}
}
