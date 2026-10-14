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

// aliasRenderDialects are the dialects the alias-quoting regression tests
// parse and re-parse in; "" is the default dialect.
var aliasRenderDialects = []keywords.SQLDialect{
	"",
	keywords.DialectPostgreSQL,
	keywords.DialectMySQL,
	keywords.DialectSQLServer,
	keywords.DialectOracle,
	keywords.DialectSnowflake,
	keywords.DialectClickHouse,
	keywords.DialectSQLite,
}

// aliasRenderCase is one hostile alias or name position: Input stores Want
// in the position Extract reads back.
type aliasRenderCase struct {
	Name    string
	Input   string
	Want    string
	Extract func(ast.Statement) string
}

func firstSelect(s ast.Statement) *ast.SelectStatement {
	sel, _ := s.(*ast.SelectStatement)
	return sel
}

// aliasRenderCases mirrors the list in
// pkg/sql/ast/render_alias_quoting_632_test.go: every alias and
// statement-target name position the formatter used to write verbatim (#632).
func aliasRenderCases() []aliasRenderCase {
	const hostile = `a; DROP TABLE x; --`
	const hostileQ = `"a; DROP TABLE x; --"`
	return []aliasRenderCase{
		{"select_item_alias", `SELECT 1 AS ` + hostileQ + ` FROM t`, hostile, func(s ast.Statement) string {
			if sel := firstSelect(s); sel != nil && len(sel.Columns) > 0 {
				if a, ok := sel.Columns[0].(*ast.AliasedExpression); ok {
					return a.Alias
				}
			}
			return ""
		}},
		{"select_item_alias_backtick", "SELECT 1 AS `" + hostile + "` FROM t", hostile, func(s ast.Statement) string {
			if sel := firstSelect(s); sel != nil && len(sel.Columns) > 0 {
				if a, ok := sel.Columns[0].(*ast.AliasedExpression); ok {
					return a.Alias
				}
			}
			return ""
		}},
		{"select_item_alias_embedded_quote", `SELECT 1 AS "a""; DROP TABLE x; --" FROM t`, `a"; DROP TABLE x; --`, func(s ast.Statement) string {
			if sel := firstSelect(s); sel != nil && len(sel.Columns) > 0 {
				if a, ok := sel.Columns[0].(*ast.AliasedExpression); ok {
					return a.Alias
				}
			}
			return ""
		}},
		{"table_alias", `SELECT * FROM t AS ` + hostileQ, hostile, func(s ast.Statement) string {
			if sel := firstSelect(s); sel != nil && len(sel.From) > 0 {
				return sel.From[0].Alias
			}
			return ""
		}},
		{"derived_table_alias", `SELECT * FROM (SELECT 1) AS ` + hostileQ, hostile, func(s ast.Statement) string {
			if sel := firstSelect(s); sel != nil && len(sel.From) > 0 {
				return sel.From[0].Alias
			}
			return ""
		}},
		{"join_alias", `SELECT * FROM a JOIN b AS ` + hostileQ + ` ON 1 = 1`, hostile, func(s ast.Statement) string {
			if sel := firstSelect(s); sel != nil && len(sel.Joins) > 0 {
				return sel.Joins[0].Right.Alias
			}
			return ""
		}},
		{"window_name", `SELECT SUM(x) OVER ` + hostileQ + ` FROM t WINDOW ` + hostileQ + ` AS (ORDER BY x)`, hostile, func(s ast.Statement) string {
			if sel := firstSelect(s); sel != nil && len(sel.Windows) > 0 {
				return sel.Windows[0].Name
			}
			return ""
		}},
		{"over_window_name", `SELECT SUM(x) OVER ` + hostileQ + ` FROM t WINDOW ` + hostileQ + ` AS (ORDER BY x)`, hostile, func(s ast.Statement) string {
			if sel := firstSelect(s); sel != nil && len(sel.Columns) > 0 {
				if f, ok := sel.Columns[0].(*ast.FunctionCall); ok && f.Over != nil {
					return f.Over.Name
				}
			}
			return ""
		}},
		{"array_join_alias", `SELECT a FROM t ARRAY JOIN arr AS ` + hostileQ, hostile, func(s ast.Statement) string {
			if sel := firstSelect(s); sel != nil && sel.ArrayJoin != nil && len(sel.ArrayJoin.Elements) > 0 {
				return sel.ArrayJoin.Elements[0].Alias
			}
			return ""
		}},
		{"pivot_alias", `SELECT * FROM t PIVOT (SUM(s) FOR r IN ('a')) AS ` + hostileQ, hostile, func(s ast.Statement) string {
			if sel := firstSelect(s); sel != nil && len(sel.From) > 0 {
				return sel.From[0].Alias
			}
			return ""
		}},
		{"update_table", `UPDATE ` + hostileQ + ` SET a = 1`, hostile, func(s ast.Statement) string {
			if u, ok := s.(*ast.UpdateStatement); ok {
				return u.TableName
			}
			return ""
		}},
		{"delete_table", `DELETE FROM ` + hostileQ + ` WHERE a = 1`, hostile, func(s ast.Statement) string {
			if d, ok := s.(*ast.DeleteStatement); ok {
				return d.TableName
			}
			return ""
		}},
		{"insert_table", `INSERT INTO ` + hostileQ + ` (a) VALUES (1)`, hostile, func(s ast.Statement) string {
			if i, ok := s.(*ast.InsertStatement); ok {
				return i.TableName
			}
			return ""
		}},
		{"merge_target_alias", `MERGE INTO t AS ` + hostileQ + ` USING s ON 1 = 1 WHEN MATCHED THEN DELETE`, hostile, func(s ast.Statement) string {
			if m, ok := s.(*ast.MergeStatement); ok {
				return m.TargetAlias
			}
			return ""
		}},
		{"merge_source_alias", `MERGE INTO t USING s AS ` + hostileQ + ` ON 1 = 1 WHEN MATCHED THEN DELETE`, hostile, func(s ast.Statement) string {
			if m, ok := s.(*ast.MergeStatement); ok {
				return m.SourceAlias
			}
			return ""
		}},
	}
}

// TestHostileAliases_FormatAST_ReparseAsOneStatement_PR632 checks that
// FormatAST, in compact and readable styles, quotes aliases and statement
// target names that are not plain identifiers, so the output re-parses to
// exactly one statement carrying the same name.
func TestHostileAliases_FormatAST_ReparseAsOneStatement_PR632(t *testing.T) {
	for _, tc := range aliasRenderCases() {
		if tc.Name == "array_join_alias" {
			continue // FormatAST does not render ARRAY JOIN yet
		}
		t.Run(tc.Name, func(t *testing.T) {
			parsed := 0
			for _, d := range aliasRenderDialects {
				tree, err := gosqlx.ParseWithDialect(tc.Input, d)
				if err != nil {
					continue
				}
				if len(tree.Statements) != 1 || tc.Extract(tree.Statements[0]) != tc.Want {
					ast.ReleaseAST(tree)
					continue // this dialect does not store the name in the tested position
				}
				parsed++
				for _, opts := range []ast.FormatOptions{ast.CompactStyle(), ast.ReadableStyle()} {
					rendered := formatter.FormatAST(tree, opts)
					tree2, err := gosqlx.ParseWithDialect(rendered, d)
					if err != nil {
						t.Errorf("[%s] re-parse of %q: %v", d, rendered, err)
						continue
					}
					if n := len(tree2.Statements); n != 1 {
						t.Errorf("[%s] FormatAST output re-parses to %d statements, want 1: %s", d, n, rendered)
					} else if got := tc.Extract(tree2.Statements[0]); got != tc.Want {
						t.Errorf("[%s] name after round trip = %q, want %q (SQL: %s)", d, got, tc.Want, rendered)
					}
					ast.ReleaseAST(tree2)
				}
				ast.ReleaseAST(tree)
			}
			if parsed == 0 {
				t.Fatalf("no dialect parsed %q", tc.Input)
			}
		})
	}
}

// TestFormat_AliasQuoting_PR632 pins gosqlx.Format output: hostile aliases
// are quoted, plain aliases are unchanged, case-only quoted aliases render
// bare like their references (F3) and reserved-word aliases stay quoted like
// their references.
func TestFormat_AliasQuoting_PR632(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{`SELECT 1 AS "a; DROP TABLE x; --" FROM t`, "SELECT 1 AS \"a; DROP TABLE x; --\"\nFROM t"},
		{`SELECT * FROM t AS "u; DROP TABLE x; --"`, "SELECT *\nFROM t \"u; DROP TABLE x; --\""},
		{`SELECT amount AS total FROM t`, "SELECT amount AS total\nFROM t"},
		{`SELECT * FROM t AS u`, "SELECT *\nFROM t u"},
		{`SELECT amount AS "Total" FROM t ORDER BY "Total"`, "SELECT amount AS Total\nFROM t\nORDER BY Total"},
		{`SELECT amount AS "select" FROM t ORDER BY "select"`, "SELECT amount AS \"select\"\nFROM t\nORDER BY \"select\""},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := gosqlx.Format(tc.input, gosqlx.DefaultFormatOptions())
			if err != nil {
				t.Fatalf("Format(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("Format mismatch\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}
