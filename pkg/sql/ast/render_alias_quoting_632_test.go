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
	"testing"

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

// aliasRenderCases lists every alias and statement-target name position that
// SQL() and the formatter used to write verbatim (#632);
// pkg/formatter/render_alias_quoting_632_test.go mirrors this list for FormatAST.
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

// TestHostileAliases_SQL_ReparseAsOneStatement_PR632 checks that SQL() quotes
// aliases and statement target names whose text is not a plain identifier,
// so the output re-parses to exactly one statement carrying the same name.
func TestHostileAliases_SQL_ReparseAsOneStatement_PR632(t *testing.T) {
	for _, tc := range aliasRenderCases() {
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
				rendered := tree.SQL()
				ast.ReleaseAST(tree)

				tree2, err := gosqlx.ParseWithDialect(rendered, d)
				if err != nil {
					t.Errorf("[%s] re-parse of %q: %v", d, rendered, err)
					continue
				}
				if n := len(tree2.Statements); n != 1 {
					t.Errorf("[%s] SQL() output re-parses to %d statements, want 1: %s", d, n, rendered)
				} else if got := tc.Extract(tree2.Statements[0]); got != tc.Want {
					t.Errorf("[%s] name after round trip = %q, want %q (SQL: %s)", d, got, tc.Want, rendered)
				}
				ast.ReleaseAST(tree2)
			}
			if parsed == 0 {
				t.Fatalf("no dialect parsed %q", tc.Input)
			}
		})
	}
}

// TestAliasRendering_BenignAndReserved_PR632 pins the exact SQL() output for
// plain aliases (unchanged, bare), case-only quoted aliases (bare, matching
// the reference per F3) and reserved-word aliases (quoted, matching the
// quoted reference), and checks that each output re-parses to one statement
// that renders identically.
func TestAliasRendering_BenignAndReserved_PR632(t *testing.T) {
	cases := []struct {
		dialect keywords.SQLDialect
		input   string
		want    string
	}{
		{"", `SELECT amount AS total FROM t`, `SELECT amount AS total FROM t`},
		{"", `SELECT * FROM t AS u`, `SELECT * FROM t u`},
		{"", `SELECT * FROM t u JOIN v AS w ON u.id = w.id`, `SELECT * FROM t u INNER JOIN v w ON u.id = w.id`},
		{"", `SELECT amount AS "Total" FROM t ORDER BY "Total"`, `SELECT amount AS Total FROM t ORDER BY Total`},
		{"", `SELECT amount AS "select" FROM t ORDER BY "select"`, `SELECT amount AS "select" FROM t ORDER BY "select"`},
		{"", `SELECT * FROM t AS "from"`, `SELECT * FROM t "from"`},
		{"", `SELECT SUM(x) OVER w FROM t WINDOW w AS (ORDER BY x)`, `SELECT SUM(x) OVER w FROM t WINDOW w AS (ORDER BY x)`},
		{"", `SELECT SUM(x) OVER (PARTITION BY y) FROM t`, `SELECT SUM(x) OVER (PARTITION BY y) FROM t`},
		{"", `SELECT "from".a FROM t AS "from"`, `SELECT "from".a FROM t "from"`},
		{"", `UPDATE t SET a = 1`, `UPDATE t SET a = 1`},
		{"", `DELETE FROM s.t WHERE a = 1`, `DELETE FROM s.t WHERE a = 1`},
		{"", `INSERT INTO s.t (a) VALUES (1)`, `INSERT INTO s.t (a) VALUES (1)`},
		{"", `MERGE INTO t AS tgt USING s AS src ON tgt.id = src.id WHEN MATCHED THEN DELETE`,
			`MERGE INTO t tgt USING s src ON tgt.id = src.id WHEN MATCHED THEN DELETE`},
		{keywords.DialectSQLServer, `INSERT INTO #tmp (a) VALUES (1)`, `INSERT INTO #tmp (a) VALUES (1)`},
		{keywords.DialectSQLServer, `SELECT * FROM #tmp AS t`, `SELECT * FROM #tmp t`},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.input, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.input, err)
			}
			defer ast.ReleaseAST(tree)
			got := tree.SQL()
			if got != tc.want {
				t.Errorf("SQL() mismatch\n got: %s\nwant: %s", got, tc.want)
			}
			tree2, err := gosqlx.ParseWithDialect(got, tc.dialect)
			if err != nil {
				t.Fatalf("re-parse of %q: %v", got, err)
			}
			defer ast.ReleaseAST(tree2)
			if n := len(tree2.Statements); n != 1 {
				t.Fatalf("SQL() output re-parses to %d statements, want 1: %s", n, got)
			}
			if again := tree2.SQL(); again != got {
				t.Errorf("SQL() not stable across a round trip\n first: %s\nsecond: %s", got, again)
			}
		})
	}
}

// TestHandBuiltHostileAliases_NoStatementBreak_PR632 checks hand-built ASTs:
// alias and target-name strings that never came from the parser must not
// escape their position either.
func TestHandBuiltHostileAliases_NoStatementBreak_PR632(t *testing.T) {
	const evil = `x; DROP TABLE y; --`
	nodes := []interface{ SQL() string }{
		&ast.AliasedExpression{Expr: &ast.Identifier{Name: "a"}, Alias: evil},
		&ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "a"}},
			From:    []ast.TableReference{{Name: "t", Alias: evil}},
			Windows: []ast.WindowSpec{{Name: evil}},
		},
		&ast.UpdateStatement{TableName: evil, Alias: evil,
			Assignments: []ast.UpdateExpression{{Column: &ast.Identifier{Name: "a"}, Value: &ast.LiteralValue{Value: "1", Type: "INTEGER"}}}},
		&ast.DeleteStatement{TableName: evil, Alias: evil},
		&ast.InsertStatement{TableName: evil, Values: [][]ast.Expression{{&ast.LiteralValue{Value: "1", Type: "INTEGER"}}}},
		&ast.MergeStatement{TargetTable: ast.TableReference{Name: "t"}, TargetAlias: evil,
			SourceTable: ast.TableReference{Name: "s"}, SourceAlias: evil,
			OnCondition: &ast.LiteralValue{Value: "TRUE", Type: "BOOLEAN"}},
	}
	for _, n := range nodes {
		assertNoStatementBreak(t, n.SQL())
	}
}
