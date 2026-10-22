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

package parser_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// Regression tests for issue #521: MySQL view definitions (SHOW CREATE VIEW
// output, e.g. sakila.customer_list) failed to parse because
//   - a column reference with three or more parts (`sakila`.`city`.`city`)
//     stopped after the second part ("got PERIOD"), and
//   - a leading parenthesized join group in FROM was always treated as a
//     derived table ("expected SELECT in derived table, got LPAREN").

// issue521Full is the query from the issue, verbatim.
const issue521Full = "SELECT\n" +
	"  `cu`.`customer_id` AS `ID`,\n" +
	"  CONCAT(`cu`.`first_name`, ' ', `cu`.`last_name`) AS `name`,\n" +
	"  `a`.`address` AS `address`,\n" +
	"  `a`.`postal_code` AS `zip code`,\n" +
	"  `a`.`phone` AS `phone`,\n" +
	"  `sakila`.`city`.`city` AS `city`,\n" +
	"  `sakila`.`country`.`country` AS `country`,\n" +
	"  IF(`cu`.`active`, 'active', '') AS `notes`,\n" +
	"  `cu`.`store_id` AS `SID`\n" +
	"FROM (\n" +
	"  (\n" +
	"    (\n" +
	"      `sakila`.`customer` `cu`\n" +
	"      JOIN `sakila`.`address` `a`\n" +
	"        ON (`cu`.`address_id` = `a`.`address_id`)\n" +
	"    )\n" +
	"    JOIN `sakila`.`city`\n" +
	"      ON (`a`.`city_id` = `sakila`.`city`.`city_id`)\n" +
	"  )\n" +
	"  JOIN `sakila`.`country`\n" +
	"    ON (`sakila`.`city`.`country_id` = `sakila`.`country`.`country_id`)\n" +
	");"

const issue521Repro1 = "SELECT\n  `sakila`.`city`.`city` AS `city`\nFROM `sakila`.`city`;"

const issue521Repro2 = "SELECT\n  `cu`.`customer_id` AS `ID`\nFROM (\n  (\n    `sakila`.`customer` `cu`\n" +
	"    JOIN `sakila`.`address` `a`\n      ON (`cu`.`address_id` = `a`.`address_id`)\n  )\n);"

// issue521RoundTrip is issue521Full with the "zip code" alias replaced by
// zip_code. Rendering an alias that contains a space unquoted is a separate,
// pre-existing bug (SQL() emits `AS zip code`), unrelated to #521.
var issue521RoundTrip = strings.Replace(issue521Full, "`zip code`", "`zip_code`", 1)

// issue521FlatFrom is the FROM clause the parenthesized form must flatten to.
const issue521FlatFrom = "FROM sakila.customer cu INNER JOIN sakila.address a ON (cu.address_id = a.address_id) " +
	"INNER JOIN sakila.city ON (a.city_id = sakila.city.city_id) " +
	"INNER JOIN sakila.country ON (sakila.city.country_id = sakila.country.country_id)"

func issue521Select(t *testing.T, tree *ast.AST) *ast.SelectStatement {
	t.Helper()
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
	}
	return sel
}

func issue521AliasedIdent(t *testing.T, e ast.Expression, wantAlias, wantTable, wantName string) {
	t.Helper()
	al, ok := e.(*ast.AliasedExpression)
	if !ok {
		t.Fatalf("expected *ast.AliasedExpression, got %T", e)
	}
	if al.Alias != wantAlias {
		t.Errorf("alias = %q, want %q", al.Alias, wantAlias)
	}
	id, ok := al.Expr.(*ast.Identifier)
	if !ok {
		t.Fatalf("expected *ast.Identifier, got %T", al.Expr)
	}
	if id.Table != wantTable || id.Name != wantName {
		t.Errorf("identifier = Table %q Name %q, want Table %q Name %q", id.Table, id.Name, wantTable, wantName)
	}
}

func TestIssue521_ExactReport(t *testing.T) {
	dialects := []keywords.SQLDialect{keywords.DialectMySQL, keywords.DialectMariaDB}
	for _, d := range dialects {
		t.Run(string(d), func(t *testing.T) {
			t.Run("full query", func(t *testing.T) {
				tree, err := gosqlx.ParseWithDialect(issue521Full, d)
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				sel := issue521Select(t, tree)

				if len(sel.From) != 1 || sel.From[0].Name != "sakila.customer" || sel.From[0].Alias != "cu" {
					t.Fatalf("From = %+v, want single sakila.customer cu", sel.From)
				}
				if len(sel.Joins) != 3 {
					t.Fatalf("Joins len = %d, want 3", len(sel.Joins))
				}
				wantRight := []struct{ name, alias string }{
					{"sakila.address", "a"}, {"sakila.city", ""}, {"sakila.country", ""},
				}
				for i, w := range wantRight {
					j := sel.Joins[i]
					if j.Type != "INNER" {
						t.Errorf("Joins[%d].Type = %q, want INNER", i, j.Type)
					}
					if j.Right.Name != w.name || j.Right.Alias != w.alias {
						t.Errorf("Joins[%d].Right = %q/%q, want %q/%q", i, j.Right.Name, j.Right.Alias, w.name, w.alias)
					}
				}
				if sel.Joins[0].Left.Name != "sakila.customer" {
					t.Errorf("Joins[0].Left.Name = %q", sel.Joins[0].Left.Name)
				}
				if sel.Joins[1].Left.Name != "(sakila.customer_with_1_joins)" {
					t.Errorf("Joins[1].Left.Name = %q", sel.Joins[1].Left.Name)
				}

				if len(sel.Columns) != 9 {
					t.Fatalf("Columns len = %d, want 9", len(sel.Columns))
				}
				issue521AliasedIdent(t, sel.Columns[5], "city", "sakila.city", "city")
				issue521AliasedIdent(t, sel.Columns[6], "country", "sakila.country", "country")

				paren, ok := sel.Joins[1].Condition.(*ast.ParenthesizedExpression)
				if !ok {
					t.Fatalf("Joins[1].Condition = %T, want *ast.ParenthesizedExpression", sel.Joins[1].Condition)
				}
				bin, ok := paren.Expr.(*ast.BinaryExpression)
				if !ok {
					t.Fatalf("paren.Expr = %T, want *ast.BinaryExpression", paren.Expr)
				}
				right, ok := bin.Right.(*ast.Identifier)
				if !ok {
					t.Fatalf("bin.Right = %T, want *ast.Identifier", bin.Right)
				}
				if right.Table != "sakila.city" || right.Name != "city_id" {
					t.Errorf("bin.Right = %q.%q, want sakila.city.city_id", right.Table, right.Name)
				}
			})

			t.Run("minimal repro 1: three-part column", func(t *testing.T) {
				tree, err := gosqlx.ParseWithDialect(issue521Repro1, d)
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				sel := issue521Select(t, tree)
				issue521AliasedIdent(t, sel.Columns[0], "city", "sakila.city", "city")
				if len(sel.From) != 1 || sel.From[0].Name != "sakila.city" {
					t.Errorf("From = %+v, want sakila.city", sel.From)
				}
			})

			t.Run("minimal repro 2: parenthesized join", func(t *testing.T) {
				tree, err := gosqlx.ParseWithDialect(issue521Repro2, d)
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				sel := issue521Select(t, tree)
				if len(sel.From) != 1 || sel.From[0].Name != "sakila.customer" || sel.From[0].Alias != "cu" {
					t.Fatalf("From = %+v, want sakila.customer cu", sel.From)
				}
				if len(sel.Joins) != 1 || sel.Joins[0].Right.Name != "sakila.address" || sel.Joins[0].Right.Alias != "a" {
					t.Fatalf("Joins = %+v, want one join to sakila.address a", sel.Joins)
				}
			})
		})
	}
}

func TestIssue521_ParenthesizedJoinEquivalentToFlat(t *testing.T) {
	pairs := []struct{ name, paren, flat string }{
		{"single table in parens", "SELECT * FROM (t1)", "SELECT * FROM t1"},
		{
			"parenthesized table then join",
			"SELECT * FROM (t1) JOIN t2 ON t1.id = t2.id",
			"SELECT * FROM t1 JOIN t2 ON t1.id = t2.id",
		},
		{
			"left-nested group with where and order by",
			"SELECT * FROM ((a JOIN b ON a.id = b.id) LEFT JOIN c ON c.id = b.id) WHERE a.x = 1 ORDER BY a.id",
			"SELECT * FROM a JOIN b ON a.id = b.id LEFT JOIN c ON c.id = b.id WHERE a.x = 1 ORDER BY a.id",
		},
		{
			"derived table inside group",
			"SELECT * FROM ((SELECT 1 AS x) d JOIN t ON d.x = t.x)",
			"SELECT * FROM (SELECT 1 AS x) d JOIN t ON d.x = t.x",
		},
		{
			"natural join group then cross join",
			"SELECT * FROM (a NATURAL JOIN b) CROSS JOIN c",
			"SELECT * FROM a NATURAL JOIN b CROSS JOIN c",
		},
		{
			"deeply nested",
			"SELECT * FROM (((a JOIN b ON a.id = b.id) JOIN c ON c.id = b.id) JOIN d ON d.id = c.id) JOIN e ON e.id = d.id",
			"SELECT * FROM a JOIN b ON a.id = b.id JOIN c ON c.id = b.id JOIN d ON d.id = c.id JOIN e ON e.id = d.id",
		},
		{
			"issue query vs plain join chain",
			"SELECT `cu`.`customer_id` AS `ID`, `sakila`.`city`.`city` AS `city` FROM ((( `sakila`.`customer` `cu` " +
				"JOIN `sakila`.`address` `a` ON (`cu`.`address_id` = `a`.`address_id`)) " +
				"JOIN `sakila`.`city` ON (`a`.`city_id` = `sakila`.`city`.`city_id`)) " +
				"JOIN `sakila`.`country` ON (`sakila`.`city`.`country_id` = `sakila`.`country`.`country_id`))",
			"SELECT `cu`.`customer_id` AS `ID`, `sakila`.`city`.`city` AS `city` FROM `sakila`.`customer` `cu` " +
				"JOIN `sakila`.`address` `a` ON (`cu`.`address_id` = `a`.`address_id`) " +
				"JOIN `sakila`.`city` ON (`a`.`city_id` = `sakila`.`city`.`city_id`) " +
				"JOIN `sakila`.`country` ON (`sakila`.`city`.`country_id` = `sakila`.`country`.`country_id`)",
		},
	}
	dialects := []keywords.SQLDialect{
		keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectPostgreSQL,
		keywords.DialectSQLServer, keywords.DialectSQLite, keywords.DialectGeneric,
	}
	for _, d := range dialects {
		for _, pr := range pairs {
			t.Run(string(d)+"/"+pr.name, func(t *testing.T) {
				// Backtick identifiers are MySQL-family syntax.
				if strings.Contains(pr.paren, "`") && d != keywords.DialectMySQL && d != keywords.DialectMariaDB {
					t.Skip("backtick quoting is MySQL/MariaDB syntax")
				}
				pt, err := gosqlx.ParseWithDialect(pr.paren, d)
				if err != nil {
					t.Fatalf("parse parenthesized %q: %v", pr.paren, err)
				}
				ft, err := gosqlx.ParseWithDialect(pr.flat, d)
				if err != nil {
					t.Fatalf("parse flat %q: %v", pr.flat, err)
				}
				if got, want := pt.SQL(), ft.SQL(); got != want {
					t.Errorf("SQL() mismatch\n paren: %s\n  flat: %s", got, want)
				}
			})
		}
	}

	t.Run("issue FROM renders flat", func(t *testing.T) {
		tree, err := gosqlx.ParseWithDialect(issue521RoundTrip, keywords.DialectMySQL)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		got := tree.SQL()
		if !strings.Contains(got, issue521FlatFrom) {
			t.Errorf("SQL() does not contain expected FROM\n got: %s\nwant: %s", got, issue521FlatFrom)
		}
	})
}

func TestIssue521_RoundTrip(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect(issue521RoundTrip, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s1 := tree.SQL()
	if !strings.Contains(s1, "sakila.city.city AS city") {
		t.Errorf("SQL() lost the three-part column: %s", s1)
	}
	if strings.Contains(s1, "((") {
		t.Errorf("SQL() should render the join group flat, got: %s", s1)
	}
	tree2, err := gosqlx.ParseWithDialect(s1, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("reparse of SQL() output failed: %v\nSQL: %s", err, s1)
	}
	if s2 := tree2.SQL(); s2 != s1 {
		t.Errorf("SQL() not idempotent\n s1: %s\n s2: %s", s1, s2)
	}

	styles := map[string]ast.FormatOptions{
		"compact":  ast.CompactStyle(),
		"readable": ast.ReadableStyle(),
	}
	for name, style := range styles {
		t.Run("formatter/"+name, func(t *testing.T) {
			c1 := formatter.FormatAST(tree, style)
			ft, err := gosqlx.ParseWithDialect(c1, keywords.DialectMySQL)
			if err != nil {
				t.Fatalf("reparse of formatted output failed: %v\nformatted: %s", err, c1)
			}
			if c2 := formatter.FormatAST(ft, style); c2 != c1 {
				t.Errorf("formatter not idempotent\n c1: %s\n c2: %s", c1, c2)
			}
		})
	}
}

func TestIssue521_ExtractTables(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect(issue521Full, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := gosqlx.ExtractTables(tree)
	sort.Strings(got)
	want := []string{"sakila.address", "sakila.city", "sakila.country", "sakila.customer"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("ExtractTables = %v, want %v", got, want)
	}
}

func TestIssue521_Rejections(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		wantErr string // substring of err.Error(); empty means any error
	}{
		{"comma after group with joins", keywords.DialectMySQL,
			"SELECT * FROM (a JOIN b ON a.id = b.id), c", "comma-separated table list after a parenthesized join"},
		{"comma inside group", keywords.DialectMySQL,
			"SELECT * FROM (a, b) JOIN c ON a.id = c.id", "inside a parenthesized join"},
		{"unclosed group", keywords.DialectMySQL,
			"SELECT * FROM (a JOIN b ON a.id = b.id", ""},
		{"alias on join group", keywords.DialectMySQL,
			"SELECT * FROM (a JOIN b ON a.id = b.id) j", ""},
		{"VALUES without ROW in MySQL", keywords.DialectMySQL,
			"SELECT * FROM (VALUES (1)) AS v(a)", "ROW( in VALUES"},
		{"excessive nesting", keywords.DialectMySQL,
			"SELECT * FROM " + strings.Repeat("(", 300) + "t" + strings.Repeat(")", 300), "recursion depth"},
		{"trailing dot", keywords.DialectMySQL,
			"SELECT t.col. FROM t", "expected column name or * after table qualifier"},
		{"asterisk followed by more parts", keywords.DialectMySQL,
			"SELECT a.b.*.c FROM t", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tt.sql, tt.dialect)
			if err == nil {
				t.Fatalf("expected an error for %q, got AST %v", tt.sql, tree != nil)
			}
			if tt.wantErr != "" && !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErr)) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
