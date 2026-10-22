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
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// assertSingleStatement re-parses rendered SQL in dialect d and fails unless
// it yields exactly one statement.
func assertSingleStatement(t *testing.T, rendered string, d keywords.SQLDialect) {
	t.Helper()
	tree, err := gosqlx.ParseWithDialect(rendered, d)
	if err != nil {
		t.Fatalf("re-parse of %q: %v", rendered, err)
	}
	defer ast.ReleaseAST(tree)
	if n := len(tree.Statements); n != 1 {
		t.Fatalf("rendered SQL re-parses to %d statements, want 1: %s", n, rendered)
	}
}

// assertNoStatementBreak tokenizes rendered SQL and fails if it contains a
// statement terminator, i.e. if a hand-built name or value escaped its
// position. The output need not re-parse: the parser rejects some of the
// quoted fallbacks, which is the safe outcome.
func assertNoStatementBreak(t *testing.T, rendered string) {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	toks, err := tkz.Tokenize([]byte(rendered))
	if err != nil {
		t.Fatalf("tokenize %q: %v", rendered, err)
	}
	for _, tok := range toks {
		if tok.Token.Type == models.TokenTypeSemicolon {
			t.Fatalf("rendered SQL contains a statement terminator: %s", rendered)
		}
	}
}

// TestTableHints_RejectNonWordHints_PR632 checks that the parser refuses
// table hints that are not bare words: string literals, quoted or bracketed
// identifiers and operators would otherwise be stored without their quotes
// and rendered verbatim by SQL(), splitting one SELECT into several.
func TestTableHints_RejectNonWordHints_PR632(t *testing.T) {
	inputs := []string{
		`SELECT * FROM t WITH ('x); DROP TABLE y; --')`,
		`SELECT * FROM t WITH ("x); DROP TABLE y; --")`,
		`SELECT * FROM t WITH ([x); DROP TABLE y; --])`,
		`SELECT * FROM t WITH (NOLOCK, "a b")`,
		// INDEX = ix is accepted and stored as INDEX(ix); its argument must
		// still be a bare word or number.
		`SELECT * FROM t WITH (INDEX = 'x); DROP TABLE y; --')`,
		`SELECT * FROM t WITH (INDEX("x); DROP TABLE y; --"))`,
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(in, keywords.DialectSQLServer)
			if err == nil {
				defer ast.ReleaseAST(tree)
				t.Fatalf("expected a parse error, got SQL() = %s", tree.SQL())
			}
		})
	}
}

// TestTableHints_HandBuiltUnsafeHint_PR632 checks that SQL() never writes a
// hand-built hint that is not a bare word verbatim.
func TestTableHints_HandBuiltUnsafeHint_PR632(t *testing.T) {
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		From: []ast.TableReference{{
			Name:       "t",
			TableHints: []string{"NOLOCK", "X); DROP TABLE Y; --"},
		}},
	}
	got := stmt.SQL()
	want := `SELECT * FROM t WITH (NOLOCK, "X); DROP TABLE Y; --")`
	if got != want {
		t.Fatalf("SQL() mismatch\n got: %s\nwant: %s", got, want)
	}
	assertNoStatementBreak(t, got)
}

// pivotInjectionCases are parsed PIVOT/UNPIVOT inputs whose names or values
// lose their source quotes in the AST.
var pivotInjectionCases = []struct {
	name    string
	dialect keywords.SQLDialect
	input   string
	want    string
}{
	{
		"oracle_string_in_value", keywords.DialectOracle,
		`SELECT * FROM s PIVOT (SUM(v) FOR k IN ('a)) AS p; DROP TABLE y; --')) AS p`,
		`SELECT * FROM s PIVOT (SUM(v) FOR k IN ('a)) AS p; DROP TABLE y; --')) AS p`,
	},
	{
		"oracle_string_in_value_escaped_quote", keywords.DialectOracle,
		`SELECT * FROM s PIVOT (SUM(v) FOR k IN ('it''s')) AS p`,
		`SELECT * FROM s PIVOT (SUM(v) FOR k IN ('it''s')) AS p`,
	},
	{
		"oracle_string_in_values_benign", keywords.DialectOracle,
		`SELECT * FROM s PIVOT (SUM(v) FOR k IN ('JAN', 'FEB')) AS p`,
		`SELECT * FROM s PIVOT (SUM(v) FOR k IN ('JAN', 'FEB')) AS p`,
	},
	{
		"oracle_string_in_value_alias", keywords.DialectOracle,
		`SELECT * FROM s PIVOT (SUM(v) FOR k IN ('a' AS "x)) AS p; DROP TABLE y; --")) AS p`,
		`SELECT * FROM s PIVOT (SUM(v) FOR k IN ('a' AS "x)) AS p; DROP TABLE y; --")) AS p`,
	},
	{
		"snowflake_unpivot_value_column", keywords.DialectSnowflake,
		`SELECT * FROM s UNPIVOT ("v FOR k IN (a)) AS u; DROP TABLE y; --" FOR k IN (a, b)) AS u`,
		`SELECT * FROM s UNPIVOT ("v FOR k IN (a)) AS u; DROP TABLE y; --" FOR k IN (a, b)) AS u`,
	},
	{
		"snowflake_unpivot_name_column", keywords.DialectSnowflake,
		`SELECT * FROM s UNPIVOT (v FOR "k IN (a)) AS u; DROP TABLE y; --" IN (a, b)) AS u`,
		`SELECT * FROM s UNPIVOT (v FOR "k IN (a)) AS u; DROP TABLE y; --" IN (a, b)) AS u`,
	},
	{
		"sqlserver_pivot_column", keywords.DialectSQLServer,
		`SELECT * FROM s PIVOT (SUM(v) FOR "k IN (1)) AS p; DROP TABLE y; --" IN ([a])) AS p`,
		`SELECT * FROM s PIVOT (SUM(v) FOR "k IN (1)) AS p; DROP TABLE y; --" IN ([a])) AS p`,
	},
}

// TestPivot_QuotedNamesAndStrings_PR632 checks that PIVOT/UNPIVOT column
// names and IN-list string literals keep their quoting through SQL(), so the
// output re-parses as one statement with the same meaning.
func TestPivot_QuotedNamesAndStrings_PR632(t *testing.T) {
	for _, tc := range pivotInjectionCases {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.input, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.input, err)
			}
			defer ast.ReleaseAST(tree)
			got := tree.SQL()
			if got != tc.want {
				t.Fatalf("SQL() mismatch\n got: %s\nwant: %s", got, tc.want)
			}
			assertSingleStatement(t, got, tc.dialect)
		})
	}
}

// TestPivot_HandBuiltUnsafeItems_PR632 checks that SQL() quotes hand-built
// PIVOT/UNPIVOT names and IN-list entries that are not well formed.
func TestPivot_HandBuiltUnsafeItems_PR632(t *testing.T) {
	const evil = "x)) AS p; DROP TABLE y; --"
	sel := func(r ast.TableReference) *ast.SelectStatement {
		return &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
			From:    []ast.TableReference{r},
		}
	}
	cases := []struct {
		name string
		ref  ast.TableReference
		want string
	}{
		{"pivot_column", ast.TableReference{Name: "s", Pivot: &ast.PivotClause{AggregateFunction: &ast.Identifier{Name: "v"}, PivotColumn: evil, InValues: []string{"a"}}},
			`SELECT * FROM s PIVOT (v FOR "x)) AS p; DROP TABLE y; --" IN (a))`},
		{"pivot_in_value", ast.TableReference{Name: "s", Pivot: &ast.PivotClause{AggregateFunction: &ast.Identifier{Name: "v"}, PivotColumn: "k", InValues: []string{"[Q1]", "'a'", "1 AS one", evil, "'b\\'"}}},
			`SELECT * FROM s PIVOT (v FOR k IN ([Q1], 'a', 1 AS one, "x)) AS p; DROP TABLE y; --", "'b\'"))`},
		{"unpivot_columns", ast.TableReference{Name: "s", Unpivot: &ast.UnpivotClause{ValueColumn: evil, NameColumn: "n m", InColumns: []string{"c1 AS 'North'", evil}}},
			`SELECT * FROM s UNPIVOT ("x)) AS p; DROP TABLE y; --" FOR "n m" IN (c1 AS 'North', "x)) AS p; DROP TABLE y; --"))`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sel(tc.ref).SQL()
			if got != tc.want {
				t.Fatalf("SQL() mismatch\n got: %s\nwant: %s", got, tc.want)
			}
			assertNoStatementBreak(t, got)
		})
	}
}

// TestQuotedIdentifier_ConsistentWithDefinitions_PR632 checks that a quoted
// reference renders with the same quoting as the alias or CTE column it
// refers to. Those definitions are stored as plain strings and render bare
// (case folded by the database), so a case-only quoted reference must render
// bare too or it no longer matches its definition.
func TestQuotedIdentifier_ConsistentWithDefinitions_PR632(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want string
	}{
		{"order_by_alias", `SELECT amount AS "Total" FROM t ORDER BY "Total"`, `SELECT amount AS Total FROM t ORDER BY Total`},
		{"cte_column", `WITH cte (a, "B") AS (SELECT 1, 2) SELECT "B" FROM cte`, `WITH cte (a, B) AS (SELECT 1, 2) SELECT B FROM cte`},
		{"derived_alias", `SELECT s."Total" FROM (SELECT amount AS "Total" FROM t) AS s`, `SELECT s.Total FROM (SELECT amount AS Total FROM t) s`},
		{"metabase_style", `SELECT "source"."CATEGORY" AS "CATEGORY" FROM (SELECT category AS "CATEGORY" FROM p) AS "source" GROUP BY "source"."CATEGORY"`,
			`SELECT source.CATEGORY AS CATEGORY FROM (SELECT category AS CATEGORY FROM p) source GROUP BY source.CATEGORY`},
		// Reserved words still keep their quotes.
		{"reserved_kept", `SELECT "select", "key" FROM t`, `SELECT "select", "key" FROM t`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, keywords.DialectPostgreSQL)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.sql, err)
			}
			defer ast.ReleaseAST(tree)
			if got := tree.SQL(); got != tc.want {
				t.Fatalf("SQL() mismatch\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}
