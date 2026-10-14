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
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

var allRenderDialects = []keywords.SQLDialect{
	keywords.DialectGeneric, keywords.DialectPostgreSQL, keywords.DialectMySQL,
	keywords.DialectSQLServer, keywords.DialectOracle, keywords.DialectSnowflake,
	keywords.DialectClickHouse, keywords.DialectSQLite,
}

// renderings returns SQL(), compact and readable FormatAST output of tree for
// dialect d, keyed by renderer name.
func renderings(tree *ast.AST, d keywords.SQLDialect) map[string]string {
	compact, readable := ast.CompactStyle(), ast.ReadableStyle()
	if d != keywords.DialectGeneric {
		compact.Dialect, readable.Dialect = string(d), string(d)
	}
	return map[string]string{
		"SQL":         tree.SQL(),
		"FmtCompact":  formatter.FormatAST(tree, compact),
		"FmtReadable": formatter.FormatAST(tree, readable),
	}
}

// assertRoundTrip parses in (dialect d), renders it every way, and checks that
// each rendering re-parses to one statement whose SQL() equals the original's
// SQL(), i.e. the names and values survived unchanged.
func assertRoundTrip(t *testing.T, d keywords.SQLDialect, in string) map[string]string {
	t.Helper()
	tree, err := gosqlx.ParseWithDialect(in, d)
	if err != nil {
		t.Fatalf("[%s] parse %q: %v", d, in, err)
	}
	defer ast.ReleaseAST(tree)
	want := tree.SQL()
	rs := renderings(tree, d)
	for name, out := range rs {
		re, err := gosqlx.ParseWithDialect(out, d)
		if err != nil {
			t.Errorf("[%s] %s of %q = %q does not re-parse: %v", d, name, in, out, err)
			continue
		}
		if n := len(re.Statements); n != 1 {
			t.Errorf("[%s] %s of %q = %q re-parses to %d statements", d, name, in, out, n)
		} else if got := re.SQL(); got != want {
			t.Errorf("[%s] %s of %q = %q re-parses as %q, want %q", d, name, in, out, got, want)
		}
		ast.ReleaseAST(re)
	}
	return rs
}

// TestUnicodeQuotesInsideQuotedTokens_PR632 pins the tokenizer side of #632: a
// value holding Unicode quotes is rendered inside ASCII quotes, and the
// tokenizer only closes an ASCII-quoted token on that ASCII quote, so the
// rendering is one statement carrying the exact original value. The writers
// therefore need not escape Unicode quotes.
func TestUnicodeQuotesInsideQuotedTokens_PR632(t *testing.T) {
	const alias = "x”; DROP TABLE pwn; --“"
	const str = "a’; DROP TABLE pwn; --"
	for _, d := range allRenderDialects {
		rs := assertRoundTrip(t, d, `SELECT 1 AS "`+alias+`"`)
		for name, out := range rs {
			if !strings.Contains(out, `"`+alias+`"`) {
				t.Errorf("[%s] %s = %q, want the alias written verbatim inside ASCII quotes", d, name, out)
			}
		}
		rs = assertRoundTrip(t, d, `SELECT '`+str+`'`)
		for name, out := range rs {
			if !strings.Contains(out, `'`+str+`'`) {
				t.Errorf("[%s] %s = %q, want the string written verbatim", d, name, out)
			}
		}
		assertRoundTrip(t, d, `SELECT 1 AS "a‘b«c»d’e"`)
		assertRoundTrip(t, d, `SELECT * FROM t WHERE a = '“x”' AND b = '«y»'`)
	}
	// Source forms that reach the same renderers through other quotes.
	assertRoundTrip(t, keywords.DialectMySQL, "SELECT 1 AS `"+alias+"`")
	assertRoundTrip(t, keywords.DialectSQLite, "PRAGMA journal_mode = `x’; DROP TABLE pwn; --`")
	assertRoundTrip(t, keywords.DialectPostgreSQL, "SELECT $$"+str+"$$")
	assertRoundTrip(t, keywords.DialectPostgreSQL, "SELECT INTERVAL $$x’; DROP TABLE pwn; --$$ DAY")

	f, err := gosqlx.Format("SELECT 1 AS `"+alias+"`", gosqlx.DefaultFormatOptions())
	if err != nil {
		t.Fatal(err)
	}
	if tree, err := gosqlx.Parse(f); err != nil || len(tree.Statements) != 1 {
		t.Errorf("gosqlx.Format output %q does not re-parse to one statement (err %v)", f, err)
	}
}

// TestFreeTextKeywordFields_HandBuilt_PR632 covers AST fields the renderers
// wrote verbatim: interval qualifiers, set and binary operators, null
// treatment and the view WITH option. A hand-built value that is not keyword
// or operator text must never reach the output as SQL.
func TestFreeTextKeywordFields_HandBuilt_PR632(t *testing.T) {
	const evil = "x; DROP TABLE pwn; --"
	one := &ast.LiteralValue{Value: 1, Type: "int"}
	sel := func(e ast.Expression) *ast.SelectStatement {
		return &ast.SelectStatement{Columns: []ast.Expression{e}}
	}
	stmts := map[string]ast.Statement{
		"interval": sel(&ast.IntervalExpression{Value: "1", Qualifier: evil}),
		"setop":    &ast.SetOperation{Left: sel(one), Operator: evil, Right: sel(one)},
		"binary":   sel(&ast.BinaryExpression{Left: one, Operator: evil, Right: one}),
		"any":      sel(&ast.AnyExpression{Expr: one, Operator: evil, Subquery: sel(one)}),
		"all":      sel(&ast.AllExpression{Expr: one, Operator: evil, Subquery: sel(one)}),
		"nulls":    sel(&ast.FunctionCall{Name: "f", Arguments: []ast.Expression{one}, NullTreatment: evil}),
		"view":     &ast.CreateViewStatement{Name: "v", Query: sel(one), WithOption: evil},
	}
	for name, s := range stmts {
		tree := &ast.AST{Statements: []ast.Statement{s}}
		for r, out := range renderings(tree, keywords.DialectGeneric) {
			assertPayloadContained(t, name+"/"+r, out)
		}
	}
}

// assertPayloadContained tokenizes out and fails if it holds a statement
// terminator other than a trailing one, or a DROP keyword outside a quoted
// token, i.e. if hand-built text escaped into the SQL.
func assertPayloadContained(t *testing.T, label, out string) {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	toks, err := tkz.Tokenize([]byte(out))
	if err != nil {
		return // untokenizable output fails closed
	}
	for i, tok := range toks {
		last := i+2 >= len(toks) // the final token before EOF
		if tok.Token.Type == models.TokenTypeSemicolon && !last {
			t.Errorf("%s: rendered SQL contains a statement terminator: %q", label, out)
			return
		}
		if tok.Token.Type != models.TokenTypeDoubleQuotedString && strings.EqualFold(tok.Token.Value, "DROP") {
			t.Errorf("%s: hand-built text reached the SQL unquoted: %q", label, out)
			return
		}
	}
}

// TestFreeTextKeywordFields_Parsed_PR632 checks that the parsed (keyword)
// values of those fields still render and round-trip.
func TestFreeTextKeywordFields_Parsed_PR632(t *testing.T) {
	cases := []struct {
		d    keywords.SQLDialect
		in   string
		want string
	}{
		{keywords.DialectGeneric, "SELECT INTERVAL '1-2' YEAR TO MONTH", "YEAR TO MONTH"},
		{keywords.DialectGeneric, "SELECT x + INTERVAL '1' DAY FROM t", "INTERVAL '1' DAY"},
		{keywords.DialectGeneric, "SELECT a FROM t UNION ALL SELECT b FROM u", "UNION ALL"},
		{keywords.DialectGeneric, "SELECT a FROM t EXCEPT SELECT b FROM u", "EXCEPT"},
		{keywords.DialectGeneric, "SELECT a FROM t WHERE x NOT LIKE 'a%' AND y >= 2", ">="},
		{keywords.DialectPostgreSQL, "SELECT d ->> 'k', d #> '{a}', d @> '{}' FROM t", "->>"},
		{keywords.DialectGeneric, "SELECT a FROM t WHERE a IS NOT NULL OR b <> 1", "<>"},
		{keywords.DialectSnowflake, "SELECT FIRST_VALUE(x) IGNORE NULLS OVER (ORDER BY y) FROM t", "IGNORE NULLS"},
		{keywords.DialectPostgreSQL, "CREATE VIEW v AS SELECT a FROM t WITH CHECK OPTION", "WITH CHECK OPTION"},
		{keywords.DialectPostgreSQL, "CREATE VIEW v AS SELECT a FROM t WITH LOCAL CHECK OPTION", "WITH LOCAL CHECK OPTION"},
	}
	for _, tc := range cases {
		for name, out := range assertRoundTrip(t, tc.d, tc.in) {
			if !strings.Contains(out, tc.want) {
				t.Errorf("[%s] %s of %q = %q, want it to contain %q", tc.d, name, tc.in, out, tc.want)
			}
		}
	}
}

// TestDigitLeadingNamesQuoted_PR632: a name starting with a digit must be
// quoted, or SELECT "1abc" renders as SELECT 1abc and re-parses as 1 AS abc.
func TestDigitLeadingNamesQuoted_PR632(t *testing.T) {
	inputs := []string{
		`SELECT "1abc" FROM t`,
		`SELECT t."1abc" FROM t`,
		`SELECT a AS "1abc" FROM t`,
		`SELECT * FROM "1t"`,
		`SELECT * FROM t AS "9x"`,
		`WITH "2cte" AS (SELECT 1) SELECT * FROM "2cte"`,
		`CREATE TABLE "3t" ("4c" INT)`,
	}
	for _, in := range inputs {
		for name, out := range assertRoundTrip(t, keywords.DialectPostgreSQL, in) {
			if strings.Contains(out, " 1abc") || strings.Contains(out, " 1t") {
				t.Errorf("%s of %q = %q, want digit-leading names quoted", name, in, out)
			}
		}
	}
}

// TestQuotedDataTypes_PR632: a quoted custom data type that is not plain type
// text keeps its quotes; known multi-word types built by hand stay bare.
func TestQuotedDataTypes_PR632(t *testing.T) {
	for _, in := range []string{
		`SELECT CAST(x AS "a b") FROM t`,
		`SELECT CAST(x AS "a]b") FROM t`,
		`CREATE TABLE t (c "a b")`,
		`CREATE TABLE t (c "a]b")`,
	} {
		assertRoundTrip(t, keywords.DialectPostgreSQL, in)
	}
	for _, typ := range []string{"DOUBLE PRECISION", "CHARACTER VARYING(10)", "TIMESTAMP WITH TIME ZONE", "TIMESTAMP(6) WITHOUT TIME ZONE", "INT UNSIGNED", "Tuple(a UInt8, b String)"} {
		if got := ast.QuoteDataType(typ); got != typ {
			t.Errorf("QuoteDataType(%q) = %q, want it unchanged", typ, got)
		}
	}
	for _, typ := range []string{"a b", "INT x", "INT ", " INT", "VARCHAR(10) a"} {
		if got := ast.QuoteDataType(typ); got == typ {
			t.Errorf("QuoteDataType(%q) left it bare", typ)
		}
	}
}

// TestReservedWordTargetsQuoted_PR632: a reserved word used as an INSERT
// column, SET target, conflict target, PIVOT column or function name must be
// quoted like any other name.
func TestReservedWordTargetsQuoted_PR632(t *testing.T) {
	cases := []struct {
		d  keywords.SQLDialect
		in string
	}{
		{keywords.DialectPostgreSQL, `INSERT INTO t ("select", "from") VALUES (1, 2)`},
		{keywords.DialectPostgreSQL, `UPDATE t SET "select" = 1, "where" = 2`},
		{keywords.DialectPostgreSQL, `INSERT INTO t (a) VALUES (1) ON CONFLICT ("select") DO UPDATE SET "select" = 2`},
		{keywords.DialectMySQL, "INSERT INTO t (`select`) VALUES (1) ON DUPLICATE KEY UPDATE `select` = 2"},
		{keywords.DialectMySQL, "UPDATE t SET `order` = 1"},
		{keywords.DialectSQLServer, `SELECT * FROM s PIVOT (SUM(v) FOR [select] IN ([a], [b])) AS p`},
		{keywords.DialectPostgreSQL, `SELECT "select"(x) FROM t`},
		{keywords.DialectPostgreSQL, `SELECT "from"() FROM t`},
	}
	for _, tc := range cases {
		assertRoundTrip(t, tc.d, tc.in)
	}
	// Keywords the parser accepts as function names stay bare.
	for name, out := range assertRoundTrip(t, keywords.DialectMySQL, `SELECT IF(a, 1, 2), REPLACE(b, 'x', 'y') FROM t`) {
		if !strings.Contains(out, "IF(") || !strings.Contains(out, "REPLACE(") {
			t.Errorf("%s = %q, want IF and REPLACE bare", name, out)
		}
	}
}

// TestHashNames_PR632 covers '#' names: SQL Server keeps #temp bare, and a
// SQL Server constraint name that needs quoting still re-parses.
func TestHashNames_PR632(t *testing.T) {
	for _, in := range []string{
		`SELECT * FROM #temp`,
		`CREATE TABLE t (a INT, CONSTRAINT [#x] PRIMARY KEY (a))`,
		`CREATE TABLE t (a INT, CONSTRAINT [x y] PRIMARY KEY (a))`,
		`CREATE TABLE t (a INT, CONSTRAINT "x y" UNIQUE (a))`,
	} {
		assertRoundTrip(t, keywords.DialectSQLServer, in)
	}
}
