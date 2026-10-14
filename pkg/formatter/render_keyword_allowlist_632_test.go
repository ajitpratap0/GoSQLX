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

// freeTextKeywordFieldCases are keyword fields whose out-of-list fallback is
// a quoted token rather than dropping the value (set, binary and quantified
// comparison operators, the SHOW kind), plus fields that are dropped when
// unknown but are not covered by keywordFieldCases.
var freeTextKeywordFieldCases = []keywordFieldCase{
	{"null_treatment", keywords.DialectSnowflake, "SELECT FIRST_VALUE(x) IGNORE NULLS OVER (ORDER BY y) FROM t", false,
		func(t *testing.T, s ast.Statement, v string) {
			fc, ok := selectOf(t, s).Columns[0].(*ast.FunctionCall)
			if !ok {
				t.Fatalf("got %T", selectOf(t, s).Columns[0])
			}
			fc.NullTreatment = v
		}},
	{"interval_qualifier", keywords.DialectGeneric, "SELECT a FROM t WHERE a > INTERVAL '1' DAY", false,
		func(t *testing.T, s ast.Statement, v string) {
			b, ok := selectOf(t, s).Where.(*ast.BinaryExpression)
			if !ok {
				t.Fatalf("got %T", selectOf(t, s).Where)
			}
			iv, ok := b.Right.(*ast.IntervalExpression)
			if !ok {
				t.Fatalf("got %T", b.Right)
			}
			iv.Qualifier = v
		}},
	{"show_type", keywords.DialectMySQL, "SHOW COLUMNS FROM zq", false,
		func(t *testing.T, s ast.Statement, v string) {
			sh, ok := s.(*ast.ShowStatement)
			if !ok {
				t.Fatalf("got %T", s)
			}
			sh.ShowType = v
		}},
	{"show_type_bare", keywords.DialectMySQL, "SHOW TABLES", false,
		func(t *testing.T, s ast.Statement, v string) {
			sh, ok := s.(*ast.ShowStatement)
			if !ok {
				t.Fatalf("got %T", s)
			}
			sh.ShowType = v
		}},
	{"set_operator", keywords.DialectGeneric, "SELECT a FROM t UNION SELECT b FROM u", false,
		func(t *testing.T, s ast.Statement, v string) {
			so, ok := s.(*ast.SetOperation)
			if !ok {
				t.Fatalf("got %T", s)
			}
			so.Operator = v
		}},
	{"set_operator_nested", keywords.DialectGeneric, "SELECT a FROM t UNION SELECT b FROM u EXCEPT SELECT c FROM w", false,
		func(t *testing.T, s ast.Statement, v string) {
			so, ok := s.(*ast.SetOperation)
			if !ok {
				t.Fatalf("got %T", s)
			}
			left, ok := so.Left.(*ast.SetOperation)
			if !ok {
				t.Fatalf("got %T", so.Left)
			}
			left.Operator = v
		}},
	{"binary_operator", keywords.DialectGeneric, "SELECT a FROM t WHERE a = 1", false,
		func(t *testing.T, s ast.Statement, v string) {
			b, ok := selectOf(t, s).Where.(*ast.BinaryExpression)
			if !ok {
				t.Fatalf("got %T", selectOf(t, s).Where)
			}
			b.Operator = v
		}},
	{"binary_operator_select_list", keywords.DialectGeneric, "SELECT a + b FROM t", false,
		func(t *testing.T, s ast.Statement, v string) {
			b, ok := selectOf(t, s).Columns[0].(*ast.BinaryExpression)
			if !ok {
				t.Fatalf("got %T", selectOf(t, s).Columns[0])
			}
			b.Operator = v
		}},
	{"any_operator", keywords.DialectGeneric, "SELECT a FROM t WHERE a = ANY (SELECT b FROM u)", false,
		func(t *testing.T, s ast.Statement, v string) {
			e, ok := selectOf(t, s).Where.(*ast.AnyExpression)
			if !ok {
				t.Fatalf("got %T", selectOf(t, s).Where)
			}
			e.Operator = v
		}},
	{"view_with_option", keywords.DialectPostgreSQL, "CREATE VIEW v AS SELECT a FROM t WITH CHECK OPTION", false,
		func(t *testing.T, s ast.Statement, v string) {
			c, ok := s.(*ast.CreateViewStatement)
			if !ok {
				t.Fatalf("got %T", s)
			}
			c.WithOption = v
		}},
}

// wordOnlyPayloads are made only of letters and single spaces, so a gate that
// accepts any keyword-shaped text lets them through. The parser accepts
// consecutive statements without ';', so any of them written bare could add
// a statement (DROP TABLE pwn) to the rendered SQL.
var wordOnlyPayloads = []string{
	"pwn",
	"x DROP TABLE pwn",
	"DROP TABLE pwn",
	"x DROP TABLE pwn SELECT 1 FROM t",
	"x DROP TABLE pwn SELECT",
	"x DROP TABLE pwn DROP TABLE",
	"UNION ALL SELECT 1 DROP TABLE pwn",
	"CROSS JOIN c DROP TABLE pwn SELECT 1 FROM a INNER",
	"TABLE x DROP TABLE pwn DROP TABLE",
	"IGNORE NULLS DROP TABLE pwn",
	"DAY DROP TABLE pwn",
	"TABLES DROP TABLE pwn",
	"CREATE TABLE pwn",
	"CHECK OPTION DROP TABLE pwn",
	"LIKE pwn",
}

// bareWordCount returns the number of unquoted word tokens of sql equal to
// word (ignoring case), or -1 when sql does not tokenize.
func bareWordCount(sql, word string, d keywords.SQLDialect) int {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	if d != keywords.DialectGeneric {
		tkz.SetDialect(d)
	}
	toks, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return -1
	}
	n := 0
	for _, tok := range toks {
		if !strings.EqualFold(tok.Token.Value, word) || tok.Token.Quote != 0 {
			continue
		}
		if tok.Token.Type == models.TokenTypeDoubleQuotedString ||
			tok.Token.Type == models.TokenTypeSingleQuotedString ||
			(tok.Token.Word != nil && tok.Token.Word.QuoteStyle != 0) {
			continue
		}
		n++
	}
	return n
}

// TestKeywordFieldsWordOnlyPayloads_PR632 sets every keyword-valued field to
// word-only and punctuation payloads and checks that no renderer writes the
// payload as bare SQL and that no rendering re-parses to more statements than
// the original: keyword fields are written only when they are exactly one of
// the values the parser produces (any case), and anything else is dropped or
// replaced by a fallback that cannot add a statement.
func TestKeywordFieldsWordOnlyPayloads_PR632(t *testing.T) {
	cases := append(append([]keywordFieldCase(nil), keywordFieldCases...), freeTextKeywordFieldCases...)
	payloads := append(append([]string(nil), wordOnlyPayloads...), keywordFieldPayloads...)
	for _, tc := range cases {
		for _, p := range payloads {
			t.Run(tc.name, func(t *testing.T) {
				tree, err := gosqlx.ParseWithDialect(tc.sql, tc.dialect)
				if err != nil {
					t.Fatalf("parse %q: %v", tc.sql, err)
				}
				defer ast.ReleaseAST(tree)
				want := len(tree.Statements)
				tc.set(t, tree.Statements[0], p)
				for name, out := range renderings(tree, tc.dialect) {
					// SHOW stores any single word as its kind (SHOW PWN parses
					// with kind PWN), so a one-word kind is written bare; SHOW
					// consumes it, which the statement count below checks.
					oneWordShow := strings.HasPrefix(tc.name, "show_type") && !strings.Contains(p, " ")
					// -1: the output does not tokenize, which fails closed.
					if n := bareWordCount(out, "pwn", tc.dialect); n > 0 && !oneWordShow {
						t.Errorf("%s writes %s = %q as bare SQL: %s", name, tc.name, p, out)
					}
					re, err := gosqlx.ParseWithDialect(out, tc.dialect)
					if err != nil {
						continue // failing to re-parse is the safe outcome
					}
					if got := len(re.Statements); got != want {
						t.Errorf("%s of %s = %q re-parses to %d statements, want %d: %s", name, tc.name, p, got, want, out)
					}
					ast.ReleaseAST(re)
				}
			})
		}
	}
}

// TestHandBuiltAlterTableActionType_WordOnly_PR632: the legacy ALTER TABLE
// action type is written only when it is a known action keyword.
func TestHandBuiltAlterTableActionType_WordOnly_PR632(t *testing.T) {
	for _, p := range wordOnlyPayloads {
		stmt := &ast.AlterTableStatement{ //nolint:staticcheck // AlterTableStatement kept for backward compatibility
			Table:   "t",
			Actions: []ast.AlterTableAction{{Type: p}},
		}
		for name, out := range map[string]string{
			"SQL":        stmt.SQL(),
			"FmtCompact": formatter.FormatStatement(stmt, ast.CompactStyle()),
		} {
			if bareWordCount(out, "pwn", keywords.DialectGeneric) > 0 {
				t.Errorf("%s writes the alter action type %q raw: %s", name, p, out)
			}
		}
	}
}

// TestKeywordFieldsKnownValuesRoundTrip_PR632 pins that the values the
// parser stores for the allow-listed fields, in any case, still render and
// round-trip.
func TestKeywordFieldsKnownValuesRoundTrip_PR632(t *testing.T) {
	cases := []struct {
		d    keywords.SQLDialect
		in   string
		want string
	}{
		{keywords.DialectGeneric, "SELECT a FROM t INTERSECT ALL SELECT b FROM u", "INTERSECT ALL"},
		{keywords.DialectOracle, "SELECT a FROM t MINUS SELECT b FROM u", "EXCEPT"},
		{keywords.DialectGeneric, "SELECT a FROM t NATURAL JOIN u", "NATURAL JOIN"},
		{keywords.DialectGeneric, "SELECT a FROM t NATURAL FULL JOIN u", "NATURAL FULL JOIN"},
		{keywords.DialectGeneric, "DROP INDEX i", "DROP INDEX i"},
		{keywords.DialectGeneric, "DROP VIEW v", "DROP VIEW v"},
		{keywords.DialectSnowflake, "SELECT LAG(x) RESPECT NULLS OVER (ORDER BY y) FROM t", "RESPECT NULLS"},
		{keywords.DialectMySQL, "SELECT INTERVAL '1-2' YEAR_MONTH", "YEAR_MONTH"},
		{keywords.DialectGeneric, "SELECT INTERVAL '1 2:03:04' DAY TO SECOND", "DAY TO SECOND"},
		{keywords.DialectGeneric, "SELECT INTERVAL '1:02' HOUR TO MINUTE", "HOUR TO MINUTE"},
		{keywords.DialectMySQL, "SHOW TABLES", "SHOW TABLES"},
		{keywords.DialectMySQL, "SHOW DATABASES", "SHOW DATABASES"},
		{keywords.DialectMySQL, "SHOW CREATE TABLE t", "SHOW CREATE TABLE t"},
		{keywords.DialectMySQL, "SHOW CREATE VIEW v", "SHOW CREATE VIEW v"},
		{keywords.DialectMySQL, "SHOW INDEX FROM t", "SHOW INDEX FROM t"},
		{keywords.DialectMySQL, "SHOW PROCESSLIST", "SHOW PROCESSLIST"},
		{keywords.DialectMySQL, "SHOW VARIABLES", "SHOW VARIABLES"},
		{keywords.DialectPostgreSQL, "CREATE VIEW v AS SELECT a FROM t WITH CASCADED CHECK OPTION", "WITH CASCADED CHECK OPTION"},
		{keywords.DialectPostgreSQL, "SELECT a FROM t WHERE x like 'a' and y ilike 'b' or z = 1", "like"},
		{keywords.DialectSnowflake, "SELECT a FROM t WHERE x LIKE ANY ('a%', 'b%')", "LIKE ANY"},
		{keywords.DialectMySQL, "SELECT a FROM t WHERE x REGEXP 'a' AND y RLIKE 'b'", "RLIKE"},
		{keywords.DialectGeneric, "CREATE TABLE t (a INT NULL, b INT NOT NULL UNIQUE, c INT PRIMARY KEY)", "a INT NULL"},
		{keywords.DialectPostgreSQL, "CREATE TABLE t (a INT) PARTITION BY HASH (a)", "PARTITION BY HASH (a)"},
		{keywords.DialectGeneric, "MERGE INTO t USING s ON t.id = s.id WHEN NOT MATCHED BY SOURCE THEN DELETE", "NOT MATCHED BY SOURCE THEN DELETE"},
	}
	for _, tc := range cases {
		for name, out := range assertRoundTrip(t, tc.d, tc.in) {
			if name != "FmtReadable" && !strings.Contains(out, tc.want) {
				t.Errorf("[%s] %s of %q = %q, want it to contain %q", tc.d, name, tc.in, out, tc.want)
			}
		}
	}
}

// TestKeywordFieldFallbacksFailToParse_PR632 pins the fallback of required
// keyword fields: dropping an unknown DROP object type, PARTITION BY method,
// MERGE WHEN kind or action, or table constraint kind leaves SQL that does
// not parse, and an unknown set operator is written as UNION plus a quoted
// token, which does not parse either, rather than guessing a keyword that
// would silently change the statement's meaning.
func TestKeywordFieldFallbacksFailToParse_PR632(t *testing.T) {
	required := map[string]bool{
		"drop_object_type": true, "partition_by_type": true, "merge_when_type": true,
		"merge_action_type": true, "table_constraint_type": true,
		"set_operator": true, "set_operator_nested": true,
	}
	cases := append(append([]keywordFieldCase(nil), keywordFieldCases...), freeTextKeywordFieldCases...)
	for _, tc := range cases {
		if !required[tc.name] {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.sql, err)
			}
			defer ast.ReleaseAST(tree)
			tc.set(t, tree.Statements[0], "x DROP TABLE pwn")
			for name, out := range renderings(tree, tc.dialect) {
				if re, err := gosqlx.ParseWithDialect(out, tc.dialect); err == nil {
					t.Errorf("%s output %q re-parses (as %q); want a parse error", name, out, re.SQL())
					ast.ReleaseAST(re)
				}
			}
		})
	}
}
