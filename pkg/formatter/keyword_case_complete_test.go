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

func TestKeywordLowerIncludesExpressions(t *testing.T) {
	cases := []string{
		"SELECT a FROM t WHERE b IS NULL AND c IN (1) ORDER BY a DESC",
		"SELECT DISTINCT CASE WHEN a BETWEEN 1 AND 2 THEN CAST(b AS INTEGER) ELSE NULL END AS result FROM t WHERE NOT EXISTS (SELECT 1 FROM u WHERE u.a LIKE 'A%')",
		"SELECT COUNT(DISTINCT a), SUM(b) OVER (PARTITION BY c ORDER BY a DESC NULLS FIRST ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) FROM t",
		"SELECT a FROM t LEFT OUTER JOIN u ON t.a = u.a WHERE a NOT IN (1) UNION ALL SELECT a FROM v ORDER BY a DESC",
		"SELECT a FROM t WINDOW win AS (PARTITION BY b ORDER BY a DESC NULLS FIRST)",
		"SELECT CAST(CASE WHEN a IS NOT NULL THEN a ELSE 0 END AS DECIMAL(10, 2)) FROM t WHERE a NOT BETWEEN 1 AND 2",
		"SELECT ARRAY[CASE WHEN a IS NULL THEN NULL ELSE a END], TRUE AND NOT FALSE, INTERVAL '1' DAY FROM t",
		"SELECT (CASE WHEN a IS NULL THEN b ELSE c END).field FROM t",
	}
	opts := ast.CompactStyle()
	opts.KeywordCase = ast.KeywordLower
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			got := formatWithDialect(t, input, keywords.DialectPostgreSQL, opts)
			// All identifiers and literal text in these cases are already lower case,
			// except the intentionally preserved string literal.
			want := strings.ReplaceAll(strings.ToLower(got), "'a%'", "'A%'")
			if got != want {
				t.Fatalf("keywords remain upper case: %s", got)
			}
			if again := formatWithDialect(t, got, keywords.DialectPostgreSQL, opts); again != got {
				t.Fatalf("not a fixpoint: %q -> %q", got, again)
			}
		})
	}
}

func TestKeywordLowerPreservesIdentifiers(t *testing.T) {
	opts := ast.CompactStyle()
	opts.KeywordCase = ast.KeywordLower
	input := `SELECT MixedCase, "QuotedName", t.VALUE AS Result, UserFunction(MixedCase) FROM TableName t WHERE MixedCase IS NULL ORDER BY MixedCase DESC`
	got := formatWithDialect(t, input, keywords.DialectPostgreSQL, opts)
	for _, name := range []string{"MixedCase", `"QuotedName"`, "t.VALUE", "Result", "UserFunction", "TableName"} {
		if !strings.Contains(got, name) {
			t.Errorf("identifier %q changed: %s", name, got)
		}
	}
}

func TestKeywordLowerPreservesExpressionSyntaxAndValues(t *testing.T) {
	opts := ast.CompactStyle()
	opts.KeywordCase = ast.KeywordLower
	cases := []struct{ input, want string }{
		{"SELECT - -1, ~ -1, -(-a) FROM t", "select - -1, ~ -1, -(-a) from t"},
		{"SELECT CAST(a AS MyDomain), CAST(a AS MySchema.NUMERIC), CAST(a AS INTEGER) FROM t", "select cast(a as MyDomain), cast(a as MySchema.NUMERIC), cast(a as integer) from t"},
		{"SELECT EXTRACT(YEAR FROM CreatedAt), SUBSTRING(Name FROM 1 FOR 3) FROM MyTable", "select extract(year from CreatedAt), substring(Name from 1 for 3) from MyTable"},
		{"SELECT a FROM t WHERE a LIKE 'X' ESCAPE EscapeValue", "select a from t where a like 'X' escape EscapeValue"},
		{"SELECT a FROM t WHERE c = SOME (SELECT z FROM w)", "select a from t where c = some (select z from w)"},
		{"SELECT gosqlx_case_slot_0_ FROM t ORDER BY gosqlx_case_slot_0_ DESC", "select gosqlx_case_slot_0_ from t order by gosqlx_case_slot_0_ desc"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.input, keywords.DialectPostgreSQL)
			if err != nil {
				t.Fatal(err)
			}
			before := tree.SQL()
			if got := formatter.FormatAST(tree, opts); got != tc.want {
				t.Fatalf("got %q; want %q", got, tc.want)
			}
			if after := tree.SQL(); after != before {
				t.Fatalf("formatting mutated AST: %q -> %q", before, after)
			}
			if again := formatWithDialect(t, tc.want, keywords.DialectPostgreSQL, opts); again != tc.want {
				t.Fatalf("not a fixpoint: %q", again)
			}
		})
	}
}

func TestKeywordLowerPreservesPostfixGrouping(t *testing.T) {
	opts := ast.CompactStyle()
	opts.KeywordCase = ast.KeywordLower
	operand := &ast.BinaryExpression{Left: &ast.Identifier{Name: "a"}, Operator: "+", Right: &ast.Identifier{Name: "b"}}
	cases := []struct {
		expr ast.Expression
		want string
	}{
		{&ast.AtTimeZoneExpression{Expr: operand, Zone: &ast.LiteralValue{Value: "UTC", Type: "STRING"}}, "(a + b) at time zone 'UTC'"},
		{&ast.CollateExpression{Expr: operand, Collation: "C", Quoted: true}, `(a + b) collate "C"`},
		{&ast.VariantPath{Root: operand, Segments: []ast.VariantPathSegment{{Name: "Key"}}}, `(a + b):"Key"`},
		{&ast.BinaryExpression{Left: &ast.LiteralValue{Type: "STRING", Value: "operator(custom.=)"}, Right: &ast.Identifier{Name: "a"}, CustomOp: &ast.CustomBinaryOperator{Parts: []string{"Custom", "="}}}, "'operator(custom.=)' operator(Custom.=) a"},
	}
	for _, tc := range cases {
		before := tc.expr.TokenLiteral()
		if got := formatter.FormatExpression(tc.expr, opts); got != tc.want {
			t.Errorf("got %q; want %q", got, tc.want)
		}
		if tc.expr.TokenLiteral() != before {
			t.Fatal("formatting mutated expression")
		}
	}
}

func TestKeywordLowerNestedDialectExpressions(t *testing.T) {
	opts := ast.CompactStyle()
	opts.KeywordCase = ast.KeywordLower
	cases := []struct {
		input   string
		dialect keywords.SQLDialect
		want    string
	}{
		{"SELECT {'key': CASE WHEN a IS NULL THEN 0 ELSE 1 END} FROM t", keywords.DialectSnowflake, "select {'key': case when a is null then 0 else 1 end} from t"},
		{"SELECT JSON_OBJECT(KEY 'Key' VALUE CASE WHEN a IS NULL THEN 0 ELSE 1 END) FROM t", keywords.DialectOracle, "select JSON_OBJECT(key 'Key' value case when a is null then 0 else 1 end) from t"},
		{"SELECT * EXCLUDE (KeepCase) REPLACE (CASE WHEN a IS NULL THEN 0 ELSE 1 END AS OtherCase) FROM t", keywords.DialectSnowflake, "select * exclude (KeepCase) replace (case when a is null then 0 else 1 end as OtherCase) from t"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := formatWithDialect(t, tc.input, tc.dialect, opts)
			if got != tc.want {
				t.Fatalf("got %q; want %q", got, tc.want)
			}
			if again := formatWithDialect(t, got, tc.dialect, opts); again != got {
				t.Fatalf("not a fixpoint: %q", again)
			}
		})
	}
}

func TestStraightJoinCommaSpacing(t *testing.T) {
	input := "SELECT * FROM t1 STRAIGHT_JOIN t2 ON t1.a = t2.a, t3"
	opts := ast.CompactStyle()
	got := formatWithDialect(t, input, keywords.DialectMySQL, opts)
	if got != input {
		t.Fatalf("FormatAST = %q; want %q", got, input)
	}
	tree, err := gosqlx.ParseWithDialect(input, keywords.DialectMySQL)
	if err != nil {
		t.Fatal(err)
	}
	if got := tree.SQL(); got != input {
		t.Fatalf("SQL = %q; want %q", got, input)
	}
	lower := opts
	lower.KeywordCase = ast.KeywordLower
	if got := formatter.FormatAST(tree, lower); got != strings.ToLower(input) {
		t.Fatalf("lower = %q", got)
	}
}
