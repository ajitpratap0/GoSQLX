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
	"errors"
	"reflect"
	"strings"
	"testing"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseIn parses query with gosqlx.Parse for the default dialect (d == "")
// and gosqlx.ParseWithDialect otherwise.
func parseIn(d keywords.SQLDialect, query string) (*ast.AST, error) {
	if d == "" {
		return gosqlx.Parse(query)
	}
	return gosqlx.ParseWithDialect(query, d)
}

// formatterOutputs returns every rendering of tree that must re-parse to the
// same AST: SQL() and the formatter in compact, readable and lower-case
// keyword styles.
func formatterOutputs(tree *ast.AST) []string {
	lower := ast.CompactStyle()
	lower.KeywordCase = ast.KeywordLower
	return []string{
		tree.SQL(),
		formatter.FormatAST(tree, ast.CompactStyle()),
		formatter.FormatAST(tree, ast.ReadableStyle()),
		formatter.FormatAST(tree, lower),
	}
}

type fieldSig struct {
	Field  string
	Quoted bool
}

func fieldSigs(tree *ast.AST) []fieldSig {
	var sigs []fieldSig
	for _, stmt := range tree.Statements {
		ast.Inspect(stmt, func(n ast.Node) bool {
			if f, ok := n.(*ast.FieldAccessExpression); ok {
				sigs = append(sigs, fieldSig{f.Field, f.Quoted})
			}
			return true
		})
	}
	return sigs
}

// TestCompositeFieldAccessReservedLabels covers #839: any keyword, reserved
// ones included, is a field label after "." (PostgreSQL ColLabel), and the
// field round-trips bare and unquoted through SQL() and the formatter.
func TestCompositeFieldAccessReservedLabels(t *testing.T) {
	cases := []struct {
		query string
		want  []fieldSig
	}{
		{`SELECT (a).order FROM t`, []fieldSig{{"order", false}}},
		{`SELECT (t).select FROM t`, []fieldSig{{"select", false}}},
		{`SELECT (f(x)).from FROM t`, []fieldSig{{"from", false}}},
		{`SELECT (a).Order FROM t`, []fieldSig{{"Order", false}}},
		{`SELECT (a).end.limit FROM t`, []fieldSig{{"limit", false}, {"end", false}}},
		{`SELECT (a).group[1].where FROM t`, []fieldSig{{"where", false}, {"group", false}}},
		{`SELECT (SELECT r FROM t).and`, []fieldSig{{"and", false}}},
		{`SELECT (a, b).null FROM t`, []fieldSig{{"null", false}}},
		{`SELECT (a).key, (a).value, (a).table FROM t`, []fieldSig{{"key", false}, {"value", false}, {"table", false}}},
		{`SELECT (a)."order", (a).order FROM t`, []fieldSig{{"order", true}, {"order", false}}},
		{`SELECT (a).order AS o FROM t WHERE (a).select = 1 ORDER BY (a).order`, []fieldSig{{"order", false}, {"select", false}, {"order", false}}},
	}
	for _, d := range []keywords.SQLDialect{"", keywords.DialectGeneric, keywords.DialectPostgreSQL, keywords.DialectBigQuery} {
		t.Run("dialect="+string(d), func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.query, func(t *testing.T) {
					tree, err := parseIn(d, tc.query)
					if err != nil {
						t.Fatalf("parse: %v", err)
					}
					defer ast.ReleaseAST(tree)
					if got := tree.SQL(); got != tc.query {
						t.Errorf("SQL() = %q, want %q", got, tc.query)
					}
					if got := fieldSigs(tree); !reflect.DeepEqual(got, tc.want) {
						t.Fatalf("fields = %+v, want %+v", got, tc.want)
					}
					for _, out := range formatterOutputs(tree) {
						again, err := parseIn(d, out)
						if err != nil {
							t.Fatalf("reparse %q: %v", out, err)
						}
						if got := fieldSigs(again); !reflect.DeepEqual(got, tc.want) {
							t.Errorf("reparse %q: fields = %+v, want %+v", out, got, tc.want)
						}
						if got := again.SQL(); got != tc.query {
							t.Errorf("reparse %q: SQL() = %q, want %q", out, got, tc.query)
						}
						ast.ReleaseAST(again)
					}
				})
			}
		})
	}
}

// TestCompositeFieldAccessLabelInvalid checks that only words follow the dot:
// literals and punctuation are still rejected.
func TestCompositeFieldAccessLabelInvalid(t *testing.T) {
	for _, query := range []string{
		`SELECT (a).`,
		`SELECT (a)., b FROM t`,
		`SELECT (a).'order' FROM t`,
		`SELECT (a).$1 FROM t`,
		`SELECT (a).(b) FROM t`,
		`SELECT (a).1 FROM t`,
	} {
		t.Run(query, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(query, keywords.DialectPostgreSQL)
			if err == nil {
				ast.ReleaseAST(tree)
				t.Fatal("expected invalid field label to be rejected")
			}
		})
	}
}

// TestCompositeFieldAccessDialectGate covers #839: (expr).field parses only
// in dialects with composite / struct values (PostgreSQL, BigQuery, Generic
// and the default dialect). Elsewhere it is a clear E4001 error, while other
// uses of a parenthesized expression keep parsing.
func TestCompositeFieldAccessDialectGate(t *testing.T) {
	gated := []keywords.SQLDialect{
		keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectSQLServer,
		keywords.DialectSQLite, keywords.DialectOracle, keywords.DialectSnowflake,
		keywords.DialectClickHouse, keywords.DialectRedshift,
	}
	rejected := []string{
		`SELECT (a).b FROM t`,
		`SELECT (f(x)).* FROM t`,
		`SELECT (SELECT a FROM t).b`,
		`SELECT (a, b).c FROM t`,
		`SELECT x FROM t WHERE (a).b = 1`,
	}
	accepted := []string{
		`SELECT (a + b) * 2 AS c FROM t`,
		`SELECT t.a FROM t WHERE (t.a) = 1`,
		`SELECT (SELECT MAX(a) FROM t) AS m`,
	}
	for _, d := range gated {
		t.Run(string(d), func(t *testing.T) {
			for _, query := range rejected {
				tree, err := gosqlx.ParseWithDialect(query, d)
				if err == nil {
					ast.ReleaseAST(tree)
					t.Errorf("%q: expected composite field access to be rejected", query)
					continue
				}
				var perr *goerrors.Error
				if !errors.As(err, &perr) || perr.Code != goerrors.ErrCodeUnsupportedFeature ||
					!strings.Contains(perr.Message, "composite field access") {
					t.Errorf("%q: want E4001 composite field access error, got %v", query, err)
				}
			}
			for _, query := range accepted {
				tree, err := gosqlx.ParseWithDialect(query, d)
				if err != nil {
					t.Errorf("%q: %v", query, err)
					continue
				}
				ast.ReleaseAST(tree)
			}
		})
	}
	for _, d := range []keywords.SQLDialect{"", keywords.DialectGeneric, keywords.DialectPostgreSQL, keywords.DialectBigQuery} {
		for _, query := range rejected {
			tree, err := parseIn(d, query)
			if err != nil {
				t.Errorf("dialect %q, %q: %v", d, query, err)
				continue
			}
			ast.ReleaseAST(tree)
		}
	}
}

type tableRefSig struct {
	Name           string
	Alias          string
	Lateral        bool
	WithOrdinality bool
	ColumnAliases  []string
}

func tableFuncSigs(tree *ast.AST) []tableRefSig {
	var sigs []tableRefSig
	add := func(r *ast.TableReference) {
		if r.TableFunc != nil {
			var cols []string
			if r.ColumnAliases != nil {
				cols = r.ColumnAliases.Names
			}
			sigs = append(sigs, tableRefSig{r.Name, r.Alias, r.Lateral, r.WithOrdinality, cols})
		}
	}
	for _, stmt := range tree.Statements {
		sel, ok := stmt.(*ast.SelectStatement)
		if !ok {
			continue
		}
		for i := range sel.From {
			add(&sel.From[i])
		}
		for i := range sel.Joins {
			add(&sel.Joins[i].Right)
		}
	}
	return sigs
}

// TestTableFunctionAliasListAndOrdinality covers #839: FROM and JOIN table
// functions accept a column alias list and PostgreSQL WITH ORDINALITY, and
// the formatter round-trips both.
func TestTableFunctionAliasListAndOrdinality(t *testing.T) {
	cases := []struct {
		query string
		sql   string // canonical SQL() output
		want  []tableRefSig
	}{
		{
			`SELECT g.a FROM unnest(arr) AS g(a)`,
			`SELECT g.a FROM unnest(arr) g(a)`,
			[]tableRefSig{{"unnest", "g", false, false, []string{"a"}}},
		},
		{
			`SELECT * FROM generate_series(1, 3) s(n)`,
			`SELECT * FROM generate_series(1, 3) s(n)`,
			[]tableRefSig{{"generate_series", "s", false, false, []string{"n"}}},
		},
		{
			`SELECT * FROM unnest(arr) WITH ORDINALITY`,
			`SELECT * FROM unnest(arr) WITH ORDINALITY`,
			[]tableRefSig{{"unnest", "", false, true, nil}},
		},
		{
			`SELECT * FROM unnest(arr) with ordinality AS t`,
			`SELECT * FROM unnest(arr) WITH ORDINALITY t`,
			[]tableRefSig{{"unnest", "t", false, true, nil}},
		},
		{
			`SELECT * FROM unnest(a, b) WITH ORDINALITY AS t(x, y, n)`,
			`SELECT * FROM unnest(a, b) WITH ORDINALITY t(x, y, n)`,
			[]tableRefSig{{"unnest", "t", false, true, []string{"x", "y", "n"}}},
		},
		{
			`SELECT * FROM unnest(a) WITH ORDINALITY AS x(v, n), t WHERE x.n > 1`,
			`SELECT * FROM unnest(a) WITH ORDINALITY x(v, n), t WHERE x.n > 1`,
			[]tableRefSig{{"unnest", "x", false, true, []string{"v", "n"}}},
		},
		{
			`SELECT u.v FROM t JOIN LATERAL unnest(t.arr) WITH ORDINALITY AS u(v, idx) ON true`,
			`SELECT u.v FROM t INNER JOIN LATERAL unnest(t.arr) WITH ORDINALITY u(v, idx) ON true`,
			[]tableRefSig{{"unnest", "u", true, true, []string{"v", "idx"}}},
		},
		{
			`SELECT e.key FROM t LEFT JOIN LATERAL jsonb_each(t.doc) AS e(key, value) ON true`,
			`SELECT e.key FROM t LEFT JOIN LATERAL jsonb_each(t.doc) e(key, value) ON true`,
			[]tableRefSig{{"jsonb_each", "e", true, false, []string{"key", "value"}}},
		},
		{
			`SELECT * FROM t JOIN unnest(t.arr) WITH ORDINALITY u ON u.ordinality = t.id`,
			`SELECT * FROM t INNER JOIN unnest(t.arr) WITH ORDINALITY u ON u.ordinality = t.id`,
			[]tableRefSig{{"unnest", "u", false, true, nil}},
		},
		{
			`SELECT * FROM unnest(arr) AS g("order", "Select")`,
			`SELECT * FROM unnest(arr) g("order", "Select")`,
			[]tableRefSig{{"unnest", "g", false, false, []string{"order", "Select"}}},
		},
		{
			`SELECT * FROM a.unnest_rows(1) WITH ORDINALITY AS r(x, n) LEFT JOIN LATERAL unnest(r.x) AS y(z) ON true`,
			`SELECT * FROM a.unnest_rows(1) WITH ORDINALITY r(x, n) LEFT JOIN LATERAL unnest(r.x) y(z) ON true`,
			[]tableRefSig{{"a.unnest_rows", "r", false, true, []string{"x", "n"}}, {"unnest", "y", true, false, []string{"z"}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.query, keywords.DialectPostgreSQL)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			defer ast.ReleaseAST(tree)
			if got := tableFuncSigs(tree); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("table functions = %+v, want %+v", got, tc.want)
			}
			if got := tree.SQL(); got != tc.sql {
				t.Errorf("SQL() = %q, want %q", got, tc.sql)
			}
			for _, out := range formatterOutputs(tree) {
				again, err := gosqlx.ParseWithDialect(out, keywords.DialectPostgreSQL)
				if err != nil {
					t.Fatalf("reparse %q: %v", out, err)
				}
				if got := tableFuncSigs(again); !reflect.DeepEqual(got, tc.want) {
					t.Errorf("reparse %q: table functions = %+v, want %+v", out, got, tc.want)
				}
				if got := again.SQL(); got != tc.sql {
					t.Errorf("reparse %q: SQL() = %q, want %q", out, got, tc.sql)
				}
				ast.ReleaseAST(again)
			}
		})
	}
}

func TestTableFunctionAliasListInvalid(t *testing.T) {
	for _, query := range []string{
		`SELECT * FROM unnest(a) AS g()`,
		`SELECT * FROM unnest(a) AS g(x,)`,
		`SELECT * FROM unnest(a) AS g(x y)`,
		`SELECT * FROM unnest(a) AS g(x`,
		`SELECT * FROM unnest(a) AS g(order)`,
		`SELECT * FROM unnest(a) AS g(1)`,
		`SELECT * FROM t CROSS JOIN LATERAL unnest(t.a) AS g(x,)`,
		`SELECT * FROM unnest(a) WITH ORDINALITY AS`,
		`SELECT * FROM unnest(a) WITH ORDINALITY WITH ORDINALITY`,
	} {
		t.Run(query, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(query, keywords.DialectPostgreSQL)
			if err == nil {
				ast.ReleaseAST(tree)
				t.Fatal("expected malformed table function alias to be rejected")
			}
		})
	}
	// WITH ORDINALITY is PostgreSQL-only; the other table-function dialects
	// keep rejecting it.
	for _, d := range []keywords.SQLDialect{keywords.DialectBigQuery, keywords.DialectSnowflake, keywords.DialectClickHouse} {
		tree, err := gosqlx.ParseWithDialect(`SELECT * FROM unnest(arr) WITH ORDINALITY`, d)
		if err == nil {
			ast.ReleaseAST(tree)
			t.Errorf("%s: WITH ORDINALITY must stay PostgreSQL-only", d)
		}
	}
}

// TestTableFunctionFieldsReleased checks that a pooled statement reused after
// a WITH ORDINALITY / alias-list parse does not leak those fields.
func TestTableFunctionFieldsReleased(t *testing.T) {
	for i := 0; i < 50; i++ {
		tree, err := gosqlx.ParseWithDialect(`SELECT * FROM unnest(a) WITH ORDINALITY AS g(x, n)`, keywords.DialectPostgreSQL)
		if err != nil {
			t.Fatal(err)
		}
		ast.ReleaseAST(tree)
		plain, err := gosqlx.ParseWithDialect(`SELECT * FROM unnest(a) g`, keywords.DialectPostgreSQL)
		if err != nil {
			t.Fatal(err)
		}
		got := tableFuncSigs(plain)
		ast.ReleaseAST(plain)
		if want := []tableRefSig{{"unnest", "g", false, false, nil}}; !reflect.DeepEqual(got, want) {
			t.Fatalf("pooled reuse leaked table function fields: %+v", got)
		}
	}
}
