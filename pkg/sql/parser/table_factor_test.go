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
	"reflect"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseOne parses sql in dialect d and returns its single statement.
func parseOne(t *testing.T, d keywords.SQLDialect, sql string) ast.Statement {
	t.Helper()
	tree, err := gosqlx.ParseWithDialect(sql, d)
	if err != nil {
		t.Fatalf("parse %q (%s): %v", sql, d, err)
	}
	t.Cleanup(func() { ast.ReleaseAST(tree) })
	if len(tree.Statements) != 1 {
		t.Fatalf("want 1 statement, got %d", len(tree.Statements))
	}
	return tree.Statements[0]
}

// firstFrom returns the first FROM item of a SELECT.
func firstFrom(t *testing.T, s ast.Statement) *ast.TableReference {
	t.Helper()
	sel, ok := s.(*ast.SelectStatement)
	if !ok {
		t.Fatalf("want *ast.SelectStatement, got %T", s)
	}
	if len(sel.From) == 0 {
		t.Fatal("SELECT has no FROM item")
	}
	return &sel.From[0]
}

// setOpShape renders the grouping of a set-operation tree as nested
// parentheses of operator names, e.g. "(1 UNION (2 INTERSECT 3))".
func setOpShape(t *testing.T, s ast.Statement) string {
	t.Helper()
	switch v := s.(type) {
	case *ast.SetOperation:
		return "(" + setOpShape(t, v.Left) + " " + v.Operator + " " + setOpShape(t, v.Right) + ")"
	case *ast.SelectStatement:
		if len(v.Columns) != 1 {
			t.Fatalf("operand has %d columns", len(v.Columns))
		}
		lit, ok := v.Columns[0].(*ast.LiteralValue)
		if !ok {
			t.Fatalf("operand column is %T", v.Columns[0])
		}
		return lit.Value.(string)
	case *ast.Values:
		return "VALUES"
	}
	t.Fatalf("unexpected operand %T", s)
	return ""
}

func TestSetOperationPrecedence(t *testing.T) {
	cases := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		{"intersect binds tighter", keywords.DialectPostgreSQL, "SELECT 1 UNION SELECT 2 INTERSECT SELECT 3", "(1 UNION (2 INTERSECT 3))"},
		{"intersect first", keywords.DialectPostgreSQL, "SELECT 1 INTERSECT SELECT 2 UNION SELECT 3", "((1 INTERSECT 2) UNION 3)"},
		{"except then intersect", keywords.DialectSQLServer, "SELECT 1 EXCEPT SELECT 2 INTERSECT SELECT 3", "(1 EXCEPT (2 INTERSECT 3))"},
		{"intersect chain is left-deep", keywords.DialectMySQL, "SELECT 1 UNION SELECT 2 INTERSECT SELECT 3 INTERSECT SELECT 4", "(1 UNION ((2 INTERSECT 3) INTERSECT 4))"},
		{"mixed chain", keywords.DialectGeneric, "SELECT 1 INTERSECT SELECT 2 UNION SELECT 3 INTERSECT SELECT 4 EXCEPT SELECT 5", "(((1 INTERSECT 2) UNION (3 INTERSECT 4)) EXCEPT 5)"},
		{"equal precedence left-deep", keywords.DialectPostgreSQL, "SELECT 1 UNION SELECT 2 EXCEPT SELECT 3", "((1 UNION 2) EXCEPT 3)"},
		{"sqlite groups left to right", keywords.DialectSQLite, "SELECT 1 UNION SELECT 2 INTERSECT SELECT 3", "((1 UNION 2) INTERSECT 3)"},
		{"oracle groups left to right", keywords.DialectOracle, "SELECT 1 FROM dual UNION SELECT 2 FROM dual INTERSECT SELECT 3 FROM dual", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stmt := parseOne(t, tc.dialect, tc.sql)
			if tc.want == "" {
				// Oracle: assert the shape without the FROM-bearing operands.
				so, ok := stmt.(*ast.SetOperation)
				if !ok || so.Operator != "INTERSECT" {
					t.Fatalf("want top-level INTERSECT, got %#v", stmt)
				}
				if left, ok := so.Left.(*ast.SetOperation); !ok || left.Operator != "UNION" {
					t.Fatalf("want UNION on the left, got %T", so.Left)
				}
				return
			}
			if got := setOpShape(t, stmt); got != tc.want {
				t.Errorf("shape = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestSetOperationQuantifiersAndMinus(t *testing.T) {
	cases := []struct {
		name         string
		dialect      keywords.SQLDialect
		sql          string
		op           string
		all, distinc bool
		minus        bool
	}{
		{"intersect distinct", keywords.DialectMariaDB, "SELECT a FROM t1 INTERSECT DISTINCT SELECT a FROM t2", "INTERSECT", false, true, false},
		{"union distinct", keywords.DialectMySQL, "SELECT a FROM t1 UNION DISTINCT SELECT a FROM t2", "UNION", false, true, false},
		{"union all", keywords.DialectClickHouse, "SELECT 1 UNION ALL SELECT 2", "UNION", true, false, false},
		{"oracle minus", keywords.DialectOracle, "SELECT a FROM t MINUS SELECT a FROM u", "EXCEPT", false, false, true},
		{"snowflake minus", keywords.DialectSnowflake, "SELECT a FROM t MINUS SELECT a FROM u", "EXCEPT", false, false, true},
		{"plain except", keywords.DialectPostgreSQL, "SELECT a FROM t EXCEPT SELECT a FROM u", "EXCEPT", false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			so, ok := parseOne(t, tc.dialect, tc.sql).(*ast.SetOperation)
			if !ok {
				t.Fatal("want *ast.SetOperation")
			}
			if so.Operator != tc.op || so.All != tc.all || so.Distinct != tc.distinc || so.Minus != tc.minus {
				t.Errorf("got op=%s all=%v distinct=%v minus=%v", so.Operator, so.All, so.Distinct, so.Minus)
			}
		})
	}
}

func TestTableSampleClause(t *testing.T) {
	cases := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    ast.TableSampleClause // Args/Seed/Pos are checked by count
		args    int
		seed    bool
		alias   string
	}{
		{"pg system", keywords.DialectPostgreSQL, "SELECT * FROM sales TABLESAMPLE SYSTEM (10)",
			ast.TableSampleClause{Keyword: "TABLESAMPLE", Method: "SYSTEM", AfterAlias: true}, 1, false, ""},
		{"pg bernoulli repeatable", keywords.DialectPostgreSQL, "SELECT * FROM sales s TABLESAMPLE BERNOULLI (10) REPEATABLE (1)",
			ast.TableSampleClause{Keyword: "TABLESAMPLE", Method: "BERNOULLI", SeedKeyword: "REPEATABLE", AfterAlias: true}, 1, true, "s"},
		{"sqlserver percent", keywords.DialectSQLServer, "SELECT * FROM sales TABLESAMPLE (10 PERCENT)",
			ast.TableSampleClause{Keyword: "TABLESAMPLE", Unit: "PERCENT", AfterAlias: true}, 1, false, ""},
		{"snowflake rows seed", keywords.DialectSnowflake, "SELECT * FROM t SAMPLE ROW (10 ROWS) SEED (7)",
			ast.TableSampleClause{Keyword: "SAMPLE", Method: "ROW", Unit: "ROWS", SeedKeyword: "SEED", AfterAlias: true}, 1, true, ""},
		{"oracle before alias", keywords.DialectOracle, "SELECT * FROM t SAMPLE BLOCK (10, 2) SEED (5) x",
			ast.TableSampleClause{Keyword: "SAMPLE", Method: "BLOCK", SeedKeyword: "SEED"}, 2, true, "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref := firstFrom(t, parseOne(t, tc.dialect, tc.sql))
			s := ref.TableSample
			if s == nil {
				t.Fatal("TableSample not set")
			}
			got := *s
			if len(got.Args) != tc.args || (got.Seed != nil) != tc.seed {
				t.Errorf("args=%d seed=%v, want args=%d seed=%v", len(got.Args), got.Seed != nil, tc.args, tc.seed)
			}
			got.Args, got.Seed, got.Pos = nil, nil, tc.want.Pos
			// An Oracle sample precedes the alias; the others follow the
			// table (and alias, when there is one).
			if tc.dialect == keywords.DialectOracle {
				tc.want.AfterAlias = false
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("TableSample = %+v, want %+v", got, tc.want)
			}
			if ref.Alias != tc.alias {
				t.Errorf("alias = %q, want %q", ref.Alias, tc.alias)
			}
		})
	}
}

func TestTableFactorModifiers(t *testing.T) {
	cases := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		check   func(t *testing.T, ref *ast.TableReference)
	}{
		{"postgres only", keywords.DialectPostgreSQL, "SELECT * FROM ONLY parent_tbl p", func(t *testing.T, ref *ast.TableReference) {
			if !ref.Only || ref.Name != "parent_tbl" || ref.Alias != "p" {
				t.Errorf("got %+v", ref)
			}
		}},
		{"oracle db link", keywords.DialectOracle, "SELECT * FROM t@lnk.example.com x", func(t *testing.T, ref *ast.TableReference) {
			if ref.Modifiers == nil || ref.Modifiers.DBLink != "lnk.example.com" || ref.Name != "t" || ref.Alias != "x" {
				t.Errorf("got %+v / %+v", ref, ref.Modifiers)
			}
		}},
		{"oracle as of scn", keywords.DialectOracle, "SELECT * FROM t AS OF SCN 123 x", func(t *testing.T, ref *ast.TableReference) {
			f := ref.Flashback
			if f == nil || f.Versions || f.Kind != "SCN" || f.Point == nil || ref.Alias != "x" {
				t.Errorf("got %+v", f)
			}
		}},
		{"oracle versions between", keywords.DialectOracle, "SELECT * FROM t VERSIONS BETWEEN SCN MINVALUE AND MAXVALUE", func(t *testing.T, ref *ast.TableReference) {
			f := ref.Flashback
			if f == nil || !f.Versions || f.Kind != "SCN" || f.Start == nil || f.End == nil {
				t.Errorf("got %+v", f)
			}
		}},
		{"mysql partition", keywords.DialectMySQL, "SELECT * FROM t PARTITION (p0, p1) AS x", func(t *testing.T, ref *ast.TableReference) {
			if ref.Modifiers == nil || !reflect.DeepEqual(ref.Modifiers.Partitions, []string{"p0", "p1"}) || ref.Alias != "x" {
				t.Errorf("got %+v", ref.Modifiers)
			}
		}},
		{"mysql index hints", keywords.DialectMySQL, "SELECT * FROM t x FORCE INDEX FOR JOIN (ix, PRIMARY) USE KEY ()", func(t *testing.T, ref *ast.TableReference) {
			want := []ast.IndexHint{
				{Action: "FORCE", Keyword: "INDEX", For: "JOIN", Names: []string{"ix", "PRIMARY"}},
				{Action: "USE", Keyword: "KEY"},
			}
			if ref.Modifiers == nil || !reflect.DeepEqual(ref.Modifiers.IndexHints, want) || ref.Alias != "x" {
				t.Errorf("got %+v", ref.Modifiers)
			}
		}},
		{"mariadb ignore index order by", keywords.DialectMariaDB, "SELECT * FROM t IGNORE INDEX FOR ORDER BY (ix)", func(t *testing.T, ref *ast.TableReference) {
			if ref.Modifiers == nil || len(ref.Modifiers.IndexHints) != 1 || ref.Modifiers.IndexHints[0].For != "ORDER BY" || ref.Alias != "" {
				t.Errorf("got %+v / alias %q", ref.Modifiers, ref.Alias)
			}
		}},
		{"sqlite indexed by", keywords.DialectSQLite, "SELECT * FROM t AS x INDEXED BY i WHERE a = 1", func(t *testing.T, ref *ast.TableReference) {
			if ref.Modifiers == nil || ref.Modifiers.IndexedBy != "i" || ref.Alias != "x" {
				t.Errorf("got %+v", ref.Modifiers)
			}
		}},
		{"sqlite not indexed", keywords.DialectSQLite, "SELECT * FROM t NOT INDEXED", func(t *testing.T, ref *ast.TableReference) {
			if ref.Modifiers == nil || !ref.Modifiers.NotIndexed {
				t.Errorf("got %+v", ref.Modifiers)
			}
		}},
		{"sqlserver bare hint", keywords.DialectSQLServer, "SELECT * FROM t x (NOLOCK, READPAST)", func(t *testing.T, ref *ast.TableReference) {
			if !reflect.DeepEqual(ref.TableHints, []string{"NOLOCK", "READPAST"}) || ref.TableFunc != nil || ref.Alias != "x" {
				t.Errorf("got hints %v func %v alias %q", ref.TableHints, ref.TableFunc, ref.Alias)
			}
		}},
		{"sqlserver index hint", keywords.DialectSQLServer, "SELECT * FROM t WITH (NOLOCK, INDEX(ix_a, ix_b))", func(t *testing.T, ref *ast.TableReference) {
			if !reflect.DeepEqual(ref.TableHints, []string{"NOLOCK", "INDEX(ix_a, ix_b)"}) {
				t.Errorf("got %v", ref.TableHints)
			}
		}},
		{"sqlserver for system_time", keywords.DialectSQLServer, "SELECT * FROM t FOR SYSTEM_TIME CONTAINED IN ('2024-01-01', '2025-01-01') AS x", func(t *testing.T, ref *ast.TableReference) {
			f := ref.ForSystemTime
			if f == nil || f.Type != ast.SystemTimeContainedIn || f.Start == nil || f.End == nil || ref.Alias != "x" {
				t.Errorf("got %+v alias %q", f, ref.Alias)
			}
		}},
		{"mariadb for system_time before alias", keywords.DialectMariaDB, "SELECT * FROM t FOR SYSTEM_TIME ALL AS x", func(t *testing.T, ref *ast.TableReference) {
			if ref.ForSystemTime == nil || ref.ForSystemTime.Type != ast.SystemTimeAll || ref.Alias != "x" {
				t.Errorf("got %+v alias %q", ref.ForSystemTime, ref.Alias)
			}
		}},
		{"clickhouse final after alias", keywords.DialectClickHouse, "SELECT * FROM t AS x FINAL", func(t *testing.T, ref *ast.TableReference) {
			if !ref.Final || ref.Alias != "x" {
				t.Errorf("got final=%v alias=%q", ref.Final, ref.Alias)
			}
		}},
		{"values derived table", keywords.DialectPostgreSQL, "SELECT * FROM (VALUES (1, 'a'), (2, 'b')) AS v(id, name)", func(t *testing.T, ref *ast.TableReference) {
			if ref.Values == nil || len(ref.Values.Rows) != 2 || ref.Alias != "v" ||
				ref.ColumnAliases == nil || !reflect.DeepEqual(ref.ColumnAliases.Names, []string{"id", "name"}) {
				t.Errorf("got %+v", ref)
			}
		}},
		{"mysql values row", keywords.DialectMySQL, "SELECT * FROM (VALUES ROW(1, 2), ROW(3, 4)) AS v(a, b)", func(t *testing.T, ref *ast.TableReference) {
			if ref.Values == nil || !ref.Values.RowConstructor || len(ref.Values.Rows) != 2 {
				t.Errorf("got %+v", ref.Values)
			}
		}},
		{"derived table column aliases", keywords.DialectPostgreSQL, "SELECT * FROM (SELECT 1 AS x) AS s(y)", func(t *testing.T, ref *ast.TableReference) {
			if ref.Subquery == nil || ref.ColumnAliases == nil || !reflect.DeepEqual(ref.ColumnAliases.Names, []string{"y"}) {
				t.Errorf("got %+v", ref)
			}
		}},
		{"typed record function aliases", keywords.DialectPostgreSQL, "SELECT * FROM jsonb_to_recordset(j) AS t(a int, b text)", func(t *testing.T, ref *ast.TableReference) {
			if ref.TableFunc == nil || ref.ColumnAliases == nil ||
				!reflect.DeepEqual(ref.ColumnAliases.Names, []string{"a", "b"}) ||
				!reflect.DeepEqual(ref.ColumnAliases.Types, []string{"int", "text"}) {
				t.Errorf("got %+v", ref.ColumnAliases)
			}
		}},
		{"sqlserver table function", keywords.DialectSQLServer, "SELECT * FROM STRING_SPLIT('a,b', ',') s", func(t *testing.T, ref *ast.TableReference) {
			if ref.TableFunc == nil || ref.Alias != "s" {
				t.Errorf("got %+v", ref)
			}
		}},
		{"sqlite table function", keywords.DialectSQLite, "SELECT * FROM json_each('[1]')", func(t *testing.T, ref *ast.TableReference) {
			if ref.TableFunc == nil {
				t.Errorf("got %+v", ref)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, firstFrom(t, parseOne(t, tc.dialect, tc.sql)))
		})
	}
}

func TestTableFactorModifiersOnJoins(t *testing.T) {
	sel, ok := parseOne(t, keywords.DialectSnowflake,
		"SELECT * FROM t AS x SAMPLE (25) JOIN u AT (OFFSET => -60) y ON x.a = y.a").(*ast.SelectStatement)
	if !ok || len(sel.Joins) != 1 {
		t.Fatal("want a SELECT with one join")
	}
	if sel.From[0].TableSample == nil {
		t.Error("FROM sample dropped")
	}
	right := sel.Joins[0].Right
	if right.TimeTravel == nil || right.Alias != "y" {
		t.Errorf("join right = %+v", right)
	}
}

func TestCTEValuesBody(t *testing.T) {
	sel, ok := parseOne(t, keywords.DialectPostgreSQL,
		"WITH RECURSIVE r(n) AS (VALUES (1) UNION ALL SELECT n + 1 FROM r WHERE n < 5) SELECT * FROM r").(*ast.SelectStatement)
	if !ok || sel.With == nil || len(sel.With.CTEs) != 1 {
		t.Fatal("want a SELECT with one CTE")
	}
	so, ok := sel.With.CTEs[0].Statement.(*ast.SetOperation)
	if !ok {
		t.Fatalf("CTE body is %T", sel.With.CTEs[0].Statement)
	}
	if _, ok := so.Left.(*ast.Values); !ok {
		t.Errorf("left operand is %T, want *ast.Values", so.Left)
	}
}

func TestNamedArgumentKeywordNames(t *testing.T) {
	sel, ok := parseOne(t, keywords.DialectSnowflake,
		"SELECT * FROM t, LATERAL FLATTEN(input => t.a, outer => TRUE, recursive => FALSE) f").(*ast.SelectStatement)
	if !ok || len(sel.From) != 2 || sel.From[1].TableFunc == nil {
		t.Fatal("want FLATTEN table function as second FROM item")
	}
	var names []string
	for _, a := range sel.From[1].TableFunc.Arguments {
		na, ok := a.(*ast.NamedArgument)
		if !ok {
			t.Fatalf("argument is %T", a)
		}
		names = append(names, na.Name)
	}
	if !reflect.DeepEqual(names, []string{"input", "outer", "recursive"}) {
		t.Errorf("names = %v", names)
	}
}

func TestCTEKeywordNamesAndSearchCycle(t *testing.T) {
	sel, ok := parseOne(t, keywords.DialectSnowflake,
		"WITH source AS (SELECT 1 AS a), final AS (SELECT a FROM source) SELECT * FROM final").(*ast.SelectStatement)
	if !ok || sel.With == nil || len(sel.With.CTEs) != 2 {
		t.Fatal("want a SELECT with two CTEs")
	}
	if sel.With.CTEs[0].Name != "source" || sel.With.CTEs[1].Name != "final" || sel.From[0].Name != "final" {
		t.Errorf("names = %q, %q, from %q", sel.With.CTEs[0].Name, sel.With.CTEs[1].Name, sel.From[0].Name)
	}

	sel, ok = parseOne(t, keywords.DialectOracle,
		"WITH b (id) AS (SELECT 1 FROM dual) SEARCH BREADTH FIRST BY id SET ord CYCLE id SET c TO 'Y' DEFAULT 'N' SELECT * FROM b").(*ast.SelectStatement)
	if !ok || sel.With == nil || len(sel.With.CTEs) != 1 {
		t.Fatal("want a SELECT with one CTE")
	}
	cte := sel.With.CTEs[0]
	if cte.Search == nil || !cte.Search.Breadth || !reflect.DeepEqual(cte.Search.By, []string{"id"}) || cte.Search.Set != "ord" {
		t.Errorf("Search = %+v", cte.Search)
	}
	if cte.Cycle == nil || !reflect.DeepEqual(cte.Cycle.Columns, []string{"id"}) || cte.Cycle.Set != "c" ||
		cte.Cycle.To == nil || cte.Cycle.Default == nil || cte.Cycle.Using != "" {
		t.Errorf("Cycle = %+v", cte.Cycle)
	}

	// Reserved words are still rejected as CTE names.
	if tree, err := gosqlx.ParseWithDialect("WITH select AS (SELECT 1) SELECT 1", keywords.DialectPostgreSQL); err == nil {
		ast.ReleaseAST(tree)
		t.Error("WITH select AS (...) parsed")
	}
	// FINAL stays a table modifier in ClickHouse.
	if tree, err := gosqlx.ParseWithDialect("SELECT * FROM final", keywords.DialectClickHouse); err == nil {
		ast.ReleaseAST(tree)
		t.Error("ClickHouse FROM final parsed as a table name")
	}
}

func TestPivotExtensions(t *testing.T) {
	cases := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		check   func(t *testing.T, ref *ast.TableReference)
	}{
		{"aggregates with aliases", keywords.DialectOracle, "SELECT * FROM t PIVOT (SUM(c) AS total, COUNT(*) cnt FOR a IN (1 AS x))", func(t *testing.T, ref *ast.TableReference) {
			p := ref.Pivot
			if p == nil || len(p.Aggregates) != 2 || p.Aggregates[0].Alias != "total" || p.Aggregates[1].Alias != "cnt" ||
				p.AggregateFunction != p.Aggregates[0].Expr {
				t.Errorf("got %+v", p)
			}
		}},
		{"single aggregate keeps the simple form", keywords.DialectSQLServer, "SELECT * FROM t PIVOT (SUM(a) FOR q IN ([Q1])) AS p", func(t *testing.T, ref *ast.TableReference) {
			if ref.Pivot == nil || ref.Pivot.Aggregates != nil || ref.Pivot.AggregateFunction == nil || ref.Alias != "p" {
				t.Errorf("got %+v alias %q", ref.Pivot, ref.Alias)
			}
		}},
		{"source alias", keywords.DialectSQLServer, "SELECT * FROM (SELECT a, q FROM t) s PIVOT (SUM(a) FOR q IN ([Q1])) AS p", func(t *testing.T, ref *ast.TableReference) {
			if ref.Pivot == nil || ref.Pivot.SourceAlias != "s" || ref.Alias != "p" {
				t.Errorf("got source %+v alias %q", ref.Pivot, ref.Alias)
			}
		}},
		{"xml any", keywords.DialectOracle, "SELECT * FROM t PIVOT XML (SUM(a) FOR p IN (ANY))", func(t *testing.T, ref *ast.TableReference) {
			if ref.Pivot == nil || !ref.Pivot.XML || !ref.Pivot.InAny {
				t.Errorf("got %+v", ref.Pivot)
			}
		}},
		{"any order by", keywords.DialectSnowflake, "SELECT * FROM t PIVOT (AVG(a) FOR q IN (ANY ORDER BY q DESC))", func(t *testing.T, ref *ast.TableReference) {
			if ref.Pivot == nil || !ref.Pivot.InAny || len(ref.Pivot.InAnyOrderBy) != 1 || ref.Pivot.InAnyOrderBy[0].Ascending {
				t.Errorf("got %+v", ref.Pivot)
			}
		}},
		{"in subquery", keywords.DialectSnowflake, "SELECT * FROM t PIVOT (AVG(a) FOR q IN (SELECT q FROM u))", func(t *testing.T, ref *ast.TableReference) {
			if ref.Pivot == nil || ref.Pivot.InSubquery == nil {
				t.Errorf("got %+v", ref.Pivot)
			}
		}},
		{"alias column list", keywords.DialectSnowflake, "SELECT * FROM m PIVOT (SUM(a) FOR q IN ('A')) AS p (k, a)", func(t *testing.T, ref *ast.TableReference) {
			if ref.Alias != "p" || ref.ColumnAliases == nil || !reflect.DeepEqual(ref.ColumnAliases.Names, []string{"k", "a"}) {
				t.Errorf("got alias %q columns %+v", ref.Alias, ref.ColumnAliases)
			}
		}},
		{"unpivot nulls and columns", keywords.DialectOracle, "SELECT * FROM w UNPIVOT EXCLUDE NULLS ((u, r) FOR p IN ((u1, r1) AS 'P1'))", func(t *testing.T, ref *ast.TableReference) {
			u := ref.Unpivot
			if u == nil || u.NullHandling != "EXCLUDE" || !reflect.DeepEqual(u.ValueColumns, []string{"u", "r"}) ||
				u.ValueColumn != "u" || !reflect.DeepEqual(u.InColumns, []string{"(u1, r1) AS 'P1'"}) {
				t.Errorf("got %+v", u)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, firstFrom(t, parseOne(t, tc.dialect, tc.sql)))
		})
	}
}

func TestSnowflakeFromValuesAndStagePath(t *testing.T) {
	ref := firstFrom(t, parseOne(t, keywords.DialectSnowflake, "SELECT * FROM VALUES (1, 'a'), (2, 'b') AS v (id, name)"))
	if ref.Values == nil || len(ref.Values.Rows) != 2 || ref.Alias != "v" {
		t.Errorf("got %+v", ref)
	}
	ref = firstFrom(t, parseOne(t, keywords.DialectSnowflake, "SELECT $1 FROM @my_stage/2024/data.csv (FILE_FORMAT => 'f') t"))
	if ref.Name != "@my_stage/2024/data.csv" || ref.TableFunc == nil || ref.Alias != "t" {
		t.Errorf("got name %q func %v alias %q", ref.Name, ref.TableFunc, ref.Alias)
	}
}

func TestQualifiedNameForms(t *testing.T) {
	ref := firstFrom(t, parseOne(t, keywords.DialectSQLServer, "SELECT * FROM db..t"))
	if ref.Name != "db..t" {
		t.Errorf("name = %q, want db..t", ref.Name)
	}
	if tree, err := gosqlx.ParseWithDialect("SELECT * FROM db..t", keywords.DialectPostgreSQL); err == nil {
		ast.ReleaseAST(tree)
		t.Error("db..t parsed outside SQL Server")
	}
	sel, ok := parseOne(t, keywords.DialectSnowflake, "SELECT t.$1 FROM @s t").(*ast.SelectStatement)
	if !ok || len(sel.Columns) != 1 {
		t.Fatal("want one select column")
	}
	id, ok := sel.Columns[0].(*ast.Identifier)
	if !ok || id.Table != "t" || id.Name != "$1" {
		t.Errorf("column = %#v", sel.Columns[0])
	}
	ref = firstFrom(t, parseOne(t, keywords.DialectSQLServer, "SELECT * FROM OPENJSON(@j) WITH (Id INT '$.id', R NVARCHAR(MAX) AS JSON) AS x"))
	want := []ast.OpenJSONColumn{{Name: "Id", Type: "INT", Path: "$.id"}, {Name: "R", Type: "NVARCHAR(MAX)", AsJSON: true}}
	if ref.Modifiers == nil || !reflect.DeepEqual(ref.Modifiers.WithSchema, want) || ref.Alias != "x" || len(ref.TableHints) != 0 {
		t.Errorf("got %+v alias %q hints %v", ref.Modifiers, ref.Alias, ref.TableHints)
	}
}
