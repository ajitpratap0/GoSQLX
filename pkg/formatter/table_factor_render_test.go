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
	"reflect"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestRender_QueryExpressionsAndTableFactors checks that set operations,
// CTE modifiers and table-factor modifiers survive the formatter and
// tree.SQL(): the compact output must equal want, re-parse with the same
// dialect and format to itself again.
func TestRender_QueryExpressionsAndTableFactors(t *testing.T) {
	cases := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		// Set operations
		{"intersect precedence", keywords.DialectPostgreSQL, "SELECT 1 UNION SELECT 2 INTERSECT SELECT 3", "SELECT 1 UNION SELECT 2 INTERSECT SELECT 3"},
		{"intersect precedence trailing order by", keywords.DialectPostgreSQL, "SELECT 1 UNION SELECT 2 INTERSECT SELECT 3 ORDER BY 1 LIMIT 1", "SELECT 1 UNION SELECT 2 INTERSECT SELECT 3 ORDER BY 1 LIMIT 1"},
		{"explicit grouping kept", keywords.DialectPostgreSQL, "(SELECT 1 UNION SELECT 2) INTERSECT SELECT 3", "(SELECT 1 UNION SELECT 2) INTERSECT SELECT 3"},
		{"right grouping kept", keywords.DialectPostgreSQL, "SELECT 1 INTERSECT (SELECT 2 UNION SELECT 3)", "SELECT 1 INTERSECT (SELECT 2 UNION SELECT 3)"},
		{"intersect distinct", keywords.DialectMariaDB, "SELECT a FROM t1 INTERSECT DISTINCT SELECT a FROM t2", "SELECT a FROM t1 INTERSECT DISTINCT SELECT a FROM t2"},
		{"union distinct", keywords.DialectMySQL, "SELECT a FROM t1 UNION DISTINCT SELECT a FROM t2", "SELECT a FROM t1 UNION DISTINCT SELECT a FROM t2"},
		{"oracle minus", keywords.DialectOracle, "SELECT a FROM t MINUS SELECT a FROM u", "SELECT a FROM t MINUS SELECT a FROM u"},
		{"values operand", keywords.DialectPostgreSQL, "SELECT 1 UNION VALUES (2)", "SELECT 1 UNION VALUES (2)"},
		// CTEs
		{"not materialized", keywords.DialectPostgreSQL, "WITH a AS NOT MATERIALIZED (SELECT 1 AS x) SELECT * FROM a", "WITH a AS NOT MATERIALIZED (SELECT 1 AS x) SELECT * FROM a"},
		{"materialized sqlite", keywords.DialectSQLite, "WITH a AS MATERIALIZED (SELECT 1 AS x) SELECT * FROM a", "WITH a AS MATERIALIZED (SELECT 1 AS x) SELECT * FROM a"},
		{"clickhouse scalar cte", keywords.DialectClickHouse, "WITH (SELECT max(ts) FROM t) AS latest SELECT 1", "WITH (SELECT max(ts) FROM t) AS latest SELECT 1"},
		{"cte values body", keywords.DialectSQLite, "WITH c AS (VALUES (1), (2)) SELECT * FROM c", "WITH c AS (VALUES (1), (2)) SELECT * FROM c"},
		{"recursive cte seeded by values", keywords.DialectPostgreSQL, "WITH RECURSIVE r(n) AS (VALUES (1) UNION ALL SELECT n + 1 FROM r WHERE n < 5) SELECT * FROM r", "WITH RECURSIVE r (n) AS (VALUES (1) UNION ALL SELECT n + 1 FROM r WHERE n < 5) SELECT * FROM r"},
		// Table-factor modifiers
		{"clickhouse final", keywords.DialectClickHouse, "SELECT * FROM t AS x FINAL WHERE a = 1", "SELECT * FROM t x FINAL WHERE a = 1"},
		{"snowflake at", keywords.DialectSnowflake, "SELECT * FROM t AT (OFFSET => -60)", "SELECT * FROM t AT (OFFSET => -60)"},
		{"snowflake changes", keywords.DialectSnowflake, "SELECT * FROM t CHANGES (INFORMATION => DEFAULT) AT (OFFSET => -1) x", "SELECT * FROM t CHANGES (INFORMATION => DEFAULT) AT (OFFSET => -1) x"},
		{"mariadb system time", keywords.DialectMariaDB, "SELECT * FROM accounts FOR SYSTEM_TIME AS OF TIMESTAMP '2025-01-01 00:00:00' WHERE id = 1", "SELECT * FROM accounts FOR SYSTEM_TIME AS OF TIMESTAMP '2025-01-01 00:00:00' WHERE id = 1"},
		{"sqlserver system time", keywords.DialectSQLServer, "SELECT * FROM t FOR SYSTEM_TIME CONTAINED IN ('2024-01-01', '2025-01-01') AS x", "SELECT * FROM t FOR SYSTEM_TIME CONTAINED IN ('2024-01-01', '2025-01-01') x"},
		{"match recognize", keywords.DialectSnowflake,
			"SELECT * FROM ticker MATCH_RECOGNIZE (PARTITION BY symbol ORDER BY ts MEASURES MATCH_NUMBER() AS m ALL ROWS PER MATCH AFTER MATCH SKIP PAST LAST ROW PATTERN (UP+ DOWN*?) DEFINE UP AS price > PREV(price), DOWN AS price < PREV(price)) mr",
			"SELECT * FROM ticker MATCH_RECOGNIZE (PARTITION BY symbol ORDER BY ts MEASURES MATCH_NUMBER() AS m ALL ROWS PER MATCH AFTER MATCH SKIP PAST LAST ROW PATTERN (UP+ DOWN*?) DEFINE UP AS price > PREV(price), DOWN AS price < PREV(price)) AS mr"},
		{"pg tablesample", keywords.DialectPostgreSQL, "SELECT * FROM sales s TABLESAMPLE BERNOULLI (10) REPEATABLE (1)", "SELECT * FROM sales s TABLESAMPLE BERNOULLI (10) REPEATABLE (1)"},
		{"sqlserver tablesample", keywords.DialectSQLServer, "SELECT * FROM sales TABLESAMPLE (10 PERCENT)", "SELECT * FROM sales TABLESAMPLE (10 PERCENT)"},
		{"snowflake sample", keywords.DialectSnowflake, "SELECT * FROM t SAMPLE ROW (10 ROWS) SEED (7)", "SELECT * FROM t SAMPLE ROW (10 ROWS) SEED (7)"},
		{"oracle sample", keywords.DialectOracle, "SELECT * FROM t SAMPLE BLOCK (10, 2) SEED (5) x", "SELECT * FROM t SAMPLE BLOCK (10, 2) SEED (5) x"},
		{"pg only", keywords.DialectPostgreSQL, "SELECT * FROM ONLY parent_tbl p JOIN ONLY c ON p.id = c.id", "SELECT * FROM ONLY parent_tbl p INNER JOIN ONLY c ON p.id = c.id"},
		{"oracle flashback", keywords.DialectOracle, "SELECT * FROM t AS OF SCN 123 x", "SELECT * FROM t AS OF SCN 123 x"},
		{"oracle versions", keywords.DialectOracle, "SELECT * FROM t VERSIONS BETWEEN SCN MINVALUE AND MAXVALUE", "SELECT * FROM t VERSIONS BETWEEN SCN MINVALUE AND MAXVALUE"},
		{"oracle db link", keywords.DialectOracle, "SELECT * FROM t@lnk.example.com x", "SELECT * FROM t@lnk.example.com x"},
		{"mysql partition", keywords.DialectMySQL, "SELECT * FROM t PARTITION (p0, p1) AS x", "SELECT * FROM t PARTITION (p0, p1) x"},
		{"oracle partition", keywords.DialectOracle, "SELECT * FROM sales PARTITION (sales_q1) s", "SELECT * FROM sales PARTITION (sales_q1) s"},
		{"mysql index hints", keywords.DialectMySQL, "SELECT * FROM t x FORCE INDEX FOR JOIN (ix, PRIMARY) USE KEY ()", "SELECT * FROM t x FORCE INDEX FOR JOIN (ix, PRIMARY) USE KEY ()"},
		{"sqlite indexed by", keywords.DialectSQLite, "SELECT * FROM t AS x INDEXED BY i WHERE a = 1", "SELECT * FROM t x INDEXED BY i WHERE a = 1"},
		{"sqlite not indexed", keywords.DialectSQLite, "SELECT * FROM t NOT INDEXED", "SELECT * FROM t NOT INDEXED"},
		{"sqlserver bare hints", keywords.DialectSQLServer, "SELECT * FROM t x (NOLOCK)", "SELECT * FROM t x WITH (NOLOCK)"},
		{"sqlserver index hint", keywords.DialectSQLServer, "SELECT * FROM t WITH (NOLOCK, INDEX = ix_a)", "SELECT * FROM t WITH (NOLOCK, INDEX(ix_a))"},
		{"values derived table", keywords.DialectPostgreSQL, "SELECT * FROM (VALUES (1, 'a'), (2, 'b')) AS v(id, name)", "SELECT * FROM (VALUES (1, 'a'), (2, 'b')) v(id, name)"},
		{"mysql values row", keywords.DialectMySQL, "SELECT * FROM (VALUES ROW(1, 2), ROW(3, 4)) AS v(a, b)", "SELECT * FROM (VALUES ROW(1, 2), ROW(3, 4)) v(a, b)"},
		{"derived column aliases", keywords.DialectPostgreSQL, "SELECT * FROM (SELECT 1 AS x) AS s(y)", "SELECT * FROM (SELECT 1 AS x) s(y)"},
		{"table column aliases", keywords.DialectSnowflake, "SELECT * FROM t AS x(a, b)", "SELECT * FROM t x(a, b)"},
		{"typed record aliases", keywords.DialectPostgreSQL, "SELECT * FROM jsonb_to_recordset(j) AS t(a int, b text)", "SELECT * FROM jsonb_to_recordset(j) t(a int, b text)"},
		{"sqlserver table function", keywords.DialectSQLServer, "SELECT * FROM STRING_SPLIT('a,b', ',')", "SELECT * FROM STRING_SPLIT('a,b', ',')"},
		{"sqlite table function", keywords.DialectSQLite, "SELECT * FROM t, json_each(t.a)", "SELECT * FROM t, json_each(t.a)"},
		{"flatten keyword arguments", keywords.DialectSnowflake, "SELECT * FROM t, LATERAL FLATTEN(input => t.a, outer => TRUE) f", "SELECT * FROM t, LATERAL FLATTEN(input => t.a, outer => TRUE) f"},
		// CTE names and SEARCH / CYCLE
		{"keyword cte names", keywords.DialectSnowflake, "WITH source AS (SELECT 1 AS a), target AS (SELECT a FROM source) SELECT * FROM target", "WITH source AS (SELECT 1 AS a), target AS (SELECT a FROM source) SELECT * FROM target"},
		{"final cte name", keywords.DialectSnowflake, "WITH final AS (SELECT 1 AS a) SELECT * FROM final", "WITH final AS (SELECT 1 AS a) SELECT * FROM final"},
		{"cte search", keywords.DialectPostgreSQL, "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 5) SEARCH BREADTH FIRST BY n SET ord SELECT * FROM r ORDER BY ord", "WITH RECURSIVE r (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 5) SEARCH BREADTH FIRST BY n SET ord SELECT * FROM r ORDER BY ord"},
		{"cte cycle using", keywords.DialectPostgreSQL, "WITH RECURSIVE r AS (SELECT 1 AS n UNION SELECT n + 1 FROM r) CYCLE n SET is_cycle USING path SELECT * FROM r", "WITH RECURSIVE r AS (SELECT 1 AS n UNION SELECT n + 1 FROM r) CYCLE n SET is_cycle USING path SELECT * FROM r"},
		{"oracle search and cycle", keywords.DialectOracle, "WITH b (id, pid) AS (SELECT id, pid FROM p UNION ALL SELECT p.id, p.pid FROM p JOIN b ON p.pid = b.id) SEARCH DEPTH FIRST BY id SET ord CYCLE id SET is_cycle TO 'Y' DEFAULT 'N' SELECT * FROM b", "WITH b (id, pid) AS (SELECT id, pid FROM p UNION ALL SELECT p.id, p.pid FROM p INNER JOIN b ON p.pid = b.id) SEARCH DEPTH FIRST BY id SET ord CYCLE id SET is_cycle TO 'Y' DEFAULT 'N' SELECT * FROM b"},
		// Snowflake FROM forms
		{"snowflake bare values", keywords.DialectSnowflake, "SELECT * FROM VALUES (1, 'a'), (2, 'b') AS v (id, name)", "SELECT * FROM (VALUES (1, 'a'), (2, 'b')) v(id, name)"},
		{"snowflake stage file", keywords.DialectSnowflake, "SELECT $1, $2 FROM @my_stage/data.csv (FILE_FORMAT => 'my_csv')", "SELECT $1, $2 FROM @my_stage/data.csv (FILE_FORMAT => 'my_csv')"},
		{"snowflake qualified positional column", keywords.DialectSnowflake, "SELECT t.$1 AS id FROM @my_stage/users/ (FILE_FORMAT => 'my_csv') t", "SELECT t.$1 AS id FROM @my_stage/users/ (FILE_FORMAT => 'my_csv') t"},
		{"sqlserver default schema", keywords.DialectSQLServer, "SELECT x.a FROM srv.db..t AS x", "SELECT x.a FROM srv.db..t x"},
		{"sqlserver openjson schema", keywords.DialectSQLServer, "SELECT * FROM OPENJSON(@json) WITH (Id INT '$.id', Raw NVARCHAR(MAX) '$.raw' AS JSON) AS j", "SELECT * FROM OPENJSON(@json) WITH (Id INT '$.id', Raw NVARCHAR(MAX) '$.raw' AS JSON) j"},
		// PIVOT / UNPIVOT
		{"oracle multi aggregate pivot", keywords.DialectOracle, "SELECT * FROM (SELECT a, b, c FROM t) PIVOT (SUM(c) AS total, COUNT(*) AS cnt FOR a IN (1 AS x, 2 AS y))", "SELECT * FROM (SELECT a, b, c FROM t) PIVOT (SUM(c) AS total, COUNT(*) AS cnt FOR a IN (1 AS x, 2 AS y))"},
		{"pivot source alias", keywords.DialectSQLServer, "SELECT * FROM (SELECT a, q FROM t) s PIVOT (SUM(a) FOR q IN ([Q1], [Q2])) AS p", "SELECT * FROM (SELECT a, q FROM t) s PIVOT (SUM(a) FOR q IN ([Q1], [Q2])) AS p"},
		{"pivot xml any", keywords.DialectOracle, "SELECT * FROM sales PIVOT XML (SUM(amount) FOR product IN (ANY))", "SELECT * FROM sales PIVOT XML (SUM(amount) FOR product IN (ANY))"},
		{"pivot any order by", keywords.DialectSnowflake, "SELECT * FROM q PIVOT (AVG(amount) FOR quarter IN (ANY ORDER BY quarter))", "SELECT * FROM q PIVOT (AVG(amount) FOR quarter IN (ANY ORDER BY quarter))"},
		{"pivot in subquery", keywords.DialectSnowflake, "SELECT * FROM q PIVOT (AVG(amount) FOR quarter IN (SELECT DISTINCT quarter FROM qs))", "SELECT * FROM q PIVOT (AVG(amount) FOR quarter IN (SELECT DISTINCT quarter FROM qs))"},
		{"pivot alias columns", keywords.DialectSnowflake, "SELECT * FROM m PIVOT (SUM(amount) FOR month IN ('JAN', 'FEB')) AS p (emp_id, jan, feb)", "SELECT * FROM m PIVOT (SUM(amount) FOR month IN ('JAN', 'FEB')) AS p(emp_id, jan, feb)"},
		{"unpivot include nulls", keywords.DialectSnowflake, "SELECT * FROM m UNPIVOT INCLUDE NULLS (sales FOR month IN (jan, feb)) AS u", "SELECT * FROM m UNPIVOT INCLUDE NULLS (sales FOR month IN (jan, feb)) AS u"},
		{"multi-column unpivot", keywords.DialectOracle, "SELECT * FROM w UNPIVOT ((units, revenue) FOR period IN ((u1, r1) AS 'P1', (u2, r2) AS 'P2'))", "SELECT * FROM w UNPIVOT ((units, revenue) FOR period IN ((u1, r1) AS 'P1', (u2, r2) AS 'P2'))"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			defer ast.ReleaseAST(tree)
			got := formatter.FormatAST(tree, ast.CompactStyle())
			if got != tc.want {
				t.Errorf("formatter:\n got: %s\nwant: %s", got, tc.want)
			}
			if sql := tree.SQL(); sql != tc.want {
				t.Errorf("SQL():\n got: %s\nwant: %s", sql, tc.want)
			}
			tree2, err := gosqlx.ParseWithDialect(got, tc.dialect)
			if err != nil {
				t.Fatalf("re-parse %q: %v", got, err)
			}
			defer ast.ReleaseAST(tree2)
			if again := formatter.FormatAST(tree2, ast.CompactStyle()); again != got {
				t.Errorf("not idempotent:\n first: %s\nsecond: %s", got, again)
			}
			readable := formatter.FormatAST(tree, ast.ReadableStyle())
			if _, err := gosqlx.ParseWithDialect(readable, tc.dialect); err != nil {
				t.Errorf("readable output does not re-parse: %v\n%s", err, readable)
			}
		})
	}
}

// TestRender_SetOperationTargetDialect checks the dialect-dependent parts of
// set-operation rendering: MINUS is written as EXCEPT for a dialect without
// MINUS, and a right-nested INTERSECT keeps its parentheses for a dialect
// that gives all set operators equal precedence.
func TestRender_SetOperationTargetDialect(t *testing.T) {
	cases := []struct {
		name    string
		parseIn keywords.SQLDialect
		sql     string
		target  string
		want    string
	}{
		{"minus to postgres", keywords.DialectOracle, "SELECT a FROM t MINUS SELECT a FROM u", "postgresql", "SELECT a FROM t EXCEPT SELECT a FROM u"},
		{"minus to snowflake", keywords.DialectOracle, "SELECT a FROM t MINUS SELECT a FROM u", "snowflake", "SELECT a FROM t MINUS SELECT a FROM u"},
		{"precedence to sqlite", keywords.DialectPostgreSQL, "SELECT 1 UNION SELECT 2 INTERSECT SELECT 3", "sqlite", "SELECT 1 UNION (SELECT 2 INTERSECT SELECT 3)"},
		{"precedence to oracle", keywords.DialectPostgreSQL, "SELECT 1 UNION SELECT 2 INTERSECT SELECT 3", "oracle", "SELECT 1 UNION (SELECT 2 INTERSECT SELECT 3)"},
		{"precedence to mysql", keywords.DialectPostgreSQL, "SELECT 1 UNION SELECT 2 INTERSECT SELECT 3", "mysql", "SELECT 1 UNION SELECT 2 INTERSECT SELECT 3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, tc.parseIn)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			defer ast.ReleaseAST(tree)
			opts := ast.CompactStyle()
			opts.Dialect = tc.target
			if got := formatter.FormatAST(tree, opts); got != tc.want {
				t.Errorf("got  %s\nwant %s", got, tc.want)
			}
		})
	}
}

// TestRender_TableFactorKeywordCase checks that the table-factor and CTE
// keywords follow the formatter's keyword case.
func TestRender_TableFactorKeywordCase(t *testing.T) {
	cases := []struct {
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		{keywords.DialectPostgreSQL, "WITH a AS NOT MATERIALIZED (SELECT 1) SELECT * FROM ONLY a TABLESAMPLE SYSTEM (5) REPEATABLE (2)",
			"with a as not materialized (select 1) select * from only a tablesample system (5) repeatable (2)"},
		{keywords.DialectMySQL, "SELECT * FROM t PARTITION (P0) USE INDEX FOR ORDER BY (Ix)",
			"select * from t partition (P0) use index for order by (Ix)"},
		{keywords.DialectSQLServer, "SELECT * FROM t FOR SYSTEM_TIME ALL WITH (NOLOCK, INDEX(Ix))",
			"select * from t for system_time all with (nolock, index(Ix))"},
		{keywords.DialectOracle, "SELECT a FROM t AS OF SCN 1 MINUS SELECT a FROM u",
			"select a from t as of scn 1 minus select a from u"},
	}
	for _, tc := range cases {
		tree, err := gosqlx.ParseWithDialect(tc.sql, tc.dialect)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.sql, err)
		}
		opts := ast.CompactStyle()
		opts.KeywordCase = ast.KeywordLower
		got := formatter.FormatAST(tree, opts)
		ast.ReleaseAST(tree)
		if got != tc.want {
			t.Errorf("got  %s\nwant %s", got, tc.want)
		}
	}
}

// tableRefFieldSamples gives a non-zero sample for every exported
// TableReference field. A new field fails TestRender_TableReferenceRendersEveryField
// until it is added here (and rendered) or to tableRefFieldsNotRendered.
func tableRefFieldSamples() map[string]func(*ast.TableReference) {
	ident := func(n string) *ast.Identifier { return &ast.Identifier{Name: n} }
	num := func(v string) *ast.LiteralValue { return &ast.LiteralValue{Value: v, Type: "int"} }
	sub := func() *ast.SelectStatement { return &ast.SelectStatement{Columns: []ast.Expression{ident("s")}} }
	return map[string]func(*ast.TableReference){
		"Name":  func(r *ast.TableReference) { r.Name = "other" },
		"Alias": func(r *ast.TableReference) { r.Alias = "y" },
		// A recorded NameQuote keeps the base name "t" / alias "x" quoted.
		"NameQuote":  func(r *ast.TableReference) { r.NameQuote = ast.QuotedName('"') },
		"AliasQuote": func(r *ast.TableReference) { r.AliasQuote = ast.QuotedName('"') },
		"Subquery":   func(r *ast.TableReference) { r.Subquery = sub() },
		"Lateral":    func(r *ast.TableReference) { r.Lateral = true },
		"Final":      func(r *ast.TableReference) { r.Final = true },
		"WithOrdinality": func(r *ast.TableReference) {
			r.WithOrdinality = true
		},
		"TableHints": func(r *ast.TableReference) { r.TableHints = []string{"NOLOCK"} },
		"TableFunc": func(r *ast.TableReference) {
			r.TableFunc = &ast.FunctionCall{Name: "f", Arguments: []ast.Expression{num("1")}}
		},
		"ColumnAliases": func(r *ast.TableReference) { r.ColumnAliases = &ast.ColumnAliasList{Names: []string{"c"}} },
		"TimeTravel": func(r *ast.TableReference) {
			r.TimeTravel = &ast.TimeTravelClause{Kind: "AT", Named: map[string]ast.Expression{"OFFSET": num("1")}}
		},
		"ForSystemTime": func(r *ast.TableReference) {
			r.ForSystemTime = &ast.ForSystemTimeClause{Type: ast.SystemTimeAll}
		},
		"Pivot": func(r *ast.TableReference) {
			r.Pivot = &ast.PivotClause{AggregateFunction: &ast.FunctionCall{Name: "SUM", Arguments: []ast.Expression{ident("v")}}, PivotColumn: "k", InValues: []string{"1"}}
		},
		"Unpivot": func(r *ast.TableReference) {
			r.Unpivot = &ast.UnpivotClause{ValueColumn: "v", NameColumn: "k", InColumns: []string{"a"}}
		},
		"MatchRecognize": func(r *ast.TableReference) {
			r.MatchRecognize = &ast.MatchRecognizeClause{Pattern: "A+", Definitions: []ast.PatternDef{{Name: "A", Condition: ident("ok")}}}
		},
		"SetSubquery": func(r *ast.TableReference) {
			r.SetSubquery = &ast.SetOperation{Left: sub(), Operator: "UNION", Right: sub()}
		},
		"Only": func(r *ast.TableReference) { r.Only = true },
		"Modifiers": func(r *ast.TableReference) {
			r.Modifiers = &ast.TableModifiers{
				TableSample: &ast.TableSampleClause{Keyword: "TABLESAMPLE", Method: "SYSTEM", Args: []ast.Expression{num("5")}, AfterAlias: true},
				Flashback:   &ast.FlashbackClause{Kind: "SCN", Point: num("9")},
				DBLink:      "lnk",
				Partitions:  []string{"p0"},
				IndexHints:  []ast.IndexHint{{Action: "USE", Keyword: "INDEX", Names: []string{"ix"}}},
				IndexedBy:   "i",
			}
		},
		"Values": func(r *ast.TableReference) {
			r.Values = &ast.Values{Rows: [][]ast.Expression{{num("1")}}}
		},
	}
}

// tableRefFieldsNotRendered are TableReference fields that carry no SQL text.
var tableRefFieldsNotRendered = map[string]string{}

// TestRender_TableReferenceRendersEveryField sets each exported
// TableReference field in turn and asserts that both pkg/formatter and
// SelectStatement.SQL() output change, so a parsed table modifier cannot be
// silently dropped by either renderer.
func TestRender_TableReferenceRendersEveryField(t *testing.T) {
	base := func() *ast.SelectStatement {
		return &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "a"}},
			From:    []ast.TableReference{{Name: "t", Alias: "x"}},
		}
	}
	// WITH ORDINALITY is written only for a table function.
	baseFor := map[string]func(*ast.TableReference){
		"WithOrdinality": func(r *ast.TableReference) {
			r.TableFunc = &ast.FunctionCall{Name: "f"}
		},
	}
	samples := tableRefFieldSamples()
	typ := reflect.TypeOf(ast.TableReference{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		name := field.Name
		if _, skip := tableRefFieldsNotRendered[name]; skip {
			continue
		}
		set, ok := samples[name]
		if !ok {
			t.Errorf("TableReference.%s has no render sample: add one to tableRefFieldSamples and render it", name)
			continue
		}
		t.Run(name, func(t *testing.T) {
			before, after := base(), base()
			if prep := baseFor[name]; prep != nil {
				prep(&before.From[0])
				prep(&after.From[0])
			}
			set(&after.From[0])
			opts := ast.CompactStyle()
			f0, f1 := formatter.FormatStatement(before, opts), formatter.FormatStatement(after, opts)
			if f0 == f1 {
				t.Errorf("formatter ignores %s: %s", name, f1)
			}
			if s0, s1 := before.SQL(), after.SQL(); s0 == s1 {
				t.Errorf("SQL() ignores %s: %s", name, s1)
			}
		})
	}
}

// TestRender_TableModifiersRendersEveryField sets each exported
// TableModifiers field in turn and asserts that both renderers write it.
func TestRender_TableModifiersRendersEveryField(t *testing.T) {
	num := func(v string) *ast.LiteralValue { return &ast.LiteralValue{Value: v, Type: "int"} }
	samples := map[string]func(*ast.TableModifiers){
		"TableSample": func(m *ast.TableModifiers) {
			m.TableSample = &ast.TableSampleClause{Keyword: "SAMPLE", Args: []ast.Expression{num("5")}}
		},
		"Flashback":  func(m *ast.TableModifiers) { m.Flashback = &ast.FlashbackClause{Kind: "SCN", Point: num("9")} },
		"DBLink":     func(m *ast.TableModifiers) { m.DBLink = "lnk" },
		"Partitions": func(m *ast.TableModifiers) { m.Partitions = []string{"p0"} },
		"IndexHints": func(m *ast.TableModifiers) {
			m.IndexHints = []ast.IndexHint{{Action: "FORCE", Keyword: "INDEX", Names: []string{"ix"}}}
		},
		"IndexedBy":  func(m *ast.TableModifiers) { m.IndexedBy = "i" },
		"NotIndexed": func(m *ast.TableModifiers) { m.NotIndexed = true },
		"PartitionFor": func(m *ast.TableModifiers) {
			m.PartitionFor = &ast.PartitionForClause{Values: []ast.Expression{num("1")}}
		},
		"Group": func(m *ast.TableModifiers) {
			m.Group = &ast.JoinGroup{Tables: []ast.TableReference{{Name: "u"}, {Name: "v"}}}
		},
		"WithSchema": func(m *ast.TableModifiers) {
			m.WithSchema = []ast.OpenJSONColumn{{Name: "id", Type: "INT", Path: "$.id"}}
		},
	}
	typ := reflect.TypeOf(ast.TableModifiers{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		set, ok := samples[name]
		if !ok {
			t.Errorf("TableModifiers.%s has no render sample", name)
			continue
		}
		t.Run(name, func(t *testing.T) {
			stmt := &ast.SelectStatement{
				Columns: []ast.Expression{&ast.Identifier{Name: "a"}},
				From:    []ast.TableReference{{Name: "t", Alias: "x", Modifiers: &ast.TableModifiers{}}},
			}
			before := formatter.FormatStatement(stmt, ast.CompactStyle())
			beforeSQL := stmt.SQL()
			set(stmt.From[0].Modifiers)
			if after := formatter.FormatStatement(stmt, ast.CompactStyle()); after == before {
				t.Errorf("formatter ignores %s: %s", name, after)
			}
			if after := stmt.SQL(); after == beforeSQL {
				t.Errorf("SQL() ignores %s: %s", name, after)
			}
		})
	}
}
