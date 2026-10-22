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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestRender_SelectBodyClauses checks that SELECT-body clauses survive the
// formatter and tree.SQL(): the compact output must equal want, re-parse with
// the same dialect, and format to itself again.
func TestRender_SelectBodyClauses(t *testing.T) {
	cases := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		{"limit placeholder", keywords.DialectPostgreSQL, "SELECT 1 FROM t LIMIT $1 OFFSET $2", "SELECT 1 FROM t LIMIT $1 OFFSET $2"},
		{"limit all offset rows", keywords.DialectPostgreSQL, "SELECT * FROM t LIMIT ALL OFFSET 5 ROWS", "SELECT * FROM t LIMIT ALL OFFSET 5 ROWS"},
		{"offset before limit", keywords.DialectPostgreSQL, "SELECT * FROM t OFFSET 10 LIMIT 5", "SELECT * FROM t LIMIT 5 OFFSET 10"},
		{"limit expression", keywords.DialectPostgreSQL, "SELECT * FROM t LIMIT (SELECT 1)", "SELECT * FROM t LIMIT (SELECT 1)"},
		{"fetch first row", keywords.DialectPostgreSQL, "SELECT * FROM t FETCH FIRST ROW ONLY", "SELECT * FROM t FETCH FIRST ROW ONLY"},
		{"order by using", keywords.DialectPostgreSQL, "SELECT a FROM t ORDER BY a USING <", "SELECT a FROM t ORDER BY a USING <"},
		{"select into postgres", keywords.DialectPostgreSQL, "SELECT * INTO TEMP TABLE n FROM o WHERE x > 1", "SELECT * INTO TEMP TABLE n FROM o WHERE x > 1"},
		{"where without from", keywords.DialectPostgreSQL, "SELECT 1 WHERE 1 = 1", "SELECT 1 WHERE 1 = 1"},
		{"mysql limit offset count", keywords.DialectMySQL, "SELECT * FROM t LIMIT ?, ?", "SELECT * FROM t LIMIT ? OFFSET ?"},
		{"mysql with rollup", keywords.DialectMySQL, "SELECT a, b FROM t GROUP BY a, b WITH ROLLUP", "SELECT a, b FROM t GROUP BY a, b WITH ROLLUP"},
		{"mysql modifiers", keywords.DialectMySQL, "SELECT SQL_CALC_FOUND_ROWS * FROM t", "SELECT SQL_CALC_FOUND_ROWS * FROM t"},
		{"mysql straight join", keywords.DialectMySQL, "SELECT * FROM a STRAIGHT_JOIN b ON a.id = b.id", "SELECT * FROM a STRAIGHT_JOIN b ON a.id = b.id"},
		{"mysql join without on", keywords.DialectMySQL, "SELECT * FROM a JOIN b", "SELECT * FROM a INNER JOIN b"},
		{"mysql comma after join", keywords.DialectMySQL, "SELECT * FROM a LEFT JOIN b ON a.id = b.id, t3", "SELECT * FROM a LEFT JOIN b ON a.id = b.id , t3"},
		{"mysql lock in share mode", keywords.DialectMySQL, "SELECT * FROM t WHERE id = 1 LOCK IN SHARE MODE", "SELECT * FROM t WHERE id = 1 LOCK IN SHARE MODE"},
		{"mysql into vars", keywords.DialectMySQL, "SELECT a, b INTO @x, @y FROM t", "SELECT a, b INTO @x, @y FROM t"},
		{"mysql outfile", keywords.DialectMySQL, "SELECT * FROM o INTO OUTFILE '/tmp/o.csv' FIELDS TERMINATED BY ',' LINES TERMINATED BY ';'", "SELECT * FROM o INTO OUTFILE '/tmp/o.csv' FIELDS TERMINATED BY ',' LINES TERMINATED BY ';'"},
		{"mariadb wait", keywords.DialectMariaDB, "SELECT * FROM t FOR UPDATE WAIT 5", "SELECT * FROM t FOR UPDATE WAIT 5"},
		{"sqlite negative limit", keywords.DialectSQLite, "SELECT a FROM t LIMIT -1 OFFSET 5", "SELECT a FROM t LIMIT -1 OFFSET 5"},
		{"sqlserver offset rows fetch", keywords.DialectSQLServer, "SELECT a FROM t ORDER BY a OFFSET 5 ROWS FETCH NEXT 5 ROWS ONLY", "SELECT a FROM t ORDER BY a OFFSET 5 ROWS FETCH NEXT 5 ROWS ONLY"},
		{"sqlserver offset fetch vars", keywords.DialectSQLServer, "SELECT * FROM t ORDER BY id OFFSET @s ROWS FETCH NEXT @n ROWS ONLY", "SELECT * FROM t ORDER BY id OFFSET @s ROWS FETCH NEXT @n ROWS ONLY"},
		{"sqlserver top in derived table", keywords.DialectSQLServer, "SELECT * FROM (SELECT TOP (10) a FROM t ORDER BY a) AS s", "SELECT * FROM (SELECT TOP (10) a FROM t ORDER BY a) s"},
		{"sqlserver top variable", keywords.DialectSQLServer, "SELECT TOP (@n) * FROM t", "SELECT TOP (@n) * FROM t"},
		{"sqlserver cross apply", keywords.DialectSQLServer, "SELECT * FROM a CROSS APPLY (SELECT 1 AS x) AS t", "SELECT * FROM a CROSS APPLY (SELECT 1 AS x) t"},
		{"sqlserver apply table function", keywords.DialectSQLServer, "SELECT t.text FROM qs OUTER APPLY sys.dm_exec_sql_text(qs.h) AS t", "SELECT t.text FROM qs OUTER APPLY sys.dm_exec_sql_text(qs.h) t"},
		{"sqlserver hash join", keywords.DialectSQLServer, "SELECT o.Id FROM o INNER HASH JOIN c ON c.Id = o.CId", "SELECT o.Id FROM o INNER HASH JOIN c ON c.Id = o.CId"},
		{"sqlserver into temp", keywords.DialectSQLServer, "SELECT * INTO #t FROM u", "SELECT * INTO #t FROM u"},
		{"sqlserver for json", keywords.DialectSQLServer, "SELECT a FROM t FOR JSON PATH, ROOT('r'), INCLUDE_NULL_VALUES", "SELECT a FROM t FOR JSON PATH, ROOT('r'), INCLUDE_NULL_VALUES"},
		{"sqlserver for xml", keywords.DialectSQLServer, "SELECT a FROM t FOR XML PATH('x'), ROOT('y'), TYPE", "SELECT a FROM t FOR XML PATH('x'), ROOT('y'), TYPE"},
		{"sqlserver option", keywords.DialectSQLServer, "SELECT * FROM t WHERE c = @c OPTION (MAXDOP 1, RECOMPILE, OPTIMIZE FOR (@c UNKNOWN))", "SELECT * FROM t WHERE c = @c OPTION (MAXDOP 1, RECOMPILE, OPTIMIZE FOR (@c UNKNOWN))"},
		{"sqlserver with rollup", keywords.DialectSQLServer, "SELECT a, SUM(b) FROM t GROUP BY a WITH ROLLUP", "SELECT a, SUM(b) FROM t GROUP BY a WITH ROLLUP"},
		{"snowflake qualify", keywords.DialectSnowflake, "SELECT * FROM t QUALIFY ROW_NUMBER() OVER (ORDER BY a) = 1", "SELECT * FROM t QUALIFY ROW_NUMBER() OVER (ORDER BY a) = 1"},
		{"snowflake top", keywords.DialectSnowflake, "SELECT TOP 10 a FROM t", "SELECT TOP 10 a FROM t"},
		{"snowflake star modifiers", keywords.DialectSnowflake, "SELECT * EXCLUDE (a, b) REPLACE (UPPER(n) AS n) FROM t", "SELECT * EXCLUDE (a, b) REPLACE (UPPER(n) AS n) FROM t"},
		{"snowflake exclude qualified name", keywords.DialectSnowflake, "SELECT t.* EXCLUDE (t.a, \"my col\") FROM t", "SELECT t.* EXCLUDE (t.a, \"my col\") FROM t"},
		{"snowflake ilike rename", keywords.DialectSnowflake, "SELECT * ILIKE '%id%', b.* RENAME (id AS b_id) FROM b", "SELECT * ILIKE '%id%', b.* RENAME (id AS b_id) FROM b"},
		{"snowflake group by all", keywords.DialectSnowflake, "SELECT a, COUNT(*) FROM t GROUP BY ALL", "SELECT a, COUNT(*) FROM t GROUP BY ALL"},
		{"snowflake asof", keywords.DialectSnowflake, "SELECT * FROM t1 ASOF JOIN t2 MATCH_CONDITION (t1.ts >= t2.ts) ON t1.sym = t2.sym", "SELECT * FROM t1 ASOF JOIN t2 MATCH_CONDITION (t1.ts >= t2.ts) ON t1.sym = t2.sym"},
		{"oracle connect by", keywords.DialectOracle, "SELECT id FROM e START WITH id = 1 CONNECT BY PRIOR id = m", "SELECT id FROM e START WITH id = 1 CONNECT BY PRIOR id = m"},
		{"oracle row generator", keywords.DialectOracle, "SELECT LEVEL FROM dual CONNECT BY LEVEL <= 10", "SELECT LEVEL FROM dual CONNECT BY LEVEL <= 10"},
		{"oracle siblings", keywords.DialectOracle, "SELECT n FROM e START WITH m IS NULL CONNECT BY PRIOR id = m ORDER SIBLINGS BY n", "SELECT n FROM e START WITH m IS NULL CONNECT BY PRIOR id = m ORDER SIBLINGS BY n"},
		{"oracle fetch first 1 row", keywords.DialectOracle, "SELECT a FROM t FETCH FIRST 1 ROW ONLY", "SELECT a FROM t FETCH FIRST 1 ROW ONLY"},
		{"oracle outer apply", keywords.DialectOracle, "SELECT d.n FROM d OUTER APPLY (SELECT l FROM e WHERE e.d = d.id) e", "SELECT d.n FROM d OUTER APPLY (SELECT l FROM e WHERE e.d = d.id) e"},
		{"clickhouse prewhere", keywords.DialectClickHouse, "SELECT * FROM t PREWHERE a = 1 WHERE b = 2", "SELECT * FROM t PREWHERE a = 1 WHERE b = 2"},
		{"clickhouse array join", keywords.DialectClickHouse, "SELECT id, tag FROM t LEFT ARRAY JOIN tags AS tag", "SELECT id, tag FROM t LEFT ARRAY JOIN tags AS tag"},
		{"clickhouse limit by", keywords.DialectClickHouse, "SELECT u, p FROM e ORDER BY ts DESC LIMIT 2 BY u, p LIMIT 100", "SELECT u, p FROM e ORDER BY ts DESC LIMIT 2 BY u, p LIMIT 100"},
		{"clickhouse with totals", keywords.DialectClickHouse, "SELECT d, sum(x) FROM s GROUP BY d WITH TOTALS ORDER BY d", "SELECT d, sum(x) FROM s GROUP BY d WITH TOTALS ORDER BY d"},
		{"clickhouse global any left join", keywords.DialectClickHouse, "SELECT * FROM a GLOBAL ANY LEFT JOIN b USING (id)", "SELECT * FROM a GLOBAL ANY LEFT JOIN b USING (id)"},
		{"clickhouse asof join", keywords.DialectClickHouse, "SELECT a FROM t ASOF JOIN u ON t.a = u.a AND t.ts >= u.ts", "SELECT a FROM t ASOF JOIN u ON t.a = u.a AND t.ts >= u.ts"},
		{"clickhouse left anti join", keywords.DialectClickHouse, "SELECT * FROM a LEFT ANTI JOIN b ON a.id = b.id", "SELECT * FROM a ANTI LEFT JOIN b ON a.id = b.id"},
		{"clickhouse star except", keywords.DialectClickHouse, "SELECT * EXCEPT (a) FROM t", "SELECT * EXCEPT (a) FROM t"},
		{"clickhouse format", keywords.DialectClickHouse, "SELECT a FROM t SETTINGS max_threads = 2 FORMAT JSONEachRow", "SELECT a FROM t SETTINGS max_threads = 2 FORMAT JSONEachRow"},
		{"clickhouse limit with ties", keywords.DialectClickHouse, "SELECT x FROM t ORDER BY x LIMIT 10 WITH TIES", "SELECT x FROM t ORDER BY x LIMIT 10 WITH TIES"},
		{"clickhouse interpolate", keywords.DialectClickHouse, "SELECT d, c FROM t ORDER BY d WITH FILL STEP 1 INTERPOLATE (c AS c + 1)", "SELECT d, c FROM t ORDER BY d WITH FILL STEP 1 INTERPOLATE (c AS c + 1)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.sql, err)
			}
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

// selectFieldSamples gives a non-zero sample for every exported
// SelectStatement field that must be rendered. A new field fails
// TestRender_SelectRendersEveryField until it is added here (and rendered)
// or to selectFieldsNotRendered.
func selectFieldSamples() map[string]func(*ast.SelectStatement) {
	ident := func(n string) *ast.Identifier { return &ast.Identifier{Name: n} }
	n := func(v int) *int { return &v }
	i64 := func(v int64) *int64 { return &v }
	return map[string]func(*ast.SelectStatement){
		"With": func(s *ast.SelectStatement) {
			s.With = &ast.WithClause{CTEs: []*ast.CommonTableExpr{{Name: "c", Statement: &ast.SelectStatement{Columns: []ast.Expression{ident("x")}}}}}
		},
		"Distinct":          func(s *ast.SelectStatement) { s.Distinct = true },
		"DistinctOnColumns": func(s *ast.SelectStatement) { s.DistinctOnColumns = []ast.Expression{ident("d")} },
		"Top": func(s *ast.SelectStatement) {
			s.Top = &ast.TopClause{Count: &ast.LiteralValue{Value: "5", Type: "int"}}
		},
		"Columns": func(s *ast.SelectStatement) { s.Columns = append(s.Columns, ident("extra")) },
		"From":    func(s *ast.SelectStatement) { s.From = append(s.From, ast.TableReference{Name: "u"}) },
		"Joins": func(s *ast.SelectStatement) {
			s.Joins = []ast.JoinClause{{Type: "LEFT", Right: ast.TableReference{Name: "j"}, Condition: ident("ok")}}
		},
		"ArrayJoin": func(s *ast.SelectStatement) {
			s.ArrayJoin = &ast.ArrayJoinClause{Elements: []ast.ArrayJoinElement{{Expr: ident("arr")}}}
		},
		"PrewhereClause": func(s *ast.SelectStatement) { s.PrewhereClause = ident("pw") },
		"Sample":         func(s *ast.SelectStatement) { s.Sample = &ast.SampleClause{Value: "0.1"} },
		"Where":          func(s *ast.SelectStatement) { s.Where = ident("w") },
		"GroupBy":        func(s *ast.SelectStatement) { s.GroupBy = []ast.Expression{ident("g")} },
		"Having":         func(s *ast.SelectStatement) { s.Having = ident("h") },
		"Qualify":        func(s *ast.SelectStatement) { s.Qualify = ident("q") },
		"StartWith":      func(s *ast.SelectStatement) { s.StartWith = ident("sw") },
		"ConnectBy":      func(s *ast.SelectStatement) { s.ConnectBy = &ast.ConnectByClause{Condition: ident("cb")} },
		"Windows":        func(s *ast.SelectStatement) { s.Windows = []ast.WindowSpec{{Name: "win"}} },
		"OrderBy": func(s *ast.SelectStatement) {
			s.OrderBy = []ast.OrderByExpression{{Expression: ident("o"), Ascending: true}}
		},
		"Limit":  func(s *ast.SelectStatement) { s.Limit = n(7) },
		"Offset": func(s *ast.SelectStatement) { s.Offset = n(8) },
		"Fetch":  func(s *ast.SelectStatement) { s.Fetch = &ast.FetchClause{FetchType: "FIRST", FetchValue: i64(3)} },
		"For":    func(s *ast.SelectStatement) { s.For = &ast.ForClause{LockType: "UPDATE"} },
		"Settings": func(s *ast.SelectStatement) {
			s.Settings = []ast.QuerySetting{{Name: "max_threads", Value: &ast.LiteralValue{Value: "2", Type: "int"}}}
		},
		"SelectModifiers": func(s *ast.SelectStatement) { s.EnsureExtras().SelectModifiers = []string{"SQL_NO_CACHE"} },
		"Into": func(s *ast.SelectStatement) {
			s.EnsureExtras().Into = &ast.SelectInto{Kind: ast.SelectIntoTable, Table: "dest"}
		},
		"GroupByModifiers": func(s *ast.SelectStatement) {
			s.GroupBy = []ast.Expression{ident("g")}
			s.GroupByModifiers = ast.GroupByModifiers{WithRollup: true}
		},
		"OrderSiblings": func(s *ast.SelectStatement) {
			s.OrderBy = []ast.OrderByExpression{{Expression: ident("o"), Ascending: true}}
			s.OrderSiblings = true
		},
		"Interpolate": func(s *ast.SelectStatement) {
			s.OrderBy = []ast.OrderByExpression{{Expression: ident("o"), Ascending: true}}
			s.EnsureExtras().Interpolate = &ast.InterpolateClause{Items: []ast.InterpolateItem{{Column: "c"}}}
		},
		"LimitExpr":  func(s *ast.SelectStatement) { s.LimitExpr = &ast.Identifier{Name: "$1"} },
		"OffsetExpr": func(s *ast.SelectStatement) { s.OffsetExpr = &ast.Identifier{Name: "$2"} },
		"LimitAll":   func(s *ast.SelectStatement) { s.LimitAll = true },
		"OffsetRows": func(s *ast.SelectStatement) {
			s.Offset = n(8)
			s.OffsetRows = true
		},
		"LimitWithTies": func(s *ast.SelectStatement) {
			s.Limit = n(7)
			s.LimitWithTies = true
		},
		"LimitBy": func(s *ast.SelectStatement) {
			s.EnsureExtras().LimitBy = &ast.LimitByClause{Count: &ast.LiteralValue{Value: "1", Type: "int"}, Exprs: []ast.Expression{ident("lb")}}
		},
		"ForOutput": func(s *ast.SelectStatement) {
			s.EnsureExtras().ForOutput = &ast.ForOutputClause{Kind: "JSON", Mode: "AUTO"}
		},
		"QueryHints":   func(s *ast.SelectStatement) { s.EnsureExtras().QueryHints = []ast.QueryHint{{Name: "RECOMPILE"}} },
		"OutputFormat": func(s *ast.SelectStatement) { s.EnsureExtras().OutputFormat = "JSONEachRow" },
	}
}

// selectFieldsNotRendered are SelectStatement fields that carry no SQL text.
var selectFieldsNotRendered = map[string]string{
	"TableName": "pool/compatibility mirror of From[0].Name",
	"Pos":       "source position",
}

// TestRender_SelectRendersEveryField sets each exported SelectStatement
// field in turn and asserts that both pkg/formatter and SelectStatement.SQL()
// output change, so a parsed clause cannot be silently dropped by either
// renderer.
func TestRender_SelectRendersEveryField(t *testing.T) {
	base := func() *ast.SelectStatement {
		return &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "a"}},
			From:    []ast.TableReference{{Name: "t"}},
		}
	}
	// Some samples need a companion field set in the baseline too, so that
	// only the field under test differs.
	baseFor := map[string]func(*ast.SelectStatement){
		"GroupByModifiers": func(s *ast.SelectStatement) { s.GroupBy = []ast.Expression{&ast.Identifier{Name: "g"}} },
		"OrderSiblings": func(s *ast.SelectStatement) {
			s.OrderBy = []ast.OrderByExpression{{Expression: &ast.Identifier{Name: "o"}, Ascending: true}}
		},
		"Interpolate": func(s *ast.SelectStatement) {
			s.OrderBy = []ast.OrderByExpression{{Expression: &ast.Identifier{Name: "o"}, Ascending: true}}
		},
		"OffsetRows":    func(s *ast.SelectStatement) { v := 8; s.Offset = &v },
		"LimitWithTies": func(s *ast.SelectStatement) { v := 7; s.Limit = &v },
	}
	samples := selectFieldSamples()
	// The fields of SelectStatement.Extras are checked like the statement's
	// own fields; Extras itself is only their holder.
	var fields []reflect.StructField
	for _, typ := range []reflect.Type{reflect.TypeOf(ast.SelectStatement{}), reflect.TypeOf(ast.SelectExtras{})} {
		for i := 0; i < typ.NumField(); i++ {
			if f := typ.Field(i); f.IsExported() && f.Name != "Extras" {
				fields = append(fields, f)
			}
		}
	}
	for _, field := range fields {
		name := field.Name
		if _, skip := selectFieldsNotRendered[name]; skip {
			continue
		}
		set, ok := samples[name]
		if !ok {
			t.Errorf("SelectStatement.%s has no render sample: add one to selectFieldSamples and render it", name)
			continue
		}
		t.Run(name, func(t *testing.T) {
			before, after := base(), base()
			if prep := baseFor[name]; prep != nil {
				prep(before)
				prep(after)
			}
			set(after)
			opts := ast.CompactStyle()
			if f0, f1 := formatter.FormatStatement(before, opts), formatter.FormatStatement(after, opts); f0 == f1 {
				t.Errorf("formatter ignores %s: %s", name, f1)
			}
			if s0, s1 := before.SQL(), after.SQL(); s0 == s1 {
				t.Errorf("SQL() ignores %s: %s", name, s1)
			}
		})
	}
}

// TestRender_SelectExtKeywordCase checks that the new clause keywords follow
// the formatter's keyword case.
func TestRender_SelectExtKeywordCase(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect("SELECT a FROM t GROUP BY a WITH ROLLUP ORDER BY a OFFSET 5 ROWS FETCH NEXT 5 ROWS ONLY", keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	opts := ast.CompactStyle()
	opts.KeywordCase = ast.KeywordLower
	got := formatter.FormatAST(tree, opts)
	for _, kw := range []string{"with rollup", "offset 5 rows", "fetch next 5 rows only"} {
		if !strings.Contains(got, kw) {
			t.Errorf("lower-case output %q lacks %q", got, kw)
		}
	}
}
