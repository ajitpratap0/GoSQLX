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

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// exprSQLText renders e for assertions.
func exprSQLText(e ast.Expression) string {
	if e == nil {
		return ""
	}
	if s, ok := e.(interface{ SQL() string }); ok {
		return s.SQL()
	}
	return e.TokenLiteral()
}

type selectExtCase struct {
	name    string
	dialect keywords.SQLDialect
	sql     string
	check   func(t *testing.T, s *ast.SelectStatement)
}

func runSelectExtCases(t *testing.T, cases []selectExtCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stmt, tree := parseSelectWithDialect(t, tc.sql, tc.dialect)
			defer ast.ReleaseAST(tree)
			tc.check(t, stmt)
		})
	}
}

func TestSelectExt_LimitOffsetValues(t *testing.T) {
	limitExpr := func(want string) func(*testing.T, *ast.SelectStatement) {
		return func(t *testing.T, s *ast.SelectStatement) {
			if s.Limit != nil {
				t.Fatalf("Limit = %d, want nil", *s.Limit)
			}
			if got := exprSQLText(s.LimitExpr); got != want {
				t.Errorf("LimitExpr = %q, want %q", got, want)
			}
		}
	}
	runSelectExtCases(t, []selectExtCase{
		{"pg dollar placeholder", keywords.DialectPostgreSQL, "SELECT 1 FROM t LIMIT $1", limitExpr("$1")},
		{"mysql question placeholder", keywords.DialectMySQL, "SELECT 1 FROM t LIMIT ?", limitExpr("?")},
		{"sqlite placeholder", keywords.DialectSQLite, "SELECT 1 FROM t LIMIT ?", limitExpr("?")},
		{"arithmetic", keywords.DialectPostgreSQL, "SELECT * FROM t LIMIT 1 + 1", limitExpr("1 + 1")},
		{"subquery", keywords.DialectPostgreSQL, "SELECT * FROM t LIMIT (SELECT 1)", limitExpr("(SELECT 1)")},
		{"sqlite negative", keywords.DialectSQLite, "SELECT a FROM t LIMIT -1 OFFSET 5", func(t *testing.T, s *ast.SelectStatement) {
			if got := exprSQLText(s.LimitExpr); got != "-1" {
				t.Errorf("LimitExpr = %q, want -1", got)
			}
			if s.Offset == nil || *s.Offset != 5 {
				t.Errorf("Offset = %v, want 5", s.Offset)
			}
		}},
		{"plain integers stay ints", keywords.DialectPostgreSQL, "SELECT * FROM t LIMIT 10 OFFSET 20", func(t *testing.T, s *ast.SelectStatement) {
			if s.Limit == nil || *s.Limit != 10 || s.LimitExpr != nil {
				t.Errorf("Limit = %v / %v, want 10", s.Limit, s.LimitExpr)
			}
			if s.Offset == nil || *s.Offset != 20 || s.OffsetExpr != nil || s.OffsetRows {
				t.Errorf("Offset = %v / %v rows=%v, want 20", s.Offset, s.OffsetExpr, s.OffsetRows)
			}
		}},
		{"limit all", keywords.DialectPostgreSQL, "SELECT * FROM t LIMIT ALL", func(t *testing.T, s *ast.SelectStatement) {
			if !s.LimitAll || s.Limit != nil || s.LimitExpr != nil {
				t.Errorf("LimitAll = %v Limit = %v LimitExpr = %v", s.LimitAll, s.Limit, s.LimitExpr)
			}
		}},
		{"offset before limit", keywords.DialectPostgreSQL, "SELECT * FROM t OFFSET 10 LIMIT 5", func(t *testing.T, s *ast.SelectStatement) {
			if s.Limit == nil || *s.Limit != 5 || s.Offset == nil || *s.Offset != 10 {
				t.Errorf("Limit = %v Offset = %v, want 5 / 10", s.Limit, s.Offset)
			}
		}},
		{"offset rows", keywords.DialectPostgreSQL, "SELECT * FROM t LIMIT ALL OFFSET 5 ROWS", func(t *testing.T, s *ast.SelectStatement) {
			if !s.LimitAll || !s.OffsetRows || s.Offset == nil || *s.Offset != 5 {
				t.Errorf("LimitAll = %v OffsetRows = %v Offset = %v", s.LimitAll, s.OffsetRows, s.Offset)
			}
		}},
		{"mysql placeholders offset count", keywords.DialectMySQL, "SELECT * FROM t LIMIT ?, ?", func(t *testing.T, s *ast.SelectStatement) {
			if exprSQLText(s.LimitExpr) != "?" || exprSQLText(s.OffsetExpr) != "?" {
				t.Errorf("LimitExpr = %v OffsetExpr = %v", s.LimitExpr, s.OffsetExpr)
			}
		}},
		{"sqlite offset count", keywords.DialectSQLite, "SELECT * FROM t LIMIT 10, 20", func(t *testing.T, s *ast.SelectStatement) {
			if s.Limit == nil || *s.Limit != 20 || s.Offset == nil || *s.Offset != 10 {
				t.Errorf("Limit = %v Offset = %v, want 20 / 10", s.Limit, s.Offset)
			}
		}},
		{"sqlserver offset fetch variables", keywords.DialectSQLServer, "SELECT * FROM t ORDER BY id OFFSET @s ROWS FETCH NEXT @n ROWS ONLY", func(t *testing.T, s *ast.SelectStatement) {
			if exprSQLText(s.OffsetExpr) != "@s" || !s.OffsetRows {
				t.Errorf("OffsetExpr = %v OffsetRows = %v", s.OffsetExpr, s.OffsetRows)
			}
			if s.Fetch == nil || exprSQLText(s.Fetch.FetchExpr) != "@n" || s.Fetch.FetchValue != nil {
				t.Errorf("Fetch = %+v, want FetchExpr @n", s.Fetch)
			}
		}},
		{"fetch first row only", keywords.DialectPostgreSQL, "SELECT * FROM t FETCH FIRST ROW ONLY", func(t *testing.T, s *ast.SelectStatement) {
			if s.Fetch == nil || s.Fetch.FetchValue != nil || s.Fetch.FetchExpr != nil || s.Fetch.FetchType != "FIRST" {
				t.Errorf("Fetch = %+v, want FIRST with no count", s.Fetch)
			}
		}},
		{"clickhouse limit with ties", keywords.DialectClickHouse, "SELECT x FROM t ORDER BY x LIMIT 10 WITH TIES", func(t *testing.T, s *ast.SelectStatement) {
			if s.Limit == nil || *s.Limit != 10 || !s.LimitWithTies {
				t.Errorf("Limit = %v LimitWithTies = %v", s.Limit, s.LimitWithTies)
			}
		}},
		{"clickhouse limit by then limit", keywords.DialectClickHouse, "SELECT user_id, page FROM e ORDER BY ts DESC LIMIT 2 BY user_id, page LIMIT 100", func(t *testing.T, s *ast.SelectStatement) {
			if s.LimitBy == nil || exprSQLText(s.LimitBy.Count) != "2" || len(s.LimitBy.Exprs) != 2 || s.LimitBy.Offset != nil {
				t.Fatalf("LimitBy = %+v", s.LimitBy)
			}
			if s.Limit == nil || *s.Limit != 100 {
				t.Errorf("Limit = %v, want 100", s.Limit)
			}
		}},
		{"clickhouse limit offset by", keywords.DialectClickHouse, "SELECT a FROM t LIMIT 1 OFFSET 2 BY a", func(t *testing.T, s *ast.SelectStatement) {
			if s.LimitBy == nil || exprSQLText(s.LimitBy.Offset) != "2" || s.HasLimit() || s.HasOffset() {
				t.Errorf("LimitBy = %+v, Limit = %v, Offset = %v", s.LimitBy, s.Limit, s.Offset)
			}
		}},
	})
}

func TestSelectExt_SelectListPrologue(t *testing.T) {
	runSelectExtCases(t, []selectExtCase{
		{"mysql calc found rows", keywords.DialectMySQL, "SELECT SQL_CALC_FOUND_ROWS * FROM t", func(t *testing.T, s *ast.SelectStatement) {
			if len(s.SelectModifiers) != 1 || s.SelectModifiers[0] != "SQL_CALC_FOUND_ROWS" {
				t.Errorf("SelectModifiers = %v", s.SelectModifiers)
			}
		}},
		{"mysql modifiers before distinct", keywords.DialectMySQL, "SELECT SQL_NO_CACHE STRAIGHT_JOIN DISTINCT a FROM t", func(t *testing.T, s *ast.SelectStatement) {
			if len(s.SelectModifiers) != 2 || !s.Distinct {
				t.Errorf("SelectModifiers = %v Distinct = %v", s.SelectModifiers, s.Distinct)
			}
		}},
		{"mysql modifier name as column", keywords.DialectMySQL, "SELECT high_priority, b FROM t", func(t *testing.T, s *ast.SelectStatement) {
			if len(s.SelectModifiers) != 0 || len(s.Columns) != 2 {
				t.Errorf("SelectModifiers = %v Columns = %d", s.SelectModifiers, len(s.Columns))
			}
		}},
		{"sqlserver top parenthesized", keywords.DialectSQLServer, "SELECT TOP (10) a FROM t", func(t *testing.T, s *ast.SelectStatement) {
			if s.Top == nil || !s.Top.Parenthesized || exprSQLText(s.Top.Count) != "10" {
				t.Errorf("Top = %+v", s.Top)
			}
		}},
		{"sqlserver top variable", keywords.DialectSQLServer, "SELECT TOP (@n) * FROM t", func(t *testing.T, s *ast.SelectStatement) {
			if s.Top == nil || !s.Top.Parenthesized || exprSQLText(s.Top.Count) != "@n" {
				t.Errorf("Top = %+v", s.Top)
			}
		}},
		{"snowflake top", keywords.DialectSnowflake, "SELECT TOP 10 a FROM t", func(t *testing.T, s *ast.SelectStatement) {
			if s.Top == nil || s.Top.Parenthesized || exprSQLText(s.Top.Count) != "10" {
				t.Errorf("Top = %+v", s.Top)
			}
		}},
		{"snowflake top as column", keywords.DialectSnowflake, "SELECT top FROM t", func(t *testing.T, s *ast.SelectStatement) {
			if s.Top != nil || len(s.Columns) != 1 {
				t.Errorf("Top = %+v Columns = %v", s.Top, s.Columns)
			}
		}},
	})
}

func TestSelectExt_StarModifiers(t *testing.T) {
	star := func(t *testing.T, s *ast.SelectStatement, i int) *ast.StarExpression {
		t.Helper()
		se, ok := s.Columns[i].(*ast.StarExpression)
		if !ok {
			t.Fatalf("Columns[%d] = %T, want *ast.StarExpression", i, s.Columns[i])
		}
		return se
	}
	runSelectExtCases(t, []selectExtCase{
		{"snowflake exclude list", keywords.DialectSnowflake, "SELECT * EXCLUDE (a, b) FROM t", func(t *testing.T, s *ast.SelectStatement) {
			se := star(t, s, 0)
			if se.ExcludeKeyword != "EXCLUDE" || len(se.Exclude) != 2 || se.Exclude[1] != "b" {
				t.Errorf("StarExpression = %+v", se)
			}
		}},
		{"snowflake exclude single", keywords.DialectSnowflake, "SELECT * EXCLUDE a FROM t", func(t *testing.T, s *ast.SelectStatement) {
			if se := star(t, s, 0); len(se.Exclude) != 1 || se.Exclude[0] != "a" {
				t.Errorf("Exclude = %v", se.Exclude)
			}
		}},
		{"snowflake replace", keywords.DialectSnowflake, "SELECT * REPLACE (UPPER(name) AS name) FROM t", func(t *testing.T, s *ast.SelectStatement) {
			se := star(t, s, 0)
			if len(se.Replace) != 1 || se.Replace[0].Alias != "name" {
				t.Errorf("Replace = %+v", se.Replace)
			}
		}},
		{"snowflake ilike", keywords.DialectSnowflake, "SELECT * ILIKE '%name%' FROM t", func(t *testing.T, s *ast.SelectStatement) {
			if se := star(t, s, 0); exprSQLText(se.Ilike) != "'%name%'" {
				t.Errorf("Ilike = %v", se.Ilike)
			}
		}},
		{"snowflake qualified exclude and rename", keywords.DialectSnowflake, "SELECT a.* EXCLUDE (secret), b.* RENAME (id AS b_id) FROM a JOIN b ON a.id = b.a_id", func(t *testing.T, s *ast.SelectStatement) {
			first := star(t, s, 0)
			if id, ok := first.Star.(*ast.Identifier); !ok || id.Table != "a" {
				t.Errorf("Star = %#v, want a.*", first.Star)
			}
			second := star(t, s, 1)
			if len(second.Rename) != 1 || second.Rename[0].Column != "id" || second.Rename[0].Alias != "b_id" {
				t.Errorf("Rename = %+v", second.Rename)
			}
		}},
		{"clickhouse except is not a set operator", keywords.DialectClickHouse, "SELECT * EXCEPT (a) FROM t", func(t *testing.T, s *ast.SelectStatement) {
			if se := star(t, s, 0); se.ExcludeKeyword != "EXCEPT" || len(se.Exclude) != 1 {
				t.Errorf("StarExpression = %+v", se)
			}
			if len(s.From) != 1 {
				t.Errorf("From = %v", s.From)
			}
		}},
		{"clickhouse replace", keywords.DialectClickHouse, "SELECT * REPLACE (x + 1 AS x) FROM t", func(t *testing.T, s *ast.SelectStatement) {
			if se := star(t, s, 0); len(se.Replace) != 1 || exprSQLText(se.Replace[0].Expr) != "x + 1" {
				t.Errorf("Replace = %+v", se.Replace)
			}
		}},
		{"plain star stays identifier", keywords.DialectSnowflake, "SELECT * FROM t", func(t *testing.T, s *ast.SelectStatement) {
			if id, ok := s.Columns[0].(*ast.Identifier); !ok || id.Name != "*" {
				t.Errorf("Columns[0] = %#v", s.Columns[0])
			}
		}},
	})
}

func TestSelectExt_Into(t *testing.T) {
	runSelectExtCases(t, []selectExtCase{
		{"sqlserver temp table", keywords.DialectSQLServer, "SELECT * INTO #t FROM u", func(t *testing.T, s *ast.SelectStatement) {
			if s.Into == nil || s.Into.Kind != ast.SelectIntoTable || s.Into.Table != "#t" || s.Into.Trailing {
				t.Errorf("Into = %+v", s.Into)
			}
		}},
		{"sqlserver qualified table", keywords.DialectSQLServer, "SELECT Id, Name INTO dbo.Backup FROM dbo.Customers", func(t *testing.T, s *ast.SelectStatement) {
			if s.Into == nil || s.Into.Table != "dbo.Backup" {
				t.Errorf("Into = %+v", s.Into)
			}
		}},
		{"postgres temp table", keywords.DialectPostgreSQL, "SELECT * INTO TEMP TABLE n FROM o", func(t *testing.T, s *ast.SelectStatement) {
			if s.Into == nil || s.Into.Temporary != "TEMP" || !s.Into.TableKeyword || s.Into.Table != "n" {
				t.Errorf("Into = %+v", s.Into)
			}
		}},
		{"mysql variables", keywords.DialectMySQL, "SELECT id, total INTO @id, @total FROM orders WHERE id = 1", func(t *testing.T, s *ast.SelectStatement) {
			if s.Into == nil || s.Into.Kind != ast.SelectIntoVariables || len(s.Into.Targets) != 2 {
				t.Errorf("Into = %+v", s.Into)
			}
			if s.Where == nil {
				t.Errorf("WHERE lost")
			}
		}},
		{"mysql trailing outfile", keywords.DialectMySQL, "SELECT * FROM o INTO OUTFILE '/tmp/o.csv' FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '\"' LINES TERMINATED BY '\\n'", func(t *testing.T, s *ast.SelectStatement) {
			in := s.Into
			if in == nil || in.Kind != ast.SelectIntoOutfile || !in.Trailing || exprSQLText(in.File) != "'/tmp/o.csv'" {
				t.Fatalf("Into = %+v", in)
			}
			if len(in.FieldsOptions) != 2 || in.FieldsOptions[1].Option != "OPTIONALLY ENCLOSED BY" || len(in.LinesOptions) != 1 {
				t.Errorf("options = %+v / %+v", in.FieldsOptions, in.LinesOptions)
			}
		}},
		{"mysql into after locking", keywords.DialectMySQL, "SELECT a FROM t FOR UPDATE INTO @x", func(t *testing.T, s *ast.SelectStatement) {
			if s.For == nil || s.Into == nil || !s.Into.Trailing {
				t.Errorf("For = %+v Into = %+v", s.For, s.Into)
			}
		}},
		{"oracle bind variable", keywords.DialectOracle, "SELECT a INTO :v FROM t", func(t *testing.T, s *ast.SelectStatement) {
			if s.Into == nil || s.Into.Kind != ast.SelectIntoVariables {
				t.Errorf("Into = %+v", s.Into)
			}
		}},
	})
}

func TestSelectExt_FromlessAndGroupBy(t *testing.T) {
	runSelectExtCases(t, []selectExtCase{
		{"where without from", keywords.DialectPostgreSQL, "SELECT 1 WHERE 1 = 1", func(t *testing.T, s *ast.SelectStatement) {
			if s.Where == nil || len(s.From) != 0 {
				t.Errorf("Where = %v From = %v", s.Where, s.From)
			}
		}},
		{"group by without from", keywords.DialectPostgreSQL, "SELECT 1 GROUP BY 1 HAVING COUNT(*) > 0", func(t *testing.T, s *ast.SelectStatement) {
			if len(s.GroupBy) != 1 || s.Having == nil {
				t.Errorf("GroupBy = %v Having = %v", s.GroupBy, s.Having)
			}
		}},
		{"mysql with rollup kept as modifier", keywords.DialectMySQL, "SELECT a, b FROM t GROUP BY a, b WITH ROLLUP", func(t *testing.T, s *ast.SelectStatement) {
			if !s.GroupByModifiers.WithRollup || len(s.GroupBy) != 2 {
				t.Errorf("GroupByModifiers = %+v GroupBy = %v", s.GroupByModifiers, s.GroupBy)
			}
			if _, ok := s.GroupBy[0].(*ast.RollupExpression); ok {
				t.Errorf("WITH ROLLUP must not become ROLLUP(...)")
			}
		}},
		{"clickhouse with totals", keywords.DialectClickHouse, "SELECT d, sum(x) FROM s GROUP BY d WITH TOTALS ORDER BY d", func(t *testing.T, s *ast.SelectStatement) {
			if !s.GroupByModifiers.WithTotals || len(s.OrderBy) != 1 {
				t.Errorf("GroupByModifiers = %+v OrderBy = %v", s.GroupByModifiers, s.OrderBy)
			}
		}},
		{"snowflake group by all", keywords.DialectSnowflake, "SELECT a, COUNT(*) FROM t GROUP BY ALL", func(t *testing.T, s *ast.SelectStatement) {
			if !s.GroupByModifiers.All || len(s.GroupBy) != 0 {
				t.Errorf("GroupByModifiers = %+v GroupBy = %v", s.GroupByModifiers, s.GroupBy)
			}
		}},
		{"clickhouse group by all", keywords.DialectClickHouse, "SELECT a FROM t GROUP BY ALL", func(t *testing.T, s *ast.SelectStatement) {
			if !s.GroupByModifiers.All {
				t.Errorf("GroupByModifiers = %+v", s.GroupByModifiers)
			}
		}},
	})
}

func TestSelectExt_HierarchicalAndOrdering(t *testing.T) {
	runSelectExtCases(t, []selectExtCase{
		{"order siblings by", keywords.DialectOracle, "SELECT name FROM e START WITH m IS NULL CONNECT BY PRIOR id = m ORDER SIBLINGS BY name", func(t *testing.T, s *ast.SelectStatement) {
			if !s.OrderSiblings || len(s.OrderBy) != 1 || s.StartWith == nil || s.ConnectBy == nil {
				t.Errorf("OrderSiblings = %v OrderBy = %v", s.OrderSiblings, s.OrderBy)
			}
		}},
		{"start with after connect by", keywords.DialectOracle, "SELECT id FROM e CONNECT BY NOCYCLE PRIOR id = m START WITH id = 101", func(t *testing.T, s *ast.SelectStatement) {
			if s.ConnectBy == nil || !s.ConnectBy.NoCycle || exprSQLText(s.StartWith) != "id = 101" {
				t.Errorf("ConnectBy = %+v StartWith = %v", s.ConnectBy, s.StartWith)
			}
		}},
		{"postgres order by using", keywords.DialectPostgreSQL, "SELECT a FROM t ORDER BY a USING <, b USING >=", func(t *testing.T, s *ast.SelectStatement) {
			if len(s.OrderBy) != 2 || s.OrderBy[0].UsingOperator != "<" || s.OrderBy[1].UsingOperator != ">=" {
				t.Errorf("OrderBy = %+v", s.OrderBy)
			}
		}},
		{"clickhouse interpolate", keywords.DialectClickHouse, "SELECT d, c FROM daily ORDER BY d WITH FILL STEP 1 INTERPOLATE (c AS c + 1, e)", func(t *testing.T, s *ast.SelectStatement) {
			ip := s.Interpolate
			if ip == nil || len(ip.Items) != 2 || ip.Items[0].Column != "c" || exprSQLText(ip.Items[0].Expr) != "c + 1" || ip.Items[1].Expr != nil {
				t.Errorf("Interpolate = %+v", ip)
			}
		}},
	})
}

func TestSelectExt_TrailingClauses(t *testing.T) {
	runSelectExtCases(t, []selectExtCase{
		{"for json path options", keywords.DialectSQLServer, "SELECT Id FROM c FOR JSON PATH, ROOT('customers'), INCLUDE_NULL_VALUES", func(t *testing.T, s *ast.SelectStatement) {
			fo := s.ForOutput
			if fo == nil || fo.Kind != "JSON" || fo.Mode != "PATH" || len(fo.Options) != 2 || exprSQLText(fo.Options[0].Arg) != "'customers'" {
				t.Errorf("ForOutput = %+v", fo)
			}
			if s.For != nil {
				t.Errorf("For = %+v, want nil", s.For)
			}
		}},
		{"for xml path elements", keywords.DialectSQLServer, "SELECT Id FROM c FOR XML PATH('row'), ELEMENTS XSINIL, TYPE", func(t *testing.T, s *ast.SelectStatement) {
			fo := s.ForOutput
			if fo == nil || fo.Kind != "XML" || exprSQLText(fo.ModeArg) != "'row'" || len(fo.Options) != 2 || fo.Options[0].Name != "ELEMENTS XSINIL" {
				t.Errorf("ForOutput = %+v", fo)
			}
		}},
		{"for json in subquery", keywords.DialectSQLServer, "SELECT c.Id, (SELECT o.Id FROM o WHERE o.c = c.Id FOR JSON PATH) AS Orders FROM c FOR JSON PATH, WITHOUT_ARRAY_WRAPPER", func(t *testing.T, s *ast.SelectStatement) {
			if s.ForOutput == nil || len(s.ForOutput.Options) != 1 {
				t.Errorf("ForOutput = %+v", s.ForOutput)
			}
		}},
		{"option hints", keywords.DialectSQLServer, "SELECT * FROM t WHERE c = @c OPTION (MAXDOP 1, RECOMPILE, OPTIMIZE FOR (@c UNKNOWN), LABEL = 'x')", func(t *testing.T, s *ast.SelectStatement) {
			h := s.QueryHints
			if len(h) != 4 {
				t.Fatalf("QueryHints = %+v", h)
			}
			if h[0].Name != "MAXDOP" || exprSQLText(h[0].Value) != "1" {
				t.Errorf("hint 0 = %+v", h[0])
			}
			if h[2].Name != "OPTIMIZE FOR" || !h[2].HasArgs || len(h[2].Args) != 1 || !h[2].Args[0].Unknown {
				t.Errorf("hint 2 = %+v", h[2])
			}
			if h[3].Name != "LABEL" || !h[3].Equals {
				t.Errorf("hint 3 = %+v", h[3])
			}
		}},
		{"option after table without alias", keywords.DialectSQLServer, "SELECT * FROM t OPTION (RECOMPILE)", func(t *testing.T, s *ast.SelectStatement) {
			if len(s.QueryHints) != 1 || s.From[0].Alias != "" {
				t.Errorf("QueryHints = %+v Alias = %q", s.QueryHints, s.From[0].Alias)
			}
		}},
		{"clickhouse format", keywords.DialectClickHouse, "SELECT a FROM t FORMAT JSONEachRow", func(t *testing.T, s *ast.SelectStatement) {
			if s.OutputFormat != "JSONEachRow" || s.From[0].Alias != "" {
				t.Errorf("OutputFormat = %q Alias = %q", s.OutputFormat, s.From[0].Alias)
			}
		}},
		{"clickhouse settings then format", keywords.DialectClickHouse, "SELECT * FROM t SETTINGS max_threads = 2 FORMAT CSVWithNames", func(t *testing.T, s *ast.SelectStatement) {
			if s.OutputFormat != "CSVWithNames" || len(s.Settings) != 1 {
				t.Errorf("OutputFormat = %q Settings = %v", s.OutputFormat, s.Settings)
			}
		}},
		{"clickhouse format without from", keywords.DialectClickHouse, "SELECT 'ok' FORMAT Null", func(t *testing.T, s *ast.SelectStatement) {
			if s.OutputFormat != "Null" {
				t.Errorf("OutputFormat = %q", s.OutputFormat)
			}
		}},
		{"mysql lock in share mode", keywords.DialectMySQL, "SELECT * FROM a WHERE id = 1 LOCK IN SHARE MODE", func(t *testing.T, s *ast.SelectStatement) {
			if s.For == nil || !s.For.LockInShareMode || s.For.LockType != "SHARE" {
				t.Errorf("For = %+v", s.For)
			}
		}},
		{"mariadb for update wait", keywords.DialectMariaDB, "SELECT * FROM t FOR UPDATE WAIT 5", func(t *testing.T, s *ast.SelectStatement) {
			if s.For == nil || exprSQLText(s.For.Wait) != "5" {
				t.Errorf("For = %+v", s.For)
			}
		}},
	})
}

func TestSelectExt_Joins(t *testing.T) {
	join := func(t *testing.T, s *ast.SelectStatement, i int) ast.JoinClause {
		t.Helper()
		if len(s.Joins) <= i {
			t.Fatalf("Joins = %d, want > %d", len(s.Joins), i)
		}
		return s.Joins[i]
	}
	runSelectExtCases(t, []selectExtCase{
		{"clickhouse asof", keywords.DialectClickHouse, "SELECT a FROM t ASOF JOIN u ON t.a = u.a AND t.ts >= u.ts", func(t *testing.T, s *ast.SelectStatement) {
			if j := join(t, s, 0); j.Strictness != "ASOF" || j.Type != "INNER" || s.From[0].Alias != "" {
				t.Errorf("Join = %+v Alias = %q", j, s.From[0].Alias)
			}
		}},
		{"clickhouse global any left", keywords.DialectClickHouse, "SELECT * FROM a GLOBAL ANY LEFT JOIN b USING (id)", func(t *testing.T, s *ast.SelectStatement) {
			if j := join(t, s, 0); !j.Global || j.Strictness != "ANY" || j.Type != "LEFT" || s.From[0].Alias != "" {
				t.Errorf("Join = %+v Alias = %q", j, s.From[0].Alias)
			}
		}},
		{"clickhouse left semi", keywords.DialectClickHouse, "SELECT * FROM a LEFT SEMI JOIN b ON a.id = b.id", func(t *testing.T, s *ast.SelectStatement) {
			if j := join(t, s, 0); j.Strictness != "SEMI" || j.Type != "LEFT" {
				t.Errorf("Join = %+v", j)
			}
		}},
		{"clickhouse semi is not an alias", keywords.DialectClickHouse, "SELECT * FROM a SEMI JOIN b ON a.id = b.id", func(t *testing.T, s *ast.SelectStatement) {
			if j := join(t, s, 0); j.Strictness != "SEMI" || s.From[0].Alias != "" {
				t.Errorf("Join = %+v Alias = %q", j, s.From[0].Alias)
			}
		}},
		{"snowflake asof match condition", keywords.DialectSnowflake, "SELECT * FROM t1 ASOF JOIN t2 MATCH_CONDITION (t1.ts >= t2.ts) ON t1.sym = t2.sym", func(t *testing.T, s *ast.SelectStatement) {
			j := join(t, s, 0)
			if j.Strictness != "ASOF" || exprSQLText(j.MatchCondition) != "t1.ts >= t2.ts" || j.Condition == nil || j.Right.Alias != "" {
				t.Errorf("Join = %+v", j)
			}
		}},
		{"snowflake asof without on", keywords.DialectSnowflake, "SELECT * FROM t1 ASOF JOIN t2 MATCH_CONDITION (t1.ts >= t2.ts)", func(t *testing.T, s *ast.SelectStatement) {
			j := join(t, s, 0)
			if j.Strictness != "ASOF" || j.MatchCondition == nil || j.Condition != nil || len(j.Using) != 0 {
				t.Errorf("Join = %+v", j)
			}
		}},
		{"sqlserver hash join hint", keywords.DialectSQLServer, "SELECT o.Id FROM o INNER HASH JOIN c ON c.Id = o.CId", func(t *testing.T, s *ast.SelectStatement) {
			if j := join(t, s, 0); j.Hint != "HASH" || j.Type != "INNER" {
				t.Errorf("Join = %+v", j)
			}
		}},
		{"sqlserver loop join hint", keywords.DialectSQLServer, "SELECT o.Id FROM o LEFT OUTER LOOP JOIN c ON c.Id = o.CId", func(t *testing.T, s *ast.SelectStatement) {
			if j := join(t, s, 0); j.Hint != "LOOP" || j.Type != "LEFT" {
				t.Errorf("Join = %+v", j)
			}
		}},
		{"mysql straight join", keywords.DialectMySQL, "SELECT * FROM a STRAIGHT_JOIN b ON a.id = b.id", func(t *testing.T, s *ast.SelectStatement) {
			if j := join(t, s, 0); j.Hint != "STRAIGHT_JOIN" || j.Condition == nil || s.From[0].Alias != "" {
				t.Errorf("Join = %+v Alias = %q", j, s.From[0].Alias)
			}
		}},
		{"mysql join without on", keywords.DialectMySQL, "SELECT * FROM a JOIN b", func(t *testing.T, s *ast.SelectStatement) {
			if j := join(t, s, 0); j.Condition != nil || len(j.Using) != 0 {
				t.Errorf("Join = %+v", j)
			}
		}},
		{"comma after explicit join", keywords.DialectMySQL, "SELECT * FROM a LEFT JOIN b ON a.id = b.id, t3 JOIN t4 ON t3.x = t4.x", func(t *testing.T, s *ast.SelectStatement) {
			if len(s.Joins) != 3 {
				t.Fatalf("Joins = %d, want 3", len(s.Joins))
			}
			if j := s.Joins[1]; !j.Comma || j.Type != "CROSS" || j.Right.Name != "t3" {
				t.Errorf("comma join = %+v", j)
			}
			if j := s.Joins[2]; j.Comma || j.Right.Name != "t4" {
				t.Errorf("third join = %+v", j)
			}
		}},
		{"oracle cross apply", keywords.DialectOracle, "SELECT d.n, e.l FROM d CROSS APPLY (SELECT l FROM e WHERE e.d = d.id FETCH FIRST 3 ROWS ONLY) e", func(t *testing.T, s *ast.SelectStatement) {
			if j := join(t, s, 0); j.Type != "CROSS APPLY" {
				t.Errorf("Join = %+v", j)
			}
		}},
		{"sqlserver cross apply table function", keywords.DialectSQLServer, "SELECT t.text FROM qs CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) AS t", func(t *testing.T, s *ast.SelectStatement) {
			j := join(t, s, 0)
			if j.Type != "CROSS APPLY" || j.Right.TableFunc == nil || j.Right.Alias != "t" {
				t.Errorf("Join = %+v", j)
			}
		}},
		{"oracle outer apply", keywords.DialectOracle, "SELECT d.n FROM d OUTER APPLY (SELECT l FROM e WHERE e.d = d.id) e", func(t *testing.T, s *ast.SelectStatement) {
			if j := join(t, s, 0); j.Type != "OUTER APPLY" {
				t.Errorf("Join = %+v", j)
			}
		}},
	})
}

// TestSelectExt_DialectGating checks that dialect-specific syntax is still
// rejected where the dialect does not accept it.
func TestSelectExt_DialectGating(t *testing.T) {
	cases := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
	}{
		{"group by all in postgres", keywords.DialectPostgreSQL, "SELECT a FROM t GROUP BY ALL"},
		{"limit comma in postgres", keywords.DialectPostgreSQL, "SELECT a FROM t LIMIT 1, 2"},
		{"join without on in postgres", keywords.DialectPostgreSQL, "SELECT * FROM a JOIN b"},
		{"left join without on in mysql", keywords.DialectMySQL, "SELECT * FROM a LEFT JOIN b"},
		{"star exclude in postgres", keywords.DialectPostgreSQL, "SELECT * EXCLUDE (a) FROM t"},
		{"limit in sqlserver", keywords.DialectSQLServer, "SELECT a FROM t LIMIT $1"},
		{"select into in sqlite", keywords.DialectSQLite, "SELECT * INTO n FROM t"},
		{"for json in postgres", keywords.DialectPostgreSQL, "SELECT a FROM t FOR JSON PATH"},
		{"outfile in postgres", keywords.DialectPostgreSQL, "SELECT a FROM t INTO OUTFILE 'x'"},
		{"second limit by in clickhouse", keywords.DialectClickHouse, "SELECT * FROM t LIMIT 1 BY a LIMIT 2 BY b"},
		{"limit with ties by in clickhouse", keywords.DialectClickHouse, "SELECT * FROM t LIMIT 1 WITH TIES BY a"},
		{"offset before limit by in clickhouse", keywords.DialectClickHouse, "SELECT * FROM t OFFSET 2 LIMIT 1 BY a"},
		{"asof join without match condition in snowflake", keywords.DialectSnowflake, "SELECT * FROM t1 ASOF JOIN t2 ON t1.a = t2.a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, tc.dialect)
			if err == nil {
				ast.ReleaseAST(tree)
				t.Fatalf("ParseWithDialect(%q, %s) succeeded, want an error", tc.sql, tc.dialect)
			}
		})
	}
}
