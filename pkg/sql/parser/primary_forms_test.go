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

// parseFirstColumn parses sql in dialect d and returns the first select-list
// expression with any alias removed. The tree is released by t.Cleanup.
func parseFirstColumn(t *testing.T, d keywords.SQLDialect, sql string) ast.Expression {
	t.Helper()
	tree, err := ParseWithDialect(sql, d)
	if err != nil {
		t.Fatalf("parse %q (%s): %v", sql, d, err)
	}
	t.Cleanup(func() { ast.ReleaseAST(tree) })
	col := firstColumn(t, tree)
	if al, ok := col.(*ast.AliasedExpression); ok {
		return al.Expr
	}
	return col
}

func asFunctionCall(t *testing.T, e ast.Expression) *ast.FunctionCall {
	t.Helper()
	fc, ok := e.(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected *ast.FunctionCall, got %T", e)
	}
	return fc
}

func TestPrimary_KeywordNamedFunctions(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		name    string
		args    int
	}{
		{keywords.DialectMySQL, "SELECT LEFT(name, 2) FROM t", "LEFT", 2},
		{keywords.DialectPostgreSQL, "SELECT right(name, 2) FROM t", "right", 2},
		{keywords.DialectPostgreSQL, "SELECT GROUPING(a) FROM t GROUP BY a", "GROUPING", 1},
		{keywords.DialectSQLServer, "SELECT GROUPING(a) FROM t GROUP BY a", "GROUPING", 1},
		{keywords.DialectOracle, "SELECT GROUPING(a) FROM t GROUP BY a", "GROUPING", 1},
		{keywords.DialectMySQL, "SELECT TRUNCATE(x, 1) FROM t", "TRUNCATE", 2},
		{keywords.DialectMySQL, "SELECT DEFAULT(col) FROM t", "DEFAULT", 1},
		{keywords.DialectMySQL, "SELECT INSERT(s, 1, 2, 'x') FROM t", "INSERT", 4},
		{keywords.DialectClickHouse, "SELECT any(a) FROM t", "any", 1},
		{keywords.DialectClickHouse, "SELECT range(1, 2)", "range", 2},
		{keywords.DialectSnowflake, "SELECT HASH(a) FROM t", "HASH", 1},
		{keywords.DialectPostgreSQL, "SELECT ROW(1, 2)", "ROW", 2},
		{keywords.DialectMySQL, "SELECT INTERVAL(5, 1, 10)", "INTERVAL", 3},
		{keywords.DialectClickHouse, "SELECT extract(s, 'a+')", "extract", 2},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			fc := asFunctionCall(t, parseFirstColumn(t, tt.dialect, tt.sql))
			if fc.Name != tt.name || len(fc.Arguments) != tt.args {
				t.Errorf("got %s with %d args, want %s with %d", fc.Name, len(fc.Arguments), tt.name, tt.args)
			}
		})
	}
}

func TestPrimary_KeywordJoinsStillParse(t *testing.T) {
	// LEFT/RIGHT as join keywords and = ANY(...) as a quantifier keep working.
	for _, sql := range []string{
		"SELECT * FROM a LEFT JOIN b ON a.id = b.id",
		"SELECT * FROM a RIGHT JOIN b ON a.id = b.id",
		"SELECT * FROM t WHERE id = ANY (SELECT id FROM u)",
	} {
		tree, err := ParseWithDialect(sql, keywords.DialectPostgreSQL)
		if err != nil {
			t.Fatalf("parse %q: %v", sql, err)
		}
		ast.ReleaseAST(tree)
	}
}

func TestPrimary_QualifiedFunctionCalls(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		name    string
	}{
		{keywords.DialectPostgreSQL, "SELECT pg_catalog.now()", "pg_catalog.now"},
		{keywords.DialectPostgreSQL, "SELECT auth.uid()", "auth.uid"},
		{keywords.DialectOracle, "SELECT my_pkg.fn(1) FROM dual", "my_pkg.fn"},
		{keywords.DialectOracle, "SELECT DBMS_RANDOM.VALUE(1, 100) FROM dual", "DBMS_RANDOM.VALUE"},
		{keywords.DialectSQLServer, "SELECT db.dbo.fn(1)", "db.dbo.fn"},
	}
	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			fc := asFunctionCall(t, parseFirstColumn(t, tt.dialect, tt.sql))
			if fc.Name != tt.name {
				t.Errorf("Name = %q, want %q", fc.Name, tt.name)
			}
		})
	}
}

func TestPrimary_OuterJoinMarker(t *testing.T) {
	tree, err := ParseWithDialect("SELECT * FROM a, b WHERE a.id = b.id(+) AND c(+) = 1", keywords.DialectOracle)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer ast.ReleaseAST(tree)
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
	}
	var markers []*ast.OuterJoinMarker
	ast.Inspect(sel.Where, func(n ast.Node) bool {
		if m, ok := n.(*ast.OuterJoinMarker); ok {
			markers = append(markers, m)
		}
		return true
	})
	if len(markers) != 2 {
		t.Fatalf("found %d outer-join markers, want 2", len(markers))
	}
	id, ok := markers[0].Expr.(*ast.Identifier)
	if !ok || id.Table != "b" || id.Name != "id" {
		t.Errorf("first marker wraps %#v, want b.id", markers[0].Expr)
	}
}

func TestPrimary_TypedLiterals(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		typ     string
		value   string
	}{
		{keywords.DialectPostgreSQL, "SELECT DATE '2024-01-01'", "DATE", "2024-01-01"},
		{keywords.DialectPostgreSQL, "SELECT TIMESTAMP '2024-01-01 00:00:00'", "TIMESTAMP", "2024-01-01 00:00:00"},
		{keywords.DialectPostgreSQL, "SELECT inet '10.0.0.1'", "inet", "10.0.0.1"},
		{keywords.DialectMySQL, "SELECT TIME '12:00'", "TIME", "12:00"},
		{keywords.DialectOracle, "SELECT DATE '2024-01-01' FROM dual", "DATE", "2024-01-01"},
		{keywords.DialectSnowflake, "SELECT TIMESTAMP '2024-01-01'", "TIMESTAMP", "2024-01-01"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			lit, ok := parseFirstColumn(t, tt.dialect, tt.sql).(*ast.TypedLiteral)
			if !ok {
				t.Fatalf("expected *ast.TypedLiteral")
			}
			if lit.TypeName != tt.typ || lit.Value != tt.value {
				t.Errorf("got %s %q, want %s %q", lit.TypeName, lit.Value, tt.typ, tt.value)
			}
		})
	}
}

func TestPrimary_TypedLiteralsNotInAliasDialects(t *testing.T) {
	// SQL Server and SQLite have no typed literals; MySQL only knows the
	// datetime types, so an arbitrary word before a string stays an error.
	for _, tc := range []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectSQLServer, "SELECT DATE '2024-01-01'"},
		{keywords.DialectSQLite, "SELECT DATE '2024-01-01'"},
		{keywords.DialectMySQL, "SELECT inet '10.0.0.1'"},
	} {
		if tree, err := ParseWithDialect(tc.sql, tc.dialect); err == nil {
			ast.ReleaseAST(tree)
			t.Errorf("%s: %q parsed, want an error", tc.dialect, tc.sql)
		}
	}
}

func TestPrimary_StringLiterals(t *testing.T) {
	t.Run("national string", func(t *testing.T) {
		lit, ok := parseFirstColumn(t, keywords.DialectSQLServer, "SELECT N'abc'").(*ast.LiteralValue)
		if !ok {
			t.Fatalf("expected *ast.LiteralValue")
		}
		if lit.Value != "abc" || lit.Type != ast.NationalStringType {
			t.Errorf("got %#v, want N'abc'", lit)
		}
	})
	for _, d := range []keywords.SQLDialect{keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectPostgreSQL} {
		t.Run("adjacent strings "+string(d), func(t *testing.T) {
			lit, ok := parseFirstColumn(t, d, "SELECT 'a' 'b' 'c'").(*ast.LiteralValue)
			if !ok {
				t.Fatalf("expected *ast.LiteralValue")
			}
			if lit.Value != "abc" {
				t.Errorf("Value = %v, want abc", lit.Value)
			}
		})
	}
}

// keywordArgs returns the keywords of the KeywordArgument arguments of fc,
// with "," for a plain argument.
func keywordArgs(fc *ast.FunctionCall) []string {
	var out []string
	for _, a := range fc.Arguments {
		if ka, ok := a.(*ast.KeywordArgument); ok {
			out = append(out, ka.Keyword)
		} else {
			out = append(out, ",")
		}
	}
	return out
}

func TestPrimary_SpecialFormArguments(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		want    []string
	}{
		{keywords.DialectPostgreSQL, "SELECT substring(name FROM 2 FOR 3) FROM t", []string{",", "FROM", "FOR"}},
		{keywords.DialectMySQL, "SELECT SUBSTRING(name FROM 2) FROM t", []string{",", "FROM"}},
		{keywords.DialectMySQL, "SELECT SUBSTRING(name, 2, 3) FROM t", []string{",", ",", ","}},
		{keywords.DialectPostgreSQL, "SELECT position('a' IN b) FROM t", []string{",", "IN"}},
		{keywords.DialectPostgreSQL, "SELECT trim(BOTH ' ' FROM x) FROM t", []string{"BOTH", "FROM"}},
		{keywords.DialectOracle, "SELECT TRIM(LEADING '0' FROM x) FROM t", []string{"LEADING", "FROM"}},
		{keywords.DialectPostgreSQL, "SELECT trim(TRAILING FROM x) FROM t", []string{"TRAILING", "FROM"}},
		{keywords.DialectMySQL, "SELECT TRIM('x' FROM y) FROM t", []string{",", "FROM"}},
		{keywords.DialectPostgreSQL, "SELECT overlay(s PLACING 'ab' FROM 2 FOR 3) FROM t", []string{",", "PLACING", "FROM", "FOR"}},
		{keywords.DialectMySQL, "SELECT CONVERT(x USING utf8mb4) FROM t", []string{",", "USING"}},
		{keywords.DialectSQLServer, "SELECT TRY_PARSE('1' AS INT)", []string{",", "AS"}},
		{keywords.DialectSQLServer, "SELECT PARSE('1' AS DECIMAL(10,2) USING 'en-US')", []string{",", "AS", "USING"}},
		{keywords.DialectMariaDB, "SELECT COLUMN_GET(d, 'k' AS CHAR) FROM t", []string{",", ",", "AS"}},
		{keywords.DialectOracle, "SELECT LISTAGG(a, ',' ON OVERFLOW TRUNCATE '...' WITH COUNT) WITHIN GROUP (ORDER BY a) FROM t", []string{",", ",", "ON OVERFLOW TRUNCATE", "WITH COUNT"}},
		{keywords.DialectOracle, "SELECT LISTAGG(a, ',' ON OVERFLOW ERROR) WITHIN GROUP (ORDER BY a) FROM t", []string{",", ",", "ON OVERFLOW ERROR"}},
	}
	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			fc := asFunctionCall(t, parseFirstColumn(t, tt.dialect, tt.sql))
			got := keywordArgs(fc)
			if len(got) != len(tt.want) {
				t.Fatalf("argument keywords = %q, want %q", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("argument keywords = %q, want %q", got, tt.want)
				}
			}
		})
	}
}

func TestPrimary_SpecialFormTypeNames(t *testing.T) {
	fc := asFunctionCall(t, parseFirstColumn(t, keywords.DialectMySQL, "SELECT CONVERT(x USING utf8mb4) FROM t"))
	ka, ok := fc.Arguments[1].(*ast.KeywordArgument)
	if !ok || ka.TypeName != "utf8mb4" || ka.Value != nil {
		t.Errorf("USING argument = %#v, want TypeName utf8mb4", fc.Arguments[1])
	}
	fc = asFunctionCall(t, parseFirstColumn(t, keywords.DialectSQLServer, "SELECT TRY_PARSE('1' AS DECIMAL(10,2))"))
	ka, ok = fc.Arguments[1].(*ast.KeywordArgument)
	if !ok || ka.TypeName != "DECIMAL(10,2)" {
		t.Errorf("AS argument = %#v, want TypeName DECIMAL(10,2)", fc.Arguments[1])
	}
}

func TestPrimary_GroupConcatSeparator(t *testing.T) {
	tests := []struct {
		sql      string
		args     int
		distinct bool
		orderBy  int
		sep      string
	}{
		{"SELECT GROUP_CONCAT(a SEPARATOR '|') FROM t", 1, false, 0, "|"},
		{"SELECT GROUP_CONCAT(DISTINCT a ORDER BY a DESC SEPARATOR ',') FROM t", 1, true, 1, ","},
		{"SELECT GROUP_CONCAT(a, b SEPARATOR '') FROM t", 2, false, 0, ""},
		{"SELECT GROUP_CONCAT(a) FROM t", 1, false, 0, "<none>"},
	}
	for _, d := range []keywords.SQLDialect{keywords.DialectMySQL, keywords.DialectMariaDB} {
		for _, tt := range tests {
			t.Run(string(d)+"/"+tt.sql, func(t *testing.T) {
				fc := asFunctionCall(t, parseFirstColumn(t, d, tt.sql))
				if len(fc.Arguments) != tt.args || fc.Distinct != tt.distinct || len(fc.OrderBy) != tt.orderBy {
					t.Fatalf("got args=%d distinct=%v orderBy=%d", len(fc.Arguments), fc.Distinct, len(fc.OrderBy))
				}
				if tt.sep == "<none>" {
					if fc.Separator != nil {
						t.Errorf("Separator = %#v, want nil", fc.Separator)
					}
					return
				}
				if lit := fc.Separator; lit == nil || lit.Value != tt.sep {
					t.Errorf("Separator = %#v, want %q", fc.Separator, tt.sep)
				}
			})
		}
	}
}

func TestPrimary_Interval(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		value   string // legacy Value
		unit    string
		expr    bool // ValueExpr set
	}{
		{keywords.DialectMySQL, "SELECT INTERVAL 1 DAY", "1 DAY", "DAY", true},
		{keywords.DialectMariaDB, "SELECT INTERVAL 3 hour", "3 HOUR", "HOUR", true},
		{keywords.DialectClickHouse, "SELECT INTERVAL x DAY", "x DAY", "DAY", true},
		{keywords.DialectMySQL, "SELECT INTERVAL -2 MINUTE", "-2 MINUTE", "MINUTE", true},
		{keywords.DialectMySQL, "SELECT INTERVAL (a + 1) DAY", "(a + 1) DAY", "DAY", true},
		{keywords.DialectMySQL, "SELECT INTERVAL '1-2' YEAR_MONTH", "1-2", "", false},
		{keywords.DialectPostgreSQL, "SELECT INTERVAL '1 day'", "1 day", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			iv, ok := parseFirstColumn(t, tt.dialect, tt.sql).(*ast.IntervalExpression)
			if !ok {
				t.Fatalf("expected *ast.IntervalExpression")
			}
			if iv.Value != tt.value || iv.Unit != tt.unit || (iv.ValueExpr != nil) != tt.expr {
				t.Errorf("got Value=%q Unit=%q ValueExpr=%v", iv.Value, iv.Unit, iv.ValueExpr)
			}
		})
	}
}

func TestPrimary_IntervalErrors(t *testing.T) {
	for _, tc := range []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectMySQL, "SELECT INTERVAL FROM t"},
		{keywords.DialectMySQL, "SELECT INTERVAL 1 FROM t"},
		{keywords.DialectClickHouse, "SELECT INTERVAL x"},
		{keywords.DialectPostgreSQL, "SELECT INTERVAL(1, 2)"},
	} {
		if tree, err := ParseWithDialect(tc.sql, tc.dialect); err == nil {
			ast.ReleaseAST(tree)
			t.Errorf("%s: %q parsed, want an error", tc.dialect, tc.sql)
		}
	}
}

func TestPrimary_MatchAgainst(t *testing.T) {
	tests := []struct {
		sql      string
		columns  int
		modifier string
	}{
		{"SELECT * FROM t WHERE MATCH(a) AGAINST ('x' IN BOOLEAN MODE)", 1, "IN BOOLEAN MODE"},
		{"SELECT * FROM t WHERE MATCH(a, b) AGAINST ('x')", 2, ""},
		{"SELECT * FROM t WHERE MATCH(a) AGAINST ('x' WITH QUERY EXPANSION)", 1, "WITH QUERY EXPANSION"},
		{"SELECT * FROM t WHERE MATCH(a) AGAINST ('x' IN NATURAL LANGUAGE MODE)", 1, "IN NATURAL LANGUAGE MODE"},
	}
	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			tree, err := ParseWithDialect(tt.sql, keywords.DialectMySQL)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			defer ast.ReleaseAST(tree)
			sel, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
			}
			m, ok := sel.Where.(*ast.MatchAgainstExpression)
			if !ok {
				t.Fatalf("expected *ast.MatchAgainstExpression, got %T", sel.Where)
			}
			if len(m.Columns) != tt.columns || m.Modifier != tt.modifier {
				t.Errorf("got %d columns, modifier %q", len(m.Columns), m.Modifier)
			}
		})
	}
	if tree, err := ParseWithDialect("SELECT * FROM t WHERE MATCH(a) AGAINST ('x' IN FOO MODE)", keywords.DialectMySQL); err == nil {
		ast.ReleaseAST(tree)
		t.Error("unknown search modifier parsed, want an error")
	}
}

func TestPrimary_KeepClause(t *testing.T) {
	for _, tt := range []struct {
		sql  string
		last bool
		over bool
	}{
		{"SELECT MAX(a) KEEP (DENSE_RANK LAST ORDER BY b) FROM t", true, false},
		{"SELECT MIN(a) KEEP (DENSE_RANK FIRST ORDER BY b DESC, c) OVER (PARTITION BY d) FROM t", false, true},
	} {
		t.Run(tt.sql, func(t *testing.T) {
			fc := asFunctionCall(t, parseFirstColumn(t, keywords.DialectOracle, tt.sql))
			if fc.Keep == nil || fc.Keep.Last != tt.last || len(fc.Keep.OrderBy) == 0 {
				t.Fatalf("Keep = %#v", fc.Keep)
			}
			if (fc.Over != nil) != tt.over {
				t.Errorf("Over = %v, want set=%v", fc.Over, tt.over)
			}
		})
	}
}

func TestPrimary_HierarchicalOperators(t *testing.T) {
	root, ok := parseFirstColumn(t, keywords.DialectOracle,
		"SELECT CONNECT_BY_ROOT name FROM e CONNECT BY PRIOR id = m").(*ast.ConnectByRootExpression)
	if !ok {
		t.Fatalf("expected *ast.ConnectByRootExpression")
	}
	if id, ok := root.Expr.(*ast.Identifier); !ok || id.Name != "name" {
		t.Errorf("operand = %#v, want name", root.Expr)
	}
	prior, ok := parseFirstColumn(t, keywords.DialectOracle,
		"SELECT PRIOR name AS m FROM e CONNECT BY PRIOR id = m").(*ast.UnaryExpression)
	if !ok || prior.Operator != ast.Prior {
		t.Fatalf("expected PRIOR unary expression, got %#v", prior)
	}
	// A column named prior is still a column.
	if id, ok := parseFirstColumn(t, keywords.DialectOracle, "SELECT prior FROM t").(*ast.Identifier); !ok || id.Name != "prior" {
		t.Errorf("SELECT prior FROM t: got %#v", id)
	}
}

func TestPrimary_SequencesAndVariables(t *testing.T) {
	nv, ok := parseFirstColumn(t, keywords.DialectSQLServer, "SELECT NEXT VALUE FOR dbo.s").(*ast.NextValueForExpression)
	if !ok || nv.Sequence != "dbo.s" {
		t.Errorf("NEXT VALUE FOR: got %#v", nv)
	}
	nv, ok = parseFirstColumn(t, keywords.DialectMariaDB, "SELECT NEXT VALUE FOR s").(*ast.NextValueForExpression)
	if !ok || nv.Sequence != "s" {
		t.Errorf("NEXT VALUE FOR: got %#v", nv)
	}
	for _, tt := range []struct {
		sql, scope, name string
	}{
		{"SELECT @@version", "", "version"},
		{"SELECT @@session.sql_mode", "session", "sql_mode"},
		{"SELECT @@GLOBAL.max_connections", "GLOBAL", "max_connections"},
	} {
		sv, ok := parseFirstColumn(t, keywords.DialectMySQL, tt.sql).(*ast.SystemVariable)
		if !ok || sv.Scope != tt.scope || sv.Name != tt.name {
			t.Errorf("%s: got %#v", tt.sql, sv)
		}
	}
	as, ok := parseFirstColumn(t, keywords.DialectMySQL, "SELECT @rn := @rn + 1 AS rn FROM t").(*ast.AssignmentExpression)
	if !ok {
		t.Fatalf("expected *ast.AssignmentExpression")
	}
	if _, ok := as.Value.(*ast.BinaryExpression); !ok {
		t.Errorf("assignment value = %T, want *ast.BinaryExpression", as.Value)
	}
}

func TestPrimary_ArrayForms(t *testing.T) {
	arr, ok := parseFirstColumn(t, keywords.DialectPostgreSQL, "SELECT ARRAY[[1, 2], [3, 4]]").(*ast.ArrayConstructorExpression)
	if !ok || arr.Bracket || len(arr.Elements) != 2 {
		t.Fatalf("got %#v", arr)
	}
	if inner, ok := arr.Elements[0].(*ast.ArrayConstructorExpression); !ok || !inner.Bracket || len(inner.Elements) != 2 {
		t.Errorf("nested row = %#v, want a bracket row of 2", arr.Elements[0])
	}
	arr, ok = parseFirstColumn(t, keywords.DialectPostgreSQL, "SELECT ARRAY(SELECT 1 UNION SELECT 2)").(*ast.ArrayConstructorExpression)
	if !ok || arr.Subquery != nil {
		t.Fatalf("got %#v", arr)
	}
	if _, ok := arr.Query.(*ast.SetOperation); !ok {
		t.Errorf("Query = %T, want *ast.SetOperation", arr.Query)
	}
	arr, ok = parseFirstColumn(t, keywords.DialectSnowflake, "SELECT [1, 2, 3]").(*ast.ArrayConstructorExpression)
	if !ok || !arr.Bracket || len(arr.Elements) != 3 {
		t.Errorf("snowflake [1, 2, 3] = %#v", arr)
	}
	if _, ok := parseFirstColumn(t, keywords.DialectClickHouse, "SELECT [1, 2][1]").(*ast.ArraySubscriptExpression); !ok {
		t.Errorf("clickhouse [1, 2][1] is not a subscript")
	}
	fa, ok := parseFirstColumn(t, keywords.DialectClickHouse, "SELECT (1, 'a').1").(*ast.FieldAccessExpression)
	if !ok || fa.Field != "1" {
		t.Errorf("clickhouse (1, 'a').1 = %#v", fa)
	}
}

func TestPrimary_CastForms(t *testing.T) {
	tests := []struct {
		dialect  keywords.SQLDialect
		sql      string
		typ      string
		asString bool
	}{
		{keywords.DialectClickHouse, "SELECT CAST(x, 'UInt32')", "UInt32", true},
		{keywords.DialectClickHouse, "SELECT CAST(x AS UInt32)", "UInt32", false},
		{keywords.DialectPostgreSQL, "SELECT CAST(a AS int[])", "int[]", false},
		{keywords.DialectPostgreSQL, "SELECT CAST(a AS text[][])", "text[][]", false},
		{keywords.DialectPostgreSQL, "SELECT CAST(x AS double precision)", "double precision", false},
		{keywords.DialectPostgreSQL, "SELECT CAST(t AS timestamp with time zone)", "timestamp with time zone", false},
		{keywords.DialectPostgreSQL, "SELECT CAST(c AS character varying(20))", "character varying(20)", false},
		{keywords.DialectMySQL, "SELECT CAST(1 AS SIGNED INTEGER)", "SIGNED INTEGER", false},
	}
	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			c, ok := parseFirstColumn(t, tt.dialect, tt.sql).(*ast.CastExpression)
			if !ok {
				t.Fatalf("expected *ast.CastExpression")
			}
			if c.Type != tt.typ || c.TypeAsString != tt.asString {
				t.Errorf("got Type=%q TypeAsString=%v", c.Type, c.TypeAsString)
			}
		})
	}
	if tree, err := ParseWithDialect("SELECT CAST(x, 'UInt32')", keywords.DialectPostgreSQL); err == nil {
		ast.ReleaseAST(tree)
		t.Error("CAST(x, 'T') parsed outside ClickHouse, want an error")
	}
}

func TestPrimary_PriorOutsideOracleIsAColumn(t *testing.T) {
	// Outside Oracle, "prior" is an ordinary column name: it must never be
	// read as the PRIOR operator applied to the next word.
	for _, d := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectSnowflake} {
		tree, err := ParseWithDialect("SELECT prior x FROM t", d)
		if err != nil {
			continue // implicit aliases are not accepted in every dialect
		}
		col := firstColumn(t, tree)
		if u, ok := col.(*ast.UnaryExpression); ok && u.Operator == ast.Prior {
			t.Errorf("%s: SELECT prior x parsed as PRIOR x", d)
		}
		ast.ReleaseAST(tree)
	}
}
