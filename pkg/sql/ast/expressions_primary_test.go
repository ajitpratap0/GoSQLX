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

package ast

import "testing"

func TestPrimaryNodes_SQL(t *testing.T) {
	col := func(n string) *Identifier { return &Identifier{Name: n} }
	str := func(s string) *LiteralValue { return &LiteralValue{Value: s, Type: "string"} }
	num := func(s string) *LiteralValue { return &LiteralValue{Value: s, Type: "int"} }

	tests := []struct {
		name string
		node interface{ SQL() string }
		want string
	}{
		{"keyword args", &FunctionCall{Name: "SUBSTRING", Arguments: []Expression{
			col("s"), &KeywordArgument{Keyword: "FROM", Value: num("2")}, &KeywordArgument{Keyword: "FOR", Value: num("3")},
		}}, "SUBSTRING(s FROM 2 FOR 3)"},
		{"leading keyword arg", &FunctionCall{Name: "TRIM", Arguments: []Expression{
			&KeywordArgument{Keyword: "BOTH"}, &KeywordArgument{Keyword: "FROM", Value: col("s")},
		}}, "TRIM(BOTH FROM s)"},
		{"type keyword arg", &FunctionCall{Name: "CONVERT", Arguments: []Expression{
			col("x"), &KeywordArgument{Keyword: "USING", TypeName: "utf8mb4"},
		}}, "CONVERT(x USING utf8mb4)"},
		{"unknown keyword dropped", &KeywordArgument{Keyword: "; DROP TABLE t", Value: col("x")}, "x"},
		{"unsafe type quoted", &KeywordArgument{Keyword: "AS", TypeName: "INT); DROP"}, `AS "INT); DROP"`},
		{"separator", &FunctionCall{Name: "GROUP_CONCAT", Arguments: []Expression{col("a")}, Separator: str("|")},
			"GROUP_CONCAT(a SEPARATOR '|')"},
		{"keep", &FunctionCall{Name: "MIN", Arguments: []Expression{col("a")},
			Keep: &KeepClause{Last: true, OrderBy: []OrderByExpression{{Expression: col("b"), Ascending: true}}}},
			"MIN(a) KEEP (DENSE_RANK LAST ORDER BY b)"},
		{"typed literal", &TypedLiteral{TypeName: "DATE", Value: "2024-01-01"}, "DATE '2024-01-01'"},
		{"typed literal escaped", &TypedLiteral{TypeName: "DATE", Value: "x'y"}, "DATE 'x''y'"},
		{"outer join marker", &OuterJoinMarker{Expr: &Identifier{Table: "b", Name: "id"}}, "b.id(+)"},
		{"match", &MatchAgainstExpression{Columns: []Expression{col("a"), col("b")}, Query: str("x"), Modifier: "IN BOOLEAN MODE"},
			"MATCH(a, b) AGAINST('x' IN BOOLEAN MODE)"},
		{"match unknown modifier dropped", &MatchAgainstExpression{Columns: []Expression{col("a")}, Query: str("x"), Modifier: "x) OR (1"},
			"MATCH(a) AGAINST('x')"},
		{"next value", &NextValueForExpression{Sequence: "dbo.s"}, "NEXT VALUE FOR dbo.s"},
		{"system variable", &SystemVariable{Scope: "GLOBAL", Name: "max_connections"}, "@@GLOBAL.max_connections"},
		{"system variable unsafe name", &SystemVariable{Name: "a b"}, `@@"a b"`},
		{"assignment", &AssignmentExpression{Target: &LiteralValue{Value: "@rn", Type: "placeholder"}, Value: num("1")}, "@rn := 1"},
		{"connect by root", &ConnectByRootExpression{Expr: col("name")}, "CONNECT_BY_ROOT name"},
		{"national string", &LiteralValue{Value: "it's", Type: "string", Prefix: "N"}, "N'it''s'"},
		{"national string plain", &LiteralValue{Value: "abc", Type: "string", Prefix: "N"}, "N'abc'"},
		{"interval unquoted", &IntervalExpression{Value: "1 DAY", ValueExpr: num("1"), Unit: "DAY"}, "INTERVAL 1 DAY"},
		{"interval unsafe unit dropped", &IntervalExpression{ValueExpr: num("1"), Unit: "DAY; DROP"}, "INTERVAL 1"},
		{"interval legacy", &IntervalExpression{Value: "1 day"}, "INTERVAL '1 day'"},
		{"bracket array", &ArrayConstructorExpression{Elements: []Expression{num("1"), num("2")}, Bracket: true}, "[1, 2]"},
		{"try cast", &CastExpression{Expr: col("x"), Type: "INT", Try: true}, "TRY_CAST(x AS INT)"},
		{"cast type string", &CastExpression{Expr: col("x"), Type: "Nullable(String)", TypeAsString: true}, "CAST(x, 'Nullable(String)')"},
		{"tuple element", &FieldAccessExpression{Expr: &TupleExpression{Expressions: []Expression{num("1"), str("a")}}, Field: "1"}, "(1, 'a').1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.node.SQL(); got != tt.want {
				t.Errorf("SQL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPrimaryNodes_NilSafe(t *testing.T) {
	for _, n := range []interface{ SQL() string }{
		(*KeywordArgument)(nil), (*TypedLiteral)(nil), (*OuterJoinMarker)(nil),
		(*MatchAgainstExpression)(nil), (*NextValueForExpression)(nil), (*SystemVariable)(nil),
		(*AssignmentExpression)(nil), (*ConnectByRootExpression)(nil),
	} {
		if got := n.SQL(); got != "" {
			t.Errorf("%T(nil).SQL() = %q, want empty", n, got)
		}
	}
	if (*KeepClause)(nil).Children() != nil {
		t.Error("nil KeepClause has children")
	}
}

func TestPrimaryNodes_Children(t *testing.T) {
	a, b := &Identifier{Name: "a"}, &Identifier{Name: "b"}
	tests := []struct {
		name string
		node Node
		want int
	}{
		{"keyword arg", &KeywordArgument{Keyword: "FROM", Value: a}, 1},
		{"keyword only", &KeywordArgument{Keyword: "BOTH"}, 0},
		{"outer join", &OuterJoinMarker{Expr: a}, 1},
		{"match", &MatchAgainstExpression{Columns: []Expression{a}, Query: b}, 2},
		{"assignment", &AssignmentExpression{Target: a, Value: b}, 2},
		{"connect by root", &ConnectByRootExpression{Expr: a}, 1},
		{"interval value", &IntervalExpression{ValueExpr: a, Unit: "DAY"}, 1},
		{"function separator and keep", &FunctionCall{Name: "f", Arguments: []Expression{a}, Separator: &LiteralValue{Value: "|", Type: "string"},
			Keep: &KeepClause{OrderBy: []OrderByExpression{{Expression: a}}}}, 3},
		{"array query", &ArrayConstructorExpression{Query: &SelectStatement{}}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(tt.node.Children()); got != tt.want {
				t.Errorf("len(Children()) = %d, want %d", got, tt.want)
			}
		})
	}
}
