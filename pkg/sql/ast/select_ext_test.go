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

import (
	"reflect"
	"strings"
	"testing"
)

// TestSelectExt_SQL renders hand-built SELECT-body clauses through SQL().
func TestSelectExt_SQL(t *testing.T) {
	id := func(n string) *Identifier { return &Identifier{Name: n} }
	str := func(s string) *LiteralValue { return &LiteralValue{Value: s, Type: "string"} }
	num := func(s string) *LiteralValue { return &LiteralValue{Value: s, Type: "int"} }
	ph := func(s string) *LiteralValue { return &LiteralValue{Value: s, Type: "placeholder"} }
	base := func() *SelectStatement {
		return &SelectStatement{Columns: []Expression{id("a")}, From: []TableReference{{Name: "t"}}}
	}
	cases := []struct {
		name string
		mod  func(s *SelectStatement)
		want string
	}{
		{"limit expr", func(s *SelectStatement) { s.LimitExpr = ph("$1") }, "SELECT a FROM t LIMIT $1"},
		{"limit int wins over expr", func(s *SelectStatement) { v := 3; s.Limit = &v; s.LimitExpr = ph("$1") }, "SELECT a FROM t LIMIT 3"},
		{"limit all", func(s *SelectStatement) { s.LimitAll = true }, "SELECT a FROM t LIMIT ALL"},
		{"offset expr rows", func(s *SelectStatement) { s.OffsetExpr = ph("@s"); s.OffsetRows = true }, "SELECT a FROM t OFFSET @s ROWS"},
		{"offset one row", func(s *SelectStatement) { v := 1; s.Offset = &v; s.OffsetRows = true }, "SELECT a FROM t OFFSET 1 ROW"},
		{"offset gets rows before fetch", func(s *SelectStatement) {
			v := 4
			s.Offset = &v
			s.Fetch = &FetchClause{FetchType: "NEXT", FetchExpr: ph("@n")}
		}, "SELECT a FROM t OFFSET 4 ROWS FETCH NEXT @n ROWS ONLY"},
		{"limit by", func(s *SelectStatement) {
			s.EnsureExtras().LimitBy = &LimitByClause{Count: num("2"), Offset: num("1"), Exprs: []Expression{id("u"), id("p")}}
			v := 100
			s.Limit = &v
		}, "SELECT a FROM t LIMIT 2 OFFSET 1 BY u, p LIMIT 100"},
		{"group by all with totals", func(s *SelectStatement) { s.GroupByModifiers = GroupByModifiers{All: true, WithTotals: true} }, "SELECT a FROM t GROUP BY ALL WITH TOTALS"},
		{"group by with cube", func(s *SelectStatement) {
			s.GroupBy = []Expression{id("a")}
			s.GroupByModifiers.WithCube = true
		}, "SELECT a FROM t GROUP BY a WITH CUBE"},
		{"modifiers and top", func(s *SelectStatement) {
			s.EnsureExtras().SelectModifiers = []string{"HIGH_PRIORITY", "SQL_NO_CACHE"}
			s.Top = &TopClause{Count: ph("@n")}
		}, "SELECT HIGH_PRIORITY SQL_NO_CACHE TOP (@n) a FROM t"},
		{"top keeps parentheses", func(s *SelectStatement) { s.Top = &TopClause{Count: num("10"), Parenthesized: true} }, "SELECT TOP (10) a FROM t"},
		{"top bare number", func(s *SelectStatement) { s.Top = &TopClause{Count: num("10"), IsPercent: true} }, "SELECT TOP 10 PERCENT a FROM t"},
		{"into table", func(s *SelectStatement) {
			s.EnsureExtras().Into = &SelectInto{Kind: SelectIntoTable, Table: "db.n", Temporary: "UNLOGGED", TableKeyword: true}
		}, "SELECT a INTO UNLOGGED TABLE db.n FROM t"},
		{"into variables trailing", func(s *SelectStatement) {
			s.EnsureExtras().Into = &SelectInto{Kind: SelectIntoVariables, Targets: []Expression{ph("@x")}, Trailing: true}
			s.For = &ForClause{LockType: "UPDATE"}
		}, "SELECT a FROM t INTO @x FOR UPDATE"},
		{"into dumpfile", func(s *SelectStatement) {
			s.EnsureExtras().Into = &SelectInto{Kind: SelectIntoDumpfile, File: str("/tmp/x")}
		}, "SELECT a INTO DUMPFILE '/tmp/x' FROM t"},
		{"into outfile options", func(s *SelectStatement) {
			s.EnsureExtras().Into = &SelectInto{Kind: SelectIntoOutfile, File: str("f"), CharacterSet: "utf8mb4", Trailing: true,
				FieldsOptions: []IntoFileOption{{Option: "TERMINATED BY", Value: str(",")}, {Option: "ESCAPED BY", Value: str("x")}},
				LinesOptions:  []IntoFileOption{{Option: "STARTING BY", Value: str(">")}}}
		}, "SELECT a FROM t INTO OUTFILE 'f' CHARACTER SET utf8mb4 FIELDS TERMINATED BY ',' ESCAPED BY 'x' LINES STARTING BY '>'"},
		{"order siblings and interpolate", func(s *SelectStatement) {
			s.OrderBy = []OrderByExpression{{Expression: id("a"), Ascending: true, UsingOperator: ">"}}
			s.OrderSiblings = true
			s.EnsureExtras().Interpolate = &InterpolateClause{}
		}, "SELECT a FROM t ORDER SIBLINGS BY a USING > INTERPOLATE"},
		{"for xml raw", func(s *SelectStatement) {
			s.EnsureExtras().ForOutput = &ForOutputClause{Kind: "XML", Mode: "RAW", ModeArg: str("r"), Options: []ForOutputOption{{Name: "BINARY BASE64"}, {Name: "ROOT"}}}
		}, "SELECT a FROM t FOR XML RAW('r'), BINARY BASE64, ROOT"},
		{"for browse", func(s *SelectStatement) { s.EnsureExtras().ForOutput = &ForOutputClause{Kind: "BROWSE"} }, "SELECT a FROM t FOR BROWSE"},
		{"query hints", func(s *SelectStatement) {
			s.EnsureExtras().QueryHints = []QueryHint{
				{Name: "USE HINT", HasArgs: true, Args: []QueryHintArg{{Expr: str("X")}}},
				{Name: "MAX_GRANT_PERCENT", Equals: true, Value: num("5")},
			}
		}, "SELECT a FROM t OPTION (USE HINT ('X'), MAX_GRANT_PERCENT = 5)"},
		{"lock in share mode wait", func(s *SelectStatement) {
			s.For = &ForClause{LockType: "SHARE", LockInShareMode: true, Wait: num("3")}
		}, "SELECT a FROM t LOCK IN SHARE MODE WAIT 3"},
		{"format", func(s *SelectStatement) { s.EnsureExtras().OutputFormat = "TSV" }, "SELECT a FROM t FORMAT TSV"},
		{"qualify", func(s *SelectStatement) { s.Qualify = id("q") }, "SELECT a FROM t QUALIFY q"},
		{"joins", func(s *SelectStatement) {
			s.Joins = []JoinClause{
				{Type: "INNER", Global: true, Strictness: "all", Right: TableReference{Name: "b"}, Using: []Expression{id("k")}},
				{Type: "LEFT", Hint: "merge", Right: TableReference{Name: "c"}, Condition: id("x")},
				{Type: "CROSS", Comma: true, Right: TableReference{Name: "d"}},
				{Type: "INNER", Hint: "STRAIGHT_JOIN", Right: TableReference{Name: "e"}},
				{Type: "OUTER APPLY", Right: TableReference{Name: "f"}},
				{Type: "INNER", Strictness: "ASOF", Right: TableReference{Name: "g"}, MatchCondition: id("m"), Condition: id("y")},
			}
		}, "SELECT a FROM t GLOBAL ALL JOIN b USING (k) LEFT MERGE JOIN c ON x , d STRAIGHT_JOIN e OUTER APPLY f ASOF JOIN g MATCH_CONDITION (m) ON y"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base()
			tc.mod(s)
			if got := s.SQL(); got != tc.want {
				t.Errorf("SQL()\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// TestSelectExt_UnknownKeywordsDropped checks that a hand-built AST cannot
// inject SQL through the keyword-valued fields of the new clauses.
func TestSelectExt_UnknownKeywordsDropped(t *testing.T) {
	const evil = "x; DROP TABLE users; --"
	s := &SelectStatement{
		Columns: []Expression{&Identifier{Name: "a"}},
		From:    []TableReference{{Name: "t"}},
		Extras: &SelectExtras{
			SelectModifiers: []string{evil},
			Into:            &SelectInto{Kind: SelectIntoTable, Table: "n", Temporary: evil},
			ForOutput:       &ForOutputClause{Kind: "JSON", Mode: evil, Options: []ForOutputOption{{Name: evil}}},
			QueryHints:      []QueryHint{{Name: evil}},
			OutputFormat:    evil,
		},
		Joins:   []JoinClause{{Type: "INNER", Strictness: evil, Hint: evil, Right: TableReference{Name: "b"}}},
		OrderBy: []OrderByExpression{{Expression: &Identifier{Name: "a"}, UsingOperator: evil}},
	}
	got := s.SQL()
	if strings.Contains(got, "DROP") {
		t.Fatalf("SQL() wrote an unknown keyword: %s", got)
	}
	if forced := (&SelectStatement{Columns: []Expression{&Identifier{Name: "a"}}, Extras: &SelectExtras{ForOutput: &ForOutputClause{Kind: evil}}}).SQL(); strings.Contains(forced, "DROP") || strings.Contains(forced, "FOR") {
		t.Fatalf("unknown FOR kind written: %s", forced)
	}
}

// TestSelectExt_Children checks that the new clause nodes expose their
// expression fields to the visitor.
func TestSelectExt_Children(t *testing.T) {
	cases := []childrenCoverageCase{
		{"StarExpression", reflect.TypeOf(StarExpression{})},
		{"LimitByClause", reflect.TypeOf(LimitByClause{})},
		{"SelectInto", reflect.TypeOf(SelectInto{})},
		{"ForOutputClause", reflect.TypeOf(ForOutputClause{})},
		{"InterpolateClause", reflect.TypeOf(InterpolateClause{})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ptr := reflect.New(c.typ)
			injected := injectMockChildren(t, ptr.Elem())
			got := callChildren(t, ptr)
			for _, want := range injected {
				if !containsNode(got, want.node) {
					t.Errorf("%s.Children() dropped %s", c.name, want.fieldPath)
				}
			}
			// Zero values must be safe.
			_ = callChildren(t, reflect.New(c.typ))
		})
	}

	// Nested expression fields reached through the statement.
	lim, off, cnt := &Identifier{Name: "l"}, &Identifier{Name: "o"}, &Identifier{Name: "c"}
	s := SelectStatement{
		LimitExpr:  lim,
		OffsetExpr: off,
		Extras: &SelectExtras{
			LimitBy:    &LimitByClause{Count: cnt},
			QueryHints: []QueryHint{{Name: "MAXDOP", Value: &Identifier{Name: "h"}}},
		},
	}
	got := s.Children()
	for _, want := range []Node{lim, off, s.Extras.LimitBy, s.Extras.QueryHints[0].Value} {
		if !containsNode(got, want) {
			t.Errorf("SelectStatement.Children() lacks %v", want)
		}
	}
}

// TestSelectExt_ReleaseClearsFields checks that releasing a statement clears
// every field added for the new clauses, so a pooled statement never leaks
// them into its next use.
func TestSelectExt_ReleaseClearsFields(t *testing.T) {
	n := 3
	s := &SelectStatement{
		GroupByModifiers: GroupByModifiers{All: true},
		OrderSiblings:    true,
		LimitExpr:        &Identifier{Name: "$1"},
		OffsetExpr:       &Identifier{Name: "$2"},
		LimitAll:         true,
		OffsetRows:       true,
		LimitWithTies:    true,
		Extras: &SelectExtras{
			SelectModifiers: []string{"SQL_NO_CACHE"},
			Into:            &SelectInto{Kind: SelectIntoVariables, Targets: []Expression{&Identifier{Name: "@x"}}},
			Interpolate:     &InterpolateClause{Items: []InterpolateItem{{Column: "c", Expr: &Identifier{Name: "c"}}}},
			LimitBy:         &LimitByClause{Count: &Identifier{Name: "n"}},
			ForOutput:       &ForOutputClause{Kind: "JSON"},
			QueryHints:      []QueryHint{{Name: "RECOMPILE"}},
			OutputFormat:    "JSON",
			RowsExamined:    &Identifier{Name: "examined"},
		},
		Limit: &n,
		Fetch: &FetchClause{FetchExpr: &Identifier{Name: "f"}},
		For:   &ForClause{Wait: &Identifier{Name: "w"}},
		Joins: []JoinClause{{Global: true, Strictness: "ANY", Hint: "HASH", MatchCondition: &Identifier{Name: "m"}, Comma: true}},
	}
	extras := s.Extras
	releaseSelectStatement(s, releaseDrawn)
	if !reflect.ValueOf(extras).Elem().IsZero() {
		t.Errorf("released extras retain state: %#v", extras)
	}
	rv := reflect.ValueOf(s).Elem()
	rt := rv.Type()
	for i := 0; i < rv.NumField(); i++ {
		f := rv.Field(i)
		if f.Kind() == reflect.Slice {
			if f.Len() != 0 {
				t.Errorf("field %s not reset: len=%d", rt.Field(i).Name, f.Len())
			}
			continue
		}
		if !f.IsZero() {
			t.Errorf("field %s not reset: %#v", rt.Field(i).Name, f.Interface())
		}
	}
}
