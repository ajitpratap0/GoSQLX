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

// TestReleaseTableReference_ClearsTableFactorModifiers checks that releasing
// a TableReference leaves it equal to the zero value, including the
// table-factor modifiers.
func TestReleaseTableReference_ClearsTableFactorModifiers(t *testing.T) {
	num := func(v string) *LiteralValue { return &LiteralValue{Value: v, Type: "int"} }
	ref := TableReference{
		Name:          "t",
		Alias:         "x",
		Only:          true,
		Final:         true,
		ColumnAliases: &ColumnAliasList{Names: []string{"a"}, Types: []string{"int"}},
		Modifiers: &TableModifiers{
			TableSample: &TableSampleClause{
				Keyword: "TABLESAMPLE", Method: "SYSTEM", Args: []Expression{num("1")},
				SeedKeyword: "REPEATABLE", Seed: num("2"),
			},
			Flashback: &FlashbackClause{Versions: true, Kind: "SCN", Start: num("1"), End: num("2")},
			DBLink:    "l", Partitions: []string{"p"}, IndexedBy: "i",
		},
		Values: &Values{Rows: [][]Expression{{num("3")}}},
		ForSystemTime: &ForSystemTimeClause{
			Type: SystemTimeContainedIn, Start: num("4"), End: num("5"),
		},
	}
	releaseTableReference(&ref, releaseAll)
	if !reflect.DeepEqual(ref, TableReference{}) {
		t.Errorf("released TableReference is not zero: %+v", ref)
	}
}

// TestTableFactorRender_HandBuiltValuesAreSafe checks that hand-built
// table-factor values that the parser cannot produce are quoted or dropped
// rather than written verbatim.
func TestTableFactorRender_HandBuiltValuesAreSafe(t *testing.T) {
	const evil = "x); DROP TABLE y; --"
	cases := []struct {
		name string
		ref  TableReference
	}{
		{"sample method", TableReference{Name: "t", Modifiers: &TableModifiers{TableSample: &TableSampleClause{Keyword: "TABLESAMPLE", Method: evil, Args: []Expression{&LiteralValue{Value: "1", Type: "int"}}}}}},
		{"sample keyword", TableReference{Name: "t", Modifiers: &TableModifiers{TableSample: &TableSampleClause{Keyword: evil, Args: []Expression{&LiteralValue{Value: "1", Type: "int"}}}}}},
		{"sample unit", TableReference{Name: "t", Modifiers: &TableModifiers{TableSample: &TableSampleClause{Keyword: "SAMPLE", Unit: evil, Args: []Expression{&LiteralValue{Value: "1", Type: "int"}}}}}},
		{"flashback kind", TableReference{Name: "t", Modifiers: &TableModifiers{Flashback: &FlashbackClause{Kind: evil, Point: &LiteralValue{Value: "1", Type: "int"}}}}},
		{"db link", TableReference{Name: "t", Modifiers: &TableModifiers{DBLink: evil}}},
		{"partition", TableReference{Name: "t", Modifiers: &TableModifiers{Partitions: []string{evil}}}},
		{"index hint name", TableReference{Name: "t", Modifiers: &TableModifiers{IndexHints: []IndexHint{{Action: "USE", Keyword: "INDEX", Names: []string{evil}}}}}},
		{"index hint action", TableReference{Name: "t", Modifiers: &TableModifiers{IndexHints: []IndexHint{{Action: evil}}}}},
		{"indexed by", TableReference{Name: "t", Modifiers: &TableModifiers{IndexedBy: evil}}},
		{"time travel name", TableReference{Name: "t", TimeTravel: &TimeTravelClause{Kind: "AT", Named: map[string]Expression{evil: &LiteralValue{Value: "1", Type: "int"}}}}},
		{"time travel kind", TableReference{Name: "t", TimeTravel: &TimeTravelClause{Kind: evil}}},
		{"pattern", TableReference{Name: "t", MatchRecognize: &MatchRecognizeClause{Pattern: evil}}},
		{"after match", TableReference{Name: "t", MatchRecognize: &MatchRecognizeClause{AfterMatch: evil}}},
		{"table hint args", TableReference{Name: "t", TableHints: []string{"INDEX(" + evil + ")"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tableRefSQL(&tc.ref)
			if strings.Contains(got, ";") && !strings.Contains(got, `"`) {
				t.Errorf("unsafe value written verbatim: %s", got)
			}
			if strings.Contains(got, "DROP TABLE y; --") && !strings.Contains(got, `"`+evil+`"`) &&
				!strings.Contains(got, `"INDEX(`+evil+`)"`) {
				t.Errorf("unsafe value written without quotes: %s", got)
			}
		})
	}
}

// TestSetOperandNeedsParens pins the parenthesization rules for set
// operation operands.
func TestSetOperandNeedsParens(t *testing.T) {
	sel := &SelectStatement{}
	inter := &SetOperation{Left: sel, Operator: "INTERSECT", Right: sel}
	union := &SetOperation{Left: sel, Operator: "UNION", Right: sel}
	cases := []struct {
		name    string
		s       *SetOperation
		right   bool
		dialect string
		want    bool
	}{
		{"right intersect under union", &SetOperation{Left: sel, Operator: "UNION", Right: inter}, true, "", false},
		{"right intersect under union sqlite", &SetOperation{Left: sel, Operator: "UNION", Right: inter}, true, "sqlite", true},
		{"right union under union", &SetOperation{Left: sel, Operator: "UNION", Right: union}, true, "", true},
		{"right union under intersect", &SetOperation{Left: sel, Operator: "INTERSECT", Right: union}, true, "postgresql", true},
		{"right parenthesized select", &SetOperation{Left: sel, Operator: "UNION", Right: sel, RightParenthesized: true}, true, "", true},
		{"left looser set operation", &SetOperation{Left: union, Operator: "INTERSECT", Right: sel}, false, "", true},
		{"left looser set operation oracle", &SetOperation{Left: union, Operator: "INTERSECT", Right: sel}, false, "oracle", false},
		{"left looser set operation with CTE (hoisted by HoistLeadingWith)", &SetOperation{Left: &SetOperation{Left: &SelectStatement{With: &WithClause{}}, Operator: "UNION", Right: sel}, Operator: "INTERSECT", Right: sel}, false, "", true},
		{"left equal set operation", &SetOperation{Left: union, Operator: "EXCEPT", Right: sel}, false, "", false},
		{"left tighter set operation", &SetOperation{Left: inter, Operator: "UNION", Right: sel}, false, "", false},
		{"left parenthesized", &SetOperation{Left: union, Operator: "INTERSECT", Right: sel, LeftParenthesized: true}, false, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SetOperandNeedsParens(tc.s, tc.right, tc.dialect); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSetOperationKeyword pins operator text with quantifiers and MINUS.
func TestSetOperationKeyword(t *testing.T) {
	cases := []struct {
		s       SetOperation
		dialect string
		want    string
	}{
		{SetOperation{Operator: "UNION", All: true}, "", "UNION ALL"},
		{SetOperation{Operator: "INTERSECT", Distinct: true}, "", "INTERSECT DISTINCT"},
		{SetOperation{Operator: "EXCEPT", Minus: true}, "", "MINUS"},
		{SetOperation{Operator: "EXCEPT", Minus: true}, "oracle", "MINUS"},
		{SetOperation{Operator: "EXCEPT", Minus: true}, "postgresql", "EXCEPT"},
		{SetOperation{Operator: "MINUS"}, "", "EXCEPT"},
	}
	for _, tc := range cases {
		if got, _ := SetOperationKeyword(&tc.s, tc.dialect); got != tc.want {
			t.Errorf("%+v (%q) = %q, want %q", tc.s, tc.dialect, got, tc.want)
		}
	}
}

// TestReleaseTableReference_PivotExtensions checks that releasing a PIVOT
// with several aggregates releases each aggregate once and clears the
// extensions.
func TestReleaseTableReference_PivotExtensions(t *testing.T) {
	first := &FunctionCall{Name: "SUM", Arguments: []Expression{&Identifier{Name: "a"}}}
	second := &FunctionCall{Name: "COUNT", Arguments: []Expression{&Identifier{Name: "b"}}}
	pivot := &PivotClause{
		AggregateFunction: first,
		PivotColumn:       "k",
		PivotExtensions: PivotExtensions{
			Aggregates:   []PivotAggregate{{Expr: first, Alias: "s"}, {Expr: second, Alias: "c"}},
			InAny:        true,
			InAnyOrderBy: []OrderByExpression{{Expression: &Identifier{Name: "k"}}},
			SourceAlias:  "src",
		},
	}
	ref := TableReference{Name: "t", Pivot: pivot}
	releaseTableReference(&ref, releaseAll)
	if ref.Pivot != nil {
		t.Fatal("Pivot not cleared")
	}
	if !reflect.DeepEqual(pivot.PivotExtensions, PivotExtensions{}) {
		t.Errorf("PivotExtensions not cleared: %+v", pivot.PivotExtensions)
	}
}

// TestHoistLeadingWith pins when the WITH clause of the first SELECT is moved
// in front of a set operation, and that the original tree is not changed.
func TestHoistLeadingWith(t *testing.T) {
	with := &WithClause{}
	cte := func() *SelectStatement { return &SelectStatement{With: with} }
	sel := &SelectStatement{}
	tests := []struct {
		name    string
		s       *SetOperation
		dialect string
		want    bool
	}{
		{"nil", nil, "", false},
		{"no WITH", &SetOperation{Left: &SetOperation{Left: sel, Operator: "UNION", Right: sel}, Operator: "INTERSECT", Right: sel}, "", false},
		{"chain keeps WITH in place", &SetOperation{Left: cte(), Operator: "UNION", Right: sel}, "", false},
		{"looser left operand", &SetOperation{Left: &SetOperation{Left: cte(), Operator: "UNION", Right: sel}, Operator: "INTERSECT", Right: sel}, "", true},
		{"looser left operand, equal-precedence dialect", &SetOperation{Left: &SetOperation{Left: cte(), Operator: "UNION", Right: sel}, Operator: "INTERSECT", Right: sel}, "oracle", false},
		{"source parentheses scope the WITH", &SetOperation{Left: cte(), Operator: "UNION", Right: sel, LeftParenthesized: true}, "", false},
		{"WITH written before the parentheses", &SetOperation{Left: cte(), Operator: "UNION", Right: sel, LeftParenthesized: true, LeftWithHoisted: true}, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotWith, body := HoistLeadingWith(tc.s, tc.dialect)
			if (gotWith != nil) != tc.want {
				t.Fatalf("hoisted = %v, want %v", gotWith != nil, tc.want)
			}
			if !tc.want {
				if body != tc.s {
					t.Errorf("body is not the input when nothing is hoisted")
				}
				return
			}
			if gotWith != with {
				t.Errorf("returned WITH is not the clause of the first SELECT")
			}
			var first Statement = body
			for {
				op, ok := first.(*SetOperation)
				if !ok {
					break
				}
				first = op.Left
			}
			sel, ok := first.(*SelectStatement)
			if !ok {
				t.Fatalf("first operand is %T, want *SelectStatement", first)
			}
			if sel.With != nil {
				t.Errorf("hoisted copy still has the WITH clause")
			}
			var orig Statement = tc.s
			for {
				op, ok := orig.(*SetOperation)
				if !ok {
					break
				}
				orig = op.Left
			}
			if os, ok := orig.(*SelectStatement); !ok || os.With != with {
				t.Errorf("the input tree was modified")
			}
		})
	}
}
