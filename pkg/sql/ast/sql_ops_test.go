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

// TestOperatorNodesSQL renders the operator and predicate nodes built by
// hand, including the quoting and parenthesization rules.
func TestOperatorNodesSQL(t *testing.T) {
	id := func(n string) Expression { return &Identifier{Name: n} }
	str := func(s string) Expression { return &LiteralValue{Value: s, Type: "STRING"} }
	sel := &SelectStatement{Columns: []Expression{&LiteralValue{Value: "1", Type: "INTEGER"}}}

	tests := []struct {
		name string
		expr Expression
		want string
	}{
		{"at time zone", &AtTimeZoneExpression{Expr: id("t"), Zone: str("UTC")}, "t AT TIME ZONE 'UTC'"},
		{"at time zone parenthesizes infix operand",
			&AtTimeZoneExpression{Expr: &BinaryExpression{Left: id("a"), Operator: "+", Right: id("b")}, Zone: str("UTC")},
			"(a + b) AT TIME ZONE 'UTC'"},
		{"collate bare", &CollateExpression{Expr: id("x"), Collation: "utf8mb4_bin"}, "x COLLATE utf8mb4_bin"},
		{"collate quoted keeps quotes", &CollateExpression{Expr: id("x"), Collation: "C", Quoted: true}, `x COLLATE "C"`},
		{"collate qualified", &CollateExpression{Expr: id("x"), Schema: "pg_catalog", Collation: "default", Quoted: true}, `x COLLATE pg_catalog."default"`},
		{"collate dotted unquoted is qualified", &CollateExpression{Expr: id("x"), Collation: "pg_catalog.c"}, "x COLLATE pg_catalog.c"},
		{"collate quoted dot stays in the name", &CollateExpression{Expr: id("x"), Collation: "en_US.utf8", Quoted: true}, `x COLLATE "en_US.utf8"`},
		{"collate literal", &CollateExpression{Expr: id("x"), Collation: "en", Literal: true}, "x COLLATE 'en'"},
		{"collate reserved word is quoted", &CollateExpression{Expr: id("x"), Collation: "select"}, `x COLLATE "select"`},
		{"any array", &AnyAllExpression{Expr: id("a"), Operator: "=", Quantifier: "ANY", Array: id("tags")}, "a = ANY (tags)"},
		{"all array", &AnyAllExpression{Expr: id("a"), Operator: "<>", Quantifier: "ALL", Array: id("tags")}, "a <> ALL (tags)"},
		{"some array", &AnyAllExpression{Expr: id("a"), Operator: "=", Quantifier: "some", Array: id("tags")}, "a = SOME (tags)"},
		{"empty quantifier defaults to any", &AnyAllExpression{Expr: id("a"), Operator: "=", Array: id("tags")}, "a = ANY (tags)"},
		{"some subquery has one pair of parentheses",
			&AnyAllExpression{Expr: id("a"), Operator: "=", Quantifier: "SOME", Array: &SubqueryExpression{Subquery: sel}},
			"a = SOME (SELECT 1)"},
		{"hostile operator is quoted", &AnyAllExpression{Expr: id("a"), Operator: "= 1; DROP TABLE x; --", Quantifier: "ANY", Array: id("tags")},
			`a "= 1; DROP TABLE x; --" ANY (tags)`},
		{"ternary", &TernaryExpression{Cond: id("a"), Then: str("x"), Else: str("y")}, "a ? 'x' : 'y'"},
		{"in global", &InExpression{Expr: id("a"), Subquery: sel, Global: true}, "a GLOBAL IN (SELECT 1)"},
		{"in global not", &InExpression{Expr: id("a"), List: []Expression{id("b")}, Global: true, Not: true}, "a GLOBAL NOT IN (b)"},
		{"in bare", &InExpression{Expr: id("a"), List: []Expression{id("tbl")}, Bare: true}, "a IN tbl"},
		{"in bare not", &InExpression{Expr: id("a"), List: []Expression{id("tbl")}, Bare: true, Not: true}, "a NOT IN tbl"},
		{"in empty", &InExpression{Expr: id("a")}, "a IN ()"},
		{"like escape", &BinaryExpression{Left: id("a"), Operator: "LIKE", Right: str("x"), Escape: str("!")}, "a LIKE 'x' ESCAPE '!'"},
		{"not like escape", &BinaryExpression{Left: id("a"), Operator: "LIKE", Right: str("x"), Escape: str("!"), Not: true}, "a NOT LIKE 'x' ESCAPE '!'"},
		{"not regexp", &BinaryExpression{Left: id("a"), Operator: "REGEXP", Right: str("x"), Not: true}, "a NOT REGEXP 'x'"},
		{"not glob", &BinaryExpression{Left: id("a"), Operator: "GLOB", Right: str("x"), Not: true}, "a NOT GLOB 'x'"},
		{"is distinct from", &BinaryExpression{Left: id("a"), Operator: "IS DISTINCT FROM", Right: id("b")}, "a IS DISTINCT FROM b"},
		{"is not true", &BinaryExpression{Left: id("a"), Operator: "IS NOT", Right: &LiteralValue{Value: "TRUE", Type: "BOOLEAN"}}, "a IS NOT TRUE"},
		{"sounds like", &BinaryExpression{Left: id("a"), Operator: "SOUNDS LIKE", Right: id("b")}, "a SOUNDS LIKE b"},
		{"match", &BinaryExpression{Left: id("a"), Operator: "MATCH", Right: str("x")}, "a MATCH 'x'"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, ok := tc.expr.(interface{ SQL() string })
			if !ok {
				t.Fatalf("%T has no SQL()", tc.expr)
			}
			if got := s.SQL(); got != tc.want {
				t.Errorf("SQL() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestOperatorNodesChildren checks that the visitor sees every operand.
func TestOperatorNodesChildren(t *testing.T) {
	a, b, c := &Identifier{Name: "a"}, &Identifier{Name: "b"}, &Identifier{Name: "c"}
	tests := []struct {
		name string
		node Node
		want int
	}{
		{"at time zone", &AtTimeZoneExpression{Expr: a, Zone: b}, 2},
		{"collate", &CollateExpression{Expr: a, Collation: "x"}, 1},
		{"any all", &AnyAllExpression{Expr: a, Array: b}, 2},
		{"ternary", &TernaryExpression{Cond: a, Then: b, Else: c}, 3},
		{"binary with escape", &BinaryExpression{Left: a, Right: b, Escape: c}, 3},
		{"nil operands", &AtTimeZoneExpression{}, 0},
	}
	for _, tc := range tests {
		if got := len(tc.node.Children()); got != tc.want {
			t.Errorf("%s: Children() = %d nodes, want %d", tc.name, got, tc.want)
		}
	}
}

// TestDataTypeCharsetAndSignedPlain checks that the multi-word cast types the
// parser produces are written verbatim and that near misses stay quoted.
func TestDataTypeCharsetAndSignedPlain(t *testing.T) {
	plain := []string{
		"SIGNED INTEGER", "UNSIGNED INT", "CHAR CHARACTER SET utf8mb4", "CHAR(10) CHARACTER SET utf8mb4",
		"VARCHAR(10) CHARSET latin1", "text[]", "int[3][4]", "timestamp(3) without time zone", "public.mood",
	}
	for _, typ := range plain {
		if got := QuoteDataType(typ); got != typ {
			t.Errorf("QuoteDataType(%q) = %q, want it unchanged", typ, got)
		}
	}
	quoted := []string{" INT", "INT x", "CHAR CHARACTER SET", "CHAR CHARACTER SET ;DROP", "CHAR SET"}
	for _, typ := range quoted {
		if got := QuoteDataType(typ); got == typ {
			t.Errorf("QuoteDataType(%q) left it bare", typ)
		}
	}
}

// TestPooledOperatorFieldsAreCleared checks that the fields added for LIKE
// ESCAPE and GLOBAL / bare IN do not survive a trip through the pools.
func TestPooledOperatorFieldsAreCleared(t *testing.T) {
	lit := &LiteralValue{Value: "!", Type: "STRING"}

	for i := 0; i < 50; i++ {
		b := GetBinaryExpression()
		b.Operator, b.Escape = "LIKE", lit
		PutBinaryExpression(b)

		in := GetInExpression()
		in.Global, in.Bare = true, true
		PutInExpression(in)

		b2 := GetBinaryExpression()
		if b2.Escape != nil || b2.Operator != "" {
			t.Fatalf("pooled BinaryExpression kept Escape=%v Operator=%q", b2.Escape, b2.Operator)
		}
		in2 := GetInExpression()
		if in2.Global || in2.Bare {
			t.Fatalf("pooled InExpression kept Global=%v Bare=%v", in2.Global, in2.Bare)
		}
		PutBinaryExpression(b2)
		PutInExpression(in2)
	}
}
