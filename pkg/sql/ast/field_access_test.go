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
	"bytes"
	"testing"
)

func TestFieldAccessExpression(t *testing.T) {
	var nilField *FieldAccessExpression
	if nilField.SQL() != "" {
		t.Fatal("nil field access must render empty SQL")
	}
	var buf bytes.Buffer
	nilField.writeSQL(&buf)
	if buf.Len() != 0 {
		t.Fatal("nil field access must not write")
	}
	empty := &FieldAccessExpression{}
	if empty.TokenLiteral() != "." || len(empty.Children()) != 0 {
		t.Fatal("unexpected empty node metadata")
	}
	PutExpression(empty)

	for _, tt := range []struct {
		field  string
		quoted bool
		want   string
	}{
		{"a", false, "(f()).a"},
		{"*", false, "(f()).*"},
		{"*", true, `(f())."*"`},
		{"MixedCase", true, `(f())."MixedCase"`},
		{"a.b", false, `(f())."a.b"`},
		// Any keyword is a bare field label after the dot (#839), so an
		// unquoted reserved word stays bare and keeps Quoted false.
		{"order", false, "(f()).order"},
		{"SELECT", false, "(f()).SELECT"},
		{"order", true, `(f())."order"`},
		{"1st", false, `(f())."1st"`},
		{`x"; SELECT 1; --`, false, `(f())."x""; SELECT 1; --"`},
	} {
		t.Run(tt.want, func(t *testing.T) {
			fn := &FunctionCall{Name: "f"}
			field := &FieldAccessExpression{Expr: fn, Field: tt.field, Quoted: tt.quoted}
			if got := field.SQL(); got != tt.want {
				t.Fatalf("SQL() = %q, want %q", got, tt.want)
			}
			if children := field.Children(); len(children) != 1 || children[0] != fn {
				t.Fatal("base expression must remain traversable")
			}
		})
	}
	group := &FieldAccessExpression{
		Expr: &ParenthesizedExpression{Expr: &BinaryExpression{
			Left: &Identifier{Name: "a"}, Operator: "+", Right: &Identifier{Name: "b"},
		}},
		Field: "value",
	}
	if got := group.SQL(); got != "(a + b).value" {
		t.Fatalf("field selection changed its base grouping: %q", got)
	}
}

func TestFieldAccessReleaseChildren(t *testing.T) {
	for _, release := range []func(Expression){PutExpression, func(e Expression) {
		ReleaseAST(&AST{Statements: []Statement{&SelectStatement{Columns: []Expression{e}}}})
	}} {
		tuple := GetTupleExpression()
		tuple.Expressions = append(tuple.Expressions, &Identifier{Name: "payload"})
		field := &FieldAccessExpression{Expr: &ParenthesizedExpression{Expr: tuple}, Field: "item"}
		release(field)
		if field.Expr != nil || len(tuple.Expressions) != 0 {
			t.Fatal("release must detach the field and return its pooled descendants")
		}
	}
}
