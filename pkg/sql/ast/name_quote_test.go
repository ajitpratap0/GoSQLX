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

package ast_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestNameQuote_Bits(t *testing.T) {
	q := ast.NameQuote(0).AppendPart(true).AppendPart(false).AppendPart(true)
	if !q.Part(0) || q.Part(1) || !q.Part(2) || q.Part(3) {
		t.Fatalf("AppendPart parts = %08b, want parts 0 and 2", q)
	}
	if q.HasStyle() || q.Style() != '"' {
		t.Fatalf("no style recorded: HasStyle=%v Style=%q", q.HasStyle(), q.Style())
	}
	for _, style := range []rune{'"', '`', '['} {
		s := q.WithStyle(style)
		if s.Style() != style || !s.HasStyle() || !s.Part(0) || !s.Part(2) {
			t.Errorf("WithStyle(%q) = %08b", style, s)
		}
		if got := s.WithDefaultStyle('`').Style(); got != style {
			t.Errorf("WithDefaultStyle kept %q, want %q", got, style)
		}
	}
	if got := q.WithDefaultStyle('`').Style(); got != '`' {
		t.Errorf("WithDefaultStyle on unstyled = %q, want '`'", got)
	}
	if ast.NameQuoteOf('x').HasStyle() {
		t.Error("NameQuoteOf('x') recorded a style")
	}
	if q.WithPart(-1) != q || q.WithPart(5) != q || q.Part(7) {
		t.Error("out-of-range parts must be ignored")
	}
	// A sixth part pushes the first one out.
	six := ast.NameQuote(0).AppendPart(true)
	for i := 0; i < 5; i++ {
		six = six.AppendPart(false)
	}
	if six.HasParts() {
		t.Errorf("parts beyond five not dropped: %08b", six)
	}
	h := q.WithBareHash(true)
	if !h.BareHash() || h.WithBareHash(false).BareHash() || h.WithStyle('`').BareHash() != true {
		t.Errorf("BareHash flag not independent of style/parts: %08b", h)
	}
	if got := ast.QuotedName('`'); !got.Part(0) || got.Style() != '`' {
		t.Errorf("QuotedName('`') = %08b", got)
	}
	merged := ast.NameQuote(0).WithParts(ast.QuotedName('['))
	if !merged.Part(0) || merged.Style() != '[' {
		t.Errorf("WithParts = %08b", merged)
	}
}

func TestDelimitedNameMustStayQuoted(t *testing.T) {
	tests := []struct {
		name string
		fold ast.IdentifierCaseFolding
		want bool
	}{
		{"users", ast.FoldLower, false},
		{"Users", ast.FoldLower, true},
		{"USERS", ast.FoldLower, true},
		{"USERS", ast.FoldUpper, false},
		{"users", ast.FoldUpper, true},
		{"Users", ast.FoldNone, false},
		{"select", ast.FoldNone, true},
		{"a b", ast.FoldNone, true},
		{"1abc", ast.FoldNone, true},
		{"", ast.FoldNone, true},
		{"Ünïcode", ast.FoldLower, true},
		{"ünïcode", ast.FoldLower, false},
		{"ünïcode", ast.FoldUpper, true},
		{"_x1", ast.FoldUpper, true},
		{"_X1", ast.FoldUpper, false},
	}
	for _, tc := range tests {
		if got := ast.DelimitedNameMustStayQuoted(tc.name, tc.fold); got != tc.want {
			t.Errorf("DelimitedNameMustStayQuoted(%q, %d) = %v, want %v", tc.name, tc.fold, got, tc.want)
		}
	}
}

func TestQuoteWith(t *testing.T) {
	kept := ast.QuotedName('"')
	tests := []struct {
		label string
		got   string
		want  string
	}{
		{"name zero quote", ast.QuoteNameWith("Total", 0), "Total"},
		{"name kept", ast.QuoteNameWith("Total", kept), `"Total"`},
		{"name backtick reserved", ast.QuoteNameWith("exists", ast.NameQuoteOf('`')), "`exists`"},
		{"name bracket space", ast.QuoteNameWith("a b", ast.NameQuoteOf('[')), "[a b]"},
		{"name bracket escape", ast.QuoteNameWith("a]b", ast.QuotedName('[')), "[a]]b]"},
		{"name backtick escape", ast.QuoteNameWith("a`b", ast.QuotedName('`')), "`a``b`"},
		{"name ansi escape", ast.QuoteNameWith(`a"b`, kept), `"a""b"`},
		{"alias kept", ast.QuoteTableAliasWith("T", kept), `"T"`},
		{"alias plain", ast.QuoteTableAliasWith("t", ast.NameQuoteOf('`')), "t"},
		{"column kept", ast.QuoteColumnNameWith("ColA", kept), `"ColA"`},
		{"qualified last part", ast.QuoteQualifiedNameWith("s.Orders", kept), `s."Orders"`},
		{"qualified first part", ast.QuoteQualifiedNameWith("Sales.orders", ast.NameQuote(0).AppendPart(true).AppendPart(false).WithStyle('"')), `"Sales".orders`},
		{"qualified reserved backtick", ast.QuoteQualifiedNameWith("db.order", ast.NameQuoteOf('`')), "db.`order`"},
		{"qualified zero quote", ast.QuoteQualifiedNameWith("Sales.Orders", 0), "Sales.Orders"},
		{"stage reference verbatim", ast.QuoteQualifiedNameWith("@stage/path", kept), "@stage/path"},
		{"function qualified reserved", ast.QuoteFunctionNameWith("s.select", ast.NameQuote(0).AppendPart(false).AppendPart(true)), `s."select"`},
		{"function bare keyword member", ast.QuoteFunctionNameWith("DBMS_RANDOM.VALUE", 0), "DBMS_RANDOM.VALUE"},
		{"function mixed case", ast.QuoteFunctionNameWith("MyFunc", kept), `"MyFunc"`},
		{"oracle bare hash", ast.QuoteNameWith("emp#", ast.NameQuote(0).WithBareHash(true)), "emp#"},
		{"hash without flag", ast.QuoteNameWith("emp#", 0), `"emp#"`},
		{"bare hash leading", ast.QuoteNameWith("#emp", ast.NameQuote(0).WithBareHash(true)), `"#emp"`},
		{"bare hash reserved", ast.QuoteTableAliasWith("select", ast.NameQuote(0).WithBareHash(true)), `"select"`},
		{"qualified bare hash", ast.QuoteQualifiedNameWith("s.tab#1", ast.NameQuote(0).WithBareHash(true)), "s.tab#1"},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.label, tc.got, tc.want)
		}
	}
}

func TestIdentifierSQL_Quotes(t *testing.T) {
	tests := []struct {
		label string
		id    ast.Identifier
		want  string
	}{
		{"bare", ast.Identifier{Name: "Mixed"}, "Mixed"},
		{"name kept", ast.Identifier{Name: "Mixed", Quoted: true, QuoteStyle: '"', Quotes: ast.QuotedName('"')}, `"Mixed"`},
		{"qualifier kept", ast.Identifier{Table: "T", Name: "id", Quotes: ast.NameQuote(0).AppendPart(true).AppendPart(false).WithStyle('"')}, `"T".id`},
		{"three parts", ast.Identifier{Table: "Db.s", Name: "c", Quotes: ast.NameQuote(0).AppendPart(true).AppendPart(false).AppendPart(true).WithStyle('`')}, "`Db`.s.`c`"},
		{"style overrides QuoteStyle", ast.Identifier{Name: "select", QuoteStyle: '"', Quotes: ast.NameQuoteOf('[')}, "[select]"},
		{"content quoting uses style", ast.Identifier{Name: "a b", Quotes: ast.NameQuoteOf('`')}, "`a b`"},
		{"bare hash", ast.Identifier{Table: "s", Name: "serial#", Quotes: ast.NameQuote(0).WithBareHash(true)}, "s.serial#"},
		{"hash without flag", ast.Identifier{Name: "serial#"}, `"serial#"`},
	}
	for _, tc := range tests {
		id := tc.id
		if got := id.SQL(); got != tc.want {
			t.Errorf("%s: SQL() = %s, want %s", tc.label, got, tc.want)
		}
	}
}

// TestColumnRefSQL_UsesSourceDelimiter checks that a write-target column the
// source delimited keeps its delimiter: a MySQL `select` must not turn into
// "select", which MySQL reads as a string.
func TestColumnRefSQL_UsesSourceDelimiter(t *testing.T) {
	tests := []struct {
		label string
		id    *ast.Identifier
		want  string
	}{
		{"backtick reserved", &ast.Identifier{Name: "select", QuoteStyle: '`', Quotes: ast.QuotedName('`')}, "`select`"},
		{"unrecorded reserved", &ast.Identifier{Name: "select"}, `"select"`},
		{"qualified unrecorded reserved", &ast.Identifier{Table: "t", Name: "order"}, `t."order"`},
		{"plain", &ast.Identifier{Name: "a"}, "a"},
	}
	for _, tc := range tests {
		if got := ast.ColumnRefSQL(tc.id); got != tc.want {
			t.Errorf("%s: ColumnRefSQL = %s, want %s", tc.label, got, tc.want)
		}
	}
}

func TestSetNameQuoteStyle(t *testing.T) {
	sel := &ast.SelectStatement{
		Columns: []ast.Expression{
			&ast.AliasedExpression{
				Expr:       &ast.Identifier{Name: "my col", QuoteStyle: '`', Quotes: ast.QuotedName('`')},
				Alias:      "My Alias",
				AliasQuote: ast.QuotedName('`'),
			},
			&ast.Identifier{Table: "s", Name: "serial#", Quotes: ast.NameQuote(0).WithBareHash(true)},
			&ast.FunctionCall{Name: "MyFunc", NameQuote: ast.QuotedName('`')},
		},
		From: []ast.TableReference{{Name: "My Table", NameQuote: ast.QuotedName('`'), Alias: "t"}},
	}
	ast.SetNameQuoteStyle(sel, '"', false)
	want := `SELECT "my col" AS "My Alias", s."serial#", "MyFunc"() FROM "My Table" t`
	if got := sel.SQL(); got != want {
		t.Fatalf("after SetNameQuoteStyle('\"'):\n got: %s\nwant: %s", got, want)
	}
	ast.SetNameQuoteStyle(sel, '[', false)
	want = `SELECT [my col] AS [My Alias], s.[serial#], [MyFunc]() FROM [My Table] t`
	if got := sel.SQL(); got != want {
		t.Fatalf("after SetNameQuoteStyle('['):\n got: %s\nwant: %s", got, want)
	}
	ast.SetNameQuoteStyle(nil, '"', false) // must not panic
}
