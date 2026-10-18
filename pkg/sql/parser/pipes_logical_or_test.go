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

// Package parser - pipes_logical_or_test.go
// Tests for dialect-aware || (issue #781): logical OR in MySQL and MariaDB by
// default, concatenation with WithPipesAsConcat and in every other dialect.

package parser

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

var pipesOrDialects = []keywords.SQLDialect{keywords.DialectMySQL, keywords.DialectMariaDB}

// parsePipesWhere parses "SELECT * FROM t WHERE <where>" in dialect d with a
// pooled parser configured by opts, and returns the WHERE shape and SQL().
func parsePipesWhere(t *testing.T, d keywords.SQLDialect, where string, opts ...ParserOption) (shape, sql string) {
	t.Helper()
	input := "SELECT * FROM t WHERE " + where
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tkz.SetDialect(d)
	tokens, err := tkz.Tokenize([]byte(input))
	if err != nil {
		t.Fatalf("Tokenize(%q, %s): %v", input, d, err)
	}
	p := GetParser()
	defer PutParser(p)
	p.ApplyOptions(append([]ParserOption{WithDialect(string(d))}, opts...)...)
	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("parse(%q, %s): %v", input, d, err)
	}
	defer ast.ReleaseAST(tree)
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}
	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
	}
	return rhs596Shape(t, stmt.Where), tree.SQL()
}

// TestParser_PipesLogicalOr_MySQL_Issue781 checks that || is logical OR at OR
// precedence in MySQL and MariaDB, gives exactly the AST of the OR keyword,
// and that SQL() renders the OR form, which re-parses to itself.
func TestParser_PipesLogicalOr_MySQL_Issue781(t *testing.T) {
	cases := []struct {
		name, where, wantShape string
	}{
		// Acceptance criterion from the issue.
		{"issue_repro", "a = 1 || b", "(OR (= a 1) b)"},
		{"lhs_operand", "a || b = 1", "(OR a (= b 1))"},
		{"left_assoc", "a || b || c", "(OR (OR a b) c)"},
		{"mixed_with_or", "a || b OR c", "(OR (OR a b) c)"},
		{"comparisons", "a = 1 || b = 2", "(OR (= a 1) (= b 2))"},

		// AND binds tighter than ||.
		{"and_rhs", "a = 1 || b = 2 AND c = 3", "(OR (= a 1) (AND (= b 2) (= c 3)))"},
		{"and_lhs", "a = 1 AND b = 2 || c = 3", "(OR (AND (= a 1) (= b 2)) (= c 3))"},
		{"parens_override", "(a || b) AND c", "(AND (PAREN (OR a b)) c)"},

		// NOT binds tighter than ||.
		{"not_lhs", "NOT a || b", "(OR (NOT a) b)"},
		{"not_rhs", "a || NOT b", "(OR a (NOT b))"},
		{"not_comparison", "NOT a = 1 || b = 2", "(OR (NOT (= a 1)) (= b 2))"},

		// Arithmetic and comparison operands bind tighter than ||.
		{"arithmetic", "a + 1 || b * 2 > 3", "(OR (+ a 1) (> (* b 2) 3))"},
		{"between", "a BETWEEN 1 AND 2 || b", "(OR (BETWEEN a 1 2) b)"},
		{"in_and_is_null", "a IN (1, 2) || b IS NULL", "(OR (IN a [1 2]) (IS NULL b NULL))"},
		{"like", "a LIKE b || '%'", "(OR (LIKE a b) '%')"},
		{"regexp", "a REGEXP b || 'x'", "(OR (REGEXP a b) 'x')"},

		// Classic injection tautology shape.
		{"tautology", "user = 'x' || 1 = 1", "(OR (= user 'x') (= 1 1))"},
	}
	for _, tc := range cases {
		for _, d := range pipesOrDialects {
			t.Run(tc.name+"/"+string(d), func(t *testing.T) {
				shape, sql := parsePipesWhere(t, d, tc.where)
				if shape != tc.wantShape {
					t.Fatalf("WHERE shape = %s, want %s", shape, tc.wantShape)
				}

				// Same AST as the OR spelling.
				orWhere := strings.ReplaceAll(tc.where, "||", "OR")
				orShape, orSQL := parsePipesWhere(t, d, orWhere)
				if orShape != shape {
					t.Fatalf("|| shape %s differs from OR shape %s", shape, orShape)
				}

				// SQL() renders OR, and the OR form is a fixpoint.
				if want := "SELECT * FROM t WHERE " + orWhere; sql != want {
					t.Fatalf("SQL() = %q, want %q", sql, want)
				}
				if sql != orSQL {
					t.Fatalf("SQL() %q differs from OR spelling SQL() %q", sql, orSQL)
				}
				reShape, reSQL := parsePipesWhere(t, d, strings.TrimPrefix(sql, "SELECT * FROM t WHERE "))
				if reShape != shape || reSQL != sql {
					t.Fatalf("re-parse of %q gave %s / %q", sql, reShape, reSQL)
				}
			})
		}
	}
}

// pipesConcatCases are parsed as concatenation in every dialect except
// MySQL/MariaDB, and in MySQL/MariaDB with WithPipesAsConcat.
var pipesConcatCases = []struct {
	name, where, wantShape string
}{
	{"issue_repro", "a = 1 || b", "(= a (|| 1 b))"},
	{"concat_rhs", "a = b || 'x' || c", "(= a (|| (|| b 'x') c))"},
	{"concat_of_sum", "a = b || c + 1", "(= a (|| b (+ c 1)))"},
	{"concat_and_or", "a = b || c AND d = 1 OR e = 2", "(OR (AND (= a (|| b c)) (= d 1)) (= e 2))"},
	{"not_concat", "NOT a || b = c", "(NOT (= (|| a b) c))"},
	{"like", "a LIKE b || '%'", "(LIKE a (|| b '%'))"},
}

// TestParser_PipesAsConcat_OptIn_Issue781 checks the PIPES_AS_CONCAT opt-in
// for MySQL and MariaDB, applied before or after WithDialect.
func TestParser_PipesAsConcat_OptIn_Issue781(t *testing.T) {
	cases := append(pipesConcatCases[:len(pipesConcatCases):len(pipesConcatCases)],
		struct{ name, where, wantShape string }{"regexp", "a REGEXP b || 'x'", "(REGEXP a (|| b 'x'))"})
	for _, tc := range cases {
		for _, d := range pipesOrDialects {
			t.Run(tc.name+"/"+string(d), func(t *testing.T) {
				shape, sql := parsePipesWhere(t, d, tc.where, WithPipesAsConcat())
				if shape != tc.wantShape {
					t.Fatalf("WHERE shape = %s, want %s", shape, tc.wantShape)
				}
				if want := "SELECT * FROM t WHERE " + tc.where; sql != want {
					t.Fatalf("SQL() = %q, want %q", sql, want)
				}

				// Option order must not matter.
				p := NewParser(WithPipesAsConcat(), WithDialect(string(d)))
				if !p.pipesAsConcat || p.pipesAsOr {
					t.Fatalf("WithPipesAsConcat before WithDialect: pipesAsConcat=%v pipesAsOr=%v",
						p.pipesAsConcat, p.pipesAsOr)
				}
			})
		}
	}
}

// TestParser_PipesConcat_OtherDialects_Issue781 checks that || stays
// concatenation in the six other dialects and in the default dialect, with
// or without WithPipesAsConcat.
func TestParser_PipesConcat_OtherDialects_Issue781(t *testing.T) {
	for _, tc := range pipesConcatCases {
		for _, d := range rhs596ConcatDialects {
			for _, optIn := range []bool{false, true} {
				name := tc.name + "/" + string(d)
				var opts []ParserOption
				if optIn {
					name += "/pipes_as_concat"
					opts = append(opts, WithPipesAsConcat())
				}
				t.Run(name, func(t *testing.T) {
					shape, sql := parsePipesWhere(t, d, tc.where, opts...)
					if shape != tc.wantShape {
						t.Fatalf("WHERE shape = %s, want %s", shape, tc.wantShape)
					}
					if want := "SELECT * FROM t WHERE " + tc.where; sql != want {
						t.Fatalf("SQL() = %q, want %q", sql, want)
					}
				})
			}
		}
	}

	// Default (no dialect) parser.
	tree, err := ParseBytes([]byte("SELECT * FROM t WHERE a = 1 || b"))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	defer ast.ReleaseAST(tree)
	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
	}
	if got := rhs596Shape(t, stmt.Where); got != "(= a (|| 1 b))" {
		t.Fatalf("default dialect WHERE shape = %s, want (= a (|| 1 b))", got)
	}
}

// TestParser_PipesLogicalOr_SelectList_Issue781 checks || outside WHERE: a
// MySQL select-list item is a boolean OR, not a concatenation.
func TestParser_PipesLogicalOr_SelectList_Issue781(t *testing.T) {
	for _, d := range pipesOrDialects {
		tree, err := ParseWithDialect("SELECT a || b FROM t", d)
		if err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		stmt, ok := tree.Statements[0].(*ast.SelectStatement)
		if !ok {
			t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
		}
		if len(stmt.Columns) != 1 {
			t.Fatalf("%s: expected 1 column, got %d", d, len(stmt.Columns))
		}
		bin, ok := stmt.Columns[0].(*ast.BinaryExpression)
		if !ok {
			t.Fatalf("%s: column is %T, want *ast.BinaryExpression", d, stmt.Columns[0])
		}
		if bin.Operator != "OR" {
			t.Fatalf("%s: operator = %q, want OR", d, bin.Operator)
		}
		if bin.Pos.Line != 1 || bin.Pos.Column != 10 {
			t.Fatalf("%s: operator position = %d:%d, want 1:10", d, bin.Pos.Line, bin.Pos.Column)
		}
		ast.ReleaseAST(tree)
	}
}

// TestParser_PipesMode_PoolReset_Issue781 checks that PIPES_AS_CONCAT does not
// leak to the next user of a pooled parser, and that a pooled parser matches
// a fresh one in every mode.
func TestParser_PipesMode_PoolReset_Issue781(t *testing.T) {
	p := GetParser()
	p.ApplyOptions(WithDialect("mysql"), WithPipesAsConcat())
	if p.pipesAsOr || !p.pipesAsConcat {
		t.Fatalf("mysql + PIPES_AS_CONCAT: pipesAsOr=%v pipesAsConcat=%v", p.pipesAsOr, p.pipesAsConcat)
	}
	p.Reset()
	if p.pipesAsOr || p.pipesAsConcat {
		t.Fatalf("after Reset: pipesAsOr=%v pipesAsConcat=%v", p.pipesAsOr, p.pipesAsConcat)
	}
	p.ApplyOptions(WithDialect("mysql"))
	if !p.pipesAsOr {
		t.Fatal("mysql after Reset: pipesAsOr = false, want true")
	}
	// Switching dialect away from MySQL turns || back into concatenation.
	p.ApplyOptions(WithDialect("postgresql"))
	if p.pipesAsOr {
		t.Fatal("postgresql: pipesAsOr = true, want false")
	}
	PutParser(p)

	for _, d := range []string{"", "mysql", "mariadb", "postgresql", "sqlite"} {
		fresh := NewParser(WithDialect(d))
		pooled := GetParser()
		pooled.ApplyOptions(WithDialect(d))
		if fresh.pipesAsOr != pooled.pipesAsOr {
			t.Fatalf("%q: fresh pipesAsOr=%v, pooled pipesAsOr=%v", d, fresh.pipesAsOr, pooled.pipesAsOr)
		}
		PutParser(pooled)
	}
}
