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
	"runtime/debug"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// nestedForm builds head + prefix*n + mid + suffix*n + tail.
type nestedForm struct {
	name                          string
	head, prefix, mid, suffix, tl string
}

func (f nestedForm) build(n int) string {
	return f.head + strings.Repeat(f.prefix, n) + f.mid + strings.Repeat(f.suffix, n) + f.tl
}

// prefixDepthForms are nesting shapes whose recursion does not pass through
// parseExpression: unary +/-, boolean NOT, and derived tables.
var prefixDepthForms = []nestedForm{
	{name: "unary_minus", head: "SELECT ", prefix: "- ", mid: "1"},
	{name: "unary_plus", head: "SELECT ", prefix: "+", mid: "1"},
	{name: "unary_minus_plus", head: "SELECT ", prefix: "-+", mid: "1"},
	{name: "not_where", head: "SELECT 1 FROM t WHERE ", prefix: "NOT ", mid: "TRUE"},
	{name: "not_select", head: "SELECT ", prefix: "NOT ", mid: "a"},
	{name: "unary_order_by", head: "SELECT a FROM t ORDER BY ", prefix: "- ", mid: "a"},
	{name: "not_delete", head: "DELETE FROM t WHERE ", prefix: "NOT ", mid: "TRUE"},
	{name: "derived_table", head: "SELECT * FROM ", prefix: "(SELECT * FROM ", mid: "t", suffix: ") x"},
	{name: "derived_table_join", head: "SELECT * FROM ", prefix: "(SELECT * FROM a JOIN ", mid: "b ON 1=1", suffix: ") x ON 1=1"},
}

// parseWith tokenizes sql and parses it with p.
func parseWith(t *testing.T, p *Parser, sql string) (*ast.AST, error) {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return nil, err
	}
	return p.ParseFromModelTokens(tokens)
}

// TestParser_UnaryDepthLimit checks that long runs of prefix operators and
// nested derived tables are bounded by MaxRecursionDepth: far past the limit
// parsing returns a recursion depth error (with a reduced goroutine stack
// limit), and nesting well below the limit still parses.
func TestParser_UnaryDepthLimit(t *testing.T) {
	prev := debug.SetMaxStack(64 << 20)
	defer debug.SetMaxStack(prev)

	for _, f := range prefixDepthForms {
		t.Run(f.name, func(t *testing.T) {
			// derived_table_join nests via the JOIN operand; its inner
			// "a JOIN" makes deeper levels need an ON per level.
			if f.name != "derived_table_join" {
				tree, err := parseSQLMayFail(t, f.build(40))
				if err != nil {
					t.Fatalf("40 levels: unexpected error: %v", err)
				}
				ast.ReleaseAST(tree)
			}

			// Large enough that one stack frame chain per level would exceed
			// the reduced stack limit, small enough to stay within MaxTokens.
			n := 200_000
			if strings.Contains(f.prefix, "SELECT") {
				n = 50_000
			}
			_, err := parseSQLMayFail(t, f.build(n))
			if err == nil {
				t.Fatalf("%d levels: expected a recursion depth error, got nil", n)
			}
			if !strings.Contains(err.Error(), "E2007") || !strings.Contains(err.Error(), "recursion depth") {
				t.Fatalf("%d levels: expected E2007 recursion depth error, got: %v", n, err)
			}
		})
	}
}

// TestParser_UnaryDepthLimit_Boundary pins the limit for unary minus: each
// operator adds one level on top of the select-list expression.
func TestParser_UnaryDepthLimit_Boundary(t *testing.T) {
	build := func(n int) string { return "SELECT " + strings.Repeat("- ", n) + "1" }

	ok := MaxRecursionDepth - 1 // plus the select-list parseExpression level
	tree, err := parseSQLMayFail(t, build(ok))
	if err != nil {
		t.Fatalf("%d unary operators: unexpected error: %v", ok, err)
	}
	ast.ReleaseAST(tree)

	if _, err := parseSQLMayFail(t, build(ok+1)); err == nil || !strings.Contains(err.Error(), "E2007") {
		t.Fatalf("%d unary operators: expected E2007, got %v", ok+1, err)
	}
}

// TestParser_DepthResetAfterUnaryLimit checks that the depth counter is fully
// restored after a depth error from a unary run, so the same parser parses
// ordinary SQL afterwards.
func TestParser_DepthResetAfterUnaryLimit(t *testing.T) {
	p := NewParser()
	defer p.Release()

	for _, sql := range []string{
		"SELECT " + strings.Repeat("- ", 500) + "1",
		"SELECT 1 FROM t WHERE " + strings.Repeat("NOT ", 500) + "TRUE",
		"SELECT * FROM " + strings.Repeat("(SELECT * FROM ", 500) + "t" + strings.Repeat(") x", 500),
	} {
		if _, err := parseWith(t, p, sql); err == nil {
			t.Fatalf("expected a depth error for %.40q...", sql)
		}
		if p.depth != 0 {
			t.Fatalf("depth = %d after error, want 0", p.depth)
		}
		tree, err := parseWith(t, p, "SELECT -a, NOT b FROM (SELECT a, b FROM t) x WHERE NOT -a > 1")
		if err != nil {
			t.Fatalf("ordinary query after depth error: %v", err)
		}
		ast.ReleaseAST(tree)
	}
}
