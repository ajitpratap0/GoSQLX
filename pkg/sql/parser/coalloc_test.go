// Copyright 2026 GoSQLX Contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// parseKeep parses sql and returns the tree together with the parser, so a
// test can inspect parser state afterwards. The caller releases the parser.
func parseKeep(t *testing.T, sql string) (*ast.AST, *Parser, error) {
	t.Helper()
	tkz, err := tokenizer.NewWithDialect("postgresql")
	if err != nil {
		t.Fatalf("tokenizer: %v", err)
	}
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize %q: %v", sql, err)
	}
	p := NewParser(WithDialect("postgresql"))
	tree, err := p.ParseFromModelTokens(tokens)
	return tree, p, err
}

func mustSelect(t *testing.T, tree *ast.AST, i int) *ast.SelectStatement {
	t.Helper()
	sel, ok := tree.Statements[i].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("statement %d is %T, want *ast.SelectStatement", i, tree.Statements[i])
	}
	return sel
}

// assertScratchEmpty checks that the scratch stacks are balanced and that no
// stale node survives anywhere in their backing arrays.
func assertScratchEmpty(t *testing.T, p *Parser, what string) {
	t.Helper()
	if len(p.exprScratch) != 0 || len(p.orderScratch) != 0 {
		t.Errorf("%s: scratch stacks not balanced: expr=%d order=%d", what, len(p.exprScratch), len(p.orderScratch))
	}
	for i, e := range p.exprScratch[:cap(p.exprScratch)] {
		if e != nil {
			t.Errorf("%s: exprScratch[%d] retains %T", what, i, e)
		}
	}
	for i, o := range p.orderScratch[:cap(p.orderScratch)] {
		if !reflect.DeepEqual(o, ast.OrderByExpression{}) {
			t.Errorf("%s: orderScratch[%d] retains a value", what, i)
		}
	}
}

// The scratch stacks must be empty and zeroed after every parse, successful or
// not, including nested lists and failures in the middle of a list.
func TestScratchBalancedAfterParse(t *testing.T) {
	queries := []string{
		"SELECT 1",
		"SELECT a, b, c, d, e, f FROM t",
		"SELECT f(a, g(b, h(c, d, e, 1)), (SELECT max(x) FROM u GROUP BY y ORDER BY z DESC)) FROM t",
		"SELECT a FROM t GROUP BY a, b ORDER BY a DESC, b",
		"SELECT string_agg(a, ',' ORDER BY b DESC, c) FROM t",
		"SELECT count(*) FROM (SELECT x, y FROM t ORDER BY x) s GROUP BY y ORDER BY y",
		"SELECT a FROM t UNION SELECT b FROM u ORDER BY 1",
		"WITH c AS (SELECT a, b FROM t) SELECT f(a) FROM c",
		// Failures inside a list, at several nesting depths.
		"SELECT a, f(b, FROM t",
		"SELECT a, f(b, g(c, ) FROM t",
		"SELECT a FROM t GROUP BY a, ORDER",
		"SELECT a FROM t ORDER BY a, b DESC, ,",
		"SELECT a, (SELECT b, c FROM u ORDER BY",
		"SELECT f(a, b => ) FROM t",
		"SELECT f(a, b => g(c, )) FROM t",
		"SELECT a FROM t GROUP BY a, (",
		"SELECT a FROM t GROUP BY a, f(b,",
		"SELECT a FROM t ORDER BY a, b USING",
		"SELECT a, b INTO",
		"SELECT a, f(b) FROM t ORDER BY a, g(c,",
		"SELECT",
	}
	for _, sql := range queries {
		t.Run(sql, func(t *testing.T) {
			_, p, _ := parseKeep(t, sql) // both outcomes must leave the stacks balanced
			defer p.Release()
			assertScratchEmpty(t, p, sql)
		})
	}
}

// Reset clears whatever a previous parse left behind and drops oversized
// stacks, so a pooled parser neither retains nodes nor grows without bound.
func TestScratchResetClearsAndBounds(t *testing.T) {
	p := NewParser()
	defer p.Release()
	p.exprScratch = append(p.exprScratch, &ast.Identifier{Name: "x"})
	p.orderScratch = append(p.orderScratch, ast.OrderByExpression{Expression: &ast.Identifier{Name: "y"}})
	p.Reset()
	assertScratchEmpty(t, p, "after Reset")

	p.exprScratch = make([]ast.Expression, 0, maxPooledScratch+1)
	p.orderScratch = make([]ast.OrderByExpression, 0, maxPooledScratch+1)
	p.Reset()
	if p.exprScratch != nil || p.orderScratch != nil {
		t.Errorf("oversized scratch kept: expr cap %d, order cap %d", cap(p.exprScratch), cap(p.orderScratch))
	}
}

// Lists are exact-size (len == cap), so an append by a consumer reallocates
// instead of writing into a neighbouring field of the co-allocated block.
func TestCoallocatedListsAreExactAndIndependent(t *testing.T) {
	const sql = "SELECT a, f(b, c), g(h(d), 2, 3, 4) FROM t GROUP BY a, b ORDER BY a DESC, b"
	tree, p, err := parseKeep(t, sql)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer p.Release()
	sel := mustSelect(t, tree, 0)

	if len(sel.Columns) != 3 || cap(sel.Columns) != len(sel.Columns) {
		t.Errorf("Columns len/cap = %d/%d, want 3/3", len(sel.Columns), cap(sel.Columns))
	}
	if len(sel.From) != 1 || sel.From[0].Name != "t" {
		t.Fatalf("From = %+v, want the single table t", sel.From)
	}
	if len(sel.GroupBy) != 2 || cap(sel.GroupBy) != 2 {
		t.Errorf("GroupBy len/cap = %d/%d, want 2/2", len(sel.GroupBy), cap(sel.GroupBy))
	}
	if len(sel.OrderBy) != 2 || cap(sel.OrderBy) != 2 {
		t.Errorf("OrderBy len/cap = %d/%d, want 2/2", len(sel.OrderBy), cap(sel.OrderBy))
	}
	if sel.OrderBy[0].Ascending || !sel.OrderBy[1].Ascending {
		t.Errorf("ORDER BY directions = %v, %v, want DESC, ASC", sel.OrderBy[0].Ascending, sel.OrderBy[1].Ascending)
	}

	f, ok := sel.Columns[1].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("Columns[1] is %T, want *ast.FunctionCall", sel.Columns[1])
	}
	g, ok := sel.Columns[2].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("Columns[2] is %T, want *ast.FunctionCall", sel.Columns[2])
	}
	if len(f.Arguments) != 2 || cap(f.Arguments) != 2 || len(g.Arguments) != 4 || cap(g.Arguments) != 4 {
		t.Errorf("argument len/cap: f %d/%d (want 2/2), g %d/%d (want 4/4)",
			len(f.Arguments), cap(f.Arguments), len(g.Arguments), cap(g.Arguments))
	}

	// Growing each list must not disturb anything else.
	before := tree.Statements[0].(*ast.SelectStatement).From[0].Name
	sel.Columns = append(sel.Columns, &ast.Identifier{Name: "extra"})
	f.Arguments = append(f.Arguments, &ast.Identifier{Name: "extra"})
	sel.From = append(sel.From, ast.TableReference{Name: "extra"})
	if sel.From[0].Name != before || len(g.Arguments) != 4 {
		t.Errorf("append corrupted a neighbouring field: From[0]=%q, len(g.Arguments)=%d", sel.From[0].Name, len(g.Arguments))
	}
	if id, ok := g.Arguments[0].(*ast.FunctionCall); !ok || id.Name != "h" {
		t.Errorf("g.Arguments[0] = %#v, want call h", g.Arguments[0])
	}
}

// Every list length that crosses a co-allocation boundary keeps its elements
// in source order.
func TestCoallocatedListLengths(t *testing.T) {
	for n := 1; n <= 7; n++ {
		names := make([]string, n)
		for i := range names {
			names[i] = fmt.Sprintf("c%d", i)
		}
		list := strings.Join(names, ", ")

		for _, from := range []string{"", " FROM t", " FROM t1, t2", " FROM t1 JOIN t2 ON t1.a = t2.a"} {
			sql := "SELECT " + list + from
			tree, p, err := parseKeep(t, sql)
			if err != nil {
				t.Fatalf("%s: %v", sql, err)
			}
			sel := mustSelect(t, tree, 0)
			if len(sel.Columns) != n || cap(sel.Columns) != n {
				t.Errorf("%s: Columns len/cap = %d/%d, want %d/%d", sql, len(sel.Columns), cap(sel.Columns), n, n)
			}
			for i, c := range sel.Columns {
				if id, ok := c.(*ast.Identifier); !ok || id.Name != names[i] {
					t.Errorf("%s: Columns[%d] = %#v, want identifier %s", sql, i, c, names[i])
				}
			}
			wantFrom := map[string]int{"": 0, " FROM t": 1, " FROM t1, t2": 2, " FROM t1 JOIN t2 ON t1.a = t2.a": 1}[from]
			if len(sel.From) != wantFrom {
				t.Errorf("%s: len(From) = %d, want %d", sql, len(sel.From), wantFrom)
			}
			p.Release()
		}

		// Function calls with 0..7 arguments.
		args := strings.Join(names[:n-1], ", ")
		sql := "SELECT f(" + args + ") FROM t"
		tree, p, err := parseKeep(t, sql)
		if err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		fc, ok := mustSelect(t, tree, 0).Columns[0].(*ast.FunctionCall)
		if !ok {
			t.Fatalf("%s: column is not a function call", sql)
		}
		if len(fc.Arguments) != n-1 || cap(fc.Arguments) != len(fc.Arguments) {
			t.Errorf("%s: Arguments len/cap = %d/%d, want %d/%d", sql, len(fc.Arguments), cap(fc.Arguments), n-1, n-1)
		}
		for i, a := range fc.Arguments {
			if id, ok := a.(*ast.Identifier); !ok || id.Name != names[i] {
				t.Errorf("%s: Arguments[%d] = %#v, want identifier %s", sql, i, a, names[i])
			}
		}
		p.Release()
	}
}

// Nested lists share the scratch stacks; the inner list must not leak into or
// overwrite the outer one.
func TestScratchNestedListsKeepOwnElements(t *testing.T) {
	const sql = "SELECT f(a, (SELECT g(x, y), z FROM u GROUP BY x, y ORDER BY x, y), b), c FROM t ORDER BY c, d"
	tree, p, err := parseKeep(t, sql)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer p.Release()
	sel := mustSelect(t, tree, 0)
	if len(sel.Columns) != 2 || len(sel.OrderBy) != 2 {
		t.Fatalf("outer lists: %d columns, %d order items; want 2 and 2", len(sel.Columns), len(sel.OrderBy))
	}
	f, ok := sel.Columns[0].(*ast.FunctionCall)
	if !ok || len(f.Arguments) != 3 {
		t.Fatalf("Columns[0] = %#v, want call f with 3 arguments", sel.Columns[0])
	}
	if id, ok := f.Arguments[0].(*ast.Identifier); !ok || id.Name != "a" {
		t.Errorf("f.Arguments[0] = %#v, want a", f.Arguments[0])
	}
	if id, ok := f.Arguments[2].(*ast.Identifier); !ok || id.Name != "b" {
		t.Errorf("f.Arguments[2] = %#v, want b", f.Arguments[2])
	}
	sub, ok := f.Arguments[1].(*ast.SubqueryExpression)
	if !ok {
		t.Fatalf("f.Arguments[1] is %T, want subquery", f.Arguments[1])
	}
	inner, ok := sub.Subquery.(*ast.SelectStatement)
	if !ok {
		t.Fatalf("subquery is %T", sub.Subquery)
	}
	if len(inner.Columns) != 2 || len(inner.GroupBy) != 2 || len(inner.OrderBy) != 2 {
		t.Errorf("inner lists: %d columns, %d group, %d order; want 2, 2, 2", len(inner.Columns), len(inner.GroupBy), len(inner.OrderBy))
	}
	if g, ok := inner.Columns[0].(*ast.FunctionCall); !ok || g.Name != "g" || len(g.Arguments) != 2 {
		t.Errorf("inner.Columns[0] = %#v, want g(x, y)", inner.Columns[0])
	}
}

// A pooled parser reused for a second statement must not alias the first
// tree's lists.
func TestCoallocatedTreesIndependentAcrossParses(t *testing.T) {
	p := GetParser()
	defer PutParser(p)
	parse := func(sql string) *ast.SelectStatement {
		tkz, err := tokenizer.NewWithDialect("postgresql")
		if err != nil {
			t.Fatal(err)
		}
		tokens, err := tkz.Tokenize([]byte(sql))
		if err != nil {
			t.Fatal(err)
		}
		tree, err := p.ParseFromModelTokens(tokens)
		if err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return mustSelect(t, tree, 0)
	}
	first := parse("SELECT a, f(b, c) FROM t1 GROUP BY a ORDER BY a")
	wantFirst := first.SQL()
	for _, sql := range []string{
		"SELECT x, y, z, w, v FROM t2 GROUP BY x, y ORDER BY y DESC, x",
		"SELECT g(1, 2, 3, 4) FROM t3",
	} {
		_ = parse(sql)
	}
	if got := first.SQL(); got != wantFirst {
		t.Errorf("first tree changed by later parses:\n got %s\nwant %s", got, wantFirst)
	}
}
