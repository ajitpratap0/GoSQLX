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
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func joinHintTokens(t *testing.T, sql string) []models.TokenWithSpan {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	toks, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize %q: %v", sql, err)
	}
	return preprocessTokens(toks)
}

func joinsOf(t *testing.T, sql string) []ast.JoinClause {
	t.Helper()
	p := &Parser{}
	tree, err := p.parseTokens(joinHintTokens(t, sql))
	if err != nil {
		t.Fatalf("parse %q: %v", sql, err)
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	return sel.Joins
}

func joinQuery(n int) string {
	var b strings.Builder
	b.WriteString("SELECT * FROM t0")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, " JOIN t%d ON t%d.id = t0.id", i, i)
	}
	return b.String()
}

// The initial joins capacity is 1 plus the JOINs ahead, capped at 8, and the
// parsed joins are complete and ordered for every count, including above the cap.
func TestJoinsSliceCapacityAndContent(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 8, 9, 12} {
		joins := joinsOf(t, joinQuery(n))
		if len(joins) != n {
			t.Fatalf("n=%d: got %d joins", n, len(joins))
		}
		for i, j := range joins {
			if want := fmt.Sprintf("t%d", i+1); j.Right.Name != want {
				t.Errorf("n=%d join %d: right=%q want %q", n, i, j.Right.Name, want)
			}
		}
		wantCap := min(n, 8)
		if n <= 8 && cap(joins) != wantCap {
			t.Errorf("n=%d: cap=%d want %d", n, cap(joins), wantCap)
		}
		if n > 8 && cap(joins) < n {
			t.Errorf("n=%d: cap=%d below len", n, cap(joins))
		}
	}
}

func TestJoinsCapWindowAndCap(t *testing.T) {
	p := &Parser{}
	p.tokens = joinHintTokens(t, joinQuery(20))
	p.currentPos = 0
	if got := p.joinsCap(); got != 8 {
		t.Errorf("cap=%d want 8", got)
	}
	// Past the end of the stream there is nothing to look at.
	p.currentPos = len(p.tokens)
	if got := p.joinsCap(); got != 1 {
		t.Errorf("cap=%d want 1 at end of stream", got)
	}
}

// A join-free statement among join statements must not be affected, and a
// multi-statement script parses identically statement by statement.
func TestJoinsCapMultiStatement(t *testing.T) {
	script := "SELECT * FROM a JOIN b ON a.i=b.i; SELECT 1; SELECT * FROM c JOIN d ON c.i=d.i JOIN e ON e.i=d.i"
	p := &Parser{}
	tree, err := p.parseTokens(joinHintTokens(t, script))
	if err != nil {
		t.Fatal(err)
	}
	want := []int{1, 0, 2}
	if len(tree.Statements) != len(want) {
		t.Fatalf("got %d statements", len(tree.Statements))
	}
	for i, st := range tree.Statements {
		sel, ok := st.(*ast.SelectStatement)
		if !ok {
			t.Fatalf("stmt %d: %T", i, st)
		}
		if len(sel.Joins) != want[i] {
			t.Errorf("stmt %d: %d joins want %d", i, len(sel.Joins), want[i])
		}
	}
}

func selectStatements(t *testing.T, sql string) []*ast.SelectStatement {
	t.Helper()
	p := &Parser{}
	tree, err := p.parseTokens(joinHintTokens(t, sql))
	if err != nil {
		t.Fatalf("parse %q: %v", sql, err)
	}
	var out []*ast.SelectStatement
	var walk func(st ast.Statement)
	walk = func(st ast.Statement) {
		switch s := st.(type) {
		case *ast.SelectStatement:
			out = append(out, s)
			for _, f := range s.From {
				if f.Subquery != nil {
					walk(f.Subquery)
				}
			}
		case *ast.SetOperation:
			walk(s.Left)
			walk(s.Right)
		}
	}
	for _, st := range tree.Statements {
		walk(st)
	}
	return out
}

// The hint must not look past the current statement, set-operation branch or
// subquery: every one-join SELECT below must get capacity exactly 1.
func TestJoinsCapStopsAtBoundaries(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want []int // cap of Joins for each SELECT with joins, in order
	}{
		{"script of single-join statements",
			strings.Repeat("SELECT * FROM a JOIN b ON a.i=b.i; ", 5), []int{1, 1, 1, 1, 1}},
		{"union branches",
			"SELECT a.x FROM a JOIN b ON a.i=b.i UNION ALL SELECT c.x FROM c JOIN d ON c.i=d.i", []int{1, 1}},
		{"except branches",
			"SELECT a.x FROM a JOIN b ON a.i=b.i EXCEPT SELECT c.x FROM c JOIN d ON c.i=d.i JOIN e ON e.i=d.i", []int{1, 2}},
		{"intersect branches",
			"SELECT a.x FROM a JOIN b ON a.i=b.i INTERSECT SELECT c.x FROM c JOIN d ON c.i=d.i", []int{1, 1}},
		{"mixed one and two join statements",
			"SELECT * FROM a JOIN b ON a.i=b.i; SELECT * FROM c JOIN d ON c.i=d.i JOIN e ON e.i=d.i; SELECT * FROM f JOIN g ON f.i=g.i", []int{1, 2, 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []int
			for _, s := range selectStatements(t, tc.sql) {
				if len(s.Joins) > 0 {
					got = append(got, cap(s.Joins))
				}
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("caps=%v want %v", got, tc.want)
			}
		})
	}
}

// A subquery's join must not count the outer query's later joins, and the
// outer query must not count joins nested in subqueries.
func TestJoinsCapSubqueryDepth(t *testing.T) {
	sql := "SELECT * FROM (SELECT * FROM a JOIN b ON a.i=b.i) s JOIN c ON c.i=s.i JOIN d ON d.i=c.i"
	var inner, outer *ast.SelectStatement
	for _, s := range selectStatements(t, sql) {
		if len(s.Joins) == 2 {
			outer = s
		} else if len(s.Joins) == 1 {
			inner = s
		}
	}
	if inner == nil || outer == nil {
		t.Fatalf("did not find inner and outer selects (inner=%v outer=%v)", inner != nil, outer != nil)
	}
	if cap(inner.Joins) != 1 {
		t.Errorf("subquery joins cap=%d want 1", cap(inner.Joins))
	}
	if cap(outer.Joins) != 2 {
		t.Errorf("outer joins cap=%d want 2", cap(outer.Joins))
	}

	// Joins nested inside a parenthesised subquery ahead do not count.
	sql = "SELECT * FROM a JOIN b ON b.i IN (SELECT x FROM c JOIN d ON c.i=d.i JOIN e ON e.i=d.i)"
	for _, s := range selectStatements(t, sql) {
		if len(s.Joins) == 1 && cap(s.Joins) != 1 {
			t.Errorf("outer cap=%d want 1", cap(s.Joins))
		}
	}
}

// BenchmarkParseManyShortJoinStatements keeps the multi-statement trade-off
// visible: each statement has one JOIN, so each joins slice must stay cap 1.
func BenchmarkParseManyShortJoinStatements(b *testing.B) {
	sql := strings.Repeat("SELECT * FROM a JOIN b ON a.i=b.i; ", 50)
	tkz := tokenizer.GetTokenizer()
	toks, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		b.Fatal(err)
	}
	pt := preprocessTokens(toks)
	tokenizer.PutTokenizer(tkz)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := &Parser{}
		tree, err := p.parseTokens(pt)
		if err != nil {
			b.Fatal(err)
		}
		ast.ReleaseAST(tree)
	}
}
