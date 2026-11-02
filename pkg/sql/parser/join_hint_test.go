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
