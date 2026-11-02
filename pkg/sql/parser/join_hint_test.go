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
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestJoinsCap(t *testing.T) {
	cases := map[int]int{-1: 2, 0: 2, 1: 1, 2: 2, 5: 5, 8: 8, 9: 8, 100: 8}
	for hint, want := range cases {
		p := &Parser{joinHint: hint}
		if got := p.joinsCap(); got != want {
			t.Errorf("joinHint=%d: cap=%d want %d", hint, got, want)
		}
	}
}

func lexForHint(t *testing.T, sql string) []models.TokenWithSpan {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	toks, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize %q: %v", sql, err)
	}
	return append([]models.TokenWithSpan(nil), toks...)
}

// The hint equals the number of JOIN tokens in the normalised stream and the
// token output is identical to preprocessTokensInto.
func TestPreprocessTokensCount(t *testing.T) {
	cases := []struct {
		sql  string
		want int
	}{
		{"SELECT 1", 0},
		{"SELECT * FROM a JOIN b ON a.id = b.id", 1},
		{"SELECT * FROM a INNER JOIN b ON a.id = b.id LEFT JOIN c ON c.id = b.id", 2},
		{"SELECT * FROM a CROSS JOIN b", 1},
		{"SELECT * FROM a LEFT OUTER JOIN b ON a.x = b.x", 1},
		{"SELECT * FROM a JOIN (SELECT * FROM b JOIN c ON b.i = c.i) d ON a.i = d.i", 2},
	}
	for _, c := range cases {
		toks := lexForHint(t, c.sql)
		got, n := preprocessTokensCount(nil, toks)
		if n != c.want {
			t.Errorf("%q: hint=%d want %d", c.sql, n, c.want)
		}
		if ref := preprocessTokensInto(nil, toks); !reflect.DeepEqual(got, ref) {
			t.Errorf("%q: token stream differs from preprocessTokensInto", c.sql)
		}
	}
}

// Parsing must not depend on the hint: every hint value yields an identical AST.
func TestJoinHintDoesNotChangeAST(t *testing.T) {
	var parts []string
	for i := 1; i <= 12; i++ {
		parts = append(parts, fmt.Sprintf("JOIN t%d ON t%d.id = t0.id", i, i))
	}
	queries := []string{
		"SELECT * FROM t0 " + strings.Join(parts[:1], " "),
		"SELECT * FROM t0 " + strings.Join(parts[:3], " "),
		"SELECT * FROM t0 " + strings.Join(parts, " "),
		"SELECT * FROM t0 LEFT JOIN t1 ON t1.id = t0.id CROSS JOIN t2",
		"SELECT * FROM (t0 JOIN t1 ON t1.id = t0.id) JOIN t2 ON t2.id = t0.id",
		"SELECT * FROM t0, t1 JOIN t2 ON t2.id = t1.id",
	}
	for _, q := range queries {
		toks := lexForHint(t, q)
		var base *ast.AST
		for _, hint := range []int{-1, 0, 1, 2, 3, 8, 50} {
			p := &Parser{}
			pre := preprocessTokensInto(nil, toks)
			p.joinHint = hint
			tree, err := p.parseTokens(pre)
			if err != nil {
				t.Fatalf("%q hint=%d: %v", q, hint, err)
			}
			if base == nil {
				base = tree
				continue
			}
			if !reflect.DeepEqual(base.Statements, tree.Statements) {
				t.Errorf("%q: AST differs for hint=%d", q, hint)
			}
		}
	}
}

// Reset clears a stale hint, and preprocess refreshes it on every parse.
func TestJoinHintResetAndRefresh(t *testing.T) {
	p := &Parser{}
	p.preprocess(lexForHint(t, "SELECT * FROM a JOIN b ON a.i=b.i JOIN c ON c.i=b.i"))
	if p.joinHint != 2 {
		t.Fatalf("joinHint=%d want 2", p.joinHint)
	}
	p.Reset()
	if p.joinHint != 0 {
		t.Fatalf("Reset left joinHint=%d", p.joinHint)
	}
	p.preprocess(lexForHint(t, "SELECT 1"))
	if p.joinHint != 0 {
		t.Fatalf("joinHint=%d want 0 after join-free stream", p.joinHint)
	}
}
