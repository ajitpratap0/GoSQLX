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
	"runtime"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// parseTree tokenizes and parses sql and returns the AST without releasing it.
func parseTree(t *testing.T, sql string) *ast.AST {
	t.Helper()

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize %q: %v", sql, err)
	}

	p := parser.GetParser()
	defer parser.PutParser(p)

	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("parse %q: %v", sql, err)
	}
	return tree
}

// assertDistinctSelectGets takes three statements from the pool and fails if
// any pointer is handed out twice, which happens when one object was Put
// twice. The statements are returned to the pool afterwards.
func assertDistinctSelectGets(t *testing.T) []*ast.SelectStatement {
	t.Helper()
	got := []*ast.SelectStatement{
		ast.GetSelectStatement(),
		ast.GetSelectStatement(),
		ast.GetSelectStatement(),
	}
	for i := 0; i < len(got); i++ {
		for j := i + 1; j < len(got); j++ {
			if got[i] == got[j] {
				t.Errorf("GetSelectStatement #%d and #%d returned the same pointer %p: a statement was Put twice", i, j, got[i])
			}
		}
	}
	return got
}

func putSelects(stmts []*ast.SelectStatement) {
	for _, s := range stmts {
		ast.PutSelectStatement(s)
	}
}

// TestReleaseAST_DerivedTableJoin_NoDoublePut guards against #555: the parser
// copies From[0] into Joins[0].Left, so releasing through Left Put the
// derived-table subquery twice and two later Gets shared one statement.
func TestReleaseAST_DerivedTableJoin_NoDoublePut(t *testing.T) {
	cases := []struct {
		name string
		sql  string
	}{
		{"single join", "SELECT * FROM (SELECT a FROM x) t JOIN u ON t.a = u.a"},
		{"two joins", "SELECT * FROM (SELECT a FROM x) t JOIN u ON t.a = u.a JOIN v ON v.a = u.a"},
		{"array and tuple in subquery", "SELECT * FROM (SELECT ARRAY[1] AS arr, (1, 2) AS tup FROM x) t JOIN u ON t.a = u.a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			tree := parseTree(t, tc.sql)
			if len(tree.Statements) != 1 {
				t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
			}
			sel, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
			}
			if len(sel.From) == 0 || len(sel.Joins) == 0 {
				t.Fatalf("expected From and Joins, got From=%d Joins=%d", len(sel.From), len(sel.Joins))
			}
			if sel.From[0].Subquery == nil {
				t.Fatal("expected a derived-table subquery in From[0]")
			}
			// Documents the aliasing PutSelectStatement relies on. If the
			// parser stops copying From[0] into Joins[0].Left, revisit the
			// JOIN release comment in PutSelectStatement.
			if sel.From[0].Subquery != sel.Joins[0].Left.Subquery {
				t.Fatalf("expected Joins[0].Left.Subquery to alias From[0].Subquery")
			}

			ast.ReleaseAST(tree)
			putSelects(assertDistinctSelectGets(t))
			assertDistinctDrawnExprGets(t)
		})
	}
}

// assertDistinctDrawnExprGets fails if the ArrayConstructor or Tuple pools
// hand out one pointer twice, which guards the node types ReleaseAST still
// Puts. The nodes are returned to their pools afterwards.
func assertDistinctDrawnExprGets(t *testing.T) {
	t.Helper()
	arrs := make([]*ast.ArrayConstructorExpression, 4)
	tups := make([]*ast.TupleExpression, 4)
	for i := range arrs {
		arrs[i] = ast.GetArrayConstructor()
		tups[i] = ast.GetTupleExpression()
	}
	for i := 0; i < len(arrs); i++ {
		for j := i + 1; j < len(arrs); j++ {
			if arrs[i] == arrs[j] {
				t.Errorf("GetArrayConstructor #%d and #%d returned the same pointer %p: Put twice", i, j, arrs[i])
			}
			if tups[i] == tups[j] {
				t.Errorf("GetTupleExpression #%d and #%d returned the same pointer %p: Put twice", i, j, tups[i])
			}
		}
	}
	for i := range arrs {
		ast.PutExpression(arrs[i])
		ast.PutExpression(tups[i])
	}
}

// TestPutSelectStatement_HandBuilt_LeftAliasFrom builds the same aliasing by
// hand and checks that the released statements come back fully reset.
func TestPutSelectStatement_HandBuilt_LeftAliasFrom(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	stmt := ast.GetSelectStatement()
	sub := ast.GetSelectStatement()
	stmt.From = append(stmt.From, ast.TableReference{Subquery: sub, Alias: "t"})
	stmt.Joins = []ast.JoinClause{{
		Type:  "INNER",
		Left:  stmt.From[0],
		Right: ast.TableReference{Name: "u"},
		Pos:   models.Location{Line: 1, Column: 30},
	}}
	stmt.Pos = models.Location{Line: 1, Column: 1}

	ast.PutSelectStatement(stmt)

	got := assertDistinctSelectGets(t)
	defer putSelects(got)
	for i, s := range got {
		if len(s.Joins) != 0 || len(s.From) != 0 {
			t.Errorf("Get #%d: expected empty Joins/From, got Joins=%d From=%d", i, len(s.Joins), len(s.From))
		}
		if s.Pos != (models.Location{}) {
			t.Errorf("Get #%d: expected zero Pos, got %+v", i, s.Pos)
		}
		if cap(s.Joins) > 0 {
			if j := s.Joins[:1][0]; j.Left.Subquery != nil || j.Pos != (models.Location{}) || j.Type != "" {
				t.Errorf("Get #%d: Joins backing array retains a stale JoinClause: %+v", i, j)
			}
		}
	}
}
