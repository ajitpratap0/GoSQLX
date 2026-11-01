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

package linter_test

import (
	"reflect"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestContextNodesInspectOrder(t *testing.T) {
	parsed := 0
	for _, dialect := range nodeTestDialects {
		for _, input := range lintCorpusInputs(t, dialect, true) {
			tree, err := gosqlx.ParseWithDialect(input.sql, keywords.SQLDialect(dialect))
			if err != nil {
				continue
			}
			func() {
				defer ast.ReleaseAST(tree)
				var want []ast.Node
				for _, statement := range tree.Statements {
					ast.Inspect(statement, func(node ast.Node) bool {
						if node != nil {
							want = append(want, node)
						}
						return true
					})
				}
				ctx := linter.NewContext(input.sql, input.name).WithAST(tree, nil)
				got := ctx.Nodes()
				if len(got) != len(want) {
					t.Fatalf("%s/%s: got %d nodes, want %d", dialect, input.name, len(got), len(want))
				}
				for i := range want {
					if got[i] != want[i] {
						t.Fatalf("%s/%s: node %d: got %T, want %T", dialect, input.name, i, got[i], want[i])
					}
				}
				if len(got) > 0 && &got[0] != &ctx.Nodes()[0] {
					t.Fatalf("%s/%s: node slice not cached", dialect, input.name)
				}
			}()
			parsed++
		}
	}
	if parsed == 0 {
		t.Fatal("no corpus inputs parsed")
	}
	t.Logf("checked preorder on %d parsed inputs", parsed)
}

func TestContextNodesNilAndReplacement(t *testing.T) {
	ctx := linter.NewContext("", "")
	if got := ctx.Nodes(); got != nil {
		t.Fatalf("nil AST: %v", got)
	}
	ctx.WithAST(&ast.AST{Statements: []ast.Statement{nil}}, nil)
	if got := ctx.Nodes(); len(got) != 0 {
		t.Fatalf("nil statement: %v", got)
	}
	first := &ast.SelectStatement{}
	second := &ast.DeleteStatement{}
	ctx.WithAST(&ast.AST{Statements: []ast.Statement{nil, first, nil}}, nil)
	if got := ctx.Nodes(); !reflect.DeepEqual(got, []ast.Node{first}) {
		t.Fatalf("first AST: %v", got)
	}
	ctx.WithAST(&ast.AST{Statements: []ast.Statement{second}}, nil)
	if got := ctx.Nodes(); !reflect.DeepEqual(got, []ast.Node{second}) {
		t.Fatalf("replacement AST: %v", got)
	}
	ctx.WithAST(nil, nil)
	if got := ctx.Nodes(); got != nil {
		t.Fatalf("cleared AST: %v", got)
	}
}

func TestContextNodesDirectASTAssignment(t *testing.T) {
	first := &ast.SelectStatement{}
	second := &ast.DeleteStatement{}
	ctx := linter.NewContext("", "").WithAST(&ast.AST{Statements: []ast.Statement{first}}, nil)
	if got := ctx.Nodes(); !reflect.DeepEqual(got, []ast.Node{first}) {
		t.Fatalf("first: %v", got)
	}
	ctx.AST = &ast.AST{Statements: []ast.Statement{second}}
	if got := ctx.Nodes(); !reflect.DeepEqual(got, []ast.Node{second}) {
		t.Fatalf("direct assignment returned stale nodes: %v", got)
	}
	cp := *ctx
	cp.AST = &ast.AST{Statements: []ast.Statement{first}}
	if got := cp.Nodes(); !reflect.DeepEqual(got, []ast.Node{first}) {
		t.Fatalf("by-value copy returned stale nodes: %v", got)
	}
}

func TestContextNodesSeparateContextsConcurrent(t *testing.T) {
	for i := 0; i < 16; i++ {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			t.Parallel()
			statement := &ast.SelectStatement{}
			ctx := linter.NewContext("", "").WithAST(&ast.AST{Statements: []ast.Statement{statement}}, nil)
			for j := 0; j < 100; j++ {
				got := ctx.Nodes()
				if len(got) != 1 || got[0] != statement {
					t.Fatal("context cache contains another context's node")
				}
			}
		})
	}
}
