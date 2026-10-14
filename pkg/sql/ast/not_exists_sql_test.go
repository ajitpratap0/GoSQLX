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

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestBinaryExpression_NotExistsSQL_Issue601 covers the unary NOT shape the
// parser produces for NOT EXISTS: Operator "NOT", Left the EXISTS, Right nil.
func TestBinaryExpression_NotExistsSQL_Issue601(t *testing.T) {
	tree, err := gosqlx.Parse("SELECT 1 FROM u")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer ast.ReleaseAST(tree)
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
	}

	e := &ast.BinaryExpression{
		Operator: "NOT",
		Not:      true,
		Left:     &ast.ExistsExpression{Subquery: sel},
	}
	if got, want := e.SQL(), "NOT EXISTS (SELECT 1 FROM u)"; got != want {
		t.Errorf("SQL() = %q, want %q", got, want)
	}

	// Not flag is irrelevant: a unary NOT with no right operand is a prefix NOT.
	e.Not = false
	if got, want := e.SQL(), "NOT EXISTS (SELECT 1 FROM u)"; got != want {
		t.Errorf("SQL() with Not=false = %q, want %q", got, want)
	}

	id := &ast.BinaryExpression{Operator: "NOT", Not: true, Left: &ast.Identifier{Name: "active"}}
	if got, want := id.SQL(), "NOT active"; got != want {
		t.Errorf("SQL() = %q, want %q", got, want)
	}
}
