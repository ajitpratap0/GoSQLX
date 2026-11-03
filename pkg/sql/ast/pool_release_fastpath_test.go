// Copyright 2026 GoSQLX Contributors
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/internal/astrelease"
)

// buildTupleSelect returns a hand-built tree holding a pooled TupleExpression.
func buildTupleSelect() (*AST, *TupleExpression) {
	tup := GetTupleExpression()
	tup.Expressions = append(tup.Expressions, GetLiteralValue())
	sel := &SelectStatement{Columns: []Expression{tup}}
	tree := NewAST()
	tree.Statements = append(tree.Statements, sel)
	return tree, tup
}

func TestReleaseAST_ParserBuiltWithoutDrawsSkipsWalk(t *testing.T) {
	tree := NewAST()
	tup := &TupleExpression{Expressions: []Expression{&LiteralValue{Value: "1"}}}
	tree.Statements = append(tree.Statements, &SelectStatement{Columns: []Expression{tup}})
	tree.Comments = append(tree.Comments, models.Comment{Text: "c"})

	astrelease.MarkParserBuilt(tree, 0)
	if !tree.noPooledDraws {
		t.Fatal("zero-draw parser tree must be marked")
	}
	ReleaseAST(tree)

	if tup.Expressions == nil {
		t.Error("fast path must not walk the tree: the tuple was reset")
	}
	if len(tree.Statements) != 0 || len(tree.Comments) != 0 {
		t.Errorf("container not emptied: %d statements, %d comments", len(tree.Statements), len(tree.Comments))
	}
	if tree.noPooledDraws {
		t.Error("flag must be cleared before the container returns to the pool")
	}
}

func TestReleaseAST_ParserBuiltWithDrawsKeepsWalk(t *testing.T) {
	tree, tup := buildTupleSelect()
	astrelease.MarkParserBuilt(tree, 1)
	if tree.noPooledDraws {
		t.Fatal("a tree with pooled draws must not be marked")
	}
	ReleaseAST(tree)
	if len(tup.Expressions) != 0 {
		t.Errorf("pooled tuple not reset by the release walk: %d expressions left", len(tup.Expressions))
	}
}

func TestReleaseAST_HandBuiltTreeKeepsWalk(t *testing.T) {
	tree, tup := buildTupleSelect()
	if tree.noPooledDraws {
		t.Fatal("hand-built trees are never marked")
	}
	ReleaseAST(tree)
	if len(tup.Expressions) != 0 {
		t.Errorf("hand-built pooled tuple not reset: %d expressions left", len(tup.Expressions))
	}
}

func TestReleaseAST_FlagDoesNotSurvivePooling(t *testing.T) {
	for i := 0; i < 50; i++ {
		tree := NewAST()
		if tree.noPooledDraws {
			t.Fatal("NewAST returned a container still marked as draw-free")
		}
		astrelease.MarkParserBuilt(tree, 0)
		ReleaseAST(tree)
	}
}

func TestMarkParserBuilt_IgnoresForeignValues(t *testing.T) {
	astrelease.MarkParserBuilt(nil, 0)
	astrelease.MarkParserBuilt("not a tree", 0)
	astrelease.MarkParserBuilt((*AST)(nil), 0)
}
