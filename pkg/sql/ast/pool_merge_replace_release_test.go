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

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// MERGE can own a derived-table source and a SQL Server OUTPUT ... INTO
// target, and REPLACE ... SELECT owns a query. Both release their nested
// statements and expressions by the same policy as INSERT / UPDATE / DELETE:
// the exported Put* functions return everything, ReleaseAST only the node
// types the parser draws from pools (issue #556).

func mergeWithDerivedSource() (*ast.MergeStatement, *ast.SelectStatement, *ast.Identifier) {
	sub := ast.GetSelectStatement()
	sub.Columns = append(sub.Columns, &ast.Identifier{Name: "id"})
	sub.TableName = "s"
	intoCol := &ast.Identifier{Name: "id"}
	m := &ast.MergeStatement{
		TargetTable: ast.TableReference{Name: "t"},
		SourceTable: ast.TableReference{Subquery: sub, Alias: "src"},
		SourceAlias: "src",
		Output:      []ast.Expression{&ast.Identifier{Name: "id", Table: "inserted"}},
		OutputInto:  &ast.OutputInto{Target: "@t", Columns: []ast.Expression{intoCol}},
	}
	return m, sub, intoCol
}

func TestPutMergeStatement_ReleasesDerivedSourceAndOutputInto(t *testing.T) {
	m, sub, _ := mergeWithDerivedSource()

	ast.PutMergeStatement(m)

	if len(sub.Columns) != 0 || sub.TableName != "" {
		t.Errorf("derived-source subquery not released: %+v", *sub)
	}
	if m.SourceTable.Subquery != nil || m.OutputInto != nil || len(m.Output) != 0 {
		t.Errorf("merge not reset: SourceTable=%+v OutputInto=%v Output=%v", m.SourceTable, m.OutputInto, m.Output)
	}
}

func TestReleaseAST_MergeLeavesUndrawnNodesToGC(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	m, sub, intoCol := mergeWithDerivedSource()
	tree := ast.NewAST()
	tree.Statements = append(tree.Statements, m)

	ast.ReleaseAST(tree)

	// The derived-source subquery is reset (its nested nodes are reachable
	// from the parent) but the never-drawn identifier is not recycled.
	if m.SourceTable.Subquery != nil || m.OutputInto != nil {
		t.Errorf("merge fields not cleared: SourceTable=%+v OutputInto=%v", m.SourceTable, m.OutputInto)
	}
	if intoCol.Name != "id" {
		t.Errorf("Identifier was reset by ReleaseAST: %+v", *intoCol)
	}
	assertNeverHandedOut(t, "SelectStatement", 4, pointerSet{sub: true}, ast.GetSelectStatement, ast.PutSelectStatement)
	assertNeverHandedOut(t, "MergeStatement", 4, pointerSet{m: true}, ast.GetMergeStatement, ast.PutMergeStatement)
}

func TestReleaseAST_ReplaceFollowsDrawnPolicy(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	q := &ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "a"}}, TableName: "u"}
	whereLit := &ast.LiteralValue{Value: 1}
	where := &ast.BinaryExpression{Left: &ast.Identifier{Name: "a"}, Operator: "=", Right: whereLit}
	q.Where = where
	r := ast.GetReplaceStatement()
	r.TableName = "t"
	r.Query = q
	tree := ast.NewAST()
	tree.Statements = append(tree.Statements, r)

	ast.ReleaseAST(tree)

	if r.Query != nil || r.TableName != "" {
		t.Errorf("replace not reset: %+v", *r)
	}
	if where.Operator != "=" || where.Right == nil {
		t.Errorf("embedded BinaryExpression was reset by ReleaseAST; the parser never draws it: %+v", *where)
	}
	assertNeverHandedOut(t, "SelectStatement", 4, pointerSet{q: true}, ast.GetSelectStatement, ast.PutSelectStatement)
}

func TestPutReplaceStatement_ReleasesQuery(t *testing.T) {
	q := &ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "a"}}, TableName: "u"}
	r := ast.GetReplaceStatement()
	r.Query = q

	ast.PutReplaceStatement(r)

	if r.Query != nil {
		t.Errorf("Query not cleared: %v", r.Query)
	}
	if q.TableName != "" || len(q.Columns) != 0 {
		t.Errorf("embedded SelectStatement not released by Put: %+v", *q)
	}
}
