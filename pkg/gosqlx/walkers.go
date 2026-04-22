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

package gosqlx

import "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"

// WalkBy traverses the tree in depth-first, pre-order fashion and invokes fn
// for every node whose concrete type is T. Children of the matched node are
// descended unless fn returns false.
//
// WalkBy is a generic helper that removes the type-assertion boilerplate
// required when using Tree.Walk. It is implemented on top of ast.Inspect so
// it follows the same Node.Children() contract and descends into every
// reachable subtree (subqueries, CTEs, UNION arms, etc.).
//
// Nodes whose concrete type does not match T are skipped but still descended
// into — returning false from fn only prunes children of a matched node.
//
// Example — collect every table reference inside nested subqueries:
//
//	var names []string
//	gosqlx.WalkBy(tree, func(t *ast.TableReference) bool {
//	    names = append(names, t.Name)
//	    return true
//	})
//
// Example — short-circuit on the first SELECT with a Where clause:
//
//	var found *ast.SelectStatement
//	gosqlx.WalkBy(tree, func(s *ast.SelectStatement) bool {
//	    if s.Where != nil {
//	        found = s
//	        return false // prune this subtree (siblings still visited)
//	    }
//	    return true
//	})
func WalkBy[T ast.Node](t *Tree, fn func(T) bool) {
	if t == nil || t.ast == nil || fn == nil {
		return
	}
	ast.Inspect(t.ast, func(n ast.Node) bool {
		typed, ok := n.(T)
		if !ok {
			// Not the target type — descend so we can reach matches deeper.
			return true
		}
		return fn(typed)
	})
}

// WalkSelects invokes fn for every *ast.SelectStatement in the tree, including
// those nested inside subqueries, CTEs, and set-operation arms. Return false
// from fn to skip descent into the matched SELECT's children (siblings are
// still visited).
func (t *Tree) WalkSelects(fn func(*ast.SelectStatement) bool) {
	WalkBy(t, fn)
}

// WalkInserts invokes fn for every *ast.InsertStatement in the tree.
func (t *Tree) WalkInserts(fn func(*ast.InsertStatement) bool) {
	WalkBy(t, fn)
}

// WalkUpdates invokes fn for every *ast.UpdateStatement in the tree.
func (t *Tree) WalkUpdates(fn func(*ast.UpdateStatement) bool) {
	WalkBy(t, fn)
}

// WalkDeletes invokes fn for every *ast.DeleteStatement in the tree.
func (t *Tree) WalkDeletes(fn func(*ast.DeleteStatement) bool) {
	WalkBy(t, fn)
}

// WalkCreateTables invokes fn for every *ast.CreateTableStatement in the tree.
func (t *Tree) WalkCreateTables(fn func(*ast.CreateTableStatement) bool) {
	WalkBy(t, fn)
}

// WalkJoins invokes fn for every *ast.JoinClause in the tree. Because JoinClause
// is stored by value on SelectStatement.Joins, its Children() method exposes
// pointer access so WalkBy can locate each join node during traversal. If your
// parser version stores joins as values and they are not reachable via
// Children(), use Tree.WalkSelects and iterate s.Joins directly.
func (t *Tree) WalkJoins(fn func(*ast.JoinClause) bool) {
	WalkBy(t, fn)
}

// WalkCTEs invokes fn for every *ast.CommonTableExpr in the tree, descending
// into nested WITH clauses inside subqueries.
func (t *Tree) WalkCTEs(fn func(*ast.CommonTableExpr) bool) {
	WalkBy(t, fn)
}

// WalkFunctionCalls invokes fn for every *ast.FunctionCall in the tree,
// including window functions, aggregate functions, and scalar functions.
func (t *Tree) WalkFunctionCalls(fn func(*ast.FunctionCall) bool) {
	WalkBy(t, fn)
}

// WalkIdentifiers invokes fn for every *ast.Identifier in the tree. Useful
// for collecting column references, table aliases, or any bare name that the
// parser lowered to an Identifier node.
func (t *Tree) WalkIdentifiers(fn func(*ast.Identifier) bool) {
	WalkBy(t, fn)
}

// WalkBinaryExpressions invokes fn for every *ast.BinaryExpression in the tree.
// Useful for linting operators (=, <, LIKE, ->>, etc.) or rewriting comparison
// predicates.
func (t *Tree) WalkBinaryExpressions(fn func(*ast.BinaryExpression) bool) {
	WalkBy(t, fn)
}
