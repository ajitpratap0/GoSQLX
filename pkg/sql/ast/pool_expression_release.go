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

package ast

import (
	"sync/atomic"
)

// GetUpdateExpression gets an UpdateExpression from the pool
func GetUpdateExpression() *UpdateExpression {
	return updateExprPool.Get().(*UpdateExpression)
}

// PutUpdateExpression returns an UpdateExpression to the pool
func PutUpdateExpression(expr *UpdateExpression) {
	if expr == nil {
		return
	}

	// Clean up expressions
	PutExpression(expr.Column)
	PutExpression(expr.Value)

	// Reset fields
	expr.Column = nil
	expr.Value = nil

	// Return to pool
	updateExprPool.Put(expr)
}

// GetIdentifier gets an Identifier from the pool
func GetIdentifier() *Identifier {
	return identifierPool.Get().(*Identifier)
}

// PutIdentifier returns an Identifier to the pool
func PutIdentifier(ident *Identifier) {
	if ident == nil {
		return
	}
	PutExpression(ident)
}

// GetBinaryExpression gets a BinaryExpression from the pool
func GetBinaryExpression() *BinaryExpression {
	return binaryExprPool.Get().(*BinaryExpression)
}

// PutBinaryExpression returns a BinaryExpression to the pool
func PutBinaryExpression(expr *BinaryExpression) {
	if expr == nil {
		return
	}
	PutExpression(expr)
}

// GetExpressionSlice gets a slice of Expression from the pool
func GetExpressionSlice() *[]Expression {
	slice := exprSlicePool.Get().(*[]Expression)
	*slice = (*slice)[:0]
	return slice
}

// PutExpressionSlice returns a slice of Expression to the pool
func PutExpressionSlice(slice *[]Expression) {
	if slice == nil {
		return
	}
	for i := range *slice {
		PutExpression((*slice)[i])
		(*slice)[i] = nil
	}
	exprSlicePool.Put(slice)
}

// GetLiteralValue gets a LiteralValue from the pool
func GetLiteralValue() *LiteralValue {
	return literalValuePool.Get().(*LiteralValue)
}

// PutLiteralValue returns a LiteralValue to the pool
func PutLiteralValue(lit *LiteralValue) {
	if lit == nil {
		return
	}
	PutExpression(lit)
}

// PutExpression returns any Expression to the appropriate pool with iterative cleanup.
//
// PutExpression is the primary function for returning expression nodes to their
// respective pools. It handles all expression types and uses iterative cleanup
// to prevent stack overflow with deeply nested expression trees.
//
// Key Features:
//   - Supports all expression types (30+ pooled types)
//   - Iterative cleanup algorithm (no recursion limits)
//   - Prevents stack overflow for deeply nested expressions
//   - Work queue size limits (MaxWorkQueueSize = 100_000)
//   - Nil-safe (ignores nil expressions)
//
// Supported Expression Types:
//   - Identifier, LiteralValue, AliasedExpression
//   - BinaryExpression, UnaryExpression
//   - FunctionCall, CaseExpression
//   - BetweenExpression, InExpression
//   - SubqueryExpression, ExistsExpression, AnyExpression, AllExpression
//   - CastExpression, ExtractExpression, PositionExpression, SubstringExpression
//   - ListExpression
//
// Iterative Cleanup Algorithm:
//  1. Use work queue instead of recursion
//  2. Process expressions breadth-first
//  3. Collect child expressions and add to queue
//  4. Clean and return to pool
//  5. Limit queue size to prevent memory exhaustion
//
// Parameters:
//   - expr: Expression to return to pool (nil-safe)
//
// Usage Pattern:
//
//	expr := ast.GetBinaryExpression()
//	defer ast.PutExpression(expr)
//
//	// Build expression tree...
//
// Example - Cleaning up complex expression:
//
//	// Build: (age > 18 AND status = 'active') OR (role = 'admin')
//	expr := &ast.BinaryExpression{
//	    Left: &ast.BinaryExpression{
//	        Left:     &ast.BinaryExpression{...},
//	        Operator: "AND",
//	        Right:    &ast.BinaryExpression{...},
//	    },
//	    Operator: "OR",
//	    Right: &ast.BinaryExpression{...},
//	}
//
//	// Cleanup all nested expressions
//	ast.PutExpression(expr)  // Handles entire tree iteratively
//
// Performance Characteristics:
//   - O(n) time complexity where n = number of nodes
//   - O(min(n, MaxWorkQueueSize)) space complexity
//   - No stack overflow risk regardless of nesting depth
//   - Efficient for both shallow and deeply nested expressions
//
// Safety Guarantees:
//   - Thread-safe (uses sync.Pool internally)
//   - Nil-safe (gracefully handles nil expressions)
//   - Stack-safe (iterative, not recursive)
//   - Memory-safe (work queue size limits)
//
// IMPORTANT: This function should be used for all expression cleanup.
// Direct pool returns (e.g., binaryExprPool.Put()) bypass the iterative
// cleanup and may leave child expressions unreleased.
//
// PutExpression always returns every pooled node it reaches. ReleaseAST and
// ReleaseStatements use a narrower policy and only recycle the node types the
// parser draws from pools; see ReleaseAST. Trees built by hand from Get*
// nodes should be released with PutExpression or the matching Put* function.
//
// See also: GetBinaryExpression(), GetFunctionCall(), GetIdentifier()
func PutExpression(expr Expression) {
	releaseExpression(expr, releaseAll)
}

// releaseMode selects which pooled node types a release walk returns to
// their pools. The walk itself is the same in both modes, so pooled nodes
// nested under any parent are always reached.
type releaseMode uint8

const (
	// releaseAll returns every pooled node reachable from the root. It is
	// used by the exported Put* functions, whose contract is unchanged.
	releaseAll releaseMode = iota

	// releaseDrawn returns only the node types the parser draws from pools
	// and leaves every other node to the GC. It is used by ReleaseAST and
	// ReleaseStatements (issue #556): putting nodes the parser never Gets
	// only grows pools nobody reads from.
	//
	// Drawn expression types: TupleExpression, ArrayConstructorExpression,
	// ArraySubscriptExpression and ArraySliceExpression. Drawn statement
	// types: UnsupportedStatement, AlterStatement, ShowStatement,
	// DescribeStatement, ReplaceStatement and the sequence statements; the
	// other DDL statements are also still Put through their Put* functions.
	// This list must be kept in sync with the parser's ast.Get* (and
	// ast.NewXxxStatement) calls: a type the parser starts drawing must be
	// Put unconditionally in putExpressionImpl / releaseStatement, and its
	// constructor added to releaseDrawnConstructors in pool_drawn_policy_test.go.
	releaseDrawn
)

// releaseExpression releases expr and its subtree according to mode.
func releaseExpression(expr Expression, mode releaseMode) {
	if mode == releaseDrawn {
		switch expr.(type) {
		case nil, *Identifier, *LiteralValue:
			// Leaves the parser never draws from a pool: nothing to do.
			return
		}
		putExpressionImpl(expr, 0, mode)
		return
	}
	// Leaf fast path: Identifier and LiteralValue have no children, so they
	// never need the work queue. These are by far the most common nodes.
	switch e := expr.(type) {
	case nil:
		return
	case *Identifier:
		if e != nil {
			*e = Identifier{}
			identifierPool.Put(e)
		}
		return
	case *LiteralValue:
		if e != nil {
			*e = LiteralValue{}
			literalValuePool.Put(e)
		}
		return
	}
	putExpressionImpl(expr, 0, mode)
}

// putExpressionImpl is the internal driver for PutExpression. The depth
// parameter tracks recursive re-entries from the work-queue overflow path
// to prevent stack overflow on pathologically deep ASTs.
//
// The iterative work queue is drawn from putExpressionWorkQueuePool so that
// hot-path PutExpression calls (10-100× per parse) do not repeatedly allocate
// a fresh 32-cap []Expression. Before the queue is returned, every slot this
// call wrote is nil'd (so the pool cannot pin Expression pointers already
// returned to their own pools), and a queue that grew beyond
// maxPooledWorkQueueCap is dropped instead of returned.
//
// Hazard: in releaseDrawn mode un-drawn parents are not reset, so if a parent
// were ever reachable twice the walk would push its drawn children twice and
// they would be Put twice. The parser never shares parents today
// (JoinClause.Left is skipped; named windows and ClickHouse parametric
// aggregates allocate fresh nodes).
//
// Every pooled node is reset by assigning the zero value of its type,
// keeping only the backing arrays of its hot child slices (Arguments, List,
// WhenClauses, ...), so Get* never hands out a node with stale fields.
func putExpressionImpl(expr Expression, depth int, mode releaseMode) {
	putExpressionBounded(expr, depth, mode, MaxWorkQueueSize, MaxCleanupDepth)
}

// putExpressionBounded is putExpressionImpl with the work budget and the
// overflow-recursion limit passed in, so tests can exercise the overflow
// path with small trees. Production callers always pass MaxWorkQueueSize
// and MaxCleanupDepth.
func putExpressionBounded(expr Expression, depth int, mode releaseMode, maxWork, maxDepth int) {
	if expr == nil {
		return
	}

	// Acquire a pooled work queue. We must write the (possibly grown)
	// slice header back to the pointer before Put so that subsequent
	// Get calls see the grown capacity.
	//
	// hw is the high-water mark of len(workQueue) during this call.
	// Invariant: every slot written by this call has index < hw. Slots are
	// only written through append (at index len, after which hw is raised
	// to cover it), and an append that reallocates copies only [0:len) into
	// a zeroed array. Slots written by an earlier call were cleared by that
	// call before it returned the queue. Hence clear(workQueue[:hw]) removes
	// every pointer the queue holds, and costs O(nodes released) rather
	// than O(cap) - a queue grown once by a huge IN list no longer makes
	// every later Put pay for clearing it.
	qp := putExpressionWorkQueuePool.Get().(*[]Expression)
	workQueue := (*qp)[:0]
	hw := 0
	defer func() {
		clear(workQueue[:hw])
		if cap(workQueue) <= maxPooledWorkQueueCap {
			*qp = workQueue[:0]
			putExpressionWorkQueuePool.Put(qp)
		}
	}()
	workQueue = append(workQueue, expr)
	hw = 1

	processed := 0
	for len(workQueue) > 0 && processed < maxWork {
		// Pop from queue
		current := workQueue[len(workQueue)-1]
		workQueue = workQueue[:len(workQueue)-1]
		processed++

		if current == nil {
			continue
		}

		// Process and collect child expressions
		switch e := current.(type) {
		case *Identifier:
			if mode == releaseAll {
				*e = Identifier{}
				identifierPool.Put(e)
			}

		case *BinaryExpression:
			if e.Left != nil {
				workQueue = append(workQueue, e.Left)
			}
			if e.Right != nil {
				workQueue = append(workQueue, e.Right)
			}
			if e.DialectExtras().Escape != nil {
				workQueue = append(workQueue, e.DialectExtras().Escape)
			}
			if mode == releaseAll {
				// CustomOp is not pooled; the reset drops it for the GC.
				*e = BinaryExpression{}
				binaryExprPool.Put(e)
			}

		case *LiteralValue:
			if mode == releaseAll {
				*e = LiteralValue{}
				literalValuePool.Put(e)
			}

		case *FunctionCall:
			for _, arg := range e.Arguments {
				if arg != nil {
					workQueue = append(workQueue, arg)
				}
			}
			for _, param := range e.Parameters {
				if param != nil {
					workQueue = append(workQueue, param)
				}
			}
			if e.Filter != nil {
				workQueue = append(workQueue, e.Filter)
			}
			workQueue = appendOrderByExprs(workQueue, e.OrderBy)
			workQueue = appendOrderByExprs(workQueue, e.WithinGroup)
			workQueue = appendWindowSpecExprs(workQueue, e.Over)
			if sep := e.DialectExtras().Separator; sep != nil {
				workQueue = append(workQueue, sep)
			}
			if e.DialectExtras().Keep != nil {
				workQueue = appendOrderByExprs(workQueue, e.DialectExtras().Keep.OrderBy)
			}
			if mode == releaseAll {
				// Keep Arguments/Parameters capacity; OrderBy, WithinGroup and
				// Over are rare and left to the GC.
				args, params := e.Arguments, e.Parameters
				clear(args)
				clear(params)
				*e = FunctionCall{Arguments: args[:0], Parameters: params[:0]}
				functionCallPool.Put(e)
			}

		case *CaseExpression:
			if e.Value != nil {
				workQueue = append(workQueue, e.Value)
			}
			for i := range e.WhenClauses {
				if e.WhenClauses[i].Condition != nil {
					workQueue = append(workQueue, e.WhenClauses[i].Condition)
				}
				if e.WhenClauses[i].Result != nil {
					workQueue = append(workQueue, e.WhenClauses[i].Result)
				}
			}
			if e.ElseClause != nil {
				workQueue = append(workQueue, e.ElseClause)
			}
			if mode == releaseAll {
				wc := e.WhenClauses
				clear(wc)
				*e = CaseExpression{WhenClauses: wc[:0]}
				caseExprPool.Put(e)
			}

		case *BetweenExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			if e.Lower != nil {
				workQueue = append(workQueue, e.Lower)
			}
			if e.Upper != nil {
				workQueue = append(workQueue, e.Upper)
			}
			if mode == releaseAll {
				*e = BetweenExpression{}
				betweenExprPool.Put(e)
			}

		case *InExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			for _, item := range e.List {
				if item != nil {
					workQueue = append(workQueue, item)
				}
			}
			// Subquery is a Statement (typically *SelectStatement); release
			// it through the statement dispatcher so every nested pooled
			// node is returned. Silently setting to nil was a leak.
			if e.Subquery != nil {
				releaseStatement(e.Subquery, mode)
			}
			if mode == releaseAll {
				l := e.List
				clear(l)
				*e = InExpression{List: l[:0]}
				inExprPool.Put(e)
			}

		case *SubqueryExpression:
			if e.Subquery != nil {
				releaseStatement(e.Subquery, mode)
			}
			if mode == releaseAll {
				*e = SubqueryExpression{}
				subqueryExprPool.Put(e)
			}

		case *AtTimeZoneExpression:
			// No dedicated pool; children are freed here and the node is left
			// to the garbage collector.
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			if e.Zone != nil {
				workQueue = append(workQueue, e.Zone)
			}

		case *CollateExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}

		case *AnyAllExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			if e.Array != nil {
				workQueue = append(workQueue, e.Array)
			}

		case *TernaryExpression:
			if e.Cond != nil {
				workQueue = append(workQueue, e.Cond)
			}
			if e.Then != nil {
				workQueue = append(workQueue, e.Then)
			}
			if e.Else != nil {
				workQueue = append(workQueue, e.Else)
			}

		case *ParenthesizedExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			e.Expr = nil
			// ParenthesizedExpression has no dedicated pool; children are freed above
			// and the node itself is left to the garbage collector.

		case *FieldAccessExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			for _, a := range e.Args {
				if a != nil {
					workQueue = append(workQueue, a)
				}
			}
			*e = FieldAccessExpression{}

		case *CastExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			if mode == releaseAll {
				*e = CastExpression{}
				castExprPool.Put(e)
			}

		case *IntervalExpression:
			if e.ValueExpr != nil {
				workQueue = append(workQueue, e.ValueExpr)
			}
			if mode == releaseAll {
				*e = IntervalExpression{}
				intervalExprPool.Put(e)
			}

		case *ArraySubscriptExpression:
			if e.Array != nil {
				workQueue = append(workQueue, e.Array)
			}
			for _, idx := range e.Indices {
				if idx != nil {
					workQueue = append(workQueue, idx)
				}
			}
			indices := e.Indices
			clear(indices)
			*e = ArraySubscriptExpression{Indices: indices[:0]}
			arraySubscriptExprPool.Put(e)

		case *ArraySliceExpression:
			if e.Array != nil {
				workQueue = append(workQueue, e.Array)
			}
			if e.Start != nil {
				workQueue = append(workQueue, e.Start)
			}
			if e.End != nil {
				workQueue = append(workQueue, e.End)
			}
			*e = ArraySliceExpression{}
			arraySliceExprPool.Put(e)

		case *ExistsExpression:
			if e.Subquery != nil {
				releaseStatement(e.Subquery, mode)
			}
			if mode == releaseAll {
				*e = ExistsExpression{}
				existsExprPool.Put(e)
			}

		case *AnyExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			if e.Subquery != nil {
				releaseStatement(e.Subquery, mode)
			}
			if mode == releaseAll {
				*e = AnyExpression{}
				anyExprPool.Put(e)
			}

		case *AllExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			if e.Subquery != nil {
				releaseStatement(e.Subquery, mode)
			}
			if mode == releaseAll {
				*e = AllExpression{}
				allExprPool.Put(e)
			}

		case *ListExpression:
			for _, v := range e.Values {
				if v != nil {
					workQueue = append(workQueue, v)
				}
			}
			if mode == releaseAll {
				vals := e.Values
				clear(vals)
				*e = ListExpression{Values: vals[:0]}
				listExprPool.Put(e)
			}

		case *TupleExpression:
			for _, x := range e.Expressions {
				if x != nil {
					workQueue = append(workQueue, x)
				}
			}
			exprs := e.Expressions
			clear(exprs)
			*e = TupleExpression{Expressions: exprs[:0]}
			tupleExprPool.Put(e)

		case *ArrayConstructorExpression:
			for _, el := range e.Elements {
				if el != nil {
					workQueue = append(workQueue, el)
				}
			}
			// Subquery is *SelectStatement — release through the
			// statement pool, not a bare nil-assign (leak before fix).
			if e.Subquery != nil {
				releaseSelectStatement(e.Subquery, mode)
			}
			// ARRAY(SELECT 1 UNION SELECT 2): the set operation itself is
			// not pooled, its operand statements are.
			if so, ok := e.Query.(*SetOperation); ok {
				releaseSetOperationOperands(so, mode)
			} else if e.Query != nil {
				releaseStatement(e.Query, mode)
			}
			elems := e.Elements
			clear(elems)
			*e = ArrayConstructorExpression{Elements: elems[:0]}
			arrayConstructorPool.Put(e)

		case *UnaryExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			if mode == releaseAll {
				*e = UnaryExpression{}
				unaryExprPool.Put(e)
			}

		case *ExtractExpression:
			if e.Source != nil {
				workQueue = append(workQueue, e.Source)
			}
			if mode == releaseAll {
				*e = ExtractExpression{}
				extractExprPool.Put(e)
			}

		case *PositionExpression:
			if e.Substr != nil {
				workQueue = append(workQueue, e.Substr)
			}
			if e.Str != nil {
				workQueue = append(workQueue, e.Str)
			}
			if mode == releaseAll {
				*e = PositionExpression{}
				positionExprPool.Put(e)
			}

		case *SubstringExpression:
			if e.Str != nil {
				workQueue = append(workQueue, e.Str)
			}
			if e.Start != nil {
				workQueue = append(workQueue, e.Start)
			}
			if e.Length != nil {
				workQueue = append(workQueue, e.Length)
			}
			if mode == releaseAll {
				*e = SubstringExpression{}
				substringExprPool.Put(e)
			}

		case *AliasedExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			if mode == releaseAll {
				*e = AliasedExpression{}
				aliasedExprPool.Put(e)
			}

		// Pass-through cases: these expression types have no sync.Pool by
		// design (the parent stays GC-owned), but their children may be
		// pooled. Release the children and detach them from the parent.
		case *RollupExpression:
			for _, x := range e.Expressions {
				if x != nil {
					workQueue = append(workQueue, x)
				}
			}
			clear(e.Expressions)
			e.Expressions = e.Expressions[:0]

		case *CubeExpression:
			for _, x := range e.Expressions {
				if x != nil {
					workQueue = append(workQueue, x)
				}
			}
			clear(e.Expressions)
			e.Expressions = e.Expressions[:0]

		case *GroupingSetsExpression:
			for _, set := range e.Sets {
				for _, x := range set {
					if x != nil {
						workQueue = append(workQueue, x)
					}
				}
				clear(set)
			}
			clear(e.Sets)
			e.Sets = e.Sets[:0]

		case *NamedArgument:
			if e.Value != nil {
				workQueue = append(workQueue, e.Value)
			}
			e.Value = nil

		case *StarExpression:
			if e.Star != nil {
				workQueue = append(workQueue, e.Star)
			}
			if e.Ilike != nil {
				workQueue = append(workQueue, e.Ilike)
			}
			for _, r := range e.Replace {
				if r != nil {
					workQueue = append(workQueue, r)
				}
			}
			for _, a := range e.Apply {
				if a != nil {
					workQueue = append(workQueue, a)
				}
			}
			e.Star, e.Ilike = nil, nil
			clear(e.Replace)
			e.Replace = e.Replace[:0]
			clear(e.Apply)
			e.Apply = e.Apply[:0]

		case *ObjectLiteral:
			for i := range e.Entries {
				if e.Entries[i].Key != nil {
					workQueue = append(workQueue, e.Entries[i].Key)
				}
				if e.Entries[i].Value != nil {
					workQueue = append(workQueue, e.Entries[i].Value)
				}
				e.Entries[i] = ObjectEntry{}
			}
			e.Entries = e.Entries[:0]

		case *VariantPath:
			if e.Root != nil {
				workQueue = append(workQueue, e.Root)
			}
			e.Root = nil
			for i := range e.Segments {
				if e.Segments[i].Index != nil {
					workQueue = append(workQueue, e.Segments[i].Index)
				}
				e.Segments[i].Index = nil
			}

		// Default case - expression type not pooled, just ignore
		// Unpooled primary-expression nodes: release their children only.
		case *KeywordArgument:
			if e.Value != nil {
				workQueue = append(workQueue, e.Value)
			}
		case *MatchAgainstExpression:
			for _, c := range e.Columns {
				if c != nil {
					workQueue = append(workQueue, c)
				}
			}
			if e.Query != nil {
				workQueue = append(workQueue, e.Query)
			}
		case *OuterJoinMarker:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
		case *ConnectByRootExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
		case *AssignmentExpression:
			if e.Target != nil {
				workQueue = append(workQueue, e.Target)
			}
			if e.Value != nil {
				workQueue = append(workQueue, e.Value)
			}

		default:
			// Unknown expression type - no pool available
		}

		if len(workQueue) > hw {
			hw = len(workQueue)
		}
	}

	// OVERFLOW DRAIN: if we hit the work-queue cap, there are still pooled
	// nodes in workQueue that would otherwise leak. Fall back to a recursive
	// drain, depth-limited to prevent stack overflow on deeply nested trees.
	// Each recursive call starts its own fresh work queue of up to
	// MaxWorkQueueSize, so the recursion depth is effectively
	// ceil(total_nodes / MaxWorkQueueSize). MaxCleanupDepth = 100 bounds this
	// at ~10_000_000 total nodes in an AST — far beyond any real SQL query.
	if len(workQueue) > 0 {
		atomic.AddUint64(&poolLeakCount, uint64(len(workQueue)))
		if depth < maxDepth {
			for _, remaining := range workQueue {
				putExpressionBounded(remaining, depth+1, mode, maxWork, maxDepth)
			}
		}
		// If depth exceeded MaxCleanupDepth we accept the leak rather than
		// blow the stack; poolLeakCount records the truncation for diagnostics.
	}
}

// appendOrderByExprs pushes every non-nil Expression reachable from obs
// (each ORDER BY expression and its WITH FILL bounds) onto q.
func appendOrderByExprs(q []Expression, obs []OrderByExpression) []Expression {
	for i := range obs {
		if obs[i].Expression != nil {
			q = append(q, obs[i].Expression)
		}
		if wf := obs[i].WithFill; wf != nil {
			if wf.From != nil {
				q = append(q, wf.From)
			}
			if wf.To != nil {
				q = append(q, wf.To)
			}
			if wf.Step != nil {
				q = append(q, wf.Step)
			}
		}
	}
	return q
}

// appendWindowSpecExprs pushes every non-nil Expression reachable from w
// (PARTITION BY, ORDER BY and frame bound values) onto q. w may be nil.
func appendWindowSpecExprs(q []Expression, w *WindowSpec) []Expression {
	if w == nil {
		return q
	}
	for _, x := range w.PartitionBy {
		if x != nil {
			q = append(q, x)
		}
	}
	q = appendOrderByExprs(q, w.OrderBy)
	if fc := w.FrameClause; fc != nil {
		if fc.Start.Value != nil {
			q = append(q, fc.Start.Value)
		}
		if fc.End != nil && fc.End.Value != nil {
			q = append(q, fc.End.Value)
		}
	}
	return q
}

// GetFunctionCall gets a FunctionCall from the pool
func GetFunctionCall() *FunctionCall {
	fc := functionCallPool.Get().(*FunctionCall)
	fc.Parameters = fc.Parameters[:0]
	fc.Arguments = fc.Arguments[:0]
	return fc
}

// PutFunctionCall returns a FunctionCall to the pool
func PutFunctionCall(fc *FunctionCall) {
	if fc == nil {
		return
	}
	PutExpression(fc)
}

// GetCaseExpression gets a CaseExpression from the pool
func GetCaseExpression() *CaseExpression {
	ce := caseExprPool.Get().(*CaseExpression)
	ce.WhenClauses = ce.WhenClauses[:0]
	return ce
}

// PutCaseExpression returns a CaseExpression to the pool
func PutCaseExpression(ce *CaseExpression) {
	if ce == nil {
		return
	}
	PutExpression(ce)
}

// GetBetweenExpression gets a BetweenExpression from the pool
func GetBetweenExpression() *BetweenExpression {
	return betweenExprPool.Get().(*BetweenExpression)
}

// PutBetweenExpression returns a BetweenExpression to the pool
func PutBetweenExpression(be *BetweenExpression) {
	if be == nil {
		return
	}
	PutExpression(be)
}

// GetInExpression gets an InExpression from the pool
func GetInExpression() *InExpression {
	ie := inExprPool.Get().(*InExpression)
	ie.List = ie.List[:0]
	return ie
}

// PutInExpression returns an InExpression to the pool
func PutInExpression(ie *InExpression) {
	if ie == nil {
		return
	}
	PutExpression(ie)
}

// GetTupleExpression gets a TupleExpression from the pool
func GetTupleExpression() *TupleExpression {
	te := tupleExprPool.Get().(*TupleExpression)
	te.Expressions = te.Expressions[:0]
	return te
}

// PutTupleExpression returns a TupleExpression to the pool
func PutTupleExpression(te *TupleExpression) {
	if te == nil {
		return
	}
	PutExpression(te)
}

// GetArrayConstructor gets an ArrayConstructorExpression from the pool
func GetArrayConstructor() *ArrayConstructorExpression {
	ac := arrayConstructorPool.Get().(*ArrayConstructorExpression)
	ac.Elements = ac.Elements[:0]
	ac.Subquery = nil
	return ac
}

// PutArrayConstructor returns an ArrayConstructorExpression to the pool
func PutArrayConstructor(ac *ArrayConstructorExpression) {
	if ac == nil {
		return
	}
	PutExpression(ac)
}

// GetSubqueryExpression gets a SubqueryExpression from the pool
func GetSubqueryExpression() *SubqueryExpression {
	return subqueryExprPool.Get().(*SubqueryExpression)
}

// PutSubqueryExpression returns a SubqueryExpression to the pool
func PutSubqueryExpression(se *SubqueryExpression) {
	if se == nil {
		return
	}
	PutExpression(se)
}

// GetCastExpression gets a CastExpression from the pool
func GetCastExpression() *CastExpression {
	return castExprPool.Get().(*CastExpression)
}

// PutCastExpression returns a CastExpression to the pool
func PutCastExpression(ce *CastExpression) {
	if ce == nil {
		return
	}
	PutExpression(ce)
}

// GetIntervalExpression gets an IntervalExpression from the pool
func GetIntervalExpression() *IntervalExpression {
	return intervalExprPool.Get().(*IntervalExpression)
}

// PutIntervalExpression returns an IntervalExpression to the pool
func PutIntervalExpression(ie *IntervalExpression) {
	if ie == nil {
		return
	}
	PutExpression(ie)
}

// GetAliasedExpression retrieves an AliasedExpression from the pool
func GetAliasedExpression() *AliasedExpression {
	return aliasedExprPool.Get().(*AliasedExpression)
}

// PutAliasedExpression returns an AliasedExpression to the pool
func PutAliasedExpression(ae *AliasedExpression) {
	if ae == nil {
		return
	}
	PutExpression(ae)
}

// GetArraySubscriptExpression gets an ArraySubscriptExpression from the pool
func GetArraySubscriptExpression() *ArraySubscriptExpression {
	return arraySubscriptExprPool.Get().(*ArraySubscriptExpression)
}

// PutArraySubscriptExpression returns an ArraySubscriptExpression to the pool
func PutArraySubscriptExpression(ase *ArraySubscriptExpression) {
	if ase == nil {
		return
	}
	PutExpression(ase)
}

// GetArraySliceExpression gets an ArraySliceExpression from the pool
func GetArraySliceExpression() *ArraySliceExpression {
	return arraySliceExprPool.Get().(*ArraySliceExpression)
}

// PutArraySliceExpression returns an ArraySliceExpression to the pool
func PutArraySliceExpression(ase *ArraySliceExpression) {
	if ase == nil {
		return
	}
	PutExpression(ase)
}
