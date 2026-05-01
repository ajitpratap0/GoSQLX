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
	ident.Name = ""
	identifierPool.Put(ident)
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
	PutExpression(expr.Left)
	PutExpression(expr.Right)
	expr.Left = nil
	expr.Right = nil
	expr.Operator = ""
	binaryExprPool.Put(expr)
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

	// Reset fields (Value is interface{}, use nil as zero value)
	lit.Value = nil
	lit.Type = ""

	// Return to pool
	literalValuePool.Put(lit)
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
//   - Work queue size limits (MaxWorkQueueSize = 1000)
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
// See also: GetBinaryExpression(), GetFunctionCall(), GetIdentifier()
func PutExpression(expr Expression) {
	if expr == nil {
		return
	}
	putExpressionImpl(expr, 0)
}

// putExpressionImpl is the internal driver for PutExpression. The depth
// parameter tracks recursive re-entries from the work-queue overflow path
// to prevent stack overflow on pathologically deep ASTs.
//
// The iterative work queue is drawn from putExpressionWorkQueuePool so that
// hot-path PutExpression calls (10-100× per parse) do not repeatedly allocate
// a fresh 32-cap []Expression. The slice is reset to zero-length and its
// element slots nil'd before being returned to the pool (preventing the
// pool from pinning Expression pointers we've already returned to their
// own pools).
func putExpressionImpl(expr Expression, depth int) {
	if expr == nil {
		return
	}

	// Acquire a pooled work queue. We must write the (possibly grown)
	// slice header back to the pointer before Put so that subsequent
	// Get calls see the grown capacity.
	qp := putExpressionWorkQueuePool.Get().(*[]Expression)
	workQueue := (*qp)[:0]
	defer func() {
		// Nil out slice elements up to the underlying capacity we used so
		// the pool cannot pin arbitrarily-aged Expression pointers. Using
		// the full capacity is safe because we only wrote through
		// append — anything beyond len was never assigned here, but prior
		// use of this pooled slice may have written to those slots. Clear
		// them all by reslicing to capacity and zeroing.
		cleared := workQueue[:cap(workQueue)]
		for i := range cleared {
			cleared[i] = nil
		}
		*qp = workQueue[:0]
		putExpressionWorkQueuePool.Put(qp)
	}()
	workQueue = append(workQueue, expr)

	processed := 0
	for len(workQueue) > 0 && processed < MaxWorkQueueSize {
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
			e.Name = ""
			identifierPool.Put(e)

		case *BinaryExpression:
			if e.Left != nil {
				workQueue = append(workQueue, e.Left)
			}
			if e.Right != nil {
				workQueue = append(workQueue, e.Right)
			}
			e.Left = nil
			e.Right = nil
			e.Operator = ""
			binaryExprPool.Put(e)

		case *LiteralValue:
			e.Value = nil
			e.Type = ""
			literalValuePool.Put(e)

		case *FunctionCall:
			for i := range e.Arguments {
				if e.Arguments[i] != nil {
					workQueue = append(workQueue, e.Arguments[i])
				}
				e.Arguments[i] = nil
			}
			e.Arguments = e.Arguments[:0]
			e.Name = ""
			e.Over = nil
			e.Distinct = false
			e.Filter = nil
			functionCallPool.Put(e)

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
			e.Value = nil
			e.WhenClauses = e.WhenClauses[:0]
			e.ElseClause = nil
			caseExprPool.Put(e)

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
			e.Expr = nil
			e.Lower = nil
			e.Upper = nil
			e.Not = false
			betweenExprPool.Put(e)

		case *InExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			for i := range e.List {
				if e.List[i] != nil {
					workQueue = append(workQueue, e.List[i])
				}
				e.List[i] = nil
			}
			e.Expr = nil
			e.List = e.List[:0]
			// Subquery is a Statement (typically *SelectStatement); release
			// it through the statement dispatcher so every nested pooled
			// node is returned. Silently setting to nil was a leak.
			if e.Subquery != nil {
				releaseStatement(e.Subquery)
				e.Subquery = nil
			}
			e.Not = false
			inExprPool.Put(e)

		case *SubqueryExpression:
			if e.Subquery != nil {
				releaseStatement(e.Subquery)
				e.Subquery = nil
			}
			subqueryExprPool.Put(e)

		case *CastExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			e.Expr = nil
			e.Type = ""
			castExprPool.Put(e)

		case *IntervalExpression:
			e.Value = ""
			intervalExprPool.Put(e)

		case *ArraySubscriptExpression:
			if e.Array != nil {
				workQueue = append(workQueue, e.Array)
			}
			for i := range e.Indices {
				if e.Indices[i] != nil {
					workQueue = append(workQueue, e.Indices[i])
				}
			}
			e.Array = nil
			e.Indices = e.Indices[:0]
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
			e.Array = nil
			e.Start = nil
			e.End = nil
			arraySliceExprPool.Put(e)

		case *ExistsExpression:
			if e.Subquery != nil {
				releaseStatement(e.Subquery)
				e.Subquery = nil
			}
			existsExprPool.Put(e)

		case *AnyExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			e.Expr = nil
			if e.Subquery != nil {
				releaseStatement(e.Subquery)
				e.Subquery = nil
			}
			e.Operator = ""
			anyExprPool.Put(e)

		case *AllExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			e.Expr = nil
			if e.Subquery != nil {
				releaseStatement(e.Subquery)
				e.Subquery = nil
			}
			e.Operator = ""
			allExprPool.Put(e)

		case *ListExpression:
			for i := range e.Values {
				if e.Values[i] != nil {
					workQueue = append(workQueue, e.Values[i])
				}
				e.Values[i] = nil
			}
			e.Values = e.Values[:0]
			listExprPool.Put(e)

		case *TupleExpression:
			for i := range e.Expressions {
				if e.Expressions[i] != nil {
					workQueue = append(workQueue, e.Expressions[i])
				}
				e.Expressions[i] = nil
			}
			e.Expressions = e.Expressions[:0]
			tupleExprPool.Put(e)

		case *ArrayConstructorExpression:
			for i := range e.Elements {
				if e.Elements[i] != nil {
					workQueue = append(workQueue, e.Elements[i])
				}
				e.Elements[i] = nil
			}
			e.Elements = e.Elements[:0]
			// Subquery is a Statement (typically *SelectStatement); route
			// through the statement dispatcher to keep dispatch consistent
			// with InExpression / SubqueryExpression / Exists / Any / All
			// and to handle non-SELECT statement types correctly.
			if e.Subquery != nil {
				releaseStatement(e.Subquery)
				e.Subquery = nil
			}
			arrayConstructorPool.Put(e)

		case *UnaryExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			e.Expr = nil
			e.Operator = 0 // UnaryOperator is int type
			unaryExprPool.Put(e)

		case *ExtractExpression:
			if e.Source != nil {
				workQueue = append(workQueue, e.Source)
			}
			e.Field = ""
			e.Source = nil
			extractExprPool.Put(e)

		case *PositionExpression:
			if e.Substr != nil {
				workQueue = append(workQueue, e.Substr)
			}
			if e.Str != nil {
				workQueue = append(workQueue, e.Str)
			}
			e.Substr = nil
			e.Str = nil
			positionExprPool.Put(e)

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
			e.Str = nil
			e.Start = nil
			e.Length = nil
			substringExprPool.Put(e)

		case *AliasedExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			e.Expr = nil
			e.Alias = ""
			aliasedExprPool.Put(e)

		// Default case - expression type not pooled, just ignore
		default:
			// Unknown expression type - no pool available
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
		if depth < MaxCleanupDepth {
			for _, remaining := range workQueue {
				putExpressionImpl(remaining, depth+1)
			}
		}
		// If depth exceeded MaxCleanupDepth we accept the leak rather than
		// blow the stack; poolLeakCount records the truncation for diagnostics.
	}
}

// GetFunctionCall gets a FunctionCall from the pool
func GetFunctionCall() *FunctionCall {
	fc := functionCallPool.Get().(*FunctionCall)
	fc.Arguments = fc.Arguments[:0]
	return fc
}

// PutFunctionCall returns a FunctionCall to the pool
func PutFunctionCall(fc *FunctionCall) {
	if fc == nil {
		return
	}
	for i := range fc.Arguments {
		PutExpression(fc.Arguments[i])
		fc.Arguments[i] = nil
	}
	fc.Arguments = fc.Arguments[:0]
	fc.Name = ""
	fc.Over = nil
	fc.Distinct = false
	fc.Filter = nil
	functionCallPool.Put(fc)
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
	PutExpression(ce.Value)
	ce.Value = nil
	for i := range ce.WhenClauses {
		PutExpression(ce.WhenClauses[i].Condition)
		PutExpression(ce.WhenClauses[i].Result)
	}
	ce.WhenClauses = ce.WhenClauses[:0]
	PutExpression(ce.ElseClause)
	ce.ElseClause = nil
	caseExprPool.Put(ce)
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
	PutExpression(be.Expr)
	PutExpression(be.Lower)
	PutExpression(be.Upper)
	be.Expr = nil
	be.Lower = nil
	be.Upper = nil
	be.Not = false
	betweenExprPool.Put(be)
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
	PutExpression(ie.Expr)
	ie.Expr = nil
	for i := range ie.List {
		PutExpression(ie.List[i])
		ie.List[i] = nil
	}
	ie.List = ie.List[:0]
	// Subquery (IN (SELECT ...)) is a Statement — release through the
	// statement dispatcher, not a bare nil-assign.
	if ie.Subquery != nil {
		releaseStatement(ie.Subquery)
		ie.Subquery = nil
	}
	ie.Not = false
	inExprPool.Put(ie)
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
	for i := range te.Expressions {
		PutExpression(te.Expressions[i])
		te.Expressions[i] = nil
	}
	te.Expressions = te.Expressions[:0]
	tupleExprPool.Put(te)
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
	for i := range ac.Elements {
		PutExpression(ac.Elements[i])
		ac.Elements[i] = nil
	}
	ac.Elements = ac.Elements[:0]
	// Subquery is a Statement; route through releaseStatement so non-SELECT
	// statement types (sequence ops etc.) dispatch correctly.
	if ac.Subquery != nil {
		releaseStatement(ac.Subquery)
		ac.Subquery = nil
	}
	arrayConstructorPool.Put(ac)
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
	// Subquery is a Statement — release it through the statement dispatcher.
	if se.Subquery != nil {
		releaseStatement(se.Subquery)
		se.Subquery = nil
	}
	subqueryExprPool.Put(se)
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
	PutExpression(ce.Expr)
	ce.Expr = nil
	ce.Type = ""
	castExprPool.Put(ce)
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
	ie.Value = ""
	intervalExprPool.Put(ie)
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
	PutExpression(ae.Expr)
	ae.Expr = nil
	ae.Alias = ""
	aliasedExprPool.Put(ae)
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
	// Clean up array expression
	if ase.Array != nil {
		PutExpression(ase.Array)
		ase.Array = nil
	}
	// Clean up indices
	for i := range ase.Indices {
		if ase.Indices[i] != nil {
			PutExpression(ase.Indices[i])
		}
	}
	ase.Indices = ase.Indices[:0] // Clear slice but keep capacity
	arraySubscriptExprPool.Put(ase)
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
	// Clean up array expression
	if ase.Array != nil {
		PutExpression(ase.Array)
		ase.Array = nil
	}
	// Clean up start/end expressions
	if ase.Start != nil {
		PutExpression(ase.Start)
		ase.Start = nil
	}
	if ase.End != nil {
		PutExpression(ase.End)
		ase.End = nil
	}
	arraySliceExprPool.Put(ase)
}
