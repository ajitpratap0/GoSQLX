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

import "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"

// Parser-owned scratch stacks for building lists.
//
// List-shaped clauses (the SELECT list, GROUP BY, ORDER BY, function
// arguments) are collected on a reusable stack and copied once into a slice of
// exactly the final length, instead of growing a fresh slice with append.
// Nested lists (a function call inside a select item, a subquery inside an
// argument) push above their parent's region and pop back to their own mark, so
// the stack is strictly LIFO.
//
// Contract for the recursive builders (parseFunctionCall, parseGroupByClause,
// parseOrderByList, parseSelectStatement):
//   - No defer. A defer would grow the frame of every recursive parse call and
//     slow ParseFresh, so cleanup is explicit.
//   - Drop to the builder's own mark (exprDrop/orderDrop) before EVERY error
//     return. A caller may swallow the error and carry on; an enclosing region
//     would otherwise copy the stale items into a later list.
//   - Move the list into its node (exprPop/orderPop, or newFunctionCall plus a
//     drop) as soon as it is complete, so no later return has anything to unwind.
//
// Only parseSelectColumnList, which is cold (OUTPUT / RETURNING), still uses a
// deferred drop.
//
// INVARIANT: scratch[len:cap] is always zeroed, so a pooled parser never keeps
// AST nodes (and through them the previous query text) alive. scratchPop and
// scratchDrop clear what they release; Reset clears whatever a panic left.

// maxPooledScratch is the largest scratch capacity (in elements) a pooled
// parser keeps across Reset.
const maxPooledScratch = 1024

// scratchPush appends v to the stack.
func scratchPush[T any](s *[]T, v T) { *s = append(*s, v) }

// scratchPop copies s[base:] into a new slice of exactly that length (nil when
// empty), clears the region and truncates the stack back to base.
func scratchPop[T any](s *[]T, base int) []T {
	n := len(*s) - base
	if n == 0 {
		return nil
	}
	out := make([]T, n)
	copy(out, (*s)[base:])
	clear((*s)[base:])
	*s = (*s)[:base]
	return out
}

// scratchDrop discards s[base:] without copying it.
func scratchDrop[T any](s *[]T, base int) {
	clear((*s)[base:])
	*s = (*s)[:base]
}

// resetScratch empties the stacks, releasing oversized backing arrays. A
// parse that finished normally leaves them empty, so the common case is two
// length checks and two capacity checks.
func (p *Parser) resetScratch() {
	if len(p.exprScratch) != 0 || len(p.orderScratch) != 0 ||
		cap(p.exprScratch) > maxPooledScratch || cap(p.orderScratch) > maxPooledScratch {
		p.exprScratch = resetScratchSlice(p.exprScratch)
		p.orderScratch = resetScratchSlice(p.orderScratch)
	}
}

func resetScratchSlice[T any](s []T) []T {
	if cap(s) > maxPooledScratch {
		return nil
	}
	clear(s)
	return s[:0]
}

func (p *Parser) exprMark() int                     { return len(p.exprScratch) }
func (p *Parser) exprPush(e ast.Expression)         { scratchPush(&p.exprScratch, e) }
func (p *Parser) exprPop(base int) []ast.Expression { return scratchPop(&p.exprScratch, base) }

// exprPushOutOfLine is exprPush for rare call sites, which would otherwise
// each inline an append into a recursive function's frame.
//
//go:noinline
func (p *Parser) exprPushOutOfLine(e ast.Expression) { scratchPush(&p.exprScratch, e) }

// exprDrop and orderDrop are error-path cleanup. They are kept out of line so
// their many call sites do not grow the frames of the recursive parse functions.
//
//go:noinline
func (p *Parser) exprDrop(base int) { scratchDrop(&p.exprScratch, base) }

func (p *Parser) orderMark() int                    { return len(p.orderScratch) }
func (p *Parser) orderPush(o ast.OrderByExpression) { scratchPush(&p.orderScratch, o) }
func (p *Parser) orderPop(base int) []ast.OrderByExpression {
	return scratchPop(&p.orderScratch, base)
}

//go:noinline
func (p *Parser) orderDrop(base int) { scratchDrop(&p.orderScratch, base) }
