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

import "bytes"

// QueryTail is the ORDER BY / LIMIT / OFFSET / FETCH written after a whole set
// operation whose last operand is parenthesized and has clauses of its own:
//
//	SELECT a FROM t UNION ALL (SELECT b FROM u ORDER BY b LIMIT 1) ORDER BY 1
//
// Here the trailing ORDER BY orders the union while the parenthesized operand
// keeps its own ORDER BY and LIMIT, so they cannot be merged into one
// SelectStatement as the parser does for A UNION B ORDER BY x (where the
// clause is stored on the last SELECT).
type QueryTail struct {
	OrderBy    []OrderByExpression
	Limit      *int
	LimitExpr  Expression
	LimitAll   bool
	Offset     *int
	OffsetExpr Expression
	OffsetRows bool
	Fetch      *FetchClause
}

// Select returns a SelectStatement that holds only the clauses of t, so the
// SELECT renderers can write them. The statement shares t's slices and nodes.
func (t *QueryTail) Select() *SelectStatement {
	if t == nil {
		return nil
	}
	s := &SelectStatement{OrderBy: t.OrderBy, Limit: t.Limit, Offset: t.Offset, Fetch: t.Fetch}
	if t.LimitExpr != nil || t.LimitAll || t.OffsetExpr != nil || t.OffsetRows {
		s.Extras = &SelectExtras{LimitExpr: t.LimitExpr, LimitAll: t.LimitAll, OffsetExpr: t.OffsetExpr, OffsetRows: t.OffsetRows}
	}
	return s
}

// QueryTailFrom returns the tail clauses of s as a QueryTail and removes them
// from s: the parser reads them into a scratch SelectStatement first.
func QueryTailFrom(s *SelectStatement) *QueryTail {
	return &QueryTail{
		OrderBy:    s.OrderBy,
		Limit:      s.Limit,
		LimitExpr:  s.DialectExtras().LimitExpr,
		LimitAll:   s.DialectExtras().LimitAll,
		Offset:     s.Offset,
		OffsetExpr: s.DialectExtras().OffsetExpr,
		OffsetRows: s.DialectExtras().OffsetRows,
		Fetch:      s.Fetch,
	}
}

// TokenLiteral returns the first clause keyword of the tail.
func (t *QueryTail) TokenLiteral() string { return "ORDER BY" }

// Children returns the ORDER BY items and the LIMIT, OFFSET and FETCH
// expressions as pointers into the tail itself.
func (t *QueryTail) Children() []Node {
	if t == nil {
		return nil
	}
	nodes := make([]Node, 0, len(t.OrderBy)+3)
	for i := range t.OrderBy {
		nodes = append(nodes, &t.OrderBy[i])
	}
	if t.LimitExpr != nil {
		nodes = append(nodes, t.LimitExpr)
	}
	if t.OffsetExpr != nil {
		nodes = append(nodes, t.OffsetExpr)
	}
	if t.Fetch != nil {
		nodes = append(nodes, t.Fetch)
	}
	return nodes
}

// writeQueryTail writes " ORDER BY ... LIMIT ... OFFSET ... FETCH ...".
func writeQueryTail(buf *bytes.Buffer, t *QueryTail) {
	if t == nil {
		return
	}
	if len(t.OrderBy) > 0 {
		buf.WriteString(" ORDER BY ")
		writeOrderBy(buf, t.OrderBy)
	}
	writeLimitOffset(buf, t.Select())
	if t.Fetch != nil {
		writeFetch(buf, t.Fetch)
	}
}

// release returns the pooled expressions of t.
func (t *QueryTail) release(mode releaseMode) {
	if t == nil {
		return
	}
	for i := range t.OrderBy {
		releaseExpression(t.OrderBy[i].Expression, mode)
	}
	releaseExpression(t.LimitExpr, mode)
	releaseExpression(t.OffsetExpr, mode)
}
