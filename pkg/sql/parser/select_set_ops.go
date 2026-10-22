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

// Package parser - select_set_ops.go
// Set operation parsing: UNION, INTERSECT, EXCEPT.

package parser

import (
	"fmt"
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseSelectWithSetOperations parses SELECT statements that may have set operations.
// It supports UNION, UNION ALL, EXCEPT, and INTERSECT operations with proper left-associative parsing.
//
// Examples:
//
//	SELECT name FROM users UNION SELECT name FROM customers
//	SELECT id FROM orders UNION ALL SELECT id FROM invoices
//	SELECT product FROM inventory EXCEPT SELECT product FROM discontinued
//	SELECT a FROM t1 UNION SELECT b FROM t2 INTERSECT SELECT c FROM t3
func (p *Parser) parseSelectWithSetOperations() (ast.Statement, error) {
	// Parse the first SELECT statement
	leftStmt, err := p.parseSelectStatement()
	if err != nil {
		return nil, err
	}
	return p.parseSetOperationChain(leftStmt, false)
}

// parseSetOperationChain parses zero or more set operations following the
// already-parsed left operand. leftParens reports that left was written as
// "(query)". A right operand may be a SELECT or a parenthesized query
// expression, e.g. SELECT 1 UNION (SELECT 2).
//
// Operators of equal precedence group left to right. INTERSECT binds tighter
// than UNION and EXCEPT/MINUS (SQL standard), so A UNION B INTERSECT C is
// A UNION (B INTERSECT C); SQLite and Oracle give all set operators equal
// precedence and group the whole chain left to right.
//
// When the last operand was parenthesized, a following ORDER BY / LIMIT /
// OFFSET / FETCH is attached by attachParenthesizedQueryTail.
func (p *Parser) parseSetOperationChain(left ast.Statement, leftParens bool) (ast.Statement, error) {
	stmt, lastParen, err := p.parseSetOperationsFrom(left, leftParens, 1)
	if err != nil {
		return nil, err
	}
	if lastParen && p.isQueryTailStart() {
		if err := p.attachParenthesizedQueryTail(stmt); err != nil {
			return nil, err
		}
	}
	return stmt, nil
}

// setOperatorPrecedence returns the precedence of the set operator at the
// current token (2 for INTERSECT, 1 for UNION / EXCEPT / MINUS), or 0 when
// the current token is not a set operator.
func (p *Parser) setOperatorPrecedence() int {
	switch {
	case p.isType(models.TokenTypeIntersect):
		if ast.SetOperatorsEqualPrecedence(p.dialect) {
			return 1
		}
		return 2
	case p.isAnyType(models.TokenTypeUnion, models.TokenTypeExcept), p.isMinusSetOp():
		return 1
	}
	return 0
}

// parseSetOperationsFrom folds the set operations of precedence minPrec or
// higher onto left by precedence climbing. It returns the resulting tree and
// whether its last operand was written in parentheses. The recursion depth
// is bounded by the number of precedence levels.
func (p *Parser) parseSetOperationsFrom(left ast.Statement, leftParens bool, minPrec int) (ast.Statement, bool, error) {
	lastParen := leftParens
	for {
		prec := p.setOperatorPrecedence()
		if prec == 0 || prec < minPrec {
			return left, lastParen, nil
		}
		setOp := &ast.SetOperation{
			Operator:          p.currentToken.Token.Value,
			LeftParenthesized: leftParens,
		}
		if p.isMinusSetOp() {
			setOp.Operator = "EXCEPT" // canonical name; the spelling is kept in Minus
			setOp.Minus = true
		}
		p.advance()

		// Optional ALL / DISTINCT quantifier
		if p.isType(models.TokenTypeAll) {
			setOp.All = true
			p.advance()
		} else if p.isType(models.TokenTypeDistinct) {
			setOp.Distinct = true
			p.advance()
		}

		right, rightParens, err := p.parseSetOperand(setOp.Operator)
		if err != nil {
			return nil, false, err
		}
		lastParen = rightParens
		// Operators that bind tighter than this one take the right operand
		// as their left: A UNION B INTERSECT C.
		for next := p.setOperatorPrecedence(); next > prec; next = p.setOperatorPrecedence() {
			right, lastParen, err = p.parseSetOperationsFrom(right, rightParens, next)
			if err != nil {
				return nil, false, err
			}
			rightParens = false
		}
		setOp.Left = left
		setOp.Right = right
		setOp.RightParenthesized = rightParens
		left = setOp // The result becomes the left side for any subsequent operations
		leftParens = false
	}
}

// parseSetOperand parses the right operand of a set operation: a SELECT or a
// parenthesized query expression. It reports whether the operand was
// parenthesized.
func (p *Parser) parseSetOperand(operationLiteral string) (ast.Statement, bool, error) {
	if p.isType(models.TokenTypeLParen) {
		// Parenthesized right operand: SELECT 1 UNION (SELECT 2)
		stmt, err := p.parseParenthesizedQuery("SELECT after set operation")
		if err != nil {
			return nil, false, goerrors.InvalidSetOperationError(
				operationLiteral,
				fmt.Sprintf("error parsing right SELECT: %v", err),
				p.currentLocation(),
				"",
			)
		}
		return stmt, true, nil
	}
	if p.isType(models.TokenTypeValues) {
		// VALUES table constructor operand: SELECT 1 UNION VALUES (2)
		v, err := p.parseValuesQuery()
		if err != nil {
			return nil, false, err
		}
		return v, false, nil
	}
	// Parse the right-hand SELECT statement
	if !p.isType(models.TokenTypeSelect) {
		return nil, false, p.expectedError("SELECT after set operation")
	}
	p.advance() // Consume SELECT

	stmt, err := p.parseSelectStatement()
	if err != nil {
		return nil, false, goerrors.InvalidSetOperationError(
			operationLiteral,
			fmt.Sprintf("error parsing right SELECT: %v", err),
			p.currentLocation(),
			"",
		)
	}
	return stmt, false, nil
}

// parseQueryExpression parses a query expression starting at SELECT, WITH or
// "(": a SELECT with optional set operations, a WITH query, or a
// parenthesized query expression followed by optional set operations.
// ctx names what was expected, for the error on any other token.
func (p *Parser) parseQueryExpression(ctx string) (ast.Statement, error) {
	switch p.currentToken.Token.Type {
	case models.TokenTypeWith:
		stmt, err := p.parseWithStatement()
		if err != nil {
			return nil, err
		}
		if _, ok := stmt.(*ast.SelectStatement); ok {
			return stmt, nil
		}
		if _, ok := stmt.(*ast.SetOperation); ok {
			return stmt, nil
		}
		return nil, p.expectedError("SELECT statement in derived table")
	case models.TokenTypeSelect:
		p.advance() // Consume SELECT
		return p.parseSelectWithSetOperations()
	case models.TokenTypeLParen:
		q, err := p.parseParenthesizedQuery(ctx)
		if err != nil {
			return nil, err
		}
		return p.parseSetOperationChain(q, true)
	case models.TokenTypeValues:
		v, err := p.parseValuesQuery()
		if err != nil {
			return nil, err
		}
		return p.parseSetOperationChain(v, false)
	}
	return nil, p.expectedError(ctx)
}

// isDerivedTableQueryStart reports whether the current token (after the
// "(" of a derived table) starts its query: SELECT, WITH, VALUES or a
// nested "(".
func (p *Parser) isDerivedTableQueryStart() bool {
	return p.isAnyType(models.TokenTypeSelect, models.TokenTypeWith, models.TokenTypeLParen, models.TokenTypeValues)
}

// parseParenthesizedQuery parses "( query_expression )" with the current
// token at "(". Each level counts against MaxRecursionDepth.
func (p *Parser) parseParenthesizedQuery(ctx string) (ast.Statement, error) {
	err := p.enterRecursion()
	defer p.leaveRecursion()
	if err != nil {
		return nil, err
	}

	p.advance() // Consume (
	if !p.isDerivedTableQueryStart() {
		return nil, p.expectedError(ctx)
	}
	q, err := p.parseQueryExpression(ctx)
	if err != nil {
		return nil, err
	}
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )
	return q, nil
}

// isQueryTailStart reports whether the current token starts a query-level
// ORDER BY / LIMIT / OFFSET / FETCH clause.
func (p *Parser) isQueryTailStart() bool {
	return p.isAnyType(models.TokenTypeOrder, models.TokenTypeLimit, models.TokenTypeOffset, models.TokenTypeFetch)
}

// attachParenthesizedQueryTail parses an ORDER BY / LIMIT / OFFSET / FETCH
// written after a parenthesized query, as in "(SELECT 1) ORDER BY 1" or
// "SELECT a FROM t UNION (SELECT a FROM u) ORDER BY a".
//
// The AST has no query-level node for these clauses. For a set operation the
// parser already stores a trailing ORDER BY / LIMIT on its last SELECT
// operand (A UNION B ORDER BY x), so the clauses are merged into that operand
// and its parentheses dropped, which gives the same tree as the unparenthesized
// form. That is only meaning-preserving when the operand is a plain SELECT
// without its own ORDER BY / LIMIT / OFFSET / FETCH / FOR clause (and, for a
// right operand, without WITH); anything else returns E4001.
func (p *Parser) attachParenthesizedQueryTail(stmt ast.Statement) error {
	var target *ast.SelectStatement
	var owner *ast.SetOperation
	switch s := stmt.(type) {
	case *ast.SelectStatement:
		target = s
	case *ast.SetOperation:
		// The last operand can sit in a right-nested operation that bound
		// tighter, as in A UNION B INTERSECT (C) ORDER BY x.
		owner = lastSetOperation(s)
		if right, ok := owner.Right.(*ast.SelectStatement); ok && right.With == nil {
			target = right
		}
	}
	if target == nil || target.OrderBy != nil || target.HasLimit() ||
		target.HasOffset() || (target.Extras != nil && target.Extras.LimitBy != nil) || target.Fetch != nil || target.For != nil {
		// The clauses cannot move into the last operand without changing
		// which rows they apply to. A set operation keeps them as the tail of
		// the whole operation; a single parenthesized query has no node for
		// them.
		// That only holds when the last operand is set apart by parentheses;
		// an unparenthesized last SELECT with LIMIT already carries a clause
		// that applies to the whole operation, and a second one would be
		// written in an order that changes the result.
		if op, ok := stmt.(*ast.SetOperation); ok && op.Tail == nil && owner != nil {
			if _, isSelect := owner.Right.(*ast.SelectStatement); owner.RightParenthesized || !isSelect {
				return p.parseQueryTail(op)
			}
		}
		return goerrors.UnsupportedFeatureError(
			"ORDER BY/LIMIT/OFFSET/FETCH after a parenthesized query that has its own ORDER BY/LIMIT/OFFSET/FETCH",
			p.currentLocation(),
			"",
		)
	}
	if owner != nil {
		owner.RightParenthesized = false
	}

	var err error
	if target.OrderBy, err = p.parseOrderByClause(); err != nil {
		return err
	}
	if err = p.parseLimitOffsetInto(target); err != nil {
		return err
	}
	if p.isType(models.TokenTypeFetch) {
		if target.Fetch, err = p.parseFetchClause(); err != nil {
			return err
		}
	}
	return nil
}

// parseQueryTail parses an ORDER BY / LIMIT / OFFSET / FETCH into the Tail of
// the set operation op, whose last operand keeps its parentheses.
func (p *Parser) parseQueryTail(op *ast.SetOperation) error {
	tmp := &ast.SelectStatement{}
	var err error
	if tmp.OrderBy, err = p.parseOrderByClause(); err != nil {
		return err
	}
	if err = p.parseLimitOffsetInto(tmp); err != nil {
		return err
	}
	if p.isType(models.TokenTypeFetch) {
		if tmp.Fetch, err = p.parseFetchClause(); err != nil {
			return err
		}
	}
	op.Tail = ast.QueryTailFrom(tmp)
	return nil
}

// lastSetOperation returns the set operation that holds the last operand of
// s: s itself, or the innermost unparenthesized set operation on its right
// spine.
func lastSetOperation(s *ast.SetOperation) *ast.SetOperation {
	for !s.RightParenthesized {
		r, ok := s.Right.(*ast.SetOperation)
		if !ok || r == nil {
			break
		}
		s = r
	}
	return s
}

// isMinusSetOp returns true if the current token is the Snowflake / Oracle
// MINUS keyword used as a set operator (synonym for EXCEPT). MINUS tokenizes
// as an identifier; gate by dialect so that MINUS as a legitimate column
// alias in other dialects is not hijacked.
func (p *Parser) isMinusSetOp() bool {
	return p.isMinusSetOpToken(p.currentToken.Token)
}

// isMinusSetOpToken is isMinusSetOp for an arbitrary token, used by
// lookahead that must not move the parser.
func (p *Parser) isMinusSetOpToken(tok models.Token) bool {
	if p.dialect != string(keywords.DialectSnowflake) &&
		p.dialect != string(keywords.DialectOracle) {
		return false
	}
	if tok.Type != models.TokenTypeIdentifier && tok.Type != models.TokenTypeDoubleQuotedString {
		return false
	}
	return strings.EqualFold(tok.Value, "MINUS")
}
