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
// already-parsed left operand and builds a left-deep tree. leftParens reports
// that left was written as "(query)". A right operand may be a SELECT or a
// parenthesized query expression, e.g. SELECT 1 UNION (SELECT 2).
//
// When the last operand was parenthesized, a following ORDER BY / LIMIT /
// OFFSET / FETCH is attached by attachParenthesizedQueryTail.
func (p *Parser) parseSetOperationChain(left ast.Statement, leftParens bool) (ast.Statement, error) {
	leftStmt := left
	lastParen := leftParens

	// Check for set operations (UNION, EXCEPT, INTERSECT). MINUS is a
	// Snowflake / Oracle synonym for EXCEPT; it tokenizes as a plain
	// identifier, so match it by value.
	for p.isAnyType(models.TokenTypeUnion, models.TokenTypeExcept, models.TokenTypeIntersect) ||
		p.isMinusSetOp() {
		// Parse the set operation type
		operationLiteral := p.currentToken.Token.Value
		if p.isMinusSetOp() {
			operationLiteral = "EXCEPT" // normalize to canonical name
		}
		p.advance()

		// Check for ALL keyword
		all := false
		if p.isType(models.TokenTypeAll) {
			all = true
			p.advance()
		}

		var rightStmt ast.Statement
		rightParens := false
		if p.isType(models.TokenTypeLParen) {
			// Parenthesized right operand: SELECT 1 UNION (SELECT 2)
			stmt, err := p.parseParenthesizedQuery("SELECT after set operation")
			if err != nil {
				return nil, goerrors.InvalidSetOperationError(
					operationLiteral,
					fmt.Sprintf("error parsing right SELECT: %v", err),
					p.currentLocation(),
					"",
				)
			}
			rightStmt = stmt
			rightParens = true
		} else {
			// Parse the right-hand SELECT statement
			if !p.isType(models.TokenTypeSelect) {
				return nil, p.expectedError("SELECT after set operation")
			}
			p.advance() // Consume SELECT

			stmt, err := p.parseSelectStatement()
			if err != nil {
				return nil, goerrors.InvalidSetOperationError(
					operationLiteral,
					fmt.Sprintf("error parsing right SELECT: %v", err),
					p.currentLocation(),
					"",
				)
			}
			rightStmt = stmt
		}

		// Create the set operation with left as the accumulated result
		setOp := &ast.SetOperation{
			Left:               leftStmt,
			Operator:           operationLiteral,
			All:                all,
			Right:              rightStmt,
			LeftParenthesized:  leftParens,
			RightParenthesized: rightParens,
		}

		leftStmt = setOp // The result becomes the left side for any subsequent operations
		leftParens = false
		lastParen = rightParens
	}

	if lastParen && p.isQueryTailStart() {
		if err := p.attachParenthesizedQueryTail(leftStmt); err != nil {
			return nil, err
		}
	}

	return leftStmt, nil
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
	}
	return nil, p.expectedError(ctx)
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
	if !p.isAnyType(models.TokenTypeSelect, models.TokenTypeWith, models.TokenTypeLParen) {
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
	switch s := stmt.(type) {
	case *ast.SelectStatement:
		target = s
	case *ast.SetOperation:
		if right, ok := s.Right.(*ast.SelectStatement); ok && right.With == nil {
			target = right
		}
	}
	if target == nil || target.OrderBy != nil || target.Limit != nil ||
		target.Offset != nil || target.Fetch != nil || target.For != nil {
		return goerrors.UnsupportedFeatureError(
			"ORDER BY/LIMIT/OFFSET/FETCH after a parenthesized query that has its own ORDER BY/LIMIT/OFFSET/FETCH or is a set operation",
			p.currentLocation(),
			"",
		)
	}
	if s, ok := stmt.(*ast.SetOperation); ok {
		s.RightParenthesized = false
	}

	var err error
	if target.OrderBy, err = p.parseOrderByClause(); err != nil {
		return err
	}
	if target.Limit, target.Offset, err = p.parseLimitOffsetClause(); err != nil {
		return err
	}
	if p.isType(models.TokenTypeFetch) {
		if target.Fetch, err = p.parseFetchClause(); err != nil {
			return err
		}
	}
	return nil
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
