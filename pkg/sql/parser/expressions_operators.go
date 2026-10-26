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

// Package parser - expressions_operators.go
// Comparison, BETWEEN, IN, LIKE, IS NULL operators and array subscript/slice expressions.

package parser

import (
	"fmt"
	"strings"
	"unicode/utf8"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// Kinds of comparison suffix reported by parseComparisonSuffix.
const (
	suffixNone       = iota // no suffix operator follows
	suffixPredicate         // BETWEEN, IN, LIKE and the other predicates, IS ...
	suffixComparison        // =, <>, <, ... and quantified comparisons
)

// parseComparisonExpression parses an expression with comparison operators
// and the predicates (BETWEEN, IN, LIKE, IS, ...). The suffix operators are
// applied left to right, so "a IN (1, 2) = TRUE" and "a BETWEEN 1 AND 2 = TRUE"
// read as a predicate compared to a value. Comparison operators themselves do
// not chain: after "a = b" another comparison operator is left for the
// caller, which rejects it.
func (p *Parser) parseComparisonExpression() (ast.Expression, error) {
	// Parse the left side with bitwise and arithmetic operators binding tighter.
	left, err := p.parseBitwiseExpression(1)
	if err != nil {
		return nil, err
	}

	afterComparison := false
	for {
		// No suffix operator starts at an operand end.
		if p.atOperandEnd() {
			return left, nil
		}
		next, kind, err := p.parseComparisonSuffix(left, afterComparison)
		if err != nil {
			return nil, err
		}
		if kind == suffixNone {
			return left, nil
		}
		left = next
		afterComparison = kind == suffixComparison
	}
}

// notOperatorFollows reports whether the NOT at the current token negates a
// predicate operator that follows it. NOT is consumed only then, which keeps
// cases like "WHERE NOT active AND name LIKE '%'" and "DEFAULT 0 NOT NULL"
// working.
func (p *Parser) notOperatorFollows() bool {
	nv := p.peekAt(1).Token.Value
	switch {
	case equalsUpper(nv, "BETWEEN"), equalsUpper(nv, "LIKE"), equalsUpper(nv, "ILIKE"), equalsUpper(nv, "IN"),
		equalsUpper(nv, "REGEXP"), equalsUpper(nv, "RLIKE"):
		return true
	case equalsUpper(nv, "SIMILAR"):
		return p.peekValueIs(2, "TO")
	case equalsUpper(nv, "GLOB"), equalsUpper(nv, "MATCH"):
		return p.IsSQLite()
	}
	return false
}

// parseComparisonSuffix parses at most one comparison or predicate operator
// following left and returns the combined expression. It returns suffixNone
// (and a nil expression) when no operator follows. afterComparison is set when
// the previous suffix was a comparison operator, which may not be followed by
// another one.
func (p *Parser) parseComparisonSuffix(left ast.Expression, afterComparison bool) (ast.Expression, int, error) {
	// None of the predicate operators below starts with a comparison
	// operator token.
	if comparisonOperatorTypes.has(p.currentToken.Token.Type) {
		return p.parseComparisonOperatorSuffix(left, afterComparison)
	}

	// Check for NOT prefix for BETWEEN, LIKE, IN operators
	notPrefix := false
	if p.isType(models.TokenTypeNot) && p.notOperatorFollows() {
		notPrefix = true
		p.advance() // Consume NOT only if followed by valid operator
	}

	// Check for BETWEEN operator
	if p.isType(models.TokenTypeBetween) {
		betweenPos := p.currentLocation()
		p.advance() // Consume BETWEEN

		// Parse lower bound - use the bitwise level to support complex expressions
		// like: price BETWEEN price * 0.9 AND price * 1.1
		lower, err := p.parseBitwiseExpression(1)
		if err != nil {
			return nil, suffixNone, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse BETWEEN lower bound: %v", err),
				p.currentLocation(),
				"",
			).WithCause(err)
		}

		// Expect AND keyword
		if !p.isType(models.TokenTypeAnd) {
			return nil, suffixNone, p.expectedError("AND")
		}
		p.advance() // Consume AND

		// Parse upper bound
		upper, err := p.parseBitwiseExpression(1)
		if err != nil {
			return nil, suffixNone, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse BETWEEN upper bound: %v", err),
				p.currentLocation(),
				"",
			).WithCause(err)
		}

		return &ast.BetweenExpression{
			Expr:  left,
			Lower: lower,
			Upper: upper,
			Not:   notPrefix,
			Pos:   betweenPos,
		}, suffixPredicate, nil
	}

	// Check for LIKE/ILIKE operator
	if p.isType(models.TokenTypeLike) || strings.EqualFold(p.currentToken.Token.Value, "ILIKE") {
		operator := p.currentToken.Token.Value
		// The tokenizer matches keywords after Unicode upper-casing, so LIKE
		// also arrives as e.g. "lıke" (dotless ı). Store the canonical ASCII
		// keyword for such a spelling so renderers see plain operator text;
		// an ASCII spelling keeps its case.
		if !isASCII(operator) {
			if p.isType(models.TokenTypeLike) {
				operator = "LIKE"
			} else {
				operator = "ILIKE"
			}
		}
		// ILIKE is supported by PostgreSQL, Snowflake, and ClickHouse natively.
		// Reject in other dialects (e.g. MySQL, SQL Server, SQLite, Oracle) where
		// it is not a recognized operator.
		if strings.EqualFold(operator, "ILIKE") && p.dialect != "" {
			switch p.dialect {
			case string(keywords.DialectPostgreSQL),
				string(keywords.DialectSnowflake),
				string(keywords.DialectClickHouse):
				// supported
			default:
				return nil, suffixNone, goerrors.UnsupportedFeatureError(
					fmt.Sprintf("ILIKE is not supported in %s; use LIKE or LOWER() for case-insensitive matching", p.dialect),
					p.currentLocation(),
					"",
				)
			}
		}
		p.advance() // Consume LIKE/ILIKE

		// Snowflake LIKE ANY / LIKE ALL / ILIKE ANY / ILIKE ALL:
		//   expr [NOT] LIKE ANY ('pattern1', 'pattern2', ...)
		//   expr [NOT] ILIKE ALL ('%a%', '%b%')
		// The ANY/ALL quantifier is followed by a parenthesised tuple.
		if p.isType(models.TokenTypeAny) || p.isType(models.TokenTypeAll) {
			quantifier := strings.ToUpper(p.currentToken.Token.Value)
			operator = strings.ToUpper(operator) + " " + quantifier
			p.advance() // Consume ANY/ALL
			// Expect a tuple: (pattern, pattern, ...)
			if !p.isType(models.TokenTypeLParen) {
				return nil, suffixNone, p.expectedError("( after " + quantifier)
			}
			tuple, err := p.parsePrimaryExpression()
			if err != nil {
				return nil, suffixNone, err
			}
			return &ast.BinaryExpression{
				Left:     left,
				Operator: operator,
				Right:    tuple,
				Not:      notPrefix,
			}, suffixPredicate, nil
		}

		// Parse the pattern at the string-concatenation level so arithmetic
		// and || bind tighter than LIKE: a LIKE b || '%' (#596).
		return p.parsePatternMatch(left, operator, notPrefix, true)
	}

	// Check for REGEXP/RLIKE operator (MySQL)
	if strings.EqualFold(p.currentToken.Token.Value, "REGEXP") || strings.EqualFold(p.currentToken.Token.Value, "RLIKE") {
		// Canonical ASCII text even for a Unicode case-folded match (the
		// Kelvin sign K folds to k in RLIKE).
		operator := "REGEXP"
		if strings.EqualFold(p.currentToken.Token.Value, "RLIKE") {
			operator = "RLIKE"
		}
		p.advance()
		return p.parsePatternMatch(left, operator, notPrefix, false)
	}

	// SIMILAR TO (PostgreSQL, Redshift): the TO keyword makes it unambiguous.
	if p.currentToken.Token.Type == models.TokenTypeIdentifier && equalsUpper(p.currentToken.Token.Value, "SIMILAR") && p.peekValueIs(1, "TO") {
		p.advance() // Consume SIMILAR
		p.advance() // Consume TO
		return p.parsePatternMatch(left, "SIMILAR TO", notPrefix, true)
	}

	// SQLite GLOB and MATCH pattern operators.
	if p.currentToken.Token.Type == models.TokenTypeIdentifier && p.IsSQLite() {
		switch {
		case equalsUpper(p.currentToken.Token.Value, "GLOB"):
			p.advance()
			return p.parsePatternMatch(left, "GLOB", notPrefix, false)
		case equalsUpper(p.currentToken.Token.Value, "MATCH"):
			p.advance()
			return p.parsePatternMatch(left, "MATCH", notPrefix, false)
		}
	}

	// MySQL SOUNDS LIKE.
	if p.currentToken.Token.Type == models.TokenTypeIdentifier && p.isMySQLFamily() &&
		equalsUpper(p.currentToken.Token.Value, "SOUNDS") && p.peekTypeAt(1) == models.TokenTypeLike {
		p.advance() // Consume SOUNDS
		p.advance() // Consume LIKE
		return p.parsePatternMatch(left, "SOUNDS LIKE", notPrefix, false)
	}

	// ClickHouse GLOBAL IN / GLOBAL NOT IN — GLOBAL is a distributed query modifier
	// before IN. It is kept on the InExpression.
	global := false
	if p.dialect == string(keywords.DialectClickHouse) && p.isTokenMatch("GLOBAL") &&
		(p.peekTypeAt(1) == models.TokenTypeIn || (p.peekTypeAt(1) == models.TokenTypeNot && p.peekTypeAt(2) == models.TokenTypeIn)) {
		global = true
		p.advance() // consume GLOBAL
		if p.isType(models.TokenTypeNot) {
			notPrefix = true
			p.advance() // consume NOT
		}
	}

	// Check for IN operator
	if p.isType(models.TokenTypeIn) {
		in, err := p.parseInTail(left, notPrefix, global)
		if err != nil {
			return nil, suffixNone, err
		}
		return in, suffixPredicate, nil
	}

	// If NOT was consumed but no BETWEEN/LIKE/IN follows, we need to handle this case
	// Put back the NOT by creating a NOT expression with left as the operand
	if notPrefix {
		return nil, suffixNone, goerrors.ExpectedTokenError(
			"BETWEEN, LIKE, or IN",
			"NOT",
			p.currentLocation(),
			"",
		)
	}

	// Check for IS NULL / IS NOT NULL / IS [NOT] TRUE|FALSE|UNKNOWN / IS [NOT] DISTINCT FROM
	if p.isType(models.TokenTypeIs) {
		isPos := p.currentLocation()
		p.advance() // Consume IS

		isNot := false
		if p.isType(models.TokenTypeNot) {
			isNot = true
			p.advance() // Consume NOT
		}

		is, err := p.parseIsSuffix(left, isPos, isNot)
		if err != nil {
			return nil, suffixNone, err
		}
		return is, suffixPredicate, nil
	}

	// PostgreSQL / SQLite postfix ISNULL and NOTNULL.
	if is, ok := p.postfixNullTest(left); ok {
		return is, suffixPredicate, nil
	}

	return p.parseComparisonOperatorSuffix(left, afterComparison)
}

// comparisonOperatorTypes holds the token types of the comparison operators
// (isComparisonOperator and combinedComparison). They are punctuation, so no
// predicate operator of parseComparisonSuffix starts with one.
var comparisonOperatorTypes = newTokenTypeSet(
	models.TokenTypeEq, models.TokenTypeLt, models.TokenTypeGt,
	models.TokenTypeNeq, models.TokenTypeLtEq, models.TokenTypeGtEq,
	models.TokenTypeTilde, models.TokenTypeTildeAsterisk,
	models.TokenTypeExclamationMarkTilde, models.TokenTypeExclamationMarkTildeAsterisk,
	models.TokenTypeSpaceship, models.TokenTypeDoubleEq,
)

// parseComparisonOperatorSuffix is the comparison-operator part of
// parseComparisonSuffix: a comparison operator, possibly quantified, and its
// right operand. It returns suffixNone when no comparison operator follows.
func (p *Parser) parseComparisonOperatorSuffix(left ast.Expression, afterComparison bool) (ast.Expression, int, error) {
	// Comparison operators do not chain: "a = b = c" is left to the caller.
	if afterComparison {
		return nil, suffixNone, nil
	}

	// Check if this is a comparison binary expression (uses O(1) switch instead of O(n) isAnyType)
	operator, nTok := p.combinedComparison()
	if nTok == 0 && p.isComparisonOperator() {
		operator, nTok = p.currentToken.Token.Value, 1
	}
	if nTok > 0 {
		// Save the operator position
		opPos := p.currentLocation()
		for i := 0; i < nTok; i++ {
			p.advance()
		}

		// Check for ANY/ALL/SOME quantified comparisons: = ANY (subquery),
		// = ANY($1), <> ALL (ARRAY[1, 2]).
		if p.isQuantifier() || p.isSomeQuantifier() {
			quantified, err := p.parseQuantifiedComparison(left, operator)
			if err != nil {
				return nil, suffixNone, err
			}
			return quantified, suffixComparison, nil
		}

		// Parse the right operand at the same level as the left one (bitwise,
		// string concatenation, additive and multiplicative levels), so
		// arithmetic binds tighter than comparison: a = 1 + 2 is a = (1 + 2)
		// (#596).
		right, err := p.parseBitwiseExpression(1)
		if err != nil {
			return nil, suffixNone, err
		}

		// Create a binary expression
		return &ast.BinaryExpression{
			Left:     left,
			Operator: operator,
			Right:    right,
			Pos:      opPos,
		}, suffixComparison, nil
	}

	return nil, suffixNone, nil
}

// parsePatternMatch parses the pattern of a LIKE-style operator whose keyword
// has been consumed, with an optional ESCAPE clause when allowEscape is set.
func (p *Parser) parsePatternMatch(left ast.Expression, operator string, not, allowEscape bool) (ast.Expression, int, error) {
	pattern, err := p.parseBitwiseExpression(1)
	if err != nil {
		return nil, suffixNone, goerrors.InvalidSyntaxError(
			fmt.Sprintf("failed to parse %s pattern: %v", operator, err),
			p.currentLocation(),
			"",
		).WithCause(err)
	}
	var escape ast.Expression
	if allowEscape {
		escape, err = p.parseEscapeClause()
		if err != nil {
			return nil, suffixNone, err
		}
	}
	node := &ast.BinaryExpression{
		Left:     left,
		Operator: operator,
		Right:    pattern,
		Not:      not,
	}
	if escape != nil {
		node.EnsureExtras().Escape = escape
	}
	return node, suffixPredicate, nil
}

// parseInTail parses the right side of IN once left (and any NOT / GLOBAL)
// has been consumed. The current token is IN.
func (p *Parser) parseInTail(left ast.Expression, notPrefix, global bool) (ast.Expression, error) {
	inPos := p.currentLocation()
	p.advance() // Consume IN

	// Expect opening parenthesis
	if !p.isType(models.TokenTypeLParen) {
		// SQLite also takes a table or table-valued function: a IN tbl.
		if p.IsSQLite() && p.isIdentifier() {
			ref, err := p.parsePrimaryExpression()
			if err != nil {
				return nil, err
			}
			return &ast.InExpression{
				Expr: left,
				List: []ast.Expression{ref},
				Not:  notPrefix,
				Bare: true,
				Pos:  inPos,
			}, nil
		}
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	// SQLite accepts an empty list: a IN () is always false.
	if p.isType(models.TokenTypeRParen) && p.IsSQLite() {
		p.advance() // Consume )
		return &ast.InExpression{Expr: left, Not: notPrefix, Pos: inPos}, nil
	}

	// Check if this is a subquery (starts with SELECT or WITH)
	if p.isType(models.TokenTypeSelect) || p.isType(models.TokenTypeWith) {
		// Parse subquery
		subquery, err := p.parseSubquery()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse IN subquery: %v", err),
				p.currentLocation(),
				"",
			).WithCause(err)
		}

		// Expect closing parenthesis
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )

		return &ast.InExpression{
			Expr:     left,
			Subquery: subquery,
			Not:      notPrefix,
			Global:   global,
			Pos:      inPos,
		}, nil
	}

	// Parse value list
	var values []ast.Expression
	for {
		value, err := p.parseExpression()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse IN value: %v", err),
				p.currentLocation(),
				"",
			)
		}
		values = append(values, value)

		if p.isType(models.TokenTypeComma) {
			p.advance() // Consume comma
		} else if p.isType(models.TokenTypeRParen) {
			break
		} else {
			return nil, p.expectedError(", or )")
		}
	}
	p.advance() // Consume )

	return &ast.InExpression{
		Expr:   left,
		List:   values,
		Not:    notPrefix,
		Global: global,
		Pos:    inPos,
	}, nil
}

// parseArrayAccessExpression parses array subscript and slice expressions.
//
// Supports:
//   - Single subscript: arr[1]
//   - Multi-dimensional subscript: arr[1][2][3]
//   - Slice with both bounds: arr[1:3]
//   - Slice from start: arr[:5]
//   - Slice to end: arr[2:]
//   - Full slice: arr[:]
//
// Examples:
//
//	tags[1]              -> ArraySubscriptExpression with single index
//	matrix[2][3]         -> Nested ArraySubscriptExpression (multi-dimensional)
//	arr[1:3]             -> ArraySliceExpression with start and end
//	arr[2:]              -> ArraySliceExpression with start only
//	arr[:5]              -> ArraySliceExpression with end only
//	(SELECT arr)[1]      -> Array access on subquery result
func (p *Parser) parseArrayAccessExpression(arrayExpr ast.Expression) (ast.Expression, error) {
	// arrayExpr is the expression before the first '['
	// We need to parse one or more '[...]' subscripts/slices

	result := arrayExpr

	// Loop to handle chained subscripts: arr[1][2][3]
	for p.isType(models.TokenTypeLBracket) {
		p.advance() // Consume [

		// Check for empty brackets [] - this is an error
		if p.isType(models.TokenTypeRBracket) {
			return nil, goerrors.InvalidSyntaxError(
				"empty array subscript [] is not allowed",
				p.currentLocation(),
				"",
			).WithHint("Use arr[index] or arr[start:end] syntax")
		}

		// Check for slice starting with colon: arr[:end]
		if p.isType(models.TokenTypeColon) {
			p.advance() // Consume :

			// Parse end expression (if not ']')
			var endExpr ast.Expression
			if !p.isType(models.TokenTypeRBracket) {
				end, err := p.parseExpression()
				if err != nil {
					return nil, goerrors.InvalidSyntaxError(
						fmt.Sprintf("failed to parse array slice end: %v", err),
						p.currentLocation(),
						"",
					)
				}
				endExpr = end
			}

			// Expect closing bracket
			if !p.isType(models.TokenTypeRBracket) {
				return nil, p.expectedError("]")
			}
			p.advance() // Consume ]

			// Create ArraySliceExpression with no start
			sliceExpr := ast.GetArraySliceExpression()
			sliceExpr.Array = result
			sliceExpr.Start = nil
			sliceExpr.End = endExpr
			result = sliceExpr
			continue
		}

		// Parse first expression (index or slice start)
		firstExpr, err := p.parseExpression()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse array index/slice: %v", err),
				p.currentLocation(),
				"",
			)
		}

		// Check if this is a slice (has colon) or subscript
		if p.isType(models.TokenTypeColon) {
			p.advance() // Consume :

			// Parse end expression (if not ']')
			var endExpr ast.Expression
			if !p.isType(models.TokenTypeRBracket) {
				end, err := p.parseExpression()
				if err != nil {
					return nil, goerrors.InvalidSyntaxError(
						fmt.Sprintf("failed to parse array slice end: %v", err),
						p.currentLocation(),
						"",
					)
				}
				endExpr = end
			}

			// Expect closing bracket
			if !p.isType(models.TokenTypeRBracket) {
				return nil, p.expectedError("]")
			}
			p.advance() // Consume ]

			// Create ArraySliceExpression
			sliceExpr := ast.GetArraySliceExpression()
			sliceExpr.Array = result
			sliceExpr.Start = firstExpr
			sliceExpr.End = endExpr
			result = sliceExpr
		} else {
			// This is a subscript, not a slice
			// Expect closing bracket
			if !p.isType(models.TokenTypeRBracket) {
				return nil, p.expectedError("]")
			}
			p.advance() // Consume ]

			// Create ArraySubscriptExpression with single index
			subscriptExpr := ast.GetArraySubscriptExpression()
			subscriptExpr.Array = result
			subscriptExpr.Indices = append(subscriptExpr.Indices, firstExpr)
			result = subscriptExpr
		}
	}

	return result, nil
}

// isASCII reports whether s holds only ASCII bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
