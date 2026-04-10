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

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseComparisonExpression parses an expression with comparison operators
func (p *Parser) parseComparisonExpression() (ast.Expression, error) {
	// Parse the left side using string concatenation expression for arithmetic support
	left, err := p.parseStringConcatExpression()
	if err != nil {
		return nil, err
	}

	// Check for NOT prefix for BETWEEN, LIKE, IN operators
	// Only consume NOT if followed by BETWEEN, LIKE, ILIKE, or IN
	// This prevents breaking cases like: WHERE NOT active AND name LIKE '%'
	notPrefix := false
	if p.isType(models.TokenTypeNot) {
		nextToken := p.peekToken()
		nextUpper := strings.ToUpper(nextToken.Token.Value)
		if nextUpper == "BETWEEN" || nextUpper == "LIKE" || nextUpper == "ILIKE" || nextUpper == "IN" {
			notPrefix = true
			p.advance() // Consume NOT only if followed by valid operator
		}
	}

	// Check for BETWEEN operator
	if p.isType(models.TokenTypeBetween) {
		betweenPos := p.currentLocation()
		p.advance() // Consume BETWEEN

		// Parse lower bound - use parseStringConcatExpression to support complex expressions
		// like: price BETWEEN price * 0.9 AND price * 1.1
		lower, err := p.parseStringConcatExpression()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse BETWEEN lower bound: %v", err),
				p.currentLocation(),
				p.currentToken.Token.Value,
			)
		}

		// Expect AND keyword
		if !p.isType(models.TokenTypeAnd) {
			return nil, p.expectedError("AND")
		}
		p.advance() // Consume AND

		// Parse upper bound - use parseStringConcatExpression to support complex expressions
		upper, err := p.parseStringConcatExpression()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse BETWEEN upper bound: %v", err),
				p.currentLocation(),
				p.currentToken.Token.Value,
			)
		}

		return &ast.BetweenExpression{
			Expr:  left,
			Lower: lower,
			Upper: upper,
			Not:   notPrefix,
			Pos:   betweenPos,
		}, nil
	}

	// Check for LIKE/ILIKE operator
	if p.isType(models.TokenTypeLike) || strings.EqualFold(p.currentToken.Token.Value, "ILIKE") {
		operator := p.currentToken.Token.Value
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
				return nil, fmt.Errorf(
					"ILIKE is not supported in %s; "+
						"use LIKE or LOWER() for case-insensitive matching", p.dialect,
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
				return nil, p.expectedError("( after " + quantifier)
			}
			tuple, err := p.parsePrimaryExpression()
			if err != nil {
				return nil, err
			}
			return &ast.BinaryExpression{
				Left:     left,
				Operator: operator,
				Right:    tuple,
				Not:      notPrefix,
			}, nil
		}

		// Parse pattern
		pattern, err := p.parsePrimaryExpression()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse LIKE pattern: %v", err),
				p.currentLocation(),
				p.currentToken.Token.Value,
			)
		}

		return &ast.BinaryExpression{
			Left:     left,
			Operator: operator,
			Right:    pattern,
			Not:      notPrefix,
		}, nil
	}

	// Check for REGEXP/RLIKE operator (MySQL)
	if strings.EqualFold(p.currentToken.Token.Value, "REGEXP") || strings.EqualFold(p.currentToken.Token.Value, "RLIKE") {
		operator := strings.ToUpper(p.currentToken.Token.Value)
		p.advance()
		pattern, err := p.parsePrimaryExpression()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse REGEXP pattern: %v", err),
				p.currentLocation(),
				p.currentToken.Token.Value,
			)
		}
		return &ast.BinaryExpression{
			Left:     left,
			Operator: operator,
			Right:    pattern,
			Not:      notPrefix,
		}, nil
	}

	// ClickHouse GLOBAL IN / GLOBAL NOT IN — GLOBAL is a distributed query modifier
	// before IN. Consume it and fall through to standard IN parsing below.
	if p.dialect == string(keywords.DialectClickHouse) && p.isTokenMatch("GLOBAL") {
		p.advance() // consume GLOBAL
		if p.isType(models.TokenTypeNot) {
			notPrefix = true
			p.advance() // consume NOT
		}
	}

	// Check for IN operator
	if p.isType(models.TokenTypeIn) {
		inPos := p.currentLocation()
		p.advance() // Consume IN

		// Expect opening parenthesis
		if !p.isType(models.TokenTypeLParen) {
			return nil, p.expectedError("(")
		}
		p.advance() // Consume (

		// Check if this is a subquery (starts with SELECT or WITH)
		if p.isType(models.TokenTypeSelect) || p.isType(models.TokenTypeWith) {
			// Parse subquery
			subquery, err := p.parseSubquery()
			if err != nil {
				return nil, goerrors.InvalidSyntaxError(
					fmt.Sprintf("failed to parse IN subquery: %v", err),
					p.currentLocation(),
					p.currentToken.Token.Value,
				)
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
			Expr: left,
			List: values,
			Not:  notPrefix,
			Pos:  inPos,
		}, nil
	}

	// If NOT was consumed but no BETWEEN/LIKE/IN follows, we need to handle this case
	// Put back the NOT by creating a NOT expression with left as the operand
	if notPrefix {
		return nil, goerrors.ExpectedTokenError(
			"BETWEEN, LIKE, or IN",
			"NOT",
			p.currentLocation(),
			"",
		)
	}

	// Check for IS NULL / IS NOT NULL
	if p.isType(models.TokenTypeIs) {
		isPos := p.currentLocation()
		p.advance() // Consume IS

		isNot := false
		if p.isType(models.TokenTypeNot) {
			isNot = true
			p.advance() // Consume NOT
		}

		if p.isType(models.TokenTypeNull) {
			p.advance() // Consume NULL
			return &ast.BinaryExpression{
				Left:     left,
				Operator: "IS NULL",
				Right:    &ast.LiteralValue{Value: nil, Type: "null"},
				Not:      isNot,
				Pos:      isPos,
			}, nil
		}

		return nil, p.expectedError("NULL")
	}

	// Check if this is a comparison binary expression (uses O(1) switch instead of O(n) isAnyType)
	if p.isComparisonOperator() {
		// Save the operator and its position
		opPos := p.currentLocation()
		operator := p.currentToken.Token.Value
		p.advance()

		// Check for ANY/ALL subquery operators (uses O(1) switch instead of O(n) isAnyType)
		if p.isQuantifier() {
			quantifier := p.currentToken.Token.Value
			p.advance() // Consume ANY/ALL

			// Expect opening parenthesis
			if !p.isType(models.TokenTypeLParen) {
				return nil, p.expectedError("(")
			}
			p.advance() // Consume (

			// Parse subquery
			subquery, err := p.parseSubquery()
			if err != nil {
				return nil, goerrors.InvalidSyntaxError(
					fmt.Sprintf("failed to parse %s subquery: %v", quantifier, err),
					p.currentLocation(),
					"",
				)
			}

			// Expect closing parenthesis
			if !p.isType(models.TokenTypeRParen) {
				return nil, p.expectedError(")")
			}
			p.advance() // Consume )

			if quantifier == "ANY" {
				return &ast.AnyExpression{
					Expr:     left,
					Operator: operator,
					Subquery: subquery,
				}, nil
			}
			return &ast.AllExpression{
				Expr:     left,
				Operator: operator,
				Subquery: subquery,
			}, nil
		}

		// Parse the right side of the expression
		right, err := p.parsePrimaryExpression()
		if err != nil {
			return nil, err
		}

		// Create a binary expression
		return &ast.BinaryExpression{
			Left:     left,
			Operator: operator,
			Right:    right,
			Pos:      opPos,
		}, nil
	}

	return left, nil
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
				"Use arr[index] or arr[start:end] syntax",
			)
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
