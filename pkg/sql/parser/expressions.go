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

// Package parser - expressions.go
// Core expression parsing: precedence-climbing hierarchy from OR down to JSON/cast operators.
// Related modules:
//   - expressions_literal.go   — literals, identifiers, qualified names, parsePrimaryExpression
//   - expressions_operators.go — comparison, BETWEEN, IN, LIKE, IS NULL, array subscripts
//   - expressions_complex.go   — CASE, CAST, INTERVAL, ARRAY constructors

package parser

import (
	"fmt"
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseExpression parses an expression with OR operators (lowest precedence)
func (p *Parser) parseExpression() (ast.Expression, error) {
	// Check context if available
	if p.ctx != nil {
		if err := p.ctx.Err(); err != nil {
			// Context cancellation is not a syntax error, wrap it directly
			return nil, fmt.Errorf("parsing cancelled: %w", err)
		}
	}

	// Check recursion depth to prevent stack overflow
	p.depth++
	defer func() { p.depth-- }()

	if p.depth > MaxRecursionDepth {
		return nil, goerrors.RecursionDepthLimitError(
			p.depth,
			MaxRecursionDepth,
			p.currentLocation(),
			"",
		)
	}

	// Start by parsing AND expressions (higher precedence)
	left, err := p.parseAndExpression()
	if err != nil {
		return nil, err
	}

	// Handle OR operators (lowest precedence, left-associative)
	for p.isType(models.TokenTypeOr) {
		opPos := p.currentLocation()
		operator := p.currentToken.Token.Value
		p.advance() // Consume OR

		right, err := p.parseAndExpression()
		if err != nil {
			return nil, err
		}

		left = &ast.BinaryExpression{
			Left:     left,
			Operator: operator,
			Right:    right,
			Pos:      opPos,
		}
	}

	return left, nil
}

// parseAndExpression parses an expression with AND operators (middle precedence)
func (p *Parser) parseAndExpression() (ast.Expression, error) {
	// Parse comparison expressions (higher precedence)
	left, err := p.parseComparisonExpression()
	if err != nil {
		return nil, err
	}

	// Handle AND operators (middle precedence, left-associative)
	for p.isType(models.TokenTypeAnd) {
		opPos := p.currentLocation()
		operator := p.currentToken.Token.Value
		p.advance() // Consume AND

		right, err := p.parseComparisonExpression()
		if err != nil {
			return nil, err
		}

		left = &ast.BinaryExpression{
			Left:     left,
			Operator: operator,
			Right:    right,
			Pos:      opPos,
		}
	}

	return left, nil
}

// parseStringConcatExpression parses expressions with || (string concatenation) operator
func (p *Parser) parseStringConcatExpression() (ast.Expression, error) {
	// Parse the left side using additive expression
	left, err := p.parseAdditiveExpression()
	if err != nil {
		return nil, err
	}

	// Handle || (string concatenation) operator (left-associative)
	for p.isType(models.TokenTypeStringConcat) {
		opPos := p.currentLocation()
		operator := p.currentToken.Token.Value
		p.advance() // Consume ||

		right, err := p.parseAdditiveExpression()
		if err != nil {
			return nil, err
		}

		left = &ast.BinaryExpression{
			Left:     left,
			Operator: operator,
			Right:    right,
			Pos:      opPos,
		}
	}

	return left, nil
}

// parseAdditiveExpression parses expressions with + and - operators
func (p *Parser) parseAdditiveExpression() (ast.Expression, error) {
	// Parse the left side using multiplicative expression
	left, err := p.parseMultiplicativeExpression()
	if err != nil {
		return nil, err
	}

	// Handle + and - operators (left-associative)
	for p.isType(models.TokenTypePlus) || p.isType(models.TokenTypeMinus) {
		opPos := p.currentLocation()
		operator := p.currentToken.Token.Value
		p.advance() // Consume operator

		right, err := p.parseMultiplicativeExpression()
		if err != nil {
			return nil, err
		}

		left = &ast.BinaryExpression{
			Left:     left,
			Operator: operator,
			Right:    right,
			Pos:      opPos,
		}
	}

	return left, nil
}

// parseMultiplicativeExpression parses expressions with *, /, and % operators
func (p *Parser) parseMultiplicativeExpression() (ast.Expression, error) {
	// Parse the left side using JSON operator expression (higher precedence)
	left, err := p.parseJSONExpression()
	if err != nil {
		return nil, err
	}

	// Handle *, /, and % operators (left-associative)
	// Note: TokenTypeAsterisk is used for both * (SELECT) and multiplication
	// We check context: after an expression, asterisk means multiplication
	for p.isType(models.TokenTypeAsterisk) || p.isType(models.TokenTypeMul) ||
		p.isType(models.TokenTypeDiv) || p.isType(models.TokenTypeMod) {
		opPos := p.currentLocation()
		operator := p.currentToken.Token.Value
		p.advance() // Consume operator

		right, err := p.parseJSONExpression()
		if err != nil {
			return nil, err
		}

		left = &ast.BinaryExpression{
			Left:     left,
			Operator: operator,
			Right:    right,
			Pos:      opPos,
		}
	}

	return left, nil
}

// parseJSONExpression parses JSON/JSONB operators (PostgreSQL) and type casting
// Handles: ->, ->>, #>, #>>, @>, <@, ?, ?|, ?&, #-, ::
func (p *Parser) parseJSONExpression() (ast.Expression, error) {
	// Parse the left side using primary expression
	left, err := p.parsePrimaryExpression()
	if err != nil {
		return nil, err
	}

	// Handle type casting (::) with highest precedence
	// PostgreSQL: expr::type (e.g., '123'::integer, column::text)
	for p.isType(models.TokenTypeDoubleColon) {
		p.advance() // Consume ::

		// Parse the target data type
		dataType, err := p.parseDataType()
		if err != nil {
			return nil, err
		}

		left = &ast.CastExpression{
			Expr: left,
			Type: dataType,
		}
	}

	// Handle JSON operators (left-associative for chaining like data->'a'->'b')
	for p.isJSONOperator() {
		opPos := p.currentLocation()
		operator := p.currentToken.Token.Value
		operatorType := p.currentToken.Token.Type
		p.advance() // Consume JSON operator

		// Parse the right side
		right, err := p.parsePrimaryExpression()
		if err != nil {
			return nil, err
		}

		left = &ast.BinaryExpression{
			Left:     left,
			Operator: operator,
			Right:    right,
			Pos:      opPos,
		}

		// Store operator type for semantic analysis if needed
		_ = operatorType

		// Check for type casting after JSON operations
		for p.isType(models.TokenTypeDoubleColon) {
			p.advance() // Consume ::

			dataType, err := p.parseDataType()
			if err != nil {
				return nil, err
			}

			left = &ast.CastExpression{
				Expr: left,
				Type: dataType,
			}
		}
	}

	return left, nil
}

// parseDataType parses a SQL data type for CAST or :: expressions
// Handles: simple types (INTEGER, TEXT), parameterized types (VARCHAR(100), NUMERIC(10,2))
func (p *Parser) parseDataType() (string, error) {
	// Data type can be an identifier or a keyword like INT, VARCHAR, etc.
	if !p.isIdentifier() && !p.isDataTypeKeyword() {
		return "", p.expectedError("data type")
	}

	// Use strings.Builder for efficient string concatenation
	var sb strings.Builder
	sb.WriteString(p.currentToken.Token.Value)
	p.advance() // Consume type name

	// Check for type parameters (e.g., VARCHAR(100), DECIMAL(10,2))
	if p.isType(models.TokenTypeLParen) {
		p.advance() // Consume (
		sb.WriteByte('(')

		paramCount := 0
		for !p.isType(models.TokenTypeRParen) {
			if paramCount > 0 {
				if !p.isType(models.TokenTypeComma) {
					return "", p.expectedError(", or )")
				}
				sb.WriteString(p.currentToken.Token.Value)
				p.advance() // Consume comma
			}

			// Parse parameter (should be a number or identifier)
			// Use token type constants for consistency
			if !p.isType(models.TokenTypeNumber) && !p.isType(models.TokenTypeIdentifier) && !p.isNumericLiteral() {
				return "", goerrors.InvalidSyntaxError(
					fmt.Sprintf("expected numeric type parameter, got '%s'", p.currentToken.Token.Value),
					p.currentLocation(),
					"Use TYPE(precision[, scale]) syntax",
				)
			}

			sb.WriteString(p.currentToken.Token.Value)
			p.advance()
			paramCount++
		}

		sb.WriteByte(')')

		if !p.isType(models.TokenTypeRParen) {
			return "", p.expectedError(")")
		}
		p.advance() // Consume )
	}

	// Check for array type suffix (e.g., INTEGER[], TEXT[])
	if p.isType(models.TokenTypeLBracket) {
		p.advance() // Consume [
		if !p.isType(models.TokenTypeRBracket) {
			return "", p.expectedError("]")
		}
		p.advance() // Consume ]
		sb.WriteString("[]")
	}

	return sb.String(), nil
}

// isNumericLiteral checks if current token is a numeric literal (handles INT/NUMBER token types)
func (p *Parser) isNumericLiteral() bool {
	if p.currentToken.Token.Type != models.TokenTypeUnknown {
		return p.currentToken.Token.Type == models.TokenTypeNumber
	}
	return false
}

// isDataTypeKeyword checks if current token is a SQL data type keyword
func (p *Parser) isDataTypeKeyword() bool {
	// Check Type for known data type tokens
	switch p.currentToken.Token.Type {
	case models.TokenTypeInt, models.TokenTypeInteger, models.TokenTypeVarchar,
		models.TokenTypeText, models.TokenTypeBoolean, models.TokenTypeFloat,
		models.TokenTypeInterval:
		return true
	}
	// Fallback: check literal for data type keywords not all represented in models
	switch strings.ToUpper(p.currentToken.Token.Value) {
	case "INT", "INTEGER", "BIGINT", "SMALLINT", "FLOAT", "DOUBLE", "DECIMAL",
		"NUMERIC", "VARCHAR", "CHAR", "TEXT", "BOOLEAN", "DATE", "TIME",
		"TIMESTAMP", "INTERVAL", "BLOB", "CLOB", "JSON", "UUID":
		return true
	}
	return false
}

// isJSONOperator checks if current token is a JSON/JSONB operator
func (p *Parser) isJSONOperator() bool {
	switch p.currentToken.Token.Type {
	case models.TokenTypeArrow, // ->
		models.TokenTypeLongArrow,     // ->>
		models.TokenTypeHashArrow,     // #>
		models.TokenTypeHashLongArrow, // #>>
		models.TokenTypeAtArrow,       // @>
		models.TokenTypeArrowAt,       // <@
		models.TokenTypeHashMinus,     // #-
		models.TokenTypeQuestion,      // ?
		models.TokenTypeQuestionPipe,  // ?|
		models.TokenTypeQuestionAnd:   // ?&
		return true
	}
	return false
}
