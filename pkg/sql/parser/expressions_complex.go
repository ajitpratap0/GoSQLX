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

// Package parser - expressions_complex.go
// Complex expression forms: CASE, CAST, INTERVAL, and ARRAY constructors.

package parser

import (
	"fmt"
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseCaseExpression parses a CASE expression (both simple and searched forms)
//
// Simple CASE: CASE expr WHEN value THEN result ... [ELSE result] END
// Searched CASE: CASE WHEN condition THEN result ... [ELSE result] END
func (p *Parser) parseCaseExpression() (*ast.CaseExpression, error) {
	casePos := p.currentLocation()
	p.advance() // Consume CASE

	caseExpr := &ast.CaseExpression{
		WhenClauses: make([]ast.WhenClause, 0),
		Pos:         casePos,
	}

	// Check if this is a simple CASE (has a value expression) or searched CASE (no value)
	// Simple CASE: CASE expr WHEN value THEN result
	// Searched CASE: CASE WHEN condition THEN result
	if !p.isType(models.TokenTypeWhen) {
		// This is a simple CASE - parse the value expression
		value, err := p.parseExpression()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse CASE value: %v", err),
				p.currentLocation(),
				"",
			)
		}
		caseExpr.Value = value
	}

	// Parse WHEN clauses (at least one required)
	for p.isType(models.TokenTypeWhen) {
		whenPos := p.currentLocation()
		p.advance() // Consume WHEN

		// Parse the condition/value expression
		condition, err := p.parseExpression()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse WHEN condition: %v", err),
				p.currentLocation(),
				"",
			)
		}

		// Expect THEN keyword
		if !p.isType(models.TokenTypeThen) {
			return nil, p.expectedError("THEN")
		}
		p.advance() // Consume THEN

		// Parse the result expression
		result, err := p.parseExpression()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse THEN result: %v", err),
				p.currentLocation(),
				"",
			)
		}

		caseExpr.WhenClauses = append(caseExpr.WhenClauses, ast.WhenClause{
			Condition: condition,
			Result:    result,
			Pos:       whenPos,
		})
	}

	// Check that we have at least one WHEN clause
	if len(caseExpr.WhenClauses) == 0 {
		return nil, goerrors.InvalidSyntaxError(
			"CASE expression requires at least one WHEN clause",
			p.currentLocation(),
			"",
		)
	}

	// Parse optional ELSE clause
	if p.isType(models.TokenTypeElse) {
		p.advance() // Consume ELSE

		elseResult, err := p.parseExpression()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse ELSE result: %v", err),
				p.currentLocation(),
				"",
			)
		}
		caseExpr.ElseClause = elseResult
	}

	// Expect END keyword
	if !p.isType(models.TokenTypeEnd) {
		return nil, p.expectedError("END")
	}
	p.advance() // Consume END

	return caseExpr, nil
}

// parseCastExpression parses a CAST expression: CAST(expr AS type)
//
// Examples:
//
//	CAST(id AS VARCHAR)
//	CAST(price AS DECIMAL(10,2))
//	CAST(name AS VARCHAR(100))
func (p *Parser) parseCastExpression() (*ast.CastExpression, error) {
	return p.parseCastLike(false)
}

// parseTryCastExpression parses a TRY_CAST expression with the same shape as
// CAST. Snowflake, SQL Server, and BigQuery return NULL on conversion failure
// instead of raising an error.
func (p *Parser) parseTryCastExpression() (*ast.CastExpression, error) {
	return p.parseCastLike(true)
}

// parseCastLike implements the body shared between CAST and TRY_CAST. The
// caller is responsible for ensuring the current token is the leading keyword.
func (p *Parser) parseCastLike(try bool) (*ast.CastExpression, error) {
	// Consume CAST / TRY_CAST keyword
	p.advance()

	// Expect opening parenthesis
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	// Parse the expression to be cast
	expr, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	// Expect AS keyword
	if !p.isType(models.TokenTypeAs) {
		return nil, p.expectedError("AS")
	}
	p.advance() // Consume AS

	// Parse the target data type
	// The type can be:
	// - Simple type: VARCHAR, INT, DECIMAL, etc.
	// - Type with precision: VARCHAR(100), DECIMAL(10,2), etc.
	if !p.isType(models.TokenTypeIdentifier) {
		return nil, p.expectedError("data type")
	}

	dataType := p.currentToken.Token.Value
	p.advance() // Consume type name

	// Check for type parameters (e.g., VARCHAR(100), DECIMAL(10,2))
	if p.isType(models.TokenTypeLParen) {
		p.advance() // Consume (

		// Build the full type string including parameters
		typeParams := "("
		paramCount := 0

		for !p.isType(models.TokenTypeRParen) {
			if paramCount > 0 {
				if !p.isType(models.TokenTypeComma) {
					return nil, p.expectedError(", or )")
				}
				typeParams += p.currentToken.Token.Value
				p.advance() // Consume comma
			}

			// Parse parameter (should be a number)
			if !p.isNumericLiteral() && !p.isType(models.TokenTypeIdentifier) {
				return nil, goerrors.InvalidSyntaxError(
					"expected numeric type parameter",
					p.currentLocation(),
					"Use CAST(expr AS TYPE(precision[, scale]))",
				)
			}

			typeParams += p.currentToken.Token.Value
			p.advance()
			paramCount++
		}

		typeParams += ")"
		dataType += typeParams

		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
	}

	// Expect closing parenthesis of CAST
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )

	return &ast.CastExpression{
		Expr: expr,
		Type: dataType,
		Try:  try,
	}, nil
}

// parseIntervalExpression parses an INTERVAL expression: INTERVAL 'value'
//
// Examples:
//
//	INTERVAL '1 day'
//	INTERVAL '2 hours'
//	INTERVAL '1 year 2 months 3 days'
//	INTERVAL '30 days'
func (p *Parser) parseIntervalExpression() (*ast.IntervalExpression, error) {
	// Consume INTERVAL keyword
	p.advance()

	// Support both PostgreSQL style: INTERVAL '1 day'
	// and MySQL style: INTERVAL 30 DAY, INTERVAL 1 HOUR
	if p.isStringLiteral() {
		value := p.currentToken.Token.Value
		p.advance()
		return &ast.IntervalExpression{Value: value}, nil
	}

	// MySQL style: INTERVAL <number> <unit>
	if p.isNumericLiteral() {
		numStr := p.currentToken.Token.Value
		p.advance()
		// Expect a unit keyword (DAY, HOUR, MINUTE, SECOND, MONTH, YEAR, WEEK, etc.)
		unit := strings.ToUpper(p.currentToken.Token.Value)
		p.advance()
		return &ast.IntervalExpression{Value: numStr + " " + unit}, nil
	}

	return nil, goerrors.InvalidSyntaxError(
		"expected string literal or number after INTERVAL keyword",
		p.currentLocation(),
		"Use INTERVAL '1 day' or INTERVAL 1 DAY syntax",
	)
}

// parseArrayConstructor parses PostgreSQL ARRAY constructor syntax.
// Supports both ARRAY[...] (square bracket) and ARRAY(...) (subquery) forms.
//
// Examples:
//
//	ARRAY[1, 2, 3]                   - Array literal with square brackets
//	ARRAY['a', 'b', 'c']             - String array
//	ARRAY[x, y, z]                   - Array from expressions
//	ARRAY(SELECT id FROM users)      - Array from subquery
func (p *Parser) parseArrayConstructor() (*ast.ArrayConstructorExpression, error) {
	p.advance() // Consume ARRAY

	arrayExpr := ast.GetArrayConstructor()

	// Check for square bracket syntax: ARRAY[...]
	if p.isType(models.TokenTypeLBracket) {
		p.advance() // Consume [

		// Parse comma-separated list of expressions (can be empty)
		if !p.isType(models.TokenTypeRBracket) {
			for {
				elem, err := p.parseExpression()
				if err != nil {
					return nil, err
				}
				arrayExpr.Elements = append(arrayExpr.Elements, elem)

				if p.isType(models.TokenTypeComma) {
					p.advance() // Consume comma
				} else if p.isType(models.TokenTypeRBracket) {
					break
				} else {
					return nil, p.expectedError(", or ]")
				}
			}
		}

		// Expect closing bracket
		if !p.isType(models.TokenTypeRBracket) {
			return nil, p.expectedError("]")
		}
		p.advance() // Consume ]

		return arrayExpr, nil
	}

	// Check for parenthesis syntax: ARRAY(SELECT ...)
	if p.isType(models.TokenTypeLParen) {
		p.advance() // Consume (

		// Expect a subquery
		if !p.isType(models.TokenTypeSelect) && !p.isType(models.TokenTypeWith) {
			return nil, p.expectedError("SELECT in ARRAY subquery")
		}

		subquery, err := p.parseSubquery()
		if err != nil {
			return nil, err
		}

		selectStmt, ok := subquery.(*ast.SelectStatement)
		if !ok {
			return nil, p.expectedError("SELECT statement in ARRAY subquery")
		}
		arrayExpr.Subquery = selectStmt

		// Expect closing parenthesis
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )

		return arrayExpr, nil
	}

	return nil, p.expectedError("[ or (")
}

// parseBracketArrayLiteral parses a ClickHouse-style bare bracket array
// literal: [expr, expr, ...]. The opening '[' is the current token.
func (p *Parser) parseBracketArrayLiteral() (*ast.ArrayConstructorExpression, error) {
	p.advance() // Consume [

	arrayExpr := ast.GetArrayConstructor()

	if !p.isType(models.TokenTypeRBracket) {
		for {
			elem, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			arrayExpr.Elements = append(arrayExpr.Elements, elem)

			if p.isType(models.TokenTypeComma) {
				p.advance()
			} else if p.isType(models.TokenTypeRBracket) {
				break
			} else {
				return nil, p.expectedError(", or ]")
			}
		}
	}

	if !p.isType(models.TokenTypeRBracket) {
		return nil, p.expectedError("]")
	}
	p.advance() // Consume ]

	return arrayExpr, nil
}
