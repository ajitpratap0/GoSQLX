// Package parser - expressions.go
// Expression parsing functions for the SQL parser.

package parser

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseExpression parses an expression with OR operators (lowest precedence)
func (p *Parser) parseExpression() (ast.Expression, error) {
	// Check context if available
	if p.ctx != nil {
		if err := p.ctx.Err(); err != nil {
			return nil, fmt.Errorf("parsing cancelled: %w", err)
		}
	}

	// Check recursion depth to prevent stack overflow
	p.depth++
	defer func() { p.depth-- }()

	if p.depth > MaxRecursionDepth {
		return nil, fmt.Errorf("maximum recursion depth exceeded (%d) - expression too deeply nested", MaxRecursionDepth)
	}

	// Start by parsing AND expressions (higher precedence)
	left, err := p.parseAndExpression()
	if err != nil {
		return nil, err
	}

	// Handle OR operators (lowest precedence, left-associative)
	for p.isType(models.TokenTypeOr) {
		operator := p.currentToken.Literal
		p.advance() // Consume OR

		right, err := p.parseAndExpression()
		if err != nil {
			return nil, err
		}

		left = &ast.BinaryExpression{
			Left:     left,
			Operator: operator,
			Right:    right,
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
		operator := p.currentToken.Literal
		p.advance() // Consume AND

		right, err := p.parseComparisonExpression()
		if err != nil {
			return nil, err
		}

		left = &ast.BinaryExpression{
			Left:     left,
			Operator: operator,
			Right:    right,
		}
	}

	return left, nil
}

// parseComparisonExpression parses an expression with comparison operators (highest precedence)
func (p *Parser) parseComparisonExpression() (ast.Expression, error) {
	// Parse the left side (primary expression)
	left, err := p.parsePrimaryExpression()
	if err != nil {
		return nil, err
	}

	// Check for NOT prefix for BETWEEN, LIKE, IN operators
	// Only consume NOT if followed by BETWEEN, LIKE, ILIKE, or IN
	// This prevents breaking cases like: WHERE NOT active AND name LIKE '%'
	notPrefix := false
	if p.isType(models.TokenTypeNot) {
		nextToken := p.peekToken()
		if nextToken.Type == "BETWEEN" || nextToken.Type == "LIKE" || nextToken.Type == "ILIKE" || nextToken.Type == "IN" {
			notPrefix = true
			p.advance() // Consume NOT only if followed by valid operator
		}
	}

	// Check for BETWEEN operator
	if p.isType(models.TokenTypeBetween) {
		p.advance() // Consume BETWEEN

		// Parse lower bound
		lower, err := p.parsePrimaryExpression()
		if err != nil {
			return nil, fmt.Errorf("failed to parse BETWEEN lower bound: %w", err)
		}

		// Expect AND keyword
		if !p.isType(models.TokenTypeAnd) {
			return nil, p.expectedError("AND")
		}
		p.advance() // Consume AND

		// Parse upper bound
		upper, err := p.parsePrimaryExpression()
		if err != nil {
			return nil, fmt.Errorf("failed to parse BETWEEN upper bound: %w", err)
		}

		return &ast.BetweenExpression{
			Expr:  left,
			Lower: lower,
			Upper: upper,
			Not:   notPrefix,
		}, nil
	}

	// Check for LIKE/ILIKE operator
	if p.isType(models.TokenTypeLike) || p.currentToken.Type == "ILIKE" {
		operator := p.currentToken.Literal
		p.advance() // Consume LIKE/ILIKE

		// Parse pattern
		pattern, err := p.parsePrimaryExpression()
		if err != nil {
			return nil, fmt.Errorf("failed to parse LIKE pattern: %w", err)
		}

		return &ast.BinaryExpression{
			Left:     left,
			Operator: operator,
			Right:    pattern,
			Not:      notPrefix,
		}, nil
	}

	// Check for IN operator
	if p.isType(models.TokenTypeIn) {
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
				return nil, fmt.Errorf("failed to parse IN subquery: %w", err)
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
			}, nil
		}

		// Parse value list
		var values []ast.Expression
		for {
			value, err := p.parseExpression()
			if err != nil {
				return nil, fmt.Errorf("failed to parse IN value: %w", err)
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
		}, nil
	}

	// If NOT was consumed but no BETWEEN/LIKE/IN follows, we need to handle this case
	// Put back the NOT by creating a NOT expression with left as the operand
	if notPrefix {
		return nil, fmt.Errorf("expected BETWEEN, LIKE, or IN after NOT")
	}

	// Check for IS NULL / IS NOT NULL
	if p.isType(models.TokenTypeIs) {
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
			}, nil
		}

		return nil, p.expectedError("NULL")
	}

	// Check if this is a comparison binary expression (uses O(1) switch instead of O(n) isAnyType)
	if p.isComparisonOperator() {
		// Save the operator
		operator := p.currentToken.Literal
		p.advance()

		// Check for ANY/ALL subquery operators (uses O(1) switch instead of O(n) isAnyType)
		if p.isQuantifier() {
			quantifier := p.currentToken.Type
			p.advance() // Consume ANY/ALL

			// Expect opening parenthesis
			if !p.isType(models.TokenTypeLParen) {
				return nil, p.expectedError("(")
			}
			p.advance() // Consume (

			// Parse subquery
			subquery, err := p.parseSubquery()
			if err != nil {
				return nil, fmt.Errorf("failed to parse %s subquery: %w", quantifier, err)
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
		}, nil
	}

	return left, nil
}

// parsePrimaryExpression parses a primary expression (literals, identifiers, function calls)
func (p *Parser) parsePrimaryExpression() (ast.Expression, error) {
	if p.isType(models.TokenTypeCase) {
		// Handle CASE expressions (both simple and searched forms)
		return p.parseCaseExpression()
	}

	if p.isType(models.TokenTypeIdentifier) {
		// Handle identifiers and function calls
		identName := p.currentToken.Literal
		p.advance()

		// Check for function call (identifier followed by parentheses)
		if p.isType(models.TokenTypeLParen) {
			// This is a function call
			funcCall, err := p.parseFunctionCall(identName)
			if err != nil {
				return nil, err
			}
			return funcCall, nil
		}

		// Handle regular identifier or qualified identifier (table.column)
		ident := &ast.Identifier{Name: identName}

		// Check for qualified identifier (table.column)
		if p.isType(models.TokenTypePeriod) {
			p.advance() // Consume .
			if !p.isType(models.TokenTypeIdentifier) {
				return nil, p.expectedError("identifier after .")
			}
			// Create a qualified identifier
			ident = &ast.Identifier{
				Table: ident.Name,
				Name:  p.currentToken.Literal,
			}
			p.advance()
		}

		return ident, nil
	}

	if p.isType(models.TokenTypeAsterisk) {
		// Handle asterisk (e.g., in COUNT(*) or SELECT *)
		p.advance()
		return &ast.Identifier{Name: "*"}, nil
	}

	if p.currentToken.Type == "STRING" {
		// Handle string literals
		value := p.currentToken.Literal
		p.advance()
		return &ast.LiteralValue{Value: value, Type: "string"}, nil
	}

	if p.currentToken.Type == "INT" {
		// Handle integer literals
		value := p.currentToken.Literal
		p.advance()
		return &ast.LiteralValue{Value: value, Type: "int"}, nil
	}

	if p.currentToken.Type == "FLOAT" {
		// Handle float literals
		value := p.currentToken.Literal
		p.advance()
		return &ast.LiteralValue{Value: value, Type: "float"}, nil
	}

	if p.isAnyType(models.TokenTypeTrue, models.TokenTypeFalse) {
		// Handle boolean literals
		value := p.currentToken.Literal
		p.advance()
		return &ast.LiteralValue{Value: value, Type: "bool"}, nil
	}

	if p.isType(models.TokenTypePlaceholder) {
		// Handle SQL placeholders (e.g., $1, $2 for PostgreSQL; @param for SQL Server)
		value := p.currentToken.Literal
		p.advance()
		return &ast.LiteralValue{Value: value, Type: "placeholder"}, nil
	}

	if p.isType(models.TokenTypeNull) {
		// Handle NULL literal
		p.advance()
		return &ast.LiteralValue{Value: nil, Type: "null"}, nil
	}

	if p.isType(models.TokenTypeLParen) {
		// Handle parenthesized expression or subquery
		p.advance() // Consume (

		// Check if this is a subquery (starts with SELECT or WITH)
		if p.isType(models.TokenTypeSelect) || p.isType(models.TokenTypeWith) {
			// Parse subquery
			subquery, err := p.parseSubquery()
			if err != nil {
				return nil, fmt.Errorf("failed to parse subquery: %w", err)
			}
			// Expect closing parenthesis
			if !p.isType(models.TokenTypeRParen) {
				return nil, p.expectedError(")")
			}
			p.advance() // Consume )
			return &ast.SubqueryExpression{Subquery: subquery}, nil
		}

		// Regular parenthesized expression
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}

		// Expect closing parenthesis
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
		return expr, nil
	}

	if p.isType(models.TokenTypeExists) {
		// Handle EXISTS (subquery)
		p.advance() // Consume EXISTS

		// Expect opening parenthesis
		if !p.isType(models.TokenTypeLParen) {
			return nil, p.expectedError("(")
		}
		p.advance() // Consume (

		// Parse the subquery
		subquery, err := p.parseSubquery()
		if err != nil {
			return nil, fmt.Errorf("failed to parse EXISTS subquery: %w", err)
		}

		// Expect closing parenthesis
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )

		return &ast.ExistsExpression{Subquery: subquery}, nil
	}

	if p.isType(models.TokenTypeNot) {
		// Handle NOT expression (NOT EXISTS, NOT boolean)
		p.advance() // Consume NOT

		if p.isType(models.TokenTypeExists) {
			// NOT EXISTS (subquery)
			p.advance() // Consume EXISTS

			if !p.isType(models.TokenTypeLParen) {
				return nil, p.expectedError("(")
			}
			p.advance() // Consume (

			subquery, err := p.parseSubquery()
			if err != nil {
				return nil, fmt.Errorf("failed to parse NOT EXISTS subquery: %w", err)
			}

			if !p.isType(models.TokenTypeRParen) {
				return nil, p.expectedError(")")
			}
			p.advance() // Consume )

			// Return NOT EXISTS as a BinaryExpression with NOT flag
			return &ast.BinaryExpression{
				Left:     &ast.ExistsExpression{Subquery: subquery},
				Operator: "NOT",
				Right:    nil,
				Not:      true,
			}, nil
		}

		// NOT followed by other expression (boolean negation)
		// Parse at comparison level for proper precedence: NOT (a > b), NOT active
		expr, err := p.parseComparisonExpression()
		if err != nil {
			return nil, err
		}
		return &ast.UnaryExpression{
			Operator: ast.Not,
			Expr:     expr,
		}, nil
	}

	return nil, fmt.Errorf("unexpected token: %s", p.currentToken.Type)
}

// parseCaseExpression parses a CASE expression (both simple and searched forms)
//
// Simple CASE: CASE expr WHEN value THEN result ... [ELSE result] END
// Searched CASE: CASE WHEN condition THEN result ... [ELSE result] END
func (p *Parser) parseCaseExpression() (*ast.CaseExpression, error) {
	p.advance() // Consume CASE

	caseExpr := &ast.CaseExpression{
		WhenClauses: make([]ast.WhenClause, 0),
	}

	// Check if this is a simple CASE (has a value expression) or searched CASE (no value)
	// Simple CASE: CASE expr WHEN value THEN result
	// Searched CASE: CASE WHEN condition THEN result
	if !p.isType(models.TokenTypeWhen) {
		// This is a simple CASE - parse the value expression
		value, err := p.parseExpression()
		if err != nil {
			return nil, fmt.Errorf("failed to parse CASE value: %w", err)
		}
		caseExpr.Value = value
	}

	// Parse WHEN clauses (at least one required)
	for p.isType(models.TokenTypeWhen) {
		p.advance() // Consume WHEN

		// Parse the condition/value expression
		condition, err := p.parseExpression()
		if err != nil {
			return nil, fmt.Errorf("failed to parse WHEN condition: %w", err)
		}

		// Expect THEN keyword
		if !p.isType(models.TokenTypeThen) {
			return nil, p.expectedError("THEN")
		}
		p.advance() // Consume THEN

		// Parse the result expression
		result, err := p.parseExpression()
		if err != nil {
			return nil, fmt.Errorf("failed to parse THEN result: %w", err)
		}

		caseExpr.WhenClauses = append(caseExpr.WhenClauses, ast.WhenClause{
			Condition: condition,
			Result:    result,
		})
	}

	// Check that we have at least one WHEN clause
	if len(caseExpr.WhenClauses) == 0 {
		return nil, fmt.Errorf("CASE expression requires at least one WHEN clause")
	}

	// Parse optional ELSE clause
	if p.isType(models.TokenTypeElse) {
		p.advance() // Consume ELSE

		elseResult, err := p.parseExpression()
		if err != nil {
			return nil, fmt.Errorf("failed to parse ELSE result: %w", err)
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

// parseSubquery parses a subquery (SELECT or WITH statement).
// Expects current token to be SELECT or WITH.
func (p *Parser) parseSubquery() (ast.Statement, error) {
	if p.isType(models.TokenTypeWith) {
		// WITH statement handles its own token consumption
		return p.parseWithStatement()
	}

	if p.isType(models.TokenTypeSelect) {
		p.advance() // Consume SELECT
		return p.parseSelectWithSetOperations()
	}

	return nil, fmt.Errorf("expected SELECT or WITH, got %s", p.currentToken.Type)
}

// parseFunctionCall parses a function call with optional OVER clause for window functions.
//
// Examples:
//
//	COUNT(*) -> regular aggregate function
//	ROW_NUMBER() OVER (ORDER BY id) -> window function with OVER clause
