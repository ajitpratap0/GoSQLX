// Package parser - expressions.go
// Expression parsing functions for the SQL parser.

package parser

import (
	"fmt"

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
			models.Location{Line: 0, Column: 0},
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

// parseComparisonExpression parses an expression with comparison operators
func (p *Parser) parseComparisonExpression() (ast.Expression, error) {
	// Parse the left side using additive expression for arithmetic support
	left, err := p.parseAdditiveExpression()
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
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse BETWEEN lower bound: %v", err),
				models.Location{Line: 0, Column: 0},
				"",
			)
		}

		// Expect AND keyword
		if !p.isType(models.TokenTypeAnd) {
			return nil, p.expectedError("AND")
		}
		p.advance() // Consume AND

		// Parse upper bound
		upper, err := p.parsePrimaryExpression()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse BETWEEN upper bound: %v", err),
				models.Location{Line: 0, Column: 0},
				"",
			)
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
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse LIKE pattern: %v", err),
				models.Location{Line: 0, Column: 0},
				"",
			)
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
				return nil, goerrors.InvalidSyntaxError(
					fmt.Sprintf("failed to parse IN subquery: %v", err),
					models.Location{Line: 0, Column: 0},
					"",
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
			}, nil
		}

		// Parse value list
		var values []ast.Expression
		for {
			value, err := p.parseExpression()
			if err != nil {
				return nil, goerrors.InvalidSyntaxError(
					fmt.Sprintf("failed to parse IN value: %v", err),
					models.Location{Line: 0, Column: 0},
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
		}, nil
	}

	// If NOT was consumed but no BETWEEN/LIKE/IN follows, we need to handle this case
	// Put back the NOT by creating a NOT expression with left as the operand
	if notPrefix {
		return nil, goerrors.ExpectedTokenError(
			"BETWEEN, LIKE, or IN",
			"NOT",
			models.Location{Line: 0, Column: 0},
			"",
		)
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
				return nil, goerrors.InvalidSyntaxError(
					fmt.Sprintf("failed to parse %s subquery: %v", quantifier, err),
					models.Location{Line: 0, Column: 0},
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
		}, nil
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
		operator := p.currentToken.Literal
		p.advance() // Consume operator

		right, err := p.parseMultiplicativeExpression()
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

// parseMultiplicativeExpression parses expressions with *, /, and % operators
func (p *Parser) parseMultiplicativeExpression() (ast.Expression, error) {
	// Parse the left side using primary expression
	left, err := p.parsePrimaryExpression()
	if err != nil {
		return nil, err
	}

	// Handle *, /, and % operators (left-associative)
	// Note: TokenTypeAsterisk is used for both * (SELECT) and multiplication
	// We check context: after an expression, asterisk means multiplication
	for p.isType(models.TokenTypeAsterisk) || p.isType(models.TokenTypeMul) ||
		p.isType(models.TokenTypeDiv) || p.currentToken.Type == "%" {
		operator := p.currentToken.Literal
		p.advance() // Consume operator

		right, err := p.parsePrimaryExpression()
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

// parsePrimaryExpression parses a primary expression (literals, identifiers, function calls)
func (p *Parser) parsePrimaryExpression() (ast.Expression, error) {
	if p.isType(models.TokenTypeCase) {
		// Handle CASE expressions (both simple and searched forms)
		return p.parseCaseExpression()
	}

	if p.isType(models.TokenTypeIdentifier) || p.isType(models.TokenTypeDoubleQuotedString) {
		// Handle identifiers and function calls
		// Double-quoted strings are treated as identifiers in SQL (e.g., "column_name")
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

		// Handle regular identifier or qualified identifier (table.column or table.*)
		ident := &ast.Identifier{Name: identName}

		// Check for qualified identifier (table.column) or qualified asterisk (table.*)
		if p.isType(models.TokenTypePeriod) {
			p.advance() // Consume .
			if p.isType(models.TokenTypeAsterisk) {
				// Handle table.* (qualified asterisk)
				ident = &ast.Identifier{
					Table: ident.Name,
					Name:  "*",
				}
				p.advance()
			} else if p.isIdentifier() {
				// Handle table.column (qualified identifier)
				ident = &ast.Identifier{
					Table: ident.Name,
					Name:  p.currentToken.Literal,
				}
				p.advance()
			} else {
				return nil, goerrors.InvalidSyntaxError(
					"expected column name or * after table qualifier",
					p.currentLocation(),
					"Use table.column or table.* syntax",
				)
			}
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

	if p.isBooleanLiteral() {
		// Handle boolean literals (uses O(1) switch instead of O(n) isAnyType)
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
				return nil, goerrors.InvalidSyntaxError(
					fmt.Sprintf("failed to parse subquery: %v", err),
					models.Location{Line: 0, Column: 0},
					"",
				)
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
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse EXISTS subquery: %v", err),
				models.Location{Line: 0, Column: 0},
				"",
			)
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
				return nil, goerrors.InvalidSyntaxError(
					fmt.Sprintf("failed to parse NOT EXISTS subquery: %v", err),
					models.Location{Line: 0, Column: 0},
					"",
				)
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

	return nil, goerrors.UnexpectedTokenError(
		string(p.currentToken.Type),
		p.currentToken.Literal,
		models.Location{Line: 0, Column: 0},
		"",
	)
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
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse CASE value: %v", err),
				models.Location{Line: 0, Column: 0},
				"",
			)
		}
		caseExpr.Value = value
	}

	// Parse WHEN clauses (at least one required)
	for p.isType(models.TokenTypeWhen) {
		p.advance() // Consume WHEN

		// Parse the condition/value expression
		condition, err := p.parseExpression()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse WHEN condition: %v", err),
				models.Location{Line: 0, Column: 0},
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
				models.Location{Line: 0, Column: 0},
				"",
			)
		}

		caseExpr.WhenClauses = append(caseExpr.WhenClauses, ast.WhenClause{
			Condition: condition,
			Result:    result,
		})
	}

	// Check that we have at least one WHEN clause
	if len(caseExpr.WhenClauses) == 0 {
		return nil, goerrors.InvalidSyntaxError(
			"CASE expression requires at least one WHEN clause",
			models.Location{Line: 0, Column: 0},
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
				models.Location{Line: 0, Column: 0},
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

	return nil, goerrors.ExpectedTokenError(
		"SELECT or WITH",
		string(p.currentToken.Type),
		models.Location{Line: 0, Column: 0},
		"",
	)
}

// parseFunctionCall parses a function call with optional OVER clause for window functions.
//
// Examples:
//
//	COUNT(*) -> regular aggregate function
//	ROW_NUMBER() OVER (ORDER BY id) -> window function with OVER clause
