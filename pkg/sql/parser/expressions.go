// Package parser - expressions.go
// Expression parsing functions for the SQL parser.

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
		nextUpper := strings.ToUpper(nextToken.Literal)
		if nextUpper == "BETWEEN" || nextUpper == "LIKE" || nextUpper == "ILIKE" || nextUpper == "IN" {
			notPrefix = true
			p.advance() // Consume NOT only if followed by valid operator
		}
	}

	// Check for BETWEEN operator
	if p.isType(models.TokenTypeBetween) {
		p.advance() // Consume BETWEEN

		// Parse lower bound - use parseStringConcatExpression to support complex expressions
		// like: price BETWEEN price * 0.9 AND price * 1.1
		lower, err := p.parseStringConcatExpression()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse BETWEEN lower bound: %v", err),
				p.currentLocation(),
				p.currentToken.Literal,
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
				p.currentToken.Literal,
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
	if p.isType(models.TokenTypeLike) || strings.EqualFold(p.currentToken.Literal, "ILIKE") {
		operator := p.currentToken.Literal
		p.advance() // Consume LIKE/ILIKE

		// Parse pattern
		pattern, err := p.parsePrimaryExpression()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse LIKE pattern: %v", err),
				p.currentLocation(),
				p.currentToken.Literal,
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
					p.currentLocation(),
					p.currentToken.Literal,
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
			quantifier := p.currentToken.Literal
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

// parseStringConcatExpression parses expressions with || (string concatenation) operator
func (p *Parser) parseStringConcatExpression() (ast.Expression, error) {
	// Parse the left side using additive expression
	left, err := p.parseAdditiveExpression()
	if err != nil {
		return nil, err
	}

	// Handle || (string concatenation) operator (left-associative)
	for p.isType(models.TokenTypeStringConcat) {
		operator := p.currentToken.Literal
		p.advance() // Consume ||

		right, err := p.parseAdditiveExpression()
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
		operator := p.currentToken.Literal
		p.advance() // Consume operator

		right, err := p.parseJSONExpression()
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
		operator := p.currentToken.Literal
		operatorType := p.currentToken.ModelType
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
	sb.WriteString(p.currentToken.Literal)
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
				sb.WriteString(p.currentToken.Literal)
				p.advance() // Consume comma
			}

			// Parse parameter (should be a number or identifier)
			// Use token type constants for consistency
			if !p.isType(models.TokenTypeNumber) && !p.isType(models.TokenTypeIdentifier) && !p.isNumericLiteral() {
				return "", goerrors.InvalidSyntaxError(
					fmt.Sprintf("expected numeric type parameter, got '%s'", p.currentToken.Literal),
					p.currentLocation(),
					"Use TYPE(precision[, scale]) syntax",
				)
			}

			sb.WriteString(p.currentToken.Literal)
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
	if p.currentToken.ModelType != modelTypeUnset {
		return p.currentToken.ModelType == models.TokenTypeNumber
	}
	// String fallback for tokens created without ModelType
	switch p.currentToken.Type {
	case "INT", "NUMBER", "FLOAT":
		return true
	}
	return false
}

// isDataTypeKeyword checks if current token is a SQL data type keyword
func (p *Parser) isDataTypeKeyword() bool {
	// Check ModelType for known data type tokens
	switch p.currentToken.ModelType {
	case models.TokenTypeInt, models.TokenTypeInteger, models.TokenTypeVarchar,
		models.TokenTypeText, models.TokenTypeBoolean, models.TokenTypeFloat,
		models.TokenTypeInterval:
		return true
	}
	// Fallback: check literal for data type keywords not all represented in models
	switch strings.ToUpper(p.currentToken.Literal) {
	case "INT", "INTEGER", "BIGINT", "SMALLINT", "FLOAT", "DOUBLE", "DECIMAL",
		"NUMERIC", "VARCHAR", "CHAR", "TEXT", "BOOLEAN", "DATE", "TIME",
		"TIMESTAMP", "INTERVAL", "BLOB", "CLOB", "JSON", "UUID":
		return true
	}
	return false
}

// isJSONOperator checks if current token is a JSON/JSONB operator
func (p *Parser) isJSONOperator() bool {
	switch p.currentToken.ModelType {
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

// parsePrimaryExpression parses a primary expression (literals, identifiers, function calls)
func (p *Parser) parsePrimaryExpression() (ast.Expression, error) {
	if p.isType(models.TokenTypeCase) {
		// Handle CASE expressions (both simple and searched forms)
		return p.parseCaseExpression()
	}

	if p.isType(models.TokenTypeCast) {
		// Handle CAST(expr AS type) expressions
		return p.parseCastExpression()
	}

	if p.isType(models.TokenTypeInterval) {
		// Handle INTERVAL 'value' expressions
		return p.parseIntervalExpression()
	}

	if p.isType(models.TokenTypeArray) {
		// Handle ARRAY[...] or ARRAY(SELECT ...) constructor
		return p.parseArrayConstructor()
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

		// Check for array subscript or slice syntax: identifier[...]
		// This handles: arr[1], arr[1][2], arr[1:3], arr[2:], arr[:5]
		if p.isType(models.TokenTypeLBracket) {
			return p.parseArrayAccessExpression(ident)
		}

		return ident, nil
	}

	if p.isType(models.TokenTypeAsterisk) {
		// Handle asterisk (e.g., in COUNT(*) or SELECT *)
		p.advance()
		return &ast.Identifier{Name: "*"}, nil
	}

	if p.isStringLiteral() {
		// Handle string literals
		value := p.currentToken.Literal
		p.advance()
		return &ast.LiteralValue{Value: value, Type: "string"}, nil
	}

	if p.isNumericLiteral() {
		// Handle numeric literals (int or float)
		value := p.currentToken.Literal
		litType := "int"
		if strings.ContainsAny(value, ".eE") {
			litType = "float"
		}
		p.advance()
		return &ast.LiteralValue{Value: value, Type: litType}, nil
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

		// Regular parenthesized expression - could be tuple (a, b, c) or single (expr)
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}

		// Check if this is a tuple (has comma after first expression)
		if p.isType(models.TokenTypeComma) {
			// This is a tuple expression (col1, col2, ...)
			tuple := ast.GetTupleExpression()
			tuple.Expressions = append(tuple.Expressions, expr)

			for p.isType(models.TokenTypeComma) {
				p.advance() // Consume comma
				nextExpr, err := p.parseExpression()
				if err != nil {
					return nil, err
				}
				tuple.Expressions = append(tuple.Expressions, nextExpr)
			}

			if !p.isType(models.TokenTypeRParen) {
				return nil, p.expectedError(")")
			}
			p.advance() // Consume )
			return tuple, nil
		}

		// Expect closing parenthesis for single expression
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )

		// Check for array subscript or slice on parenthesized expression
		// This handles: (expr)[1], (SELECT arr)[2:3]
		if p.isType(models.TokenTypeLBracket) {
			return p.parseArrayAccessExpression(expr)
		}

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

// parseCastExpression parses a CAST expression: CAST(expr AS type)
//
// Examples:
//
//	CAST(id AS VARCHAR)
//	CAST(price AS DECIMAL(10,2))
//	CAST(name AS VARCHAR(100))
func (p *Parser) parseCastExpression() (*ast.CastExpression, error) {
	// Consume CAST keyword
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

	dataType := p.currentToken.Literal
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
				typeParams += p.currentToken.Literal
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

			typeParams += p.currentToken.Literal
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

	// Expect a string literal for the interval value
	if !p.isStringLiteral() {
		return nil, goerrors.InvalidSyntaxError(
			"expected string literal after INTERVAL keyword",
			p.currentLocation(),
			"Use INTERVAL 'value' syntax (e.g., INTERVAL '1 day')",
		)
	}

	value := p.currentToken.Literal
	p.advance() // Consume the string literal

	return &ast.IntervalExpression{
		Value: value,
	}, nil
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
