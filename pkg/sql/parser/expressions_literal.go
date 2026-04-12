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

// Package parser - expressions_literal.go
// Primary expression parsing: literals, identifiers, qualified names, subqueries,
// and parenthesized expressions.

package parser

import (
	"fmt"
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parsePrimaryExpression parses a primary expression (literals, identifiers, function calls)
func (p *Parser) parsePrimaryExpression() (ast.Expression, error) {
	// Handle unary minus/plus (-6, -3.14, +x)
	if p.isType(models.TokenTypeMinus) || p.isType(models.TokenTypePlus) {
		unaryPos := p.currentLocation()
		var op ast.UnaryOperator
		if p.isType(models.TokenTypeMinus) {
			op = ast.Minus
		} else {
			op = ast.Plus
		}
		p.advance() // Consume -/+
		expr, err := p.parsePrimaryExpression()
		if err != nil {
			return nil, err
		}
		return &ast.UnaryExpression{
			Operator: op,
			Expr:     expr,
			Pos:      unaryPos,
		}, nil
	}

	if p.isType(models.TokenTypeCase) {
		// Handle CASE expressions (both simple and searched forms)
		return p.parseCaseExpression()
	}

	if p.isType(models.TokenTypeCast) {
		// Handle CAST(expr AS type) expressions
		return p.parseCastExpression()
	}

	// TRY_CAST(expr AS type) — Snowflake, SQL Server, BigQuery. Tokenized as
	// an identifier (the snowflake keyword table is not wired into the
	// tokenizer); detect by name when followed by '('.
	if (p.isType(models.TokenTypeIdentifier) || p.isType(models.TokenTypeKeyword)) &&
		strings.EqualFold(p.currentToken.Token.Value, "TRY_CAST") &&
		p.peekToken().Token.Type == models.TokenTypeLParen {
		return p.parseTryCastExpression()
	}

	if p.isType(models.TokenTypeInterval) {
		// Handle INTERVAL 'value' expressions
		return p.parseIntervalExpression()
	}

	if p.isType(models.TokenTypeArray) {
		// Handle ARRAY[...] or ARRAY(SELECT ...) constructor
		return p.parseArrayConstructor()
	}

	// ClickHouse array literal: [expr, expr, ...] without the ARRAY keyword.
	// Gated to ClickHouse to avoid colliding with subscript-style usage in other
	// dialects.
	if p.isType(models.TokenTypeLBracket) && p.dialect == string(keywords.DialectClickHouse) {
		return p.parseBracketArrayLiteral()
	}

	// Handle MySQL VALUES(column) helper in ON DUPLICATE KEY UPDATE.
	// VALUES is normally a DML keyword, but inside ON DUPLICATE KEY UPDATE it acts
	// as a scalar function that returns the value that was attempted for insertion.
	// e.g.: INSERT INTO t (id, name) VALUES (1, 'Alice') ON DUPLICATE KEY UPDATE name=VALUES(name)
	if p.isType(models.TokenTypeValues) && p.peekToken().Token.Type == models.TokenTypeLParen {
		valuesPos := p.currentLocation()
		p.advance() // Consume VALUES
		funcCall, err := p.parseFunctionCall("VALUES")
		if err != nil {
			return nil, err
		}
		if funcCall.Pos.IsZero() {
			funcCall.Pos = valuesPos
		}
		return funcCall, nil
	}

	// Handle keywords that can be used as function names (IF, REPLACE, FIRST, LAST, etc.)
	if (p.isType(models.TokenTypeIf) || p.isType(models.TokenTypeReplace) ||
		p.isType(models.TokenTypeFirst) || p.isType(models.TokenTypeLast)) && p.peekToken().Token.Type == models.TokenTypeLParen {
		kwPos := p.currentLocation()
		identName := p.currentToken.Token.Value
		p.advance()
		funcCall, err := p.parseFunctionCall(identName)
		if err != nil {
			return nil, err
		}
		if funcCall.Pos.IsZero() {
			funcCall.Pos = kwPos
		}
		return funcCall, nil
	}

	// EXTRACT(field FROM source) — SQL standard date/time extraction.
	// Tokenized as an identifier; detect by name when followed by '('.
	if (p.isType(models.TokenTypeIdentifier) || p.isType(models.TokenTypeKeyword)) &&
		strings.EqualFold(p.currentToken.Token.Value, "EXTRACT") &&
		p.peekToken().Token.Type == models.TokenTypeLParen {
		return p.parseExtractExpression()
	}

	// Oracle/MariaDB pseudo-columns: ROWNUM, ROWID, LEVEL, SYSDATE, SYSTIMESTAMP.
	// These are tokenized as keywords but act as column-like expressions.
	// We return them as zero-argument FunctionCall nodes so that implicit
	// aliasing works naturally (SELECT ROWNUM rn → AliasedExpression) and
	// they don't collide with the bare-Identifier alias guard.
	if p.isType(models.TokenTypeKeyword) && p.isOraclePseudoColumn() {
		identPos := p.currentLocation()
		identName := p.currentToken.Token.Value
		p.advance()
		// SYSDATE() / SYSTIMESTAMP() — some drivers allow parens
		if p.isType(models.TokenTypeLParen) {
			funcCall, err := p.parseFunctionCall(identName)
			if err != nil {
				return nil, err
			}
			if funcCall.Pos.IsZero() {
				funcCall.Pos = identPos
			}
			return funcCall, nil
		}
		return &ast.FunctionCall{Name: identName, Pos: identPos}, nil
	}

	if p.isType(models.TokenTypeIdentifier) || p.isType(models.TokenTypeDoubleQuotedString) || ((p.dialect == string(keywords.DialectSQLServer) || p.dialect == string(keywords.DialectClickHouse)) && p.isNonReservedKeyword()) {
		// Handle identifiers and function calls
		// Double-quoted strings are treated as identifiers in SQL (e.g., "column_name")
		// Non-reserved keywords (TARGET, SOURCE, etc.) can also be used as identifiers
		identPos := p.currentLocation()
		identName := p.currentToken.Token.Value
		p.advance()

		// Check for function call (identifier followed by parentheses)
		if p.isType(models.TokenTypeLParen) {
			// This is a function call
			funcCall, err := p.parseFunctionCall(identName)
			if err != nil {
				return nil, err
			}
			// Assign position of function name
			if funcCall.Pos.IsZero() {
				funcCall.Pos = identPos
			}

			// MySQL MATCH(...) AGAINST(...) full-text search
			if strings.EqualFold(identName, "MATCH") && strings.EqualFold(p.currentToken.Token.Value, "AGAINST") {
				return p.parseMatchAgainst(funcCall)
			}

			return funcCall, nil
		}

		// Handle regular identifier or qualified identifier (table.column or table.*)
		ident := &ast.Identifier{Name: identName, Pos: identPos}

		// Check for qualified identifier (table.column) or qualified asterisk (table.*)
		if p.isType(models.TokenTypePeriod) {
			p.advance() // Consume .
			if p.isType(models.TokenTypeAsterisk) || p.isType(models.TokenTypeMul) {
				// Handle table.* (qualified asterisk).
				// Both TokenTypeAsterisk and TokenTypeMul represent '*'.
				ident = &ast.Identifier{
					Table: ident.Name,
					Name:  "*",
					Pos:   identPos,
				}
				p.advance()
			} else if p.isIdentifier() || p.isNonReservedKeyword() {
				// Handle table.column (qualified identifier).
				// isNonReservedKeyword covers reserved words valid as column
				// names after a dot, e.g. table.KEY, schema.INDEX, alias.VIEW.
				ident = &ast.Identifier{
					Table: ident.Name,
					Name:  p.currentToken.Token.Value,
					Pos:   identPos,
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

	if p.isType(models.TokenTypeAsterisk) || p.isType(models.TokenTypeMul) {
		// Handle asterisk (e.g., in COUNT(*) or SELECT *).
		// Both TokenTypeAsterisk and TokenTypeMul represent '*' from the tokenizer.
		p.advance()
		return &ast.Identifier{Name: "*"}, nil
	}

	if p.isStringLiteral() {
		// Handle string literals
		value := p.currentToken.Token.Value
		p.advance()
		return &ast.LiteralValue{Value: value, Type: "string"}, nil
	}

	if p.isNumericLiteral() {
		// Handle numeric literals (int or float)
		value := p.currentToken.Token.Value
		litType := "int"
		if strings.ContainsAny(value, ".eE") {
			litType = "float"
		}
		p.advance()
		return &ast.LiteralValue{Value: value, Type: litType}, nil
	}

	if p.isBooleanLiteral() {
		// Handle boolean literals (uses O(1) switch instead of O(n) isAnyType)
		value := p.currentToken.Token.Value
		p.advance()
		return &ast.LiteralValue{Value: value, Type: "bool"}, nil
	}

	if p.isType(models.TokenTypePlaceholder) {
		// Handle SQL placeholders (e.g., $1, $2 for PostgreSQL; @param for SQL Server)
		value := p.currentToken.Token.Value
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
		parenPos := p.currentLocation()
		p.advance() // Consume (

		// Check if this is a subquery (starts with SELECT or WITH)
		if p.isType(models.TokenTypeSelect) || p.isType(models.TokenTypeWith) {
			// Parse subquery
			subquery, err := p.parseSubquery()
			if err != nil {
				return nil, goerrors.InvalidSyntaxError(
					fmt.Sprintf("failed to parse subquery: %v", err),
					p.currentLocation(),
					"",
				)
			}
			// Expect closing parenthesis
			if !p.isType(models.TokenTypeRParen) {
				return nil, p.expectedError(")")
			}
			p.advance() // Consume )
			return &ast.SubqueryExpression{Subquery: subquery, Pos: parenPos}, nil
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
				p.currentLocation(),
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
		notPos := p.currentLocation()
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
					p.currentLocation(),
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
				Pos:      notPos,
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
			Pos:      notPos,
		}, nil
	}

	return nil, goerrors.UnexpectedTokenError(
		p.currentToken.Token.Type.String(),
		p.currentToken.Token.Value,
		p.currentLocation(),
		"",
	)
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
		p.currentToken.Token.Type.String(),
		p.currentLocation(),
		"",
	)
}
