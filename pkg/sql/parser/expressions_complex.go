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
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
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

	// ClickHouse CAST(expr, 'Type'): the target type is a string argument.
	if !try && p.isType(models.TokenTypeComma) && p.dialect == string(keywords.DialectClickHouse) {
		return p.parseCastTypeString(expr)
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
	// - Quoted user-defined type: "my type", as :: accepts and SQL()
	//   renders a type name that is not a plain word
	if !p.isIdentifier() {
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
					"",
				).WithHint("Use CAST(expr AS TYPE(precision[, scale]))")
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

	// Multi-word types and array suffixes: DOUBLE PRECISION,
	// TIMESTAMP WITH TIME ZONE, SIGNED INTEGER, int[], text[][].
	dataType, err = p.parseCastTypeSuffix(dataType)
	if err != nil {
		return nil, err
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
// with an optional ANSI interval qualifier, or the MySQL numeric form.
//
// Examples:
//
//	INTERVAL '1 day'
//	INTERVAL '2 hours'
//	INTERVAL '1 year 2 months 3 days'
//	INTERVAL '30 days'
//	INTERVAL '1' DAY                (qualifier "DAY")
//	INTERVAL '1-2' YEAR TO MONTH    (qualifier "YEAR TO MONTH")
//	INTERVAL '1-2' YEAR_MONTH       (MySQL unit as qualifier)
//	INTERVAL 30 DAY                 (MySQL; ValueExpr 30, Unit DAY)
//	INTERVAL n DAY, INTERVAL -1 HOUR (MySQL, MariaDB, ClickHouse)
//	INTERVAL(5, 1, 10)              (MySQL/MariaDB function; a FunctionCall)
func (p *Parser) parseIntervalExpression() (ast.Expression, error) {
	intervalPos := p.currentLocation()
	// Consume INTERVAL keyword
	p.advance()

	// Support both PostgreSQL style: INTERVAL '1 day'
	// and MySQL style: INTERVAL 30 DAY, INTERVAL 1 HOUR
	if p.isStringLiteral() {
		value := p.currentToken.Token.Value
		p.advance()
		return &ast.IntervalExpression{Value: value, Qualifier: p.parseIntervalQualifier()}, nil
	}

	if !p.canStartIntervalValue() {
		return nil, goerrors.InvalidSyntaxError(
			"expected string literal or number after INTERVAL keyword",
			p.currentLocation(),
			"",
		).WithHint("Use INTERVAL '1 day' or INTERVAL 1 DAY syntax")
	}

	// MySQL/MariaDB INTERVAL(N, N1, N2, ...) returns the index of the last
	// Ni below N; INTERVAL (expr) DAY is still an interval.
	isCall := p.isType(models.TokenTypeLParen) &&
		(p.dialect == string(keywords.DialectMySQL) || p.dialect == string(keywords.DialectMariaDB))

	// Unquoted value: INTERVAL <expr> <unit>
	value, err := p.parseUnaryOperand()
	if err != nil {
		return nil, err
	}
	if unit := p.intervalUnit(); unit != "" {
		p.advance() // Consume the unit
		legacy := unit
		if lit, ok := value.(*ast.LiteralValue); ok && lit.Type != "string" {
			legacy = fmt.Sprint(lit.Value) + " " + unit
		} else if sq, ok := value.(interface{ SQL() string }); ok {
			legacy = sq.SQL() + " " + unit
		}
		return &ast.IntervalExpression{Value: legacy, ValueExpr: value, Unit: unit}, nil
	}
	if isCall {
		fc := &ast.FunctionCall{Name: "INTERVAL", Pos: intervalPos}
		switch v := value.(type) {
		case *ast.TupleExpression:
			fc.Arguments = append(fc.Arguments, v.Expressions...)
		case *ast.ParenthesizedExpression:
			fc.Arguments = append(fc.Arguments, v.Expr)
		default:
			return nil, p.expectedError("interval unit")
		}
		return fc, nil
	}
	return nil, goerrors.InvalidSyntaxError(
		"expected interval unit (DAY, HOUR, ...) after INTERVAL value",
		p.currentLocation(),
		"",
	).WithHint("Use INTERVAL '1 day' or INTERVAL 1 DAY syntax")
}

// canStartIntervalValue reports whether the current token can begin the
// unquoted value of INTERVAL <expr> <unit>.
func (p *Parser) canStartIntervalValue() bool {
	switch p.currentToken.Token.Type {
	case models.TokenTypeNumber, models.TokenTypeIdentifier, models.TokenTypeDoubleQuotedString,
		models.TokenTypeLParen, models.TokenTypeMinus, models.TokenTypePlus,
		models.TokenTypePlaceholder:
		return true
	}
	return false
}

// intervalUnit returns the upper-cased unit when the current token is an
// unquoted INTERVAL unit (DAY, YEAR_MONTH, or a plural such as DAYS), and ""
// otherwise. It does not consume the token.
func (p *Parser) intervalUnit() string {
	tok := p.currentToken.Token
	if tok.Quote != 0 || (tok.Type != models.TokenTypeIdentifier && tok.Type != models.TokenTypeKeyword) {
		return ""
	}
	u := strings.ToUpper(tok.Value)
	if isUnquotedIntervalUnit(u) || (len(u) > 1 && u[len(u)-1] == 'S' && isUnquotedIntervalUnit(u[:len(u)-1])) {
		return u
	}
	return ""
}

// isUnquotedIntervalUnit reports whether u (upper-case) is a unit of the
// unquoted INTERVAL <expr> <unit> form: any leading interval field, plus the
// ClickHouse NANOSECOND unit, which is not an ANSI interval qualifier.
func isUnquotedIntervalUnit(u string) bool {
	return intervalLeadingField(u) || u == "NANOSECOND"
}

// parseIntervalQualifier parses the optional interval qualifier that follows
// the quoted value of an INTERVAL literal and returns it upper-cased, or ""
// when the next token is not a unit. Only unquoted identifiers are units, so a
// quoted "day" stays a column alias, and plural words (DAYS) are not units. A
// trailing "TO <field>" is consumed only when <field> is a valid end field.
func (p *Parser) parseIntervalQualifier() string {
	if !p.isType(models.TokenTypeIdentifier) {
		return ""
	}
	q := strings.ToUpper(p.currentToken.Token.Value)
	if !intervalLeadingField(q) {
		return ""
	}
	p.advance() // Consume the leading field

	if p.isType(models.TokenTypeTo) ||
		(p.isType(models.TokenTypeKeyword) && equalsUpper(p.currentToken.Token.Value, "TO")) {
		next := p.peekToken()
		if next.Token.Type == models.TokenTypeIdentifier {
			end := strings.ToUpper(next.Token.Value)
			if intervalTrailingField(end) {
				p.advance() // Consume TO
				p.advance() // Consume the trailing field
				q += " TO " + end
			}
		}
	}
	return q
}

// intervalLeadingField reports whether u (upper-case) can start an interval
// qualifier: an ANSI datetime field or a MySQL interval unit.
func intervalLeadingField(u string) bool {
	switch u {
	case "YEAR", "MONTH", "DAY", "HOUR", "MINUTE", "SECOND",
		"WEEK", "QUARTER", "MICROSECOND", "MILLISECOND",
		"SECOND_MICROSECOND", "MINUTE_MICROSECOND", "MINUTE_SECOND",
		"HOUR_MICROSECOND", "HOUR_SECOND", "HOUR_MINUTE",
		"DAY_MICROSECOND", "DAY_SECOND", "DAY_MINUTE", "DAY_HOUR",
		"YEAR_MONTH":
		return true
	}
	return false
}

// intervalTrailingField reports whether u (upper-case) can end an ANSI
// "<start> TO <end>" interval qualifier.
func intervalTrailingField(u string) bool {
	switch u {
	case "MONTH", "HOUR", "MINUTE", "SECOND":
		return true
	}
	return false
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
				var elem ast.Expression
				var err error
				if p.isType(models.TokenTypeLBracket) {
					// Nested row of a multi-dimensional array: ARRAY[[1, 2], [3, 4]]
					elem, err = p.parseNestedBracketArray()
				} else {
					elem, err = p.parseExpression()
				}
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

		if selectStmt, ok := subquery.(*ast.SelectStatement); ok {
			arrayExpr.Subquery = selectStmt
		} else {
			// ARRAY(SELECT 1 UNION SELECT 2)
			arrayExpr.Query = subquery
		}

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
	arrayExpr.Bracket = true

	if !p.isType(models.TokenTypeRBracket) {
		for {
			var elem ast.Expression
			var err error
			if p.isType(models.TokenTypeLBracket) {
				elem, err = p.parseNestedBracketArray()
			} else {
				elem, err = p.parseExpression()
			}
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

// parseExtractExpression parses EXTRACT(field FROM source).
//
// SQL standard syntax:
//
//	EXTRACT(YEAR FROM created_at)
//	EXTRACT(MONTH FROM order_date)
//	EXTRACT(DOW FROM timestamp_col)
//
// The field is a date/time part keyword (YEAR, MONTH, DAY, HOUR, MINUTE,
// SECOND, DOW, DOY, EPOCH, QUARTER, WEEK, etc.). It is captured as a
// plain string rather than an enum to accommodate dialect extensions.
func (p *Parser) parseExtractExpression() (ast.Expression, error) {
	// ClickHouse extract(haystack, pattern) is the regular-expression
	// function, not EXTRACT(field FROM source).
	if p.dialect == string(keywords.DialectClickHouse) && p.tokenAt(3).Token.Type != models.TokenTypeFrom {
		return p.parseKeywordFunctionCall()
	}
	p.advance() // Consume EXTRACT

	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("( after EXTRACT")
	}
	p.advance() // Consume (

	// Field: typically a keyword like YEAR, MONTH, DAY, etc.
	field := strings.ToUpper(p.currentToken.Token.Value)
	if field == "" {
		return nil, p.expectedError("date/time field (YEAR, MONTH, DAY, etc.)")
	}
	p.advance() // Consume field

	// FROM keyword
	if !p.isType(models.TokenTypeFrom) {
		return nil, p.expectedError("FROM after EXTRACT field")
	}
	p.advance() // Consume FROM

	// Source expression
	source, err := p.parseExpression()
	if err != nil {
		return nil, goerrors.InvalidSyntaxError(
			fmt.Sprintf("EXTRACT source: %v", err),
			p.currentLocation(),
			"",
		).WithCause(err)
	}

	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") after EXTRACT expression")
	}
	p.advance() // Consume )

	return &ast.ExtractExpression{
		Field:  field,
		Source: source,
	}, nil
}
