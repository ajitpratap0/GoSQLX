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
		expr, err := p.parseUnaryOperand()
		if err != nil {
			return nil, err
		}
		return &ast.UnaryExpression{
			Operator: op,
			Expr:     expr,
			Pos:      unaryPos,
		}, nil
	}

	// Bitwise NOT (~a: MySQL, PostgreSQL, SQL Server, SQLite) and MySQL's !a,
	// a synonym of NOT with a higher precedence.
	if p.isType(models.TokenTypeTilde) || (p.isType(models.TokenTypeExclamationMark) && p.isMySQLFamily()) {
		unaryPos := p.currentLocation()
		op := ast.PGBitwiseNot
		if p.isType(models.TokenTypeExclamationMark) {
			op = ast.BangNot
		}
		p.advance() // Consume ~ / !
		expr, err := p.parseUnaryOperand()
		if err != nil {
			return nil, err
		}
		return &ast.UnaryExpression{Operator: op, Expr: expr, Pos: unaryPos}, nil
	}

	// PostgreSQL prefix operators |/ (square root), ||/ (cube root), !! (factorial)
	// and @ (absolute value).
	if op, n := p.pgPrefixOperator(); n > 0 {
		unaryPos := p.currentLocation()
		for i := 0; i < n; i++ {
			p.advance() // Consume the operator token(s)
		}
		// These are "any other operator" in PostgreSQL, which binds looser
		// than + and -: |/ a + 1 is |/ (a + 1).
		expr, err := p.parseOtherOperatorOperand()
		if err != nil {
			return nil, err
		}
		return &ast.UnaryExpression{Operator: op, Expr: expr, Pos: unaryPos}, nil
	}

	// MySQL / MariaDB BINARY expr: casts the operand to a binary string.
	if p.isMySQLBinaryOperator() {
		unaryPos := p.currentLocation()
		p.advance() // Consume BINARY
		expr, err := p.parseUnaryOperand()
		if err != nil {
			return nil, err
		}
		return &ast.UnaryExpression{Operator: ast.MySQLBinary, Expr: expr, Pos: unaryPos}, nil
	}

	// CONNECT BY: PRIOR is a prefix operator that binds to its operand, so
	// "PRIOR a + 1" is "(PRIOR a) + 1" (#783).
	if p.inConnectBy && p.isConnectByPrior() {
		priorPos := p.currentLocation()
		p.advance() // Consume PRIOR
		operand, err := p.parseUnaryOperand()
		if err != nil {
			return nil, err
		}
		return &ast.UnaryExpression{Operator: ast.Prior, Expr: operand, Pos: priorPos}, nil
	}

	if lit, ok := p.parsePrefixedStringLiteral(); ok {
		return lit, nil
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

	// ClickHouse / Snowflake array literal: [expr, expr, ...] without the
	// ARRAY keyword, optionally subscripted: [1, 2, 3][2]. Gated to those
	// dialects to avoid colliding with bracket-quoted names elsewhere.
	if p.isType(models.TokenTypeLBracket) && p.hasBracketArrayLiterals() {
		return p.parseBracketArrayPrimary()
	}

	// Snowflake object constant {'k': v, ...}.
	if p.isType(models.TokenTypeLBrace) && p.dialect == string(keywords.DialectSnowflake) {
		return p.parseObjectLiteral()
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

	if p.isType(models.TokenTypeIdentifier) || p.isType(models.TokenTypeDoubleQuotedString) || p.isKeywordColumnName() || ((p.dialect == string(keywords.DialectSQLServer) || p.dialect == string(keywords.DialectClickHouse)) && p.isNonReservedKeyword()) {
		// Handle identifiers and function calls
		// Double-quoted strings are treated as identifiers in SQL (e.g., "column_name")
		// Non-reserved keywords (TARGET, SOURCE, etc.) can also be used as identifiers
		// Typed literal: DATE '2024-01-01', inet '10.0.0.1' (PostgreSQL).
		if p.isTypedLiteralStart() {
			return p.parseTypedLiteral(), nil
		}
		// Oracle CONNECT_BY_ROOT expr, and PRIOR expr in the select list.
		if p.isHierarchicalOperator() {
			return p.parseHierarchicalOperator()
		}

		identPos := p.currentLocation()
		identName := p.currentToken.Token.Value
		identQuote := p.currentIdentQuote()
		var identQuotes ast.NameQuote
		if p.nameQuoteRelevant(identQuote) {
			identQuotes = p.appendNamePartQuoted(0, identQuote)
		}
		p.advance()

		// Check for function call (identifier followed by parentheses)
		if p.isType(models.TokenTypeLParen) {
			// Oracle outer-join marker: col(+)
			if p.isOuterJoinMarker() {
				return p.parseOuterJoinMarker(&ast.Identifier{Name: identName, Pos: identPos, Quoted: identQuote == '"', QuoteStyle: identQuote, Quotes: identQuotes}), nil
			}
			// This is a function call
			funcCall, err := p.parseFunctionCall(identName)
			if err != nil {
				return nil, err
			}
			funcCall.NameQuote = identQuotes
			// Assign position of function name
			if funcCall.Pos.IsZero() {
				funcCall.Pos = identPos
			}

			// MySQL MATCH(...) AGAINST(...) full-text search
			if strings.EqualFold(identName, "MATCH") && strings.EqualFold(p.currentToken.Token.Value, "AGAINST") {
				return p.parseMatchAgainst(funcCall)
			}

			// Subscript or slice on the call result: groupArray(x)[1],
			// quantiles(0.5, 0.9)(x)[1] (#605). Mirrors identifier[...] below.
			// SQLite tokenizes [name] as LBRACKET, where it is a bracket-quoted
			// alias (count(*) [cnt]), so it is not treated as a subscript there.
			if p.isType(models.TokenTypeLBracket) && p.dialect != string(keywords.DialectSQLite) {
				return p.parseArrayAccessExpression(funcCall)
			}

			return funcCall, nil
		}

		// Handle regular identifier or qualified identifier (table.column or table.*)
		ident := &ast.Identifier{Name: identName, Pos: identPos, Quoted: identQuote == '"', QuoteStyle: identQuote, Quotes: identQuotes}

		// Check for qualified identifier (table.column) or qualified asterisk (table.*)
		if p.isType(models.TokenTypePeriod) {
			p.advance() // Consume .
			if p.isType(models.TokenTypeAsterisk) || p.isType(models.TokenTypeMul) {
				// Handle table.* (qualified asterisk).
				// Both TokenTypeAsterisk and TokenTypeMul represent '*'.
				// ident has not escaped yet, so promote it in place
				// (one allocation per qualified reference). Pos is already identPos.
				ident.Table = ident.Name
				ident.Name = "*"
				ident.Quoted = false
				ident.Quotes = ident.Quotes.AppendPart(false)
				p.advance()
			} else if p.isQualifiedNamePart() {
				// Handle table.column (qualified identifier).
				// isNonReservedKeyword covers reserved words valid as column
				// names after a dot, e.g. table.KEY, schema.INDEX, alias.VIEW.
				// ClickHouse also allows numeric element access: d.1, tuple.2.
				// ident has not escaped yet, so promote it in place; Table must
				// be copied from Name before Name is overwritten.
				ident.Table = ident.Name
				ident.Name = p.currentToken.Token.Value
				q := p.currentIdentQuote()
				ident.Quoted = q == '"'
				if q != 0 {
					ident.QuoteStyle = q
				}
				if ident.Quotes != 0 || p.nameQuoteRelevant(q) {
					ident.Quotes = p.appendNamePartQuoted(ident.Quotes, q)
				}
				p.advance()

				// Multi-part reference: db.table.column (MySQL/MariaDB),
				// catalog.schema.table.column (PostgreSQL, SQL Server, Snowflake).
				// Every qualifier is folded into Table as a dotted string, mirroring
				// TableReference.Name ("db.table"), so Table + "." + Name always
				// reproduces the source reference. Only reached with 3+ parts, so the
				// two-part path stays single-allocation.
				if p.isType(models.TokenTypePeriod) {
					if err := p.parseMultiPartColumnRef(ident); err != nil {
						return nil, err
					}
				}
			} else {
				return nil, goerrors.InvalidSyntaxError(
					"expected column name or * after table qualifier (use table.column or table.*)",
					p.currentLocation(),
					"",
				)
			}
		}

		if p.isType(models.TokenTypeLParen) {
			// Oracle outer-join marker: t.col(+)
			if p.isOuterJoinMarker() {
				return p.parseOuterJoinMarker(ident), nil
			}
			// Qualified function call: pg_catalog.now(), pkg.fn(1)
			if ident.Table != "" && ident.Name != "*" {
				return p.parseQualifiedFunctionCall(ident)
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
		return p.parseStringLiteralExpr(), nil
	}

	if p.isNumericLiteral() {
		// Handle numeric literals (int or float)
		value := p.currentToken.Token.Value
		p.advance()
		return &ast.LiteralValue{Value: value, Type: numericLiteralType(value)}, nil
	}

	if p.isBooleanLiteral() {
		// Handle boolean literals (uses O(1) switch instead of O(n) isAnyType)
		value := p.currentToken.Token.Value
		p.advance()
		return &ast.LiteralValue{Value: value, Type: "bool"}, nil
	}

	if p.isType(models.TokenTypePlaceholder) {
		// Handle SQL placeholders (e.g., $1, $2 for PostgreSQL; @param for
		// SQL Server; ? for MySQL/MariaDB/SQLite; :1, :name for Oracle)
		value := p.currentToken.Token.Value
		p.advance()
		if p.IsSQLServer() && isMoneyPrefix(value) && p.peekMoneyFraction() {
			// SQL Server money literal $5.00: the tokenizer reads "$5" as a
			// placeholder and ".00" as a separate number.
			p.advance() // Consume .
			value += "." + p.currentToken.Token.Value
			p.advance() // Consume the fraction
			return &ast.LiteralValue{Value: value, Type: "money"}, nil
		}
		ph := &ast.LiteralValue{Value: value, Type: "placeholder"}
		// MySQL user-variable assignment: @rownum := @rownum + 1
		if p.isVariableAssignment() {
			return p.parseVariableAssignment(ph)
		}
		return ph, nil
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
			return p.parseCompositeIndirection(&ast.SubqueryExpression{Subquery: subquery, Pos: parenPos})
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
			return p.parseCompositeIndirection(tuple)
		}

		// Expect closing parenthesis for single expression
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )

		// Preserve grouping for a single parenthesized expression. Without this
		// node the parentheses are dropped and AND/OR precedence changes on
		// re-render, e.g. `(a OR b) AND c` → `a OR b AND c` (see #519).
		// Keep the wrapper before subscripts too: `(a)[1].c` must not become
		// `a[1].c`, and `(a + b)[1]` must retain its operand grouping.
		return p.parseCompositeIndirection(&ast.ParenthesizedExpression{Expr: expr, Pos: parenPos})
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
		expr, err := p.parseNotOperand()
		if err != nil {
			return nil, err
		}
		return &ast.UnaryExpression{
			Operator: ast.Not,
			Expr:     expr,
			Pos:      notPos,
		}, nil
	}

	if expr, err := p.parsePrimaryFallback(); expr != nil || err != nil {
		return expr, err
	}
	return nil, p.errUnexpectedPrimary()
}

// isConnectByPrior reports whether the current token is the PRIOR operator
// rather than a column that happens to be named prior.
func (p *Parser) isConnectByPrior() bool {
	// Only a bare word counts: a string literal 'prior' or a quoted
	// identifier "PRIOR" is an ordinary operand.
	if p.currentToken.Token.Quote != 0 ||
		!(p.isType(models.TokenTypeIdentifier) || p.isType(models.TokenTypeKeyword)) ||
		!strings.EqualFold(p.currentToken.Token.Value, "PRIOR") {
		return false
	}
	switch p.peekToken().Token.Type {
	case models.TokenTypeEq, models.TokenTypeNeq, models.TokenTypeLt, models.TokenTypeGt,
		models.TokenTypeLtEq, models.TokenTypeGtEq, models.TokenTypeDot,
		models.TokenTypeRParen, models.TokenTypeComma, models.TokenTypeSemicolon,
		models.TokenTypeEOF:
		return false
	}
	return true
}

// parseUnaryOperand parses the operand of a unary minus or plus one recursion
// level deeper, so a long run of prefix operators is bounded by
// MaxRecursionDepth like nested parentheses are.
func (p *Parser) parseUnaryOperand() (ast.Expression, error) {
	err := p.enterRecursion()
	defer p.leaveRecursion()
	if err != nil {
		return nil, err
	}
	return p.parsePrimaryExpression()
}

// parseNotOperand parses the operand of a boolean NOT one recursion level
// deeper, so a long run of NOT keywords is bounded by MaxRecursionDepth.
func (p *Parser) parseNotOperand() (ast.Expression, error) {
	err := p.enterRecursion()
	defer p.leaveRecursion()
	if err != nil {
		return nil, err
	}
	return p.parseComparisonExpression()
}

// parseSubquery parses a nested subquery (SELECT or WITH statement), such as
// an IN/EXISTS/scalar subquery. Expects current token to be SELECT or WITH.
// A nested scope never ends at a DML RETURNING clause, so the INSERT-source
// RETURNING stop is cleared for its duration (#610).
func (p *Parser) parseSubquery() (ast.Statement, error) {
	prev := p.dmlReturning
	p.dmlReturning = false
	// PRIOR is not valid inside a subquery of a CONNECT BY condition.
	prevConnectBy := p.inConnectBy
	p.inConnectBy = false
	defer func() { p.dmlReturning = prev; p.inConnectBy = prevConnectBy }()
	return p.parseQuerySource()
}

// parseQuerySource parses a SELECT or WITH statement without changing the
// DML RETURNING context.
func (p *Parser) parseQuerySource() (ast.Statement, error) {
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

// maxColumnRefParts caps the number of dot-separated parts in a column
// reference. Five covers the longest form any supported dialect accepts
// (SQL Server server.database.schema.table.column).
const maxColumnRefParts = 5

// parseMultiPartColumnRef continues a qualified column reference whose first
// two parts are already in ident (Table, Name) and whose current token is the
// third '.'. The parts are collected and joined once, so the cost is linear in
// the input, and references longer than maxColumnRefParts are rejected.
func (p *Parser) parseMultiPartColumnRef(ident *ast.Identifier) error {
	var parts [maxColumnRefParts]string
	parts[0], parts[1] = ident.Table, ident.Name
	n := 2
	lastQuoted := ident.Quoted
	for p.isType(models.TokenTypePeriod) {
		p.advance() // Consume .
		if n == maxColumnRefParts {
			return goerrors.InvalidSyntaxError(
				fmt.Sprintf("qualified column reference has more than %d parts", maxColumnRefParts),
				p.currentLocation(),
				"",
			)
		}
		switch {
		case p.isType(models.TokenTypeAsterisk) || p.isType(models.TokenTypeMul):
			parts[n] = "*"
			lastQuoted = false
			ident.Quotes = ident.Quotes.AppendPart(false)
			n++
			p.advance()
			if p.isType(models.TokenTypePeriod) {
				return p.expectedError("end of qualified name after *")
			}
		case p.isQualifiedNamePart():
			parts[n] = p.currentToken.Token.Value
			q := p.currentIdentQuote()
			lastQuoted = q == '"'
			if q != 0 {
				ident.QuoteStyle = q
			}
			if ident.Quotes != 0 || p.nameQuoteRelevant(q) {
				ident.Quotes = p.appendNamePartQuoted(ident.Quotes, q)
			}
			n++
			p.advance()
		default:
			return goerrors.InvalidSyntaxError(
				"expected column name or * after table qualifier (use db.table.column or db.table.*)",
				p.currentLocation(),
				"",
			)
		}
	}
	ident.Table = strings.Join(parts[:n-1], ".")
	ident.Name = parts[n-1]
	ident.Quoted = lastQuoted
	return nil
}

// isQualifiedNamePart reports whether the current token can follow a '.' in a
// qualified column reference: an identifier, a non-reserved keyword (t.KEY,
// schema.INDEX), or - in ClickHouse - a numeric tuple element (d.1).
func (p *Parser) isQualifiedNamePart() bool {
	return p.isIdentifier() || p.isNonReservedKeyword() || p.isKeywordColumnName() ||
		(p.dialect == string(keywords.DialectClickHouse) && p.isNumericLiteral()) ||
		p.isSnowflakePositionalColumn()
}

// pgPrefixOperator reports the PostgreSQL prefix operator that starts at the
// current token and how many tokens it spans (0 when there is none): |/ and
// ||/ are tokenized as two tokens and !! as two.
func (p *Parser) pgPrefixOperator() (ast.UnaryOperator, int) {
	switch p.currentToken.Token.Type {
	case models.TokenTypePipe:
		if p.peekTypeAt(1) == models.TokenTypeDiv && p.nextAdjacent(1) && p.IsPostgreSQL() {
			return ast.PGSquareRoot, 2
		}
	case models.TokenTypeStringConcat:
		if p.peekTypeAt(1) == models.TokenTypeDiv && p.nextAdjacent(1) && p.IsPostgreSQL() {
			return ast.PGCubeRoot, 2
		}
	case models.TokenTypeExclamationMark:
		if p.peekTypeAt(1) == models.TokenTypeExclamationMark && p.nextAdjacent(1) && p.IsPostgreSQL() {
			return ast.PGPrefixFactorial, 2
		}
	case models.TokenTypeAtSign:
		if p.IsPostgreSQL() {
			return ast.PGAbs, 1
		}
	}
	return 0, 0
}

// isMySQLBinaryOperator reports whether the current token is the BINARY prefix
// operator of MySQL and MariaDB: BINARY followed by a string literal or a
// name, as in "BINARY 'a'" or "BINARY name". BINARY( is the BINARY function.
func (p *Parser) isMySQLBinaryOperator() bool {
	if v := p.currentToken.Token.Value; len(v) != len("BINARY") || p.currentToken.Token.Quote != 0 ||
		!equalsUpper(v, "BINARY") || !p.isMySQLFamily() {
		return false
	}
	next := p.peekToken().Token
	switch next.Type {
	case models.TokenTypeString, models.TokenTypeSingleQuotedString, models.TokenTypeNumber:
		return true
	case models.TokenTypeIdentifier:
		return next.Quote != 0 || !equalsUpper(next.Value, "AS")
	}
	return false
}

// parseOtherOperatorOperand parses the operand of a PostgreSQL prefix operator
// of the "any other operator" class: an additive expression, one recursion
// level deeper.
func (p *Parser) parseOtherOperatorOperand() (ast.Expression, error) {
	err := p.enterRecursion()
	defer p.leaveRecursion()
	if err != nil {
		return nil, err
	}
	return p.parseAdditiveExpression()
}

// isMoneyPrefix reports whether a placeholder token is "$" followed by digits,
// the start of a SQL Server money literal.
func isMoneyPrefix(v string) bool {
	if len(v) < 2 || v[0] != '$' {
		return false
	}
	for i := 1; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}

// peekMoneyFraction reports whether the current token is a '.' that is
// followed, without a gap, by a number made of digits only: the fraction of a
// money literal such as $5.00.
func (p *Parser) peekMoneyFraction() bool {
	if !p.isType(models.TokenTypePeriod) {
		return false
	}
	next := p.peekToken()
	if next.Token.Type != models.TokenTypeNumber || !p.nextAdjacent(1) {
		return false
	}
	for i := 0; i < len(next.Token.Value); i++ {
		if next.Token.Value[i] < '0' || next.Token.Value[i] > '9' {
			return false
		}
	}
	return true
}

// parseObjectLiteral parses a Snowflake object constant {'k': v, ...}; the
// current token is the opening brace.
func (p *Parser) parseObjectLiteral() (ast.Expression, error) {
	obj := &ast.ObjectLiteral{Pos: p.currentLocation()}
	p.advance() // Consume {
	if p.isType(models.TokenTypeRBrace) {
		p.advance()
		return obj, nil
	}
	err := p.enterRecursion()
	defer p.leaveRecursion()
	if err != nil {
		return nil, err
	}
	for {
		// The key is a string constant; parsing a full expression would read
		// 'k': v as a variant path k:v.
		key, err := p.parsePrimaryExpression()
		if err != nil {
			return nil, err
		}
		if !p.isType(models.TokenTypeColon) {
			return nil, p.expectedError(": after object key")
		}
		p.advance() // Consume :
		value, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		obj.Entries = append(obj.Entries, ast.ObjectEntry{Key: key, Value: value})
		if p.isType(models.TokenTypeComma) {
			p.advance()
			continue
		}
		break
	}
	if !p.isType(models.TokenTypeRBrace) {
		return nil, p.expectedError("} to close the object constant")
	}
	p.advance() // Consume }
	return obj, nil
}
