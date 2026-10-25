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

// Package parser - expressions_primary_ext.go
// Primary expressions beyond identifiers, literals and plain function calls:
// keyword-named functions (LEFT(s, 2), GROUPING(a), ROW(1, 2)), qualified
// function calls (pg_catalog.now()), typed literals (DATE '2024-01-01'),
// national strings (N'abc'), the Oracle (+) marker, CONNECT_BY_ROOT, PRIOR in
// the select list, NEXT VALUE FOR, and MySQL @@system variables and
// := assignment.

package parser

import (
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// isKeywordFunctionName reports whether the current token is a keyword that
// names an ordinary function when it is directly followed by '(':
// LEFT(s, 2), RIGHT(s, 2), GROUPING(a), TRUNCATE(x, 1), DEFAULT(col),
// ROW(1, 2), INSERT(s, 1, 2, 'x'), ClickHouse any(x) and range(n), and
// Snowflake HASH(a). It is consulted only when no other primary expression
// matched, so it never changes how a valid expression parses.
func (p *Parser) isKeywordFunctionName() bool {
	if p.peekToken().Token.Type != models.TokenTypeLParen || p.currentToken.Token.Quote != 0 {
		return false
	}
	switch p.currentToken.Token.Type {
	case models.TokenTypeLeft, models.TokenTypeRight, models.TokenTypeGrouping,
		models.TokenTypeTruncate, models.TokenTypeDefault, models.TokenTypeRange,
		models.TokenTypeRow, models.TokenTypeInsert, models.TokenTypeAny:
		return true
	case models.TokenTypeKeyword:
		// Keywords without a dedicated token type (HASH, ...). Words that
		// introduce a clause are never function names.
		return isFunctionKeywordWord(p.currentToken.Token.Value)
	}
	return false
}

// isFunctionKeywordWord reports whether a generic keyword may be written as
// a function name.
func isFunctionKeywordWord(w string) bool {
	return len(w) == 4 && strings.EqualFold(w, "HASH")
}

// parseKeywordFunctionCall parses a keyword-named function call; the current
// token is the keyword and the next one is '('.
func (p *Parser) parseKeywordFunctionCall() (ast.Expression, error) {
	pos := p.currentLocation()
	name := p.currentToken.Token.Value
	p.advance() // Consume the keyword
	fc, err := p.parseFunctionCall(name)
	if err != nil {
		return nil, err
	}
	if fc.Pos.IsZero() {
		fc.Pos = pos
	}
	if p.isType(models.TokenTypeLBracket) && p.dialect != string(keywords.DialectSQLite) {
		return p.parseArrayAccessExpression(fc)
	}
	return fc, nil
}

// parseQualifiedFunctionCall parses a schema- or package-qualified function
// call such as pg_catalog.now(), auth.uid() or DBMS_RANDOM.VALUE(1, 100).
// ident holds the qualified name (Table + "." + Name) and the current token
// is '('.
func (p *Parser) parseQualifiedFunctionCall(ident *ast.Identifier) (ast.Expression, error) {
	fc, err := p.parseFunctionCall(ident.Table + "." + ident.Name)
	if err != nil {
		return nil, err
	}
	fc.NameQuote = ident.Quotes
	if fc.Pos.IsZero() {
		fc.Pos = ident.Pos
	}
	if p.isType(models.TokenTypeLBracket) && p.dialect != string(keywords.DialectSQLite) {
		return p.parseArrayAccessExpression(fc)
	}
	return fc, nil
}

// isOuterJoinMarker reports whether the current tokens are the Oracle
// outer-join marker "(+)".
func (p *Parser) isOuterJoinMarker() bool {
	return p.isType(models.TokenTypeLParen) &&
		p.peekToken().Token.Type == models.TokenTypePlus &&
		p.tokenAt(2).Token.Type == models.TokenTypeRParen
}

// parseOuterJoinMarker consumes "(+)" and wraps expr.
func (p *Parser) parseOuterJoinMarker(expr ast.Expression) ast.Expression {
	p.advance() // Consume (
	p.advance() // Consume +
	p.advance() // Consume )
	return &ast.OuterJoinMarker{Expr: expr}
}

// typedLiteralTypes are the type names that form a typed literal with a
// following string (DATE '2024-01-01') in every dialect that supports the
// syntax. PostgreSQL accepts any type name (see isTypedLiteralStart).
func isTypedLiteralType(name string) bool {
	switch len(name) {
	case 4:
		return strings.EqualFold(name, "DATE") || strings.EqualFold(name, "TIME")
	case 9:
		return strings.EqualFold(name, "TIMESTAMP")
	}
	return false
}

// isTypedLiteralStart reports whether the current identifier and the string
// literal after it form a typed literal: DATE '2024-01-01', TIMESTAMP '...',
// or in PostgreSQL any type name, as in inet '10.0.0.1'. SQL Server and
// SQLite read a string after an expression as its alias, so they have no
// typed literals. A word glued to the quote (E'..', X'..', _utf8mb4'..') is a
// string prefix, not a type.
func (p *Parser) isTypedLiteralStart() bool {
	nextType := p.peekTypeAt(1)
	if nextType != models.TokenTypeString && nextType != models.TokenTypeSingleQuotedString {
		return false
	}
	if !p.isType(models.TokenTypeIdentifier) || p.currentToken.Token.Quote != 0 {
		return false
	}
	if p.currentToken.End == p.peekToken().Start && !p.currentToken.End.IsZero() {
		return false
	}
	switch p.dialect {
	case string(keywords.DialectSQLServer), string(keywords.DialectSQLite):
		return false
	case string(keywords.DialectPostgreSQL):
		return true
	}
	return isTypedLiteralType(p.currentToken.Token.Value)
}

// parseTypedLiteral parses TYPE 'value'; the current token is the type name.
func (p *Parser) parseTypedLiteral() ast.Expression {
	lit := &ast.TypedLiteral{TypeName: p.currentToken.Token.Value, Pos: p.currentLocation()}
	p.advance() // Consume the type name
	lit.Value = p.currentToken.Token.Value
	p.advance() // Consume the string
	return lit
}

// parseStringLiteralExpr parses a string literal. In MySQL, MariaDB and
// PostgreSQL adjacent string literals are one literal ('a' 'b' is 'ab'), so
// they are merged.
func (p *Parser) parseStringLiteralExpr() ast.Expression {
	value := p.currentToken.Token.Value
	p.advance()
	if (p.isType(models.TokenTypeString) || p.isType(models.TokenTypeSingleQuotedString)) &&
		p.concatsAdjacentStrings() {
		var sb strings.Builder
		sb.WriteString(value)
		for p.isType(models.TokenTypeString) || p.isType(models.TokenTypeSingleQuotedString) {
			sb.WriteString(p.currentToken.Token.Value)
			p.advance()
		}
		value = sb.String()
	}
	return p.newStringLiteral(value)
}

// concatsAdjacentStrings reports whether the dialect reads adjacent string
// literals as one literal.
func (p *Parser) concatsAdjacentStrings() bool {
	switch p.dialect {
	case string(keywords.DialectMySQL), string(keywords.DialectMariaDB), string(keywords.DialectPostgreSQL):
		return true
	}
	return false
}

// isNextValueFor reports whether the current tokens start NEXT VALUE FOR.
func (p *Parser) isNextValueFor() bool {
	return p.isType(models.TokenTypeNext) &&
		strings.EqualFold(p.peekToken().Token.Value, "VALUE") &&
		p.tokenAt(2).Token.Type == models.TokenTypeFor
}

// parseNextValueFor parses NEXT VALUE FOR [schema.]sequence.
func (p *Parser) parseNextValueFor() (ast.Expression, error) {
	pos := p.currentLocation()
	p.advance() // Consume NEXT
	p.advance() // Consume VALUE
	p.advance() // Consume FOR
	if !p.isIdentifier() && !p.isNonReservedKeyword() {
		return nil, p.expectedError("sequence name after NEXT VALUE FOR")
	}
	var sb strings.Builder
	sb.WriteString(p.currentToken.Token.Value)
	p.advance()
	for p.isType(models.TokenTypePeriod) {
		p.advance() // Consume .
		if !p.isIdentifier() && !p.isNonReservedKeyword() {
			return nil, p.expectedError("sequence name after .")
		}
		sb.WriteByte('.')
		sb.WriteString(p.currentToken.Token.Value)
		p.advance()
	}
	return &ast.NextValueForExpression{Sequence: sb.String(), Pos: pos}, nil
}

// isSystemVariable reports whether the current token starts a MySQL/MariaDB
// system variable reference (@@name). PostgreSQL uses @@ only as an operator.
func (p *Parser) isSystemVariable() bool {
	if !p.isType(models.TokenTypeAtAt) || p.dialect == string(keywords.DialectPostgreSQL) {
		return false
	}
	next := p.peekToken().Token
	return next.Quote == 0 && next.Value != "" && isBareWord(next.Value)
}

// parseSystemVariable parses @@name or @@scope.name.
func (p *Parser) parseSystemVariable() ast.Expression {
	sv := &ast.SystemVariable{Pos: p.currentLocation()}
	p.advance() // Consume @@
	name := p.currentToken.Token.Value
	p.advance()
	if p.isType(models.TokenTypePeriod) && ast.SystemVariableScopeText(name) != "" {
		next := p.peekToken().Token
		if next.Quote == 0 && isBareWord(next.Value) {
			p.advance() // Consume .
			sv.Scope = name
			name = p.currentToken.Token.Value
			p.advance()
		}
	}
	sv.Name = name
	return sv
}

// isVariableAssignment reports whether the current tokens are the MySQL
// assignment operator ":=" after a user variable.
func (p *Parser) isVariableAssignment() bool {
	if !p.isType(models.TokenTypeAssignment) &&
		(!p.isType(models.TokenTypeColon) || p.peekToken().Token.Type != models.TokenTypeEq) {
		return false
	}
	switch p.dialect {
	case string(keywords.DialectMySQL), string(keywords.DialectMariaDB):
		return true
	}
	return false
}

// parseVariableAssignment parses ":= expr" after target.
func (p *Parser) parseVariableAssignment(target ast.Expression) (ast.Expression, error) {
	pos := p.currentLocation()
	if !p.isType(models.TokenTypeAssignment) {
		p.advance() // Consume : of a split ":="
	}
	p.advance() // Consume := or =
	value, err := p.parseExpression()
	if err != nil {
		return nil, err
	}
	return &ast.AssignmentExpression{Target: target, Value: value, Pos: pos}, nil
}

// isHierarchicalOperator reports whether the current identifier is the
// Oracle CONNECT_BY_ROOT operator, or PRIOR used in the select list, applied
// to the operand that follows.
func (p *Parser) isHierarchicalOperator() bool {
	v := p.currentToken.Token.Value
	if len(v) != len("CONNECT_BY_ROOT") && len(v) != len("PRIOR") {
		return false
	}
	if p.currentToken.Token.Quote != 0 {
		return false
	}
	oracle := p.dialect == string(keywords.DialectOracle)
	if !oracle && p.dialect != string(keywords.DialectSnowflake) {
		return false
	}
	next := p.peekToken().Token
	if next.Type != models.TokenTypeIdentifier && next.Type != models.TokenTypeDoubleQuotedString &&
		next.Type != models.TokenTypeLParen {
		return false
	}
	// PRIOR outside CONNECT BY is Oracle-only; elsewhere "prior x" is a
	// column named prior with the alias x.
	return strings.EqualFold(v, "CONNECT_BY_ROOT") || (oracle && strings.EqualFold(v, "PRIOR"))
}

// parseHierarchicalOperator parses CONNECT_BY_ROOT expr or PRIOR expr.
func (p *Parser) parseHierarchicalOperator() (ast.Expression, error) {
	pos := p.currentLocation()
	root := len(p.currentToken.Token.Value) == len("CONNECT_BY_ROOT")
	p.advance() // Consume the operator
	operand, err := p.parseUnaryOperand()
	if err != nil {
		return nil, err
	}
	if root {
		return &ast.ConnectByRootExpression{Expr: operand, Pos: pos}, nil
	}
	return &ast.UnaryExpression{Operator: ast.Prior, Expr: operand, Pos: pos}, nil
}

// parsePrimaryFallback parses the primary expressions tried only after every
// common form failed to match. It returns a nil expression when none applies.
func (p *Parser) parsePrimaryFallback() (ast.Expression, error) {
	switch {
	case p.isKeywordFunctionName():
		return p.parseKeywordFunctionCall()
	case p.isNextValueFor():
		return p.parseNextValueFor()
	case p.isSystemVariable():
		return p.parseSystemVariable(), nil
	}
	return nil, nil
}

// errUnexpectedPrimary is the error for a token that cannot start a primary
// expression.
func (p *Parser) errUnexpectedPrimary() error {
	return goerrors.UnexpectedTokenError(
		p.currentToken.Token.Type.String(),
		p.currentToken.Token.Value,
		p.currentLocation(),
		"",
	)
}

// hasBracketArrayLiterals reports whether the dialect writes array literals
// as bare brackets: [1, 2, 3].
func (p *Parser) hasBracketArrayLiterals() bool {
	return p.dialect == string(keywords.DialectClickHouse) || p.dialect == string(keywords.DialectSnowflake)
}

// parseBracketArrayPrimary parses a bare bracket array literal and any
// subscripts that follow it: [1, 2, 3][2].
func (p *Parser) parseBracketArrayPrimary() (ast.Expression, error) {
	arr, err := p.parseBracketArrayLiteral()
	if err != nil {
		return nil, err
	}
	if p.isType(models.TokenTypeLBracket) {
		return p.parseArrayAccessExpression(arr)
	}
	return arr, nil
}
