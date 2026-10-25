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

// Package parser - expressions_ops.go
// Operator and predicate helpers: bitwise and "other" binary operators,
// postfix AT TIME ZONE / COLLATE, IS forms, quantified ANY/ALL/SOME over
// arrays, and the dialect-specific word operators (DIV, MOD, XOR, GLOB, ...).

package parser

import (
	"fmt"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// peekAt returns the token offset positions after the current one (1 is the
// next token), or an empty token past the end of input.
func (p *Parser) peekAt(offset int) models.TokenWithSpan {
	if i := p.currentPos + offset; i >= 0 && i < len(p.tokens) {
		return p.tokens[i]
	}
	return models.TokenWithSpan{}
}

// peekTypeAt returns the type of the token offset positions after the current
// one, or TokenTypeUnknown past the end of input.
func (p *Parser) peekTypeAt(offset int) models.TokenType {
	if i := p.currentPos + offset; i >= 0 && i < len(p.tokens) {
		return p.tokens[i].Token.Type
	}
	return models.TokenTypeUnknown
}

// nextAdjacent reports whether the token after the current one starts exactly
// where the current one ends, so that two tokens the tokenizer split apart
// (for example "<=" and ">") really were written as one operator ("<=>").
func (p *Parser) nextAdjacent(offset int) bool {
	prev := p.currentToken
	if offset > 1 {
		prev = p.peekAt(offset - 1)
	}
	next := p.peekAt(offset)
	return prev.End == next.Start
}

// peekValueIs reports whether the token offset positions ahead has the given
// upper-case text (matched case-insensitively, whatever its token type).
func (p *Parser) peekValueIs(offset int, upper string) bool {
	return equalsUpper(p.peekAt(offset).Token.Value, upper)
}

// bitwiseOperator reports the bitwise or "other" binary operator that starts
// at the current token: its text, its precedence (1 loosest) and how many
// tokens it spans. n is 0 when the current token starts no such operator.
//
// Precedence follows MySQL, the dialect that defines the most levels:
// "|" < "&" and the PostgreSQL operators < "<<" ">>". All of them bind
// looser than + - and || and tighter than comparisons. SQL Server treats & and
// | like + and -, which parseAdditiveExpression handles, so they are not
// reported here for that dialect.
func (p *Parser) bitwiseOperator() (op string, prec, n int) {
	switch p.currentToken.Token.Type {
	case models.TokenTypePipe:
		if p.IsSQLServer() {
			return "", 0, 0
		}
		return "|", 1, 1
	case models.TokenTypeAmpersand:
		if p.IsSQLServer() {
			return "", 0, 0
		}
		return "&", 2, 1
	case models.TokenTypeAtAt:
		return "@@", 2, 1
	case models.TokenTypeOverlap:
		// MySQL and MariaDB read && as logical AND (parseAndExpression).
		if p.isMySQLFamily() {
			return "", 0, 0
		}
		return "&&", 2, 1
	case models.TokenTypeSharp:
		return "#", 2, 1
	case models.TokenTypeLtEq:
		// <=> is the null-safe equality operator in MySQL (a comparison, see
		// combinedComparison) and the cosine-distance operator of pgvector in
		// PostgreSQL.
		if p.peekTypeAt(1) == models.TokenTypeGt && p.IsPostgreSQL() && p.nextAdjacent(1) {
			return "<=>", 2, 2
		}
	case models.TokenTypeLt:
		switch p.peekTypeAt(1) {
		case models.TokenTypeLt:
			if p.nextAdjacent(1) {
				return "<<", 3, 2
			}
		case models.TokenTypeArrow:
			// a <-> b: the distance operator of pg_trgm and pgvector.
			if p.IsPostgreSQL() && p.nextAdjacent(1) {
				return "<->", 2, 2
			}
		}
	case models.TokenTypeGt:
		if p.peekTypeAt(1) == models.TokenTypeGt && p.nextAdjacent(1) {
			return ">>", 3, 2
		}
	// Single-token forms produced by the tokenizer.
	case models.TokenTypeShiftLeft:
		return "<<", 3, 1
	case models.TokenTypeShiftRight:
		return ">>", 3, 1
	case models.TokenTypeSpaceship:
		if p.IsPostgreSQL() {
			return "<=>", 2, 1
		}
	case models.TokenTypeCustomBinaryOperator:
		if p.currentToken.Token.Value == "<->" && p.IsPostgreSQL() {
			return "<->", 2, 1
		}
	}
	return "", 0, 0
}

// parseBitwiseExpression parses the bitwise and "other" binary operators with
// precedence climbing: operators with a precedence below minPrec are left to
// the caller. The operands are string-concatenation expressions.
func (p *Parser) parseBitwiseExpression(minPrec int) (ast.Expression, error) {
	left, err := p.parseStringConcatExpression()
	if err != nil {
		return nil, err
	}
	if !p.startsBitwiseOperator() {
		return left, nil
	}
	return p.parseBitwiseTail(left, minPrec)
}

// startsBitwiseOperator rejects ordinary expression terminators before entering
// the precedence-climbing path or consulting dialect-specific operator rules.
func (p *Parser) startsBitwiseOperator() bool {
	switch p.currentToken.Token.Type {
	case models.TokenTypePipe, models.TokenTypeAmpersand, models.TokenTypeAtAt,
		models.TokenTypeOverlap, models.TokenTypeSharp, models.TokenTypeLtEq,
		models.TokenTypeLt, models.TokenTypeGt, models.TokenTypeShiftLeft,
		models.TokenTypeShiftRight, models.TokenTypeSpaceship, models.TokenTypeCustomBinaryOperator:
		return true
	}
	return false
}

func (p *Parser) parseBitwiseTail(left ast.Expression, minPrec int) (ast.Expression, error) {
	for {
		op, prec, n := p.bitwiseOperator()
		if n == 0 || prec < minPrec {
			return left, nil
		}
		opPos := p.currentLocation()
		for i := 0; i < n; i++ {
			p.advance() // Consume the operator token(s)
		}
		right, err := p.parseBitwiseExpression(prec + 1)
		if err != nil {
			return nil, err
		}
		left = &ast.BinaryExpression{
			Left:     left,
			Operator: op,
			Right:    right,
			Pos:      opPos,
		}
	}
}

// sqlServerBitwise reports whether the current token is a T-SQL bitwise
// operator (&, |, ^), which shares the additive precedence level there.
func (p *Parser) sqlServerBitwise() bool {
	t := p.currentToken.Token.Type
	return (t == models.TokenTypeAmpersand || t == models.TokenTypePipe || t == models.TokenTypeCaret) && p.IsSQLServer()
}

// mysqlWordMulOperator reports whether the current token is MySQL's integer
// division or modulo keyword operator (DIV, MOD), returning its canonical
// text. They are reserved words in MySQL and MariaDB, so they cannot be an
// alias there.
func (p *Parser) mysqlWordMulOperator() (string, bool) {
	if p.currentToken.Token.Type != models.TokenTypeIdentifier || !p.isMySQLFamily() {
		return "", false
	}
	switch v := p.currentToken.Token.Value; {
	case equalsUpper(v, "DIV"):
		return "DIV", true
	case equalsUpper(v, "MOD"):
		return "MOD", true
	}
	return "", false
}

// isLogicalAnd reports whether the current token is the AND operator,
// including MySQL's && synonym.
func (p *Parser) isLogicalAnd() bool {
	t := p.currentToken.Token.Type
	return t == models.TokenTypeAnd || (t == models.TokenTypeOverlap && p.isMySQLFamily())
}

// parseXorExpression parses MySQL's logical XOR, which binds looser than AND
// and tighter than OR. Other dialects have no XOR operator and fall straight
// through to AND.
func (p *Parser) parseXorExpression() (ast.Expression, error) {
	left, err := p.parseAndExpression()
	if err != nil {
		return nil, err
	}
	if p.currentToken.Token.Type != models.TokenTypeIdentifier || !p.isMySQLFamily() || !equalsUpper(p.currentToken.Token.Value, "XOR") {
		return left, nil
	}
	return p.parseXorTail(left)
}

func (p *Parser) parseXorTail(left ast.Expression) (ast.Expression, error) {
	for p.currentToken.Token.Type == models.TokenTypeIdentifier && p.isMySQLFamily() && equalsUpper(p.currentToken.Token.Value, "XOR") {
		opPos := p.currentLocation()
		p.advance() // Consume XOR
		right, err := p.parseAndExpression()
		if err != nil {
			return nil, err
		}
		left = &ast.BinaryExpression{
			Left:     left,
			Operator: "XOR",
			Right:    right,
			Pos:      opPos,
		}
	}
	return left, nil
}

// parsePostfixOperators parses the postfix operators that bind tighter than
// the arithmetic operators: AT TIME ZONE zone and COLLATE name (PostgreSQL
// precedence: after :: and unary signs, before ^ * / + -). They chain to the
// left.
func (p *Parser) parsePostfixOperators(left ast.Expression) (ast.Expression, error) {
	for {
		switch {
		case p.currentToken.Token.Type == models.TokenTypeCollate:
			collate, err := p.parseCollateSuffix(left)
			if err != nil {
				return nil, err
			}
			left = collate
		case p.isAtTimeZone():
			atPos := p.currentLocation()
			p.advance() // Consume AT
			p.advance() // Consume TIME
			p.advance() // Consume ZONE
			zone, err := p.parseCastOperand()
			if err != nil {
				return nil, err
			}
			left = &ast.AtTimeZoneExpression{Expr: left, Zone: zone, Pos: atPos}
		default:
			return left, nil
		}
	}
}

// isAtTimeZone reports whether the current tokens spell AT TIME ZONE.
func (p *Parser) isAtTimeZone() bool {
	if p.currentToken.Token.Type != models.TokenTypeIdentifier || !equalsUpper(p.currentToken.Token.Value, "AT") {
		return false
	}
	return p.peekValueIs(1, "TIME") && p.peekValueIs(2, "ZONE")
}

// parseCastOperand parses a primary expression with any trailing :: casts,
// the operand of AT TIME ZONE ('UTC'::text).
func (p *Parser) parseCastOperand() (ast.Expression, error) {
	operand, err := p.parsePrimaryExpression()
	if err != nil {
		return nil, err
	}
	for p.isType(models.TokenTypeDoubleColon) {
		p.advance() // Consume ::
		dataType, err := p.parseDataType()
		if err != nil {
			return nil, err
		}
		operand = &ast.CastExpression{Expr: operand, Type: dataType}
	}
	return operand, nil
}

// parseCollateSuffix parses COLLATE name, with an optionally schema-qualified
// name, after left. The current token must be COLLATE.
func (p *Parser) parseCollateSuffix(left ast.Expression) (ast.Expression, error) {
	collatePos := p.currentLocation()
	p.advance() // Consume COLLATE

	if !p.isIdentifier() && !p.isNonReservedKeyword() && !p.isStringLiteral() {
		return nil, p.expectedError("collation name")
	}
	name := p.currentToken.Token.Value
	if p.isStringLiteral() {
		p.advance() // Consume the string literal
		return &ast.CollateExpression{Expr: left, Collation: name, Literal: true, Pos: collatePos}, nil
	}
	quoted := p.isType(models.TokenTypeDoubleQuotedString)
	p.advance() // Consume the name

	// Schema-qualified name: the parts before the last one form Schema, so
	// a dot inside a quoted part ("en_US.utf8") is never read as a qualifier.
	schema := ""
	for p.isType(models.TokenTypePeriod) {
		p.advance() // Consume .
		if !p.isIdentifier() && !p.isNonReservedKeyword() {
			return nil, p.expectedError("collation name")
		}
		if schema == "" {
			schema = name
		} else {
			schema += "." + name
		}
		name = p.currentToken.Token.Value
		quoted = p.isType(models.TokenTypeDoubleQuotedString)
		p.advance()
	}
	return &ast.CollateExpression{Expr: left, Schema: schema, Collation: name, Quoted: quoted, Pos: collatePos}, nil
}

// parseIsSuffix parses what follows IS [NOT] in a comparison. The current
// token is the one after IS (and NOT, when isNot is set).
//
//	IS [NOT] NULL                   IS NULL / IS NOT NULL
//	IS [NOT] TRUE | FALSE | UNKNOWN IS / IS NOT with a boolean literal
//	IS [NOT] DISTINCT FROM expr     IS [NOT] DISTINCT FROM
//	IS [NOT] expr                   SQLite only: null-safe equality
func (p *Parser) parseIsSuffix(left ast.Expression, isPos models.Location, isNot bool) (ast.Expression, error) {
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

	isOp := "IS"
	if isNot {
		isOp = "IS NOT"
	}

	switch {
	case p.isBooleanLiteral():
		right, err := p.parsePrimaryExpression()
		if err != nil {
			return nil, err
		}
		return &ast.BinaryExpression{Left: left, Operator: isOp, Right: right, Pos: isPos}, nil

	case p.currentToken.Token.Type == models.TokenTypeIdentifier && equalsUpper(p.currentToken.Token.Value, "UNKNOWN"):
		p.advance() // Consume UNKNOWN
		return &ast.BinaryExpression{
			Left:     left,
			Operator: isOp,
			Right:    &ast.LiteralValue{Value: "UNKNOWN", Type: "UNKNOWN"},
			Pos:      isPos,
		}, nil

	case p.isType(models.TokenTypeDistinct):
		p.advance() // Consume DISTINCT
		if !p.isType(models.TokenTypeFrom) {
			return nil, p.expectedError("FROM after IS DISTINCT")
		}
		p.advance() // Consume FROM
		right, err := p.parseBitwiseExpression(1)
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse IS DISTINCT FROM operand: %v", err),
				p.currentLocation(),
				"",
			).WithCause(err)
		}
		op := "IS DISTINCT FROM"
		if isNot {
			op = "IS NOT DISTINCT FROM"
		}
		return &ast.BinaryExpression{Left: left, Operator: op, Right: right, Pos: isPos}, nil

	case p.IsSQLite():
		// SQLite: "a IS b" is null-safe equality, with any expression on the right.
		right, err := p.parseBitwiseExpression(1)
		if err != nil {
			return nil, err
		}
		return &ast.BinaryExpression{Left: left, Operator: isOp, Right: right, Pos: isPos}, nil
	}

	return nil, p.expectedError("NULL, TRUE, FALSE, UNKNOWN or DISTINCT FROM")
}

// isSomeQuantifier reports whether the current token is the SOME quantifier
// (a synonym of ANY) followed by an opening parenthesis.
func (p *Parser) isSomeQuantifier() bool {
	if p.currentToken.Token.Type != models.TokenTypeSome && !equalsUpper(p.currentToken.Token.Value, "SOME") {
		return false
	}
	return p.peekTypeAt(1) == models.TokenTypeLParen
}

// parseQuantifiedComparison parses the quantifier part of "expr op ANY|ALL|SOME
// (...)": the current token is the quantifier. A subquery yields AnyExpression
// or AllExpression; any other argument (a placeholder, a column, ARRAY[...])
// yields AnyAllExpression. SOME is kept as AnyAllExpression with the SOME
// spelling so the formatter does not rewrite it.
func (p *Parser) parseQuantifiedComparison(left ast.Expression, operator string) (ast.Expression, error) {
	quantPos := p.currentLocation()
	var quantifier string
	switch {
	case p.isType(models.TokenTypeAny):
		quantifier = "ANY"
	case p.isType(models.TokenTypeAll):
		quantifier = "ALL"
	default:
		quantifier = "SOME"
	}
	p.advance() // Consume ANY/ALL/SOME

	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	isQuery := p.isType(models.TokenTypeSelect) || p.isType(models.TokenTypeWith)
	if isQuery {
		lparenPos := quantPos
		subquery, err := p.parseSubquery()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse %s subquery: %v", quantifier, err),
				p.currentLocation(),
				"",
			)
		}
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
		switch quantifier {
		case "ANY":
			return &ast.AnyExpression{Expr: left, Operator: operator, Subquery: subquery}, nil
		case "ALL":
			return &ast.AllExpression{Expr: left, Operator: operator, Subquery: subquery}, nil
		}
		return &ast.AnyAllExpression{
			Expr:       left,
			Operator:   operator,
			Quantifier: quantifier,
			Array:      &ast.SubqueryExpression{Subquery: subquery, Pos: lparenPos},
			Pos:        quantPos,
		}, nil
	}

	arg, err := p.parseExpression()
	if err != nil {
		return nil, goerrors.InvalidSyntaxError(
			fmt.Sprintf("failed to parse %s argument: %v", quantifier, err),
			p.currentLocation(),
			"",
		).WithCause(err)
	}
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )
	return &ast.AnyAllExpression{
		Expr:       left,
		Operator:   operator,
		Quantifier: quantifier,
		Array:      arg,
		Pos:        quantPos,
	}, nil
}

// parseEscapeClause parses an optional "ESCAPE expr" after a LIKE-style
// pattern. It returns nil when no ESCAPE follows.
func (p *Parser) parseEscapeClause() (ast.Expression, error) {
	if p.currentToken.Token.Type != models.TokenTypeIdentifier || !equalsUpper(p.currentToken.Token.Value, "ESCAPE") {
		return nil, nil
	}
	p.advance() // Consume ESCAPE
	esc, err := p.parseBitwiseExpression(1)
	if err != nil {
		return nil, goerrors.InvalidSyntaxError(
			fmt.Sprintf("failed to parse ESCAPE character: %v", err),
			p.currentLocation(),
			"",
		).WithCause(err)
	}
	return esc, nil
}

// combinedComparison reports a comparison operator the tokenizer splits into
// several tokens that sits at the current token: MySQL's null-safe <=> (the
// tokens <= and >) and the == spelling of equality. It returns the operator
// text and the number of tokens, or n == 0.
func (p *Parser) combinedComparison() (op string, n int) {
	switch p.currentToken.Token.Type {
	case models.TokenTypeLtEq:
		if !p.IsPostgreSQL() && p.peekTypeAt(1) == models.TokenTypeGt && p.nextAdjacent(1) {
			return "<=>", 2
		}
	case models.TokenTypeEq:
		if p.peekTypeAt(1) == models.TokenTypeEq && p.nextAdjacent(1) {
			return "==", 2
		}
	case models.TokenTypeSpaceship:
		if !p.IsPostgreSQL() {
			return "<=>", 1
		}
	case models.TokenTypeDoubleEq:
		return "==", 1
	}
	return "", 0
}

// postfixNullTest handles the PostgreSQL and SQLite postfix ISNULL / NOTNULL
// operators, which mean IS NULL and IS NOT NULL.
func (p *Parser) postfixNullTest(left ast.Expression) (ast.Expression, bool) {
	if p.currentToken.Token.Type != models.TokenTypeIdentifier || !(p.IsPostgreSQL() || p.IsSQLite()) {
		return nil, false
	}
	v := p.currentToken.Token.Value
	isNot := false
	switch {
	case equalsUpper(v, "ISNULL"):
	case equalsUpper(v, "NOTNULL"):
		isNot = true
	default:
		return nil, false
	}
	pos := p.currentLocation()
	p.advance()
	return &ast.BinaryExpression{
		Left:     left,
		Operator: "IS NULL",
		Right:    &ast.LiteralValue{Value: nil, Type: "null"},
		Not:      isNot,
		Pos:      pos,
	}, true
}
