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
//   - expressions_literal.go   - literals, identifiers, qualified names, parsePrimaryExpression
//   - expressions_operators.go - comparison, BETWEEN, IN, LIKE, IS NULL, array subscripts
//   - expressions_complex.go   - CASE, CAST, INTERVAL, ARRAY constructors

package parser

import (
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseExpression parses an expression with OR operators (lowest precedence)
func (p *Parser) parseExpression() (ast.Expression, error) {
	// Check context if available
	if p.ctx != nil {
		if err := p.ctx.Err(); err != nil {
			// Context cancellation is not a syntax error; return it directly so
			// callers can use errors.Is(err, context.Canceled/DeadlineExceeded).
			return nil, err
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

	// Start by parsing XOR/AND expressions (higher precedence)
	left, err := p.parseXorExpression()
	if err != nil {
		return nil, err
	}

	// Handle OR operators (lowest precedence, left-associative). In MySQL and
	// MariaDB (without PIPES_AS_CONCAT) || is a synonym for OR (#781); it is
	// normalised to the OR operator so linters, the security scanner and the
	// transpiler treat both spellings identically. PipesOr keeps the source
	// spelling so SQL() and the formatter write || back.
	for p.isType(models.TokenTypeOr) || (p.pipesAsOr && p.isType(models.TokenTypeStringConcat)) {
		opPos := p.currentLocation()
		// The operator is stored as the canonical upper-case keyword whatever
		// the source spelling.
		pipes := p.currentToken.Token.Type == models.TokenTypeStringConcat
		p.advance() // Consume OR / ||

		right, err := p.parseXorExpression()
		if err != nil {
			return nil, err
		}

		left = &ast.BinaryExpression{
			Left:     left,
			Operator: "OR",
			Right:    right,
			PipesOr:  pipes,
			Pos:      opPos,
		}
	}

	// ClickHouse conditional operator: cond ? then : else (right-associative).
	if p.isType(models.TokenTypeQuestion) && p.IsClickHouse() {
		return p.parseTernaryTail(left)
	}

	// MySQL / MariaDB user-variable assignment: @a := expr (right-associative,
	// the loosest operator). MySQL assigns with := in an expression only to a
	// user variable (variable: '@' ident SET_VAR expr); f(a := 1) or
	// arr[1:=2] is a syntax error there.
	if p.isMySQLFamily() && isUserVariable(left) && (p.isType(models.TokenTypeAssignment) ||
		p.isType(models.TokenTypeColon) && p.peekTypeAt(1) == models.TokenTypeEq && p.nextAdjacent(1)) {
		opPos := p.currentLocation()
		if !p.isType(models.TokenTypeAssignment) {
			p.advance() // Consume : of a split ":="
		}
		p.advance() // Consume := or =
		right, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		return &ast.AssignmentExpression{Target: left, Value: right, Pos: opPos}, nil
	}

	return left, nil
}

// parseTernaryTail parses the "? then : else" tail of the ClickHouse
// conditional operator after its condition. The current token is the ?.
func (p *Parser) parseTernaryTail(cond ast.Expression) (ast.Expression, error) {
	qPos := p.currentLocation()
	p.advance() // Consume ?

	then, err := p.parseExpression()
	if err != nil {
		return nil, err
	}
	if !p.isType(models.TokenTypeColon) {
		return nil, p.expectedError(": in conditional expression")
	}
	p.advance() // Consume :

	els, err := p.parseExpression()
	if err != nil {
		return nil, err
	}
	return &ast.TernaryExpression{Cond: cond, Then: then, Else: els, Pos: qPos}, nil
}

// enterRecursion increments the recursion depth counter and returns a
// RecursionDepthLimitError (E2007) when it exceeds MaxRecursionDepth. It is for
// recursive parse paths that do not pass through parseExpression. The caller
// must always undo the increment with a deferred leaveRecursion, whether or not
// an error is returned:
//
//	err := p.enterRecursion()
//	defer p.leaveRecursion()
//	if err != nil {
//		return nil, err
//	}
func (p *Parser) enterRecursion() error {
	p.depth++
	if p.depth > MaxRecursionDepth {
		return goerrors.RecursionDepthLimitError(
			p.depth,
			MaxRecursionDepth,
			p.currentLocation(),
			"",
		)
	}
	return nil
}

// leaveRecursion undoes one enterRecursion.
func (p *Parser) leaveRecursion() {
	p.depth--
}

// parseAndExpression parses an expression with AND operators (middle precedence)
func (p *Parser) parseAndExpression() (ast.Expression, error) {
	// Parse comparison expressions (higher precedence)
	left, err := p.parseComparisonExpression()
	if err != nil {
		return nil, err
	}

	// Handle AND operators (middle precedence, left-associative)
	// (MySQL and MariaDB also read && as AND.) The operator is stored as the
	// canonical upper-case keyword whatever the source spelling.
	for p.isLogicalAnd() {
		opPos := p.currentLocation()
		p.advance() // Consume AND

		right, err := p.parseComparisonExpression()
		if err != nil {
			return nil, err
		}

		left = &ast.BinaryExpression{
			Left:     left,
			Operator: "AND",
			Right:    right,
			Pos:      opPos,
		}
	}

	return left, nil
}

// parseStringConcatExpression parses expressions with || (string concatenation)
// operator. When || is logical OR (p.pipesAsOr, MySQL/MariaDB default) the loop
// does not consume it, leaving it for parseExpression at OR precedence.
func (p *Parser) parseStringConcatExpression() (ast.Expression, error) {
	if p.IsPostgreSQL() {
		return p.parseBitwiseExpression(1)
	}
	// Parse the left side using additive expression
	left, err := p.parseAdditiveExpression()
	if err != nil {
		return nil, err
	}
	return p.parseStringConcatTail(left)
}

// parseStringConcatTail continues a string-concatenation expression after its
// left operand.
func (p *Parser) parseStringConcatTail(left ast.Expression) (ast.Expression, error) {
	// Handle || (string concatenation) operator (left-associative)
	for !p.pipesAsOr && p.isType(models.TokenTypeStringConcat) && !p.IsPostgreSQL() {
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
	return p.parseAdditiveTail(left)
}

// parseAdditiveTail continues an additive expression after its left operand.
func (p *Parser) parseAdditiveTail(left ast.Expression) (ast.Expression, error) {
	// Handle + and - operators (left-associative)
	// (SQL Server treats the bitwise &, | like + and -.)
	for p.isType(models.TokenTypePlus) || p.isType(models.TokenTypeMinus) || p.sqlServerBitwise() {
		opPos := p.currentLocation()
		operator := p.currentToken.Token.Value
		p.advance() // Consume operator

		right, err := p.parseMultiplicativeExpression()
		if err != nil {
			return nil, err
		}

		left = &ast.BinaryExpression{
			Left:          left,
			Operator:      operator,
			Right:         right,
			BitwiseXor:    operator == "^", // only SQL Server reaches here with ^
			XorAtAdditive: operator == "^",
			Pos:           opPos,
		}
	}

	return left, nil
}

// parseMultiplicativeExpression parses expressions with *, /, and % operators
func (p *Parser) parseMultiplicativeExpression() (ast.Expression, error) {
	// Parse the left side using the power/XOR expression (higher precedence)
	left, err := p.parsePowerExpression()
	if err != nil {
		return nil, err
	}
	return p.parseMultiplicativeTail(left)
}

// parseMultiplicativeTail continues a multiplicative expression after its left
// operand.
func (p *Parser) parseMultiplicativeTail(left ast.Expression) (ast.Expression, error) {
	// Handle *, /, and % operators (left-associative)
	// Note: TokenTypeAsterisk is used for both * (SELECT) and multiplication
	// We check context: after an expression, asterisk means multiplication
	// MySQL and MariaDB also have the DIV and MOD keyword operators.
	for {
		wordOp, isWord := "", false
		if !(p.isType(models.TokenTypeAsterisk) || p.isType(models.TokenTypeMul) ||
			p.isType(models.TokenTypeDiv) || p.isType(models.TokenTypeMod)) {
			if wordOp, isWord = p.mysqlWordMulOperator(); !isWord {
				break
			}
		}
		opPos := p.currentLocation()
		operator := p.currentToken.Token.Value
		if isWord {
			operator = wordOp
		}
		p.advance() // Consume operator

		right, err := p.parsePowerExpression()
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

// caretOperator reports whether the current token is the ^ operator at a
// precedence tighter than * and /: exponentiation in PostgreSQL and bitwise
// XOR in MySQL and MariaDB. SQL Server's ^ is a bitwise operator at the
// additive level (see sqlServerBitwise); the other dialects have no ^.
func (p *Parser) caretOperator() bool {
	if !p.isType(models.TokenTypeCaret) {
		return false
	}
	return p.dialect == "" || p.dialect == string(keywords.DialectGeneric) ||
		p.IsPostgreSQL() || p.isMySQLFamily()
}

// parsePowerExpression parses the ^ operator (left-associative), which binds
// tighter than *, / and %.
func (p *Parser) parsePowerExpression() (ast.Expression, error) {
	left, err := p.parseJSONExpression()
	if err != nil || !p.caretOperator() {
		return left, err
	}
	return p.parsePowerTail(left)
}

// parsePowerTail continues a power expression after its left operand, with the
// current token at ^.
func (p *Parser) parsePowerTail(left ast.Expression) (ast.Expression, error) {
	for p.caretOperator() {
		opPos := p.currentLocation()
		p.advance() // Consume ^
		right, err := p.parseJSONExpression()
		if err != nil {
			return nil, err
		}
		left = &ast.BinaryExpression{Left: left, Operator: "^", Right: right, BitwiseXor: p.isMySQLFamily(), Pos: opPos}
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

	// Snowflake VARIANT path: `expr:field[.field|[idx]]*`. Must run before
	// the `::` cast loop so that `col:a.b::int` casts the full path rather
	// than treating the path as a bare expression.
	if p.dialect == string(keywords.DialectSnowflake) && p.isType(models.TokenTypeColon) {
		vp, err := p.parseSnowflakeVariantPath(left)
		if err != nil {
			return nil, err
		}
		left = vp
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

	// PostgreSQL JSON operators share the lower "any other operator"
	// precedence handled by parseBitwiseExpression. Other dialects keep
	// their existing JSON precedence.
	for p.isJSONOperator() && !p.IsPostgreSQL() {
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

	// Postfix AT TIME ZONE and COLLATE bind tighter than the arithmetic
	// operators. Both start on an identifier or COLLATE token, which no
	// other construct puts directly after an operand.
	if t := p.currentToken.Token.Type; t == models.TokenTypeCollate || t == models.TokenTypeIdentifier {
		return p.parsePostfixOperators(left)
	}

	return left, nil
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
		models.TokenTypeQuestionPipe,  // ?|
		models.TokenTypeQuestionAnd:   // ?&
		return true
	case models.TokenTypeQuestion: // ? (the conditional operator in ClickHouse)
		return !p.IsClickHouse()
	}
	return false
}

// parseSnowflakeVariantPath parses the tail of a Snowflake VARIANT path
// expression. The current token must be `:`. Returns a VariantPath with
// the given root and the parsed segments.
//
// Grammar:
//
//	path      := ':' step ( '.' field | '[' expr ']' )*
//	step      := field | '"' quoted '"'
//	field     := identifier
func (p *Parser) parseSnowflakeVariantPath(root ast.Expression) (*ast.VariantPath, error) {
	pos := p.currentLocation()
	if !p.isType(models.TokenTypeColon) {
		return nil, p.expectedError(":")
	}
	p.advance() // Consume leading :

	vp := &ast.VariantPath{Root: root, Pos: pos}

	// First segment must be a field name (identifier or string literal).
	name, err := p.parseVariantFieldName()
	if err != nil {
		return nil, err
	}
	vp.Segments = append(vp.Segments, ast.VariantPathSegment{Name: name})

	// Subsequent segments: `.field` | `[expr]` | `:field` (rare).
	for {
		switch {
		case p.isType(models.TokenTypePeriod):
			p.advance()
			n, err := p.parseVariantFieldName()
			if err != nil {
				return nil, err
			}
			vp.Segments = append(vp.Segments, ast.VariantPathSegment{Name: n})
		case p.isType(models.TokenTypeColon):
			p.advance()
			n, err := p.parseVariantFieldName()
			if err != nil {
				return nil, err
			}
			vp.Segments = append(vp.Segments, ast.VariantPathSegment{Name: n})
		case p.isType(models.TokenTypeLBracket):
			p.advance() // Consume [
			idx, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			if !p.isType(models.TokenTypeRBracket) {
				return nil, p.expectedError("]")
			}
			p.advance() // Consume ]
			vp.Segments = append(vp.Segments, ast.VariantPathSegment{Index: idx})
		default:
			return vp, nil
		}
	}
}

// parseVariantFieldName consumes one VARIANT path field name, which may be
// a bare identifier or a double-quoted string. Returns the name and
// advances past it.
func (p *Parser) parseVariantFieldName() (string, error) {
	tok := p.currentToken.Token
	switch {
	case p.isIdentifier(), p.isType(models.TokenTypeDoubleQuotedString):
		name := tok.Value
		p.advance()
		return name, nil
	case p.isType(models.TokenTypeKeyword):
		// Keywords may appear as field names (e.g. TYPE, VALUE, STATUS).
		name := tok.Value
		p.advance()
		return name, nil
	}
	return "", p.expectedError("field name after `:` or `.`")
}
