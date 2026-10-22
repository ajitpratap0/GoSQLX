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

// Package parser - expressions_special_forms.go
// Function calls whose arguments are introduced by keywords rather than
// commas (SQL-standard special forms), the GROUP_CONCAT SEPARATOR clause and
// the Oracle KEEP (DENSE_RANK ...) aggregate modifier.

package parser

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// specialForm identifies a function whose argument list may contain
// keyword-introduced arguments (see ast.KeywordArgument).
type specialForm uint8

const (
	formNone      specialForm = iota
	formSubstring             // SUBSTRING(s FROM a FOR b)
	formPosition              // POSITION(a IN b)
	formTrim                  // TRIM([BOTH|LEADING|TRAILING] [c] FROM s)
	formOverlay               // OVERLAY(s PLACING r FROM a [FOR b])
	formConvert               // CONVERT(x USING charset) (MySQL, MariaDB)
	formParse                 // TRY_PARSE / PARSE (x AS type [USING culture]) (SQL Server)
	formColumnGet             // COLUMN_GET(d, name AS type) (MariaDB)
	formListagg               // LISTAGG(a, sep ON OVERFLOW ...) (Oracle, Snowflake)
)

// specialFormOf returns the special form of the function named name, or
// formNone. It is called once per function call, so it compares lengths
// before folding case and never allocates.
func specialFormOf(name string) specialForm {
	switch len(name) {
	case 4:
		if strings.EqualFold(name, "TRIM") {
			return formTrim
		}
	case 5:
		if strings.EqualFold(name, "PARSE") {
			return formParse
		}
	case 6:
		if strings.EqualFold(name, "SUBSTR") {
			return formSubstring
		}
	case 7:
		switch {
		case strings.EqualFold(name, "OVERLAY"):
			return formOverlay
		case strings.EqualFold(name, "CONVERT"):
			return formConvert
		case strings.EqualFold(name, "LISTAGG"):
			return formListagg
		}
	case 8:
		if strings.EqualFold(name, "POSITION") {
			return formPosition
		}
	case 9:
		switch {
		case strings.EqualFold(name, "SUBSTRING"):
			return formSubstring
		case strings.EqualFold(name, "TRY_PARSE"):
			return formParse
		}
	case 10:
		if strings.EqualFold(name, "COLUMN_GET") {
			return formColumnGet
		}
	}
	return formNone
}

// isWord reports whether the current token is the unquoted word w (any
// case), whatever its token type.
func (p *Parser) isWord(w string) bool {
	return p.currentToken.Token.Quote == 0 && !p.isStringLiteral() &&
		len(p.currentToken.Token.Value) == len(w) && strings.EqualFold(p.currentToken.Token.Value, w)
}

// tokenAt returns the token n positions ahead of the current one (0 is the
// current token), or the EOF sentinel past the end of input.
func (p *Parser) tokenAt(n int) models.TokenWithSpan {
	if i := p.currentPos + n; i < len(p.tokens) {
		return p.tokens[i]
	}
	return models.TokenWithSpan{}
}

// parseSpecialFormArgs parses the argument list of a special-form function up
// to (not including) the closing parenthesis. Plain arguments are separated by
// commas as usual; keyword-introduced arguments are returned as
// *ast.KeywordArgument.
func (p *Parser) parseSpecialFormArgs(form specialForm) ([]ast.Expression, error) {
	var args []ast.Expression

	// TRIM(BOTH|LEADING|TRAILING [chars] FROM s)
	if form == formTrim && (p.isWord("BOTH") || p.isWord("LEADING") || p.isWord("TRAILING")) {
		ka := &ast.KeywordArgument{Keyword: strings.ToUpper(p.currentToken.Token.Value), Pos: p.currentLocation()}
		p.advance() // Consume BOTH / LEADING / TRAILING
		if !p.isType(models.TokenTypeFrom) {
			v, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			ka.Value = v
		}
		args = append(args, ka)
		if err := p.parseKeywordArgs(form, &args); err != nil {
			return nil, err
		}
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError("FROM or )")
		}
		return args, nil
	}

	for {
		var arg ast.Expression
		var err error
		if form == formPosition && len(args) == 0 {
			// POSITION(a IN b): IN is the argument separator, so the first
			// argument is parsed below the comparison level.
			arg, err = p.parseStringConcatExpression()
		} else {
			arg, err = p.parseExpression()
		}
		if err != nil {
			return nil, err
		}
		args = append(args, arg)

		if err := p.parseKeywordArgs(form, &args); err != nil {
			return nil, err
		}
		if p.isType(models.TokenTypeComma) {
			p.advance() // Consume ,
			continue
		}
		if p.isType(models.TokenTypeRParen) {
			return args, nil
		}
		return nil, p.expectedError(", or )")
	}
}

// parseKeywordArgs consumes the keyword-introduced arguments form allows at
// the current position and appends them to args.
func (p *Parser) parseKeywordArgs(form specialForm, args *[]ast.Expression) error {
	for {
		pos := p.currentLocation()
		var kw string
		switch form {
		case formSubstring, formOverlay:
			switch {
			case p.isType(models.TokenTypeFrom):
				kw = "FROM"
			case p.isType(models.TokenTypeFor):
				kw = "FOR"
			case form == formOverlay && p.isWord("PLACING"):
				kw = "PLACING"
			}
		case formTrim:
			if p.isType(models.TokenTypeFrom) {
				kw = "FROM"
			}
		case formPosition:
			if p.isType(models.TokenTypeIn) {
				kw = "IN"
			}
		case formConvert:
			if p.isType(models.TokenTypeUsing) {
				p.advance() // Consume USING
				if !p.isIdentifier() && !p.isType(models.TokenTypeKeyword) {
					return p.expectedError("character set name after USING")
				}
				*args = append(*args, &ast.KeywordArgument{Keyword: "USING", TypeName: p.currentToken.Token.Value, Pos: pos})
				p.advance() // Consume charset
				continue
			}
		case formParse, formColumnGet:
			if p.isType(models.TokenTypeAs) {
				p.advance() // Consume AS
				typ, err := p.parseDataType()
				if err != nil {
					return err
				}
				*args = append(*args, &ast.KeywordArgument{Keyword: "AS", TypeName: typ, Pos: pos})
				continue
			}
			if form == formParse && p.isType(models.TokenTypeUsing) {
				kw = "USING"
			}
		case formListagg:
			if done, err := p.parseListaggOverflow(args); done || err != nil {
				return err
			}
		}
		if kw == "" {
			return nil
		}
		p.advance() // Consume the keyword
		v, err := p.parseExpression()
		if err != nil {
			return err
		}
		*args = append(*args, &ast.KeywordArgument{Keyword: kw, Value: v, Pos: pos})
	}
}

// parseListaggOverflow parses the LISTAGG overflow clause
//
//	ON OVERFLOW ERROR
//	ON OVERFLOW TRUNCATE ['filler'] [WITH COUNT | WITHOUT COUNT]
//
// when the current token starts it. It always reports done, since nothing
// may follow the clause inside the argument list.
func (p *Parser) parseListaggOverflow(args *[]ast.Expression) (bool, error) {
	if !p.isType(models.TokenTypeOn) || !strings.EqualFold(p.peekToken().Token.Value, "OVERFLOW") {
		return true, nil
	}
	pos := p.currentLocation()
	p.advance() // Consume ON
	p.advance() // Consume OVERFLOW
	switch {
	case p.isWord("ERROR"):
		p.advance()
		*args = append(*args, &ast.KeywordArgument{Keyword: "ON OVERFLOW ERROR", Pos: pos})
		return true, nil
	case p.isWord("TRUNCATE"):
		p.advance()
	default:
		return true, p.expectedError("ERROR or TRUNCATE after ON OVERFLOW")
	}
	ka := &ast.KeywordArgument{Keyword: "ON OVERFLOW TRUNCATE", Pos: pos}
	if !p.isType(models.TokenTypeRParen) && !p.isType(models.TokenTypeWith) && !p.isWord("WITHOUT") {
		v, err := p.parseExpression()
		if err != nil {
			return true, err
		}
		ka.Value = v
	}
	*args = append(*args, ka)
	if p.isType(models.TokenTypeWith) || p.isWord("WITHOUT") {
		countPos := p.currentLocation()
		kw := "WITH COUNT"
		if p.isWord("WITHOUT") {
			kw = "WITHOUT COUNT"
		}
		p.advance() // Consume WITH / WITHOUT
		if !p.isWord("COUNT") {
			return true, p.expectedError("COUNT")
		}
		p.advance() // Consume COUNT
		*args = append(*args, &ast.KeywordArgument{Keyword: kw, Pos: countPos})
	}
	return true, nil
}

// parseKeepClause parses the Oracle aggregate modifier
// KEEP (DENSE_RANK FIRST|LAST ORDER BY ...). The current token is KEEP.
func (p *Parser) parseKeepClause() (*ast.KeepClause, error) {
	p.advance() // Consume KEEP
	p.advance() // Consume (
	p.advance() // Consume DENSE_RANK
	keep := &ast.KeepClause{}
	switch {
	case p.isType(models.TokenTypeFirst):
	case p.isType(models.TokenTypeLast):
		keep.Last = true
	default:
		return nil, p.expectedError("FIRST or LAST after DENSE_RANK")
	}
	p.advance() // Consume FIRST / LAST
	if !p.isType(models.TokenTypeOrder) {
		return nil, p.expectedError("ORDER BY in KEEP")
	}
	p.advance() // Consume ORDER
	if !p.isType(models.TokenTypeBy) {
		return nil, p.expectedError("BY after ORDER")
	}
	p.advance() // Consume BY
	orderBy, err := p.parseOrderByItems()
	if err != nil {
		return nil, err
	}
	keep.OrderBy = orderBy
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") after KEEP ORDER BY")
	}
	p.advance() // Consume )
	return keep, nil
}

// isKeepClause reports whether the current token starts an Oracle
// KEEP (DENSE_RANK ...) clause.
func (p *Parser) isKeepClause() bool {
	return p.isWord("KEEP") && p.peekToken().Token.Type == models.TokenTypeLParen &&
		strings.EqualFold(p.tokenAt(2).Token.Value, "DENSE_RANK")
}

// parseOrderByItems parses a comma-separated list of ORDER BY items
// (expr [ASC|DESC] [NULLS FIRST|LAST]) after ORDER BY.
func (p *Parser) parseOrderByItems() ([]ast.OrderByExpression, error) {
	var items []ast.OrderByExpression
	for {
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		item := ast.OrderByExpression{Expression: expr, Ascending: true}
		if p.isType(models.TokenTypeAsc) {
			p.advance()
		} else if p.isType(models.TokenTypeDesc) {
			item.Ascending = false
			p.advance()
		}
		nullsFirst, err := p.parseNullsClause()
		if err != nil {
			return nil, err
		}
		item.NullsFirst = nullsFirst
		items = append(items, item)
		if !p.isType(models.TokenTypeComma) {
			return items, nil
		}
		p.advance() // Consume ,
	}
}

// parseCastTypeString parses the rest of the ClickHouse form
// CAST(expr, 'Type'); the current token is the comma.
func (p *Parser) parseCastTypeString(expr ast.Expression) (*ast.CastExpression, error) {
	p.advance() // Consume ,
	if !p.isStringLiteral() {
		return nil, p.expectedError("type name string")
	}
	typ := p.currentToken.Token.Value
	p.advance() // Consume the type string
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )
	return &ast.CastExpression{Expr: expr, Type: typ, TypeAsString: true}, nil
}

// parseNestedBracketArray parses a nested bracket row of a multi-dimensional
// array constructor, ARRAY[[1, 2], [3, 4]], one recursion level deeper.
func (p *Parser) parseNestedBracketArray() (ast.Expression, error) {
	err := p.enterRecursion()
	defer p.leaveRecursion()
	if err != nil {
		return nil, err
	}
	return p.parseBracketArrayLiteral()
}

// isCastTypeModifierWord reports whether w continues a multi-word data type
// inside CAST(... AS type): DOUBLE PRECISION, CHARACTER VARYING,
// TIMESTAMP WITH[OUT] TIME ZONE, SIGNED/UNSIGNED [INTEGER]. The renderer
// writes these words unquoted (see ast typeModifierWords).
func isCastTypeModifierWord(w string) bool {
	switch strings.ToUpper(w) {
	case "PRECISION", "VARYING", "WITH", "WITHOUT", "LOCAL", "TIME", "ZONE",
		"UNSIGNED", "SIGNED", "ZEROFILL", "INTEGER", "INT":
		return true
	}
	return false
}

// parseCastTypeSuffix appends the later words of a multi-word type and any
// array suffixes ([] or [n]) to dataType.
func (p *Parser) parseCastTypeSuffix(dataType string) (string, error) {
	for p.currentToken.Token.Quote == 0 && !p.isStringLiteral() &&
		(p.isType(models.TokenTypeIdentifier) || p.isType(models.TokenTypeKeyword) ||
			p.isType(models.TokenTypeWith) || p.isType(models.TokenTypeInt) ||
			p.isType(models.TokenTypeInteger)) &&
		isCastTypeModifierWord(p.currentToken.Token.Value) {
		dataType += " " + p.currentToken.Token.Value
		p.advance()
		// CHARACTER VARYING(255)
		if p.isType(models.TokenTypeLParen) && p.peekToken().Token.Type == models.TokenTypeNumber &&
			p.tokenAt(2).Token.Type == models.TokenTypeRParen {
			dataType += "(" + p.peekToken().Token.Value + ")"
			p.advance()
			p.advance()
			p.advance()
		}
	}
	for p.isType(models.TokenTypeLBracket) {
		p.advance() // Consume [
		dim := ""
		if p.isType(models.TokenTypeNumber) {
			dim = p.currentToken.Token.Value
			p.advance()
		}
		if !p.isType(models.TokenTypeRBracket) {
			return "", p.expectedError("]")
		}
		p.advance() // Consume ]
		dataType += "[" + dim + "]"
	}
	return dataType, nil
}

// parseSeparatorLiteral parses the string literal after GROUP_CONCAT's
// SEPARATOR keyword; MySQL and MariaDB accept only a string literal there.
func (p *Parser) parseSeparatorLiteral() (*ast.LiteralValue, error) {
	if !p.isStringLiteral() {
		return nil, p.expectedError("string literal after SEPARATOR")
	}
	lit := p.newStringLiteral(p.currentToken.Token.Value)
	p.advance()
	return lit, nil
}
