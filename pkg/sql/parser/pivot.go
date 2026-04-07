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

// Package parser - pivot.go
// SQL Server / Oracle PIVOT and UNPIVOT clause parsing.

package parser

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// pivotDialectAllowed reports whether PIVOT/UNPIVOT is a recognized clause
// for the parser's current dialect. PIVOT/UNPIVOT are SQL Server / Oracle
// extensions; in other dialects the words must remain valid identifiers.
func (p *Parser) pivotDialectAllowed() bool {
	return p.dialect == string(keywords.DialectSQLServer) ||
		p.dialect == string(keywords.DialectOracle)
}

// isPivotKeyword returns true if the current token is the contextual PIVOT
// keyword in a dialect that supports it. PIVOT is non-reserved, so it may
// arrive as either an identifier or a keyword token.
func (p *Parser) isPivotKeyword() bool {
	if !p.pivotDialectAllowed() {
		return false
	}
	t := p.currentToken.Token.Type
	if t != models.TokenTypeKeyword && t != models.TokenTypeIdentifier {
		return false
	}
	return strings.EqualFold(p.currentToken.Token.Value, "PIVOT")
}

// isUnpivotKeyword mirrors isPivotKeyword for UNPIVOT.
func (p *Parser) isUnpivotKeyword() bool {
	if !p.pivotDialectAllowed() {
		return false
	}
	t := p.currentToken.Token.Type
	if t != models.TokenTypeKeyword && t != models.TokenTypeIdentifier {
		return false
	}
	return strings.EqualFold(p.currentToken.Token.Value, "UNPIVOT")
}

// parsePivotClause parses PIVOT (aggregate FOR column IN (values)).
// The current token must be the PIVOT keyword.
func (p *Parser) parsePivotClause() (*ast.PivotClause, error) {
	pos := p.currentLocation()
	p.advance() // consume PIVOT

	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("( after PIVOT")
	}
	p.advance() // consume (

	// Parse aggregate function expression (e.g. SUM(sales))
	aggFunc, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	// Expect FOR keyword
	if !p.isType(models.TokenTypeFor) {
		return nil, p.expectedError("FOR in PIVOT clause")
	}
	p.advance() // consume FOR

	// Parse pivot column name
	if !p.isIdentifier() {
		return nil, p.expectedError("column name after FOR in PIVOT")
	}
	pivotCol := p.currentToken.Token.Value
	p.advance()

	// Expect IN keyword
	if !p.isType(models.TokenTypeIn) {
		return nil, p.expectedError("IN in PIVOT clause")
	}
	p.advance() // consume IN

	// Expect opening parenthesis for value list
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("( after IN in PIVOT")
	}
	p.advance() // consume (

	// Parse IN values — identifiers (possibly bracket-quoted in SQL Server)
	var inValues []string
	for !p.isType(models.TokenTypeRParen) && !p.isType(models.TokenTypeEOF) {
		if !p.isIdentifier() && !p.isType(models.TokenTypeNumber) && !p.isStringLiteral() {
			return nil, p.expectedError("value in PIVOT IN list")
		}
		inValues = append(inValues, p.currentToken.Token.Value)
		p.advance()
		if p.isType(models.TokenTypeComma) {
			p.advance()
		}
	}

	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") to close PIVOT IN list")
	}
	p.advance() // close IN list )

	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") to close PIVOT clause")
	}
	p.advance() // close PIVOT )

	return &ast.PivotClause{
		AggregateFunction: aggFunc,
		PivotColumn:       pivotCol,
		InValues:          inValues,
		Pos:               pos,
	}, nil
}

// parseUnpivotClause parses UNPIVOT (value_col FOR name_col IN (columns)).
// The current token must be the UNPIVOT keyword.
func (p *Parser) parseUnpivotClause() (*ast.UnpivotClause, error) {
	pos := p.currentLocation()
	p.advance() // consume UNPIVOT

	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("( after UNPIVOT")
	}
	p.advance() // consume (

	// Parse value column name
	if !p.isIdentifier() {
		return nil, p.expectedError("value column name in UNPIVOT")
	}
	valueCol := p.currentToken.Token.Value
	p.advance()

	// Expect FOR keyword
	if !p.isType(models.TokenTypeFor) {
		return nil, p.expectedError("FOR in UNPIVOT clause")
	}
	p.advance() // consume FOR

	// Parse name column
	if !p.isIdentifier() {
		return nil, p.expectedError("name column after FOR in UNPIVOT")
	}
	nameCol := p.currentToken.Token.Value
	p.advance()

	// Expect IN keyword
	if !p.isType(models.TokenTypeIn) {
		return nil, p.expectedError("IN in UNPIVOT clause")
	}
	p.advance() // consume IN

	// Expect opening parenthesis for column list
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("( after IN in UNPIVOT")
	}
	p.advance() // consume (

	// Parse IN columns
	var cols []string
	for !p.isType(models.TokenTypeRParen) && !p.isType(models.TokenTypeEOF) {
		if !p.isIdentifier() {
			return nil, p.expectedError("column name in UNPIVOT IN list")
		}
		cols = append(cols, p.currentToken.Token.Value)
		p.advance()
		if p.isType(models.TokenTypeComma) {
			p.advance()
		}
	}

	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") to close UNPIVOT IN list")
	}
	p.advance() // close IN list )

	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") to close UNPIVOT clause")
	}
	p.advance() // close UNPIVOT )

	return &ast.UnpivotClause{
		ValueColumn: valueCol,
		NameColumn:  nameCol,
		InColumns:   cols,
		Pos:         pos,
	}, nil
}
