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

// renderQuotedIdent reproduces the original delimiters of a quoted identifier
// token so the parsed value round-trips through the formatter. The tokenizer
// strips delimiters but records the style in Token.Quote (or, for word
// tokens, Word.QuoteStyle). Embedded delimiters are escaped per dialect:
// SQL Server doubles `]`, ANSI doubles `"`, MySQL doubles “ ` “.
func renderQuotedIdent(tok models.Token) string {
	q := tok.Quote
	if q == 0 && tok.Word != nil {
		q = tok.Word.QuoteStyle
	}
	switch q {
	case '[':
		return "[" + strings.ReplaceAll(tok.Value, "]", "]]") + "]"
	case '"':
		return "\"" + strings.ReplaceAll(tok.Value, "\"", "\"\"") + "\""
	case '`':
		return "`" + strings.ReplaceAll(tok.Value, "`", "``") + "`"
	}
	return tok.Value
}

// renderPivotValue reproduces a PIVOT/UNPIVOT IN-list token in source form:
// a string literal is re-quoted and escaped the same way LiteralValue.SQL()
// writes strings, a quoted identifier keeps its delimiters
// (renderQuotedIdent), and anything else (a bare name or number) is returned
// as is.
func (p *Parser) renderPivotValue() string {
	if p.isStringLiteral() {
		return p.newStringLiteral(p.currentToken.Token.Value).SQL()
	}
	return renderQuotedIdent(p.currentToken.Token)
}

// parsePivotAlias consumes an optional alias (with or without AS) following a
// PIVOT/UNPIVOT clause. Extracted to avoid four copies of the same logic in
// the table-reference and join paths.
func (p *Parser) parsePivotAlias(ref *ast.TableReference) {
	if p.isType(models.TokenTypeAs) {
		p.advance() // consume AS
		if p.isIdentifier() {
			ref.Alias = p.currentToken.Token.Value
			p.advance()
		}
		return
	}
	if p.isIdentifier() {
		ref.Alias = p.currentToken.Token.Value
		p.advance()
	}
}

// pivotDialectAllowed reports whether PIVOT/UNPIVOT is a recognized clause
// for the parser's current dialect. PIVOT/UNPIVOT are SQL Server, Oracle,
// and Snowflake extensions; in other dialects the words must remain valid
// identifiers.
func (p *Parser) pivotDialectAllowed() bool {
	return p.dialect == string(keywords.DialectSQLServer) ||
		p.dialect == string(keywords.DialectOracle) ||
		p.dialect == string(keywords.DialectSnowflake)
}

// isPivotKeyword returns true if the current token is the contextual PIVOT
// isQualifyKeyword returns true if the current token is the Snowflake /
// BigQuery QUALIFY clause keyword. QUALIFY tokenizes as an identifier, so
// detect by value and gate by dialect to avoid consuming a legitimate
// table alias named "qualify" in other dialects.
//
// Migrated from p.dialect == "snowflake"/"bigquery" to Capabilities in
// Sprint 2. SupportsQualify is true only for Snowflake and BigQuery in
// dialect.Capabilities, preserving the exact previous behaviour.
func (p *Parser) isQualifyKeyword() bool {
	if !p.Capabilities().SupportsQualify {
		return false
	}
	return strings.EqualFold(p.currentToken.Token.Value, "QUALIFY")
}

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
	clause := &ast.PivotClause{Pos: pos}

	// Oracle PIVOT XML
	if p.IsOracle() && p.isTokenMatch("XML") && p.peekToken().Token.Type == models.TokenTypeLParen {
		clause.XML = true
		p.advance() // consume XML
	}

	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("( after PIVOT")
	}
	p.advance() // consume (

	// Parse the aggregate function expressions (e.g. SUM(sales)), each with
	// an optional alias (Oracle: SUM(c) AS total, COUNT(*) AS cnt).
	if err := p.parsePivotAggregates(clause); err != nil {
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

	clause.PivotColumn = pivotCol
	if handled, err := p.parsePivotInSpecial(clause); err != nil {
		return nil, err
	} else if handled {
		return clause, nil
	}

	// Parse IN values — identifiers, numbers, or string literals, each with
	// an optional AS alias (Oracle syntax: 'North' AS north).
	var inValues []string
	for !p.isType(models.TokenTypeRParen) && !p.isType(models.TokenTypeEOF) {
		if !p.isIdentifier() && !p.isType(models.TokenTypeNumber) && !p.isStringLiteral() {
			return nil, p.expectedError("value in PIVOT IN list")
		}
		val := p.renderPivotValue()
		p.advance()
		// Optional alias: AS <name>
		if p.isType(models.TokenTypeAs) {
			p.advance() // consume AS
			if p.isIdentifier() || p.isNonReservedKeyword() {
				val += " AS " + renderQuotedIdent(p.currentToken.Token)
				p.advance()
			}
		}
		inValues = append(inValues, val)
		if p.isType(models.TokenTypeComma) {
			p.advance()
		}
	}

	if len(inValues) == 0 {
		return nil, p.expectedError("at least one value in PIVOT IN list")
	}
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") to close PIVOT IN list")
	}
	p.advance() // close IN list )

	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") to close PIVOT clause")
	}
	p.advance() // close PIVOT )

	clause.InValues = inValues
	return clause, nil
}

// parseUnpivotClause parses UNPIVOT (value_col FOR name_col IN (columns)).
// The current token must be the UNPIVOT keyword.
func (p *Parser) parseUnpivotClause() (*ast.UnpivotClause, error) {
	pos := p.currentLocation()
	p.advance() // consume UNPIVOT

	// Oracle / Snowflake: UNPIVOT {INCLUDE | EXCLUDE} NULLS
	nullHandling := ""
	if (p.isTokenMatch("INCLUDE") || p.isTokenMatch("EXCLUDE")) &&
		equalsUpper(p.peekToken().Token.Value, "NULLS") {
		nullHandling = strings.ToUpper(p.currentToken.Token.Value)
		p.advance() // consume INCLUDE / EXCLUDE
		p.advance() // consume NULLS
	}

	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("( after UNPIVOT")
	}
	p.advance() // consume (

	// Parse value column name, or an Oracle column list: (units, revenue)
	var valueCols []string
	if p.IsOracle() && p.isType(models.TokenTypeLParen) {
		cols, err := p.parseParenthesizedWordList("value column name in UNPIVOT")
		if err != nil {
			return nil, err
		}
		valueCols = cols
	} else {
		if !p.isIdentifier() {
			return nil, p.expectedError("value column name in UNPIVOT")
		}
		valueCols = []string{p.currentToken.Token.Value}
		p.advance()
	}
	valueCol := valueCols[0]

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

	// Parse IN columns — each may have an optional AS alias (Oracle:
	// north_sales AS 'North').
	var cols []string
	for !p.isType(models.TokenTypeRParen) && !p.isType(models.TokenTypeEOF) {
		var col string
		if len(valueCols) > 1 && p.isType(models.TokenTypeLParen) {
			// Multi-column UNPIVOT entry: (u1, r1) AS 'P1'
			tuple, err := p.parsePivotTuple()
			if err != nil {
				return nil, err
			}
			col = tuple
		} else {
			if !p.isIdentifier() {
				return nil, p.expectedError("column name in UNPIVOT IN list")
			}
			col = renderQuotedIdent(p.currentToken.Token)
			p.advance()
		}
		// Optional alias: AS <string_literal_or_identifier>
		if p.isType(models.TokenTypeAs) {
			p.advance() // consume AS
			if p.isStringLiteral() || p.isIdentifier() || p.isNonReservedKeyword() {
				col += " AS " + p.renderPivotValue()
				p.advance()
			}
		}
		cols = append(cols, col)
		if p.isType(models.TokenTypeComma) {
			p.advance()
		}
	}

	if len(cols) == 0 {
		return nil, p.expectedError("at least one column in UNPIVOT IN list")
	}
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") to close UNPIVOT IN list")
	}
	p.advance() // close IN list )

	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") to close UNPIVOT clause")
	}
	p.advance() // close UNPIVOT )

	clause := &ast.UnpivotClause{
		ValueColumn:  valueCol,
		NameColumn:   nameCol,
		InColumns:    cols,
		Pos:          pos,
		NullHandling: nullHandling,
	}
	if len(valueCols) > 1 {
		clause.ValueColumns = valueCols
	}
	return clause, nil
}

// supportsTableFunction reports whether the current dialect allows
// function-call style table references in the FROM list — Snowflake
// (FLATTEN, TABLE, IDENTIFIER, GENERATOR), BigQuery (UNNEST),
// PostgreSQL (unnest, generate_series, json_each, ...), and ClickHouse
// (numbers, remote, file, s3, url, ...).
func (p *Parser) supportsTableFunction() bool {
	switch p.dialect {
	case string(keywords.DialectSnowflake),
		string(keywords.DialectBigQuery),
		string(keywords.DialectPostgreSQL),
		string(keywords.DialectClickHouse):
		return true
	}
	return false
}

// isClickHouseKeywordTableFunction reports whether the current token starts a
// ClickHouse table function whose name the tokenizer classifies as a keyword
// (url, merge, values, null) and is directly followed by '('.
func (p *Parser) isClickHouseKeywordTableFunction() bool {
	if p.dialect != string(keywords.DialectClickHouse) ||
		p.peekToken().Token.Type != models.TokenTypeLParen {
		return false
	}
	switch p.currentToken.Token.Type {
	case models.TokenTypeUrl, models.TokenTypeMerge,
		models.TokenTypeValues, models.TokenTypeNull:
		return true
	}
	return false
}

// parseSnowflakeTimeTravel parses the Snowflake time-travel / change-tracking
// modifier attached to a table reference. The current token must be one of
// AT / BEFORE / CHANGES. Returns the head clause with any additional clauses
// appended to Chained (e.g. CHANGES (...) AT (...)).
func (p *Parser) parseSnowflakeTimeTravel() (*ast.TimeTravelClause, error) {
	head, err := p.parseOneTimeTravelClause()
	if err != nil {
		return nil, err
	}
	// Allow additional clauses: CHANGES (...) AT (...) is legal.
	for p.isSnowflakeTimeTravelStart() {
		next, err := p.parseOneTimeTravelClause()
		if err != nil {
			return nil, err
		}
		head.Chained = append(head.Chained, next)
	}
	return head, nil
}

func (p *Parser) parseOneTimeTravelClause() (*ast.TimeTravelClause, error) {
	pos := p.currentLocation()
	kind := strings.ToUpper(p.currentToken.Token.Value)
	p.advance() // Consume AT / BEFORE / CHANGES
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("( after " + kind)
	}
	p.advance() // Consume (

	clause := &ast.TimeTravelClause{
		Kind:  kind,
		Named: map[string]ast.Expression{},
		Pos:   pos,
	}

	// Parse comma-separated named arguments: name => expr [, name => expr]...
	// Snowflake uses TIMESTAMP, OFFSET, STATEMENT, INFORMATION as argument
	// names; these tokenize as dedicated keyword types, not identifiers.
	// Accept any non-punctuation token with a non-empty value as the name.
	for {
		argName := strings.ToUpper(p.currentToken.Token.Value)
		if argName == "" || p.isType(models.TokenTypeRParen) ||
			p.isType(models.TokenTypeComma) || p.isType(models.TokenTypeLParen) {
			return nil, p.expectedError("argument name in " + kind)
		}
		p.advance()
		if p.currentToken.Token.Type != models.TokenTypeRArrow {
			return nil, p.expectedError("=> after " + argName)
		}
		p.advance() // =>
		// Values are typically literal expressions, but may also be bare
		// keywords like DEFAULT or APPEND_ONLY for CHANGES (INFORMATION => …).
		var value ast.Expression
		if v, err := p.parseExpression(); err == nil {
			value = v
		} else if p.currentToken.Token.Value != "" &&
			!p.isType(models.TokenTypeRParen) && !p.isType(models.TokenTypeComma) {
			value = &ast.Identifier{Name: p.currentToken.Token.Value}
			p.advance()
		} else {
			return nil, err
		}
		clause.Named[argName] = value
		if p.isType(models.TokenTypeComma) {
			p.advance()
			continue
		}
		break
	}

	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )
	return clause, nil
}

// isSnowflakeTimeTravelStart returns true when the current token begins an
// AT / BEFORE / CHANGES time-travel clause in the Snowflake dialect.
func (p *Parser) isSnowflakeTimeTravelStart() bool {
	if p.dialect != string(keywords.DialectSnowflake) {
		return false
	}
	// BEFORE / CHANGES: plain identifier or keyword
	val := p.currentToken.Token.Value
	if equalsUpper(val, "BEFORE") || equalsUpper(val, "CHANGES") {
		// Must be followed by '(' to disambiguate from other uses.
		return p.peekToken().Token.Type == models.TokenTypeLParen
	}
	// AT: either TokenTypeAt (@) or an identifier-token "AT" followed by '('.
	if equalsUpper(val, "AT") && p.peekToken().Token.Type == models.TokenTypeLParen {
		return true
	}
	return false
}

// isSampleKeyword returns true if the current token is SAMPLE or TABLESAMPLE
// followed by '(' or a sampling-method keyword, indicating a sampling clause
// rather than a table alias. Used to prevent the FROM-alias parser from
// consuming these tokens.
func (p *Parser) isSampleKeyword() bool {
	v := p.currentToken.Token.Value
	if !equalsUpper(v, "SAMPLE") && !equalsUpper(v, "TABLESAMPLE") {
		return false
	}
	// Require '(' or a method keyword as lookahead to disambiguate from
	// a table actually named "sample".
	next := p.peekToken().Token
	if next.Type == models.TokenTypeLParen {
		return true
	}
	nv := next.Value
	if equalsUpper(nv, "BERNOULLI") || equalsUpper(nv, "SYSTEM") || equalsUpper(nv, "BLOCK") || equalsUpper(nv, "ROW") {
		return true
	}
	// ClickHouse: SAMPLE followed by a number (SAMPLE 0.1, SAMPLE 10000, SAMPLE 1/10)
	if p.dialect == string(keywords.DialectClickHouse) && next.Type == models.TokenTypeNumber {
		return true
	}
	return false
}
