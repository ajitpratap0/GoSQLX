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

// Package parser - select_ext.go
// Dialect-specific SELECT-body clauses: MySQL select modifiers, star
// modifiers (EXCLUDE / EXCEPT / REPLACE / RENAME / ILIKE), SELECT ... INTO,
// LIMIT/OFFSET values as expressions, ClickHouse LIMIT BY / FORMAT, SQL Server
// FOR JSON / FOR XML and OPTION (...), MySQL LOCK IN SHARE MODE.

package parser

import (
	"strconv"
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// isUnquotedWord reports whether the current token is an unquoted
// identifier or keyword whose text equals upper (case-insensitively).
func (p *Parser) isUnquotedWord(upper string) bool {
	t := p.currentToken.Token
	switch t.Type {
	case models.TokenTypeDoubleQuotedString, models.TokenTypeString,
		models.TokenTypeSingleQuotedString, models.TokenTypeDollarQuotedString:
		return false
	}
	return equalsUpper(t.Value, upper) && !p.isQuotedIdentifierToken()
}

// isSelectExtClauseStart reports whether the current identifier starts one
// of the clauses parsed in this file (or a join written with a dialect word)
// rather than naming an alias: ClickHouse FORMAT / GLOBAL / ASOF / SEMI /
// ANTI, Snowflake ASOF / MATCH_CONDITION, MySQL STRAIGHT_JOIN / LOCK IN
// SHARE MODE, SQL Server OPTION (...).
func (p *Parser) isSelectExtClauseStart() bool {
	if p.currentToken.Token.Type != models.TokenTypeIdentifier {
		return false
	}
	switch p.dialect {
	case string(keywords.DialectClickHouse):
		return p.isFormatClauseStart() || p.isJoinStrictnessStart() ||
			(p.isUnquotedWord("GLOBAL") && p.peekStartsJoin())
	case string(keywords.DialectSnowflake):
		return p.isJoinStrictnessStart() ||
			(p.isUnquotedWord("MATCH_CONDITION") && p.peekToken().Token.Type == models.TokenTypeLParen)
	case string(keywords.DialectMySQL), string(keywords.DialectMariaDB):
		return p.isUnquotedWord("STRAIGHT_JOIN") || p.isLockInShareMode()
	case string(keywords.DialectSQLServer):
		return p.isQueryHintStart()
	case string(keywords.DialectOracle):
		// The error logging clause of INSERT ... SELECT ... LOG ERRORS.
		return p.isUnquotedWord("LOG") && p.peekValueIs(1, "ERRORS")
	}
	return false
}

// peekStartsJoin reports whether the token after the current one starts a
// join: JOIN, a join kind (INNER, LEFT, ...), ANY / ALL, or a ClickHouse /
// Snowflake strictness word followed by more join keywords.
func (p *Parser) peekStartsJoin() bool {
	next := p.peekToken().Token
	switch next.Type {
	case models.TokenTypeJoin, models.TokenTypeInner, models.TokenTypeLeft,
		models.TokenTypeRight, models.TokenTypeFull, models.TokenTypeCross,
		models.TokenTypeAny, models.TokenTypeAll, models.TokenTypeOuter:
		return true
	case models.TokenTypeIdentifier:
		v := next.Value
		return equalsUpper(v, "ASOF") || equalsUpper(v, "SEMI") || equalsUpper(v, "ANTI") ||
			equalsUpper(v, "PASTE")
	}
	return false
}

// isJoinStrictnessStart reports whether the current token is a join
// strictness word written before the join kind: ClickHouse ASOF / SEMI /
// ANTI (ANY and ALL are keywords) and Snowflake ASOF, followed by JOIN or a
// join kind.
func (p *Parser) isJoinStrictnessStart() bool {
	if p.currentToken.Token.Type != models.TokenTypeIdentifier || p.isQuotedIdentifierToken() {
		return false
	}
	v := p.currentToken.Token.Value
	switch p.dialect {
	case string(keywords.DialectClickHouse):
		if !equalsUpper(v, "ASOF") && !equalsUpper(v, "SEMI") && !equalsUpper(v, "ANTI") {
			return false
		}
		return p.peekStartsJoin()
	case string(keywords.DialectSnowflake):
		return equalsUpper(v, "ASOF") && p.peekToken().Token.Type == models.TokenTypeJoin
	}
	return false
}

// parseSelectModifiers parses MySQL / MariaDB select modifiers after SELECT
// [DISTINCT]: HIGH_PRIORITY, STRAIGHT_JOIN, SQL_SMALL_RESULT,
// SQL_BIG_RESULT, SQL_BUFFER_RESULT, SQL_NO_CACHE, SQL_CACHE,
// SQL_CALC_FOUND_ROWS. A word is a modifier only when a select-list item
// follows it, so a column with such a name still parses.
func (p *Parser) parseSelectModifiers() []string {
	if !p.isMySQLFamily() {
		return nil
	}
	var mods []string
	for p.currentToken.Token.Type == models.TokenTypeIdentifier && !p.isQuotedIdentifierToken() {
		m := ast.SelectModifierText(p.currentToken.Token.Value)
		if m == "" {
			break
		}
		switch p.peekToken().Token.Type {
		case models.TokenTypeComma, models.TokenTypeFrom, models.TokenTypeEOF,
			models.TokenTypeSemicolon, models.TokenTypePeriod, models.TokenTypeAs,
			models.TokenTypeLParen, models.TokenTypeRParen:
			return mods
		}
		mods = append(mods, strings.ToUpper(m))
		p.advance()
	}
	return mods
}

// supportsStarModifiers reports whether the dialect accepts modifiers after
// a select-list wildcard.
func (p *Parser) supportsStarModifiers() bool {
	switch p.dialect {
	case string(keywords.DialectSnowflake), string(keywords.DialectClickHouse),
		string(keywords.DialectBigQuery):
		return true
	}
	return false
}

// isStarModifierStart reports whether the current token starts a wildcard
// modifier. ClickHouse / BigQuery "* EXCEPT (" is a modifier, not the set
// operator, because a set operator never directly follows a wildcard.
func (p *Parser) isStarModifierStart() bool {
	if !p.supportsStarModifiers() {
		return false
	}
	next := p.peekToken().Token.Type
	switch {
	case p.isType(models.TokenTypeExclude) || p.isUnquotedWord("EXCLUDE"):
		return p.dialect == string(keywords.DialectSnowflake) &&
			(next == models.TokenTypeLParen || next == models.TokenTypeIdentifier)
	case p.isType(models.TokenTypeExcept):
		return p.dialect != string(keywords.DialectSnowflake) &&
			(next == models.TokenTypeLParen || next == models.TokenTypeIdentifier)
	case p.isType(models.TokenTypeReplace) || p.isUnquotedWord("REPLACE"):
		return next == models.TokenTypeLParen
	case p.isUnquotedWord("RENAME"):
		return p.dialect == string(keywords.DialectSnowflake) &&
			(next == models.TokenTypeLParen || next == models.TokenTypeIdentifier)
	case p.isUnquotedWord("ILIKE"):
		return p.dialect == string(keywords.DialectSnowflake)
	case p.isUnquotedWord("APPLY"):
		return p.dialect == string(keywords.DialectClickHouse) && next == models.TokenTypeLParen
	}
	return false
}

// parseStarModifiers parses the modifiers after a select-list wildcard and
// returns the wildcard unchanged when there are none.
func (p *Parser) parseStarModifiers(star ast.Expression) (ast.Expression, error) {
	if !p.isStarModifierStart() {
		return star, nil
	}
	se := &ast.StarExpression{Star: star}
	for p.isStarModifierStart() {
		switch {
		case p.isUnquotedWord("ILIKE"):
			p.advance() // ILIKE
			if !p.isStringLiteral() {
				return nil, p.expectedError("pattern string after ILIKE")
			}
			pat, err := p.parsePrimaryExpression()
			if err != nil {
				return nil, err
			}
			se.Ilike = pat
		case p.isType(models.TokenTypeExclude) || p.isUnquotedWord("EXCLUDE") || p.isType(models.TokenTypeExcept):
			se.ExcludeKeyword = strings.ToUpper(p.currentToken.Token.Value)
			p.advance() // EXCLUDE / EXCEPT
			cols, err := p.parseStarColumnList()
			if err != nil {
				return nil, err
			}
			se.Exclude = append(se.Exclude, cols...)
		case p.isType(models.TokenTypeReplace) || p.isUnquotedWord("REPLACE"):
			p.advance() // REPLACE
			p.advance() // (
			for {
				e, err := p.parseExpression()
				if err != nil {
					return nil, err
				}
				if !p.isType(models.TokenTypeAs) {
					return nil, p.expectedError("AS in REPLACE item")
				}
				p.advance() // AS
				if !p.isIdentifier() && !p.isNonReservedKeyword() {
					return nil, p.expectedError("column name after AS")
				}
				se.Replace = append(se.Replace, &ast.AliasedExpression{Expr: e, Alias: p.currentToken.Token.Value})
				p.advance()
				if !p.isType(models.TokenTypeComma) {
					break
				}
				p.advance() // ,
			}
			if !p.isType(models.TokenTypeRParen) {
				return nil, p.expectedError(") after REPLACE list")
			}
			p.advance() // )
		case p.isUnquotedWord("APPLY"):
			p.advance() // APPLY
			p.advance() // (
			fn, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			if !p.isType(models.TokenTypeRParen) {
				return nil, p.expectedError(") after APPLY function")
			}
			p.advance() // )
			se.Apply = append(se.Apply, fn)
		default: // RENAME
			p.advance() // RENAME
			paren := p.isType(models.TokenTypeLParen)
			if paren {
				p.advance()
			}
			for {
				if !p.isIdentifier() && !p.isNonReservedKeyword() {
					return nil, p.expectedError("column name in RENAME")
				}
				col := p.currentToken.Token.Value
				p.advance()
				if !p.isType(models.TokenTypeAs) {
					return nil, p.expectedError("AS in RENAME item")
				}
				p.advance()
				if !p.isIdentifier() && !p.isNonReservedKeyword() {
					return nil, p.expectedError("new column name in RENAME")
				}
				se.Rename = append(se.Rename, ast.StarRename{Column: col, Alias: p.currentToken.Token.Value})
				p.advance()
				if !paren || !p.isType(models.TokenTypeComma) {
					break
				}
				p.advance()
			}
			if paren {
				if !p.isType(models.TokenTypeRParen) {
					return nil, p.expectedError(") after RENAME list")
				}
				p.advance()
			}
		}
	}
	return se, nil
}

// parseStarColumnList parses "col" or "(col, ...)" after EXCLUDE / EXCEPT.
func (p *Parser) parseStarColumnList() ([]string, error) {
	if !p.isType(models.TokenTypeLParen) {
		if !p.isIdentifier() {
			return nil, p.expectedError("column name")
		}
		name := p.currentToken.Token.Value
		p.advance()
		return []string{name}, nil
	}
	p.advance() // (
	var cols []string
	for {
		if !p.isIdentifier() && !p.isNonReservedKeyword() {
			return nil, p.expectedError("column name")
		}
		name := p.currentToken.Token.Value
		p.advance()
		// Qualified names (t.col) are kept whole.
		for p.isType(models.TokenTypePeriod) {
			p.advance()
			if !p.isIdentifier() && !p.isNonReservedKeyword() {
				return nil, p.expectedError("column name after .")
			}
			name += "." + p.currentToken.Token.Value
			p.advance()
		}
		cols = append(cols, name)
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance()
	}
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance()
	return cols, nil
}

// supportsSelectInto reports whether SELECT ... INTO is accepted.
func (p *Parser) supportsSelectInto() bool {
	switch p.dialect {
	case string(keywords.DialectSQLite), string(keywords.DialectClickHouse):
		return false
	}
	return true
}

// parseSelectInto parses an INTO clause; the current token is INTO.
// trailing records that it follows the FROM ... clauses (MySQL).
func (p *Parser) parseSelectInto(trailing bool) (*ast.SelectInto, error) {
	p.advance() // INTO
	in := &ast.SelectInto{Trailing: trailing}
	switch {
	case p.isUnquotedWord("OUTFILE") || p.isUnquotedWord("DUMPFILE"):
		if !p.isMySQLFamily() {
			return nil, p.expectedError("INTO target")
		}
		in.Kind = strings.ToUpper(p.currentToken.Token.Value)
		p.advance()
		if !p.isStringLiteral() {
			return nil, p.expectedError("file name string after INTO " + in.Kind)
		}
		file, err := p.parsePrimaryExpression()
		if err != nil {
			return nil, err
		}
		in.File = file
		if in.Kind == ast.SelectIntoOutfile {
			if err := p.parseOutfileOptions(in); err != nil {
				return nil, err
			}
		}
		return in, nil
	case p.isMySQLFamily() || p.dialect == string(keywords.DialectOracle) ||
		p.isType(models.TokenTypePlaceholder):
		// Variables: @a, @b (MySQL), local variables, :bind (Oracle PL/SQL).
		in.Kind = ast.SelectIntoVariables
		for {
			e, err := p.parsePrimaryExpression()
			if err != nil {
				return nil, err
			}
			in.Targets = append(in.Targets, e)
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance()
		}
		return in, nil
	}

	// New table (SQL Server, PostgreSQL): [TEMP|TEMPORARY|UNLOGGED] [TABLE] name
	in.Kind = ast.SelectIntoTable
	if p.dialect != string(keywords.DialectSQLServer) {
		if t := ast.SelectIntoTemporaryText(p.currentToken.Token.Value); t != "" && !p.isQuotedIdentifierToken() &&
			p.peekToken().Token.Type != models.TokenTypeFrom && p.peekToken().Token.Type != models.TokenTypeEOF {
			in.Temporary = strings.ToUpper(t)
			p.advance()
		}
		if p.isType(models.TokenTypeTable) {
			in.TableKeyword = true
			p.advance()
		}
	}
	name, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.qualifiedNameError(err, "table name after INTO")
	}
	in.Table = name
	return in, nil
}

// parseOutfileOptions parses the MySQL INTO OUTFILE options:
//
//	[CHARACTER SET cs] [{FIELDS|COLUMNS} [TERMINATED BY s] [[OPTIONALLY]
//	ENCLOSED BY c] [ESCAPED BY c]] [LINES [STARTING BY s] [TERMINATED BY s]]
func (p *Parser) parseOutfileOptions(in *ast.SelectInto) error {
	if p.isUnquotedWord("CHARACTER") && strings.EqualFold(p.peekToken().Token.Value, "SET") {
		p.advance() // CHARACTER
		p.advance() // SET
		if !p.isIdentifier() && !p.isNonReservedKeyword() {
			return p.expectedError("character set name")
		}
		in.CharacterSet = p.currentToken.Token.Value
		p.advance()
	}
	if p.isUnquotedWord("FIELDS") || p.isUnquotedWord("COLUMNS") {
		p.advance()
		opts, err := p.parseIntoFileOptionList()
		if err != nil {
			return err
		}
		in.FieldsOptions = opts
	}
	if p.isUnquotedWord("LINES") {
		p.advance()
		opts, err := p.parseIntoFileOptionList()
		if err != nil {
			return err
		}
		in.LinesOptions = opts
	}
	return nil
}

// parseIntoFileOptionList parses "<option> BY 'value'" items.
func (p *Parser) parseIntoFileOptionList() ([]ast.IntoFileOption, error) {
	var opts []ast.IntoFileOption
	for {
		var name string
		switch {
		case p.isUnquotedWord("TERMINATED"):
			name = "TERMINATED BY"
		case p.isUnquotedWord("ENCLOSED"):
			name = "ENCLOSED BY"
		case p.isUnquotedWord("ESCAPED"):
			name = "ESCAPED BY"
		case p.isUnquotedWord("STARTING"):
			name = "STARTING BY"
		case p.isUnquotedWord("OPTIONALLY"):
			p.advance()
			if !p.isUnquotedWord("ENCLOSED") {
				return nil, p.expectedError("ENCLOSED after OPTIONALLY")
			}
			name = "OPTIONALLY ENCLOSED BY"
		default:
			if len(opts) == 0 {
				return nil, p.expectedError("TERMINATED, ENCLOSED, ESCAPED or STARTING")
			}
			return opts, nil
		}
		p.advance()
		if !p.isType(models.TokenTypeBy) {
			return nil, p.expectedError("BY")
		}
		p.advance()
		if !p.isStringLiteral() {
			return nil, p.expectedError("string")
		}
		v, err := p.parsePrimaryExpression()
		if err != nil {
			return nil, err
		}
		opts = append(opts, ast.IntoFileOption{Option: name, Value: v})
	}
}

// isPlainIntToken reports whether the current token is an unsigned decimal
// integer that fits in an int, and returns its value.
func (p *Parser) isPlainIntToken() (int, bool) {
	if p.currentToken.Token.Type != models.TokenTypeNumber {
		return 0, false
	}
	v := p.currentToken.Token.Value
	if v == "" {
		return 0, false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return n, true
}

// parseRowCountValue parses a LIMIT / OFFSET / FETCH value. A plain integer
// followed by a clause boundary is returned as n (the common case, without
// allocating); anything else ($1, ?, @n, -1, 1 + 1, (SELECT ...)) is parsed
// as an expression.
func (p *Parser) parseRowCountValue() (n *int, expr ast.Expression, err error) {
	if v, ok := p.isPlainIntToken(); ok {
		switch p.peekToken().Token.Type {
		case models.TokenTypePlus, models.TokenTypeMinus, models.TokenTypeMul,
			models.TokenTypeAsterisk, models.TokenTypeDiv, models.TokenTypeMod,
			models.TokenTypeCaret, models.TokenTypeStringConcat, models.TokenTypePeriod,
			models.TokenTypeLParen, models.TokenTypeDoubleColon:
		default:
			p.advance()
			return &v, nil, nil
		}
	}
	e, err := p.parseExpression()
	if err != nil {
		return nil, nil, err
	}
	return nil, e, nil
}

// limitCommaDialect reports whether "LIMIT offset, count" is accepted.
func (p *Parser) limitCommaDialect() bool {
	switch p.dialect {
	case string(keywords.DialectMySQL), string(keywords.DialectMariaDB),
		string(keywords.DialectClickHouse), string(keywords.DialectSQLite):
		return true
	}
	return false
}

// parseLimitOffsetInto parses the optional LIMIT and OFFSET clauses (in
// either order) into s, including ClickHouse LIMIT n [OFFSET m] BY expr and
// LIMIT n WITH TIES.
func (p *Parser) parseLimitOffsetInto(s *ast.SelectStatement) error {
	sawLimit, sawOffset := false, false
	for {
		switch {
		case !sawLimit && p.isType(models.TokenTypeLimit):
			sawLimit = true
			offsetBeforeLimit := sawOffset
			if err := p.parseLimitValue(s); err != nil {
				return err
			}
			// ClickHouse LIMIT n [OFFSET m] BY expr, ... [LIMIT ...]
			if p.dialect == string(keywords.DialectClickHouse) {
				if p.isType(models.TokenTypeOffset) && !sawOffset {
					sawOffset = true
					if err := p.parseOffsetValue(s); err != nil {
						return err
					}
				}
				if p.isType(models.TokenTypeBy) {
					// Only one LIMIT BY is allowed, it takes no WITH TIES,
					// and an OFFSET written before LIMIT belongs to the
					// whole result, not to LIMIT BY: reject these rather
					// than silently drop or move a clause.
					switch {
					case s.Extras != nil && s.Extras.LimitBy != nil:
						return goerrors.InvalidSyntaxError("only one LIMIT ... BY clause is allowed", p.currentLocation(), "")
					case s.DialectExtras().LimitWithTies:
						return goerrors.InvalidSyntaxError("WITH TIES cannot be used with LIMIT ... BY", p.currentLocation(), "")
					case offsetBeforeLimit:
						return goerrors.InvalidSyntaxError("OFFSET for LIMIT ... BY must follow the LIMIT count", p.currentLocation(), "")
					}
					if err := p.parseLimitByTail(s); err != nil {
						return err
					}
					sawLimit, sawOffset = false, false
				}
			}
		case !sawOffset && p.isType(models.TokenTypeOffset):
			sawOffset = true
			if err := p.parseOffsetValue(s); err != nil {
				return err
			}
		case (s.Extras == nil || s.Extras.RowsExamined == nil) && sawLimit && p.isRowsExamined():
			if err := p.parseRowsExamined(s); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

// hasSelectInto reports whether s already has an INTO clause.
func hasSelectInto(s *ast.SelectStatement) bool {
	return s.Extras != nil && s.Extras.Into != nil
}

// parseTrailingSelectInto parses a MySQL INTO written after the FROM ...
// clauses into s; the current token is INTO.
func (p *Parser) parseTrailingSelectInto(s *ast.SelectStatement) error {
	into, err := p.parseSelectInto(true)
	if err != nil {
		return err
	}
	s.EnsureExtras().Into = into
	return nil
}

// parseLimitValue parses "LIMIT value [, value] [WITH TIES]"; the current
// token is LIMIT.
func (p *Parser) parseLimitValue(s *ast.SelectStatement) error {
	// Reject LIMIT in SQL Server and Oracle - these dialects use TOP/OFFSET-FETCH or ROWNUM/FETCH FIRST.
	if p.dialect == string(keywords.DialectSQLServer) || p.dialect == string(keywords.DialectOracle) {
		msg := "LIMIT clause is not supported in SQL Server; use TOP or OFFSET/FETCH NEXT instead"
		if p.dialect == string(keywords.DialectOracle) {
			msg = "LIMIT clause is not supported in Oracle; use ROWNUM or FETCH FIRST … ROWS ONLY instead"
		}
		return goerrors.UnsupportedFeatureError(msg, p.currentLocation(), "")
	}
	p.advance() // LIMIT

	if p.isType(models.TokenTypeAll) {
		p.advance()
		s.Limit, s.EnsureExtras().LimitExpr, s.EnsureExtras().LimitAll = nil, nil, true
		return nil
	}
	if p.isType(models.TokenTypeEOF) || p.isType(models.TokenTypeSemicolon) {
		return p.expectedError("value for LIMIT")
	}
	n, e, err := p.parseRowCountValue()
	if err != nil {
		return err
	}
	// MySQL / MariaDB / SQLite / ClickHouse: LIMIT offset, count
	if p.limitCommaDialect() && p.isType(models.TokenTypeComma) {
		p.advance()
		cn, ce, err := p.parseRowCountValue()
		if err != nil {
			return err
		}
		s.Offset = n
		if e != nil || s.Extras != nil {
			s.EnsureExtras().OffsetExpr = e
		}
		n, e = cn, ce
	}
	s.Limit = n
	if e != nil || s.Extras != nil {
		x := s.EnsureExtras()
		x.LimitExpr, x.LimitAll = e, false
	}
	if p.dialect == string(keywords.DialectClickHouse) && p.isType(models.TokenTypeWith) &&
		p.peekToken().Token.Type == models.TokenTypeTies {
		p.advance() // WITH
		p.advance() // TIES
		s.EnsureExtras().LimitWithTies = true
	}
	return nil
}

// parseOffsetValue parses "OFFSET value [ROW|ROWS]"; the current token is
// OFFSET.
func (p *Parser) parseOffsetValue(s *ast.SelectStatement) error {
	p.advance() // OFFSET
	if p.isType(models.TokenTypeEOF) || p.isType(models.TokenTypeSemicolon) {
		return p.expectedError("value for OFFSET")
	}
	n, e, err := p.parseRowCountValue()
	if err != nil {
		return err
	}
	s.Offset = n
	if e != nil || s.Extras != nil {
		s.EnsureExtras().OffsetExpr = e
	}
	if p.isAnyType(models.TokenTypeRow, models.TokenTypeRows) && !p.isRowsExamined() {
		s.EnsureExtras().OffsetRows = true
		p.advance()
	}
	return nil
}

// isRowsExamined reports whether the current tokens are MariaDB's
// ROWS EXAMINED, the end of a LIMIT clause.
func (p *Parser) isRowsExamined() bool {
	return p.isMariaDB() && p.isAnyType(models.TokenTypeRows) && p.peekValueIs(1, "EXAMINED")
}

// parseRowsExamined parses "ROWS EXAMINED n" into s; the current token is ROWS.
func (p *Parser) parseRowsExamined(s *ast.SelectStatement) error {
	p.advance() // Consume ROWS
	p.advance() // Consume EXAMINED
	n, err := p.parseExpression()
	if err != nil {
		return err
	}
	s.EnsureExtras().RowsExamined = n
	return nil
}

// parseLimitByTail moves the LIMIT / OFFSET just parsed into a ClickHouse
// LIMIT BY clause and parses its BY list; the current token is BY.
func (p *Parser) parseLimitByTail(s *ast.SelectStatement) error {
	lb := &ast.LimitByClause{Count: rowCountExpr(s.Limit, s.DialectExtras().LimitExpr)}
	if s.HasOffset() {
		lb.Offset = rowCountExpr(s.Offset, s.DialectExtras().OffsetExpr)
	}
	if lb.Count == nil {
		return p.expectedError("row count before LIMIT ... BY")
	}
	s.Limit, s.EnsureExtras().LimitExpr, s.Offset, s.EnsureExtras().OffsetExpr, s.EnsureExtras().OffsetRows = nil, nil, nil, nil, false
	p.advance() // BY
	for {
		e, err := p.parseExpression()
		if err != nil {
			return err
		}
		lb.Exprs = append(lb.Exprs, e)
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance()
	}
	s.EnsureExtras().LimitBy = lb
	return nil
}

// rowCountExpr returns n as an integer literal, else e.
func rowCountExpr(n *int, e ast.Expression) ast.Expression {
	if n != nil {
		return &ast.LiteralValue{Value: strconv.Itoa(*n), Type: "int"}
	}
	return e
}

// isLockInShareMode reports whether the current tokens are MySQL / MariaDB
// LOCK IN SHARE MODE.
func (p *Parser) isLockInShareMode() bool {
	return p.isMySQLFamily() && p.isUnquotedWord("LOCK") && p.peekToken().Token.Type == models.TokenTypeIn
}

// parseLockInShareMode parses "LOCK IN SHARE MODE [WAIT n | NOWAIT]".
func (p *Parser) parseLockInShareMode() (*ast.ForClause, error) {
	p.advance() // LOCK
	p.advance() // IN
	if !p.isTokenMatch("SHARE") {
		return nil, p.expectedError("SHARE after LOCK IN")
	}
	p.advance()
	if !p.isTokenMatch("MODE") {
		return nil, p.expectedError("MODE after LOCK IN SHARE")
	}
	p.advance()
	fc := &ast.ForClause{LockType: "SHARE", LockInShareMode: true}
	if err := p.parseLockWaitOption(fc); err != nil {
		return nil, err
	}
	return fc, nil
}

// parseLockWaitOption parses the Oracle / MariaDB "WAIT n" or "NOWAIT"
// suffix of a locking clause.
func (p *Parser) parseLockWaitOption(fc *ast.ForClause) error {
	switch {
	case p.isTokenMatch("NOWAIT"):
		fc.NoWait = true
		p.advance()
	case p.isUnquotedWord("WAIT") && p.peekToken().Token.Type == models.TokenTypeNumber:
		p.advance() // WAIT
		e, err := p.parsePrimaryExpression()
		if err != nil {
			return err
		}
		fc.Wait = e
	}
	return nil
}

// isForOutputStart reports whether the current FOR starts a SQL Server FOR
// JSON / FOR XML / FOR BROWSE clause.
func (p *Parser) isForOutputStart() bool {
	if !p.isType(models.TokenTypeFor) || p.dialect != string(keywords.DialectSQLServer) {
		return false
	}
	v := p.peekToken().Token.Value
	return equalsUpper(v, "JSON") || equalsUpper(v, "XML") || equalsUpper(v, "BROWSE")
}

// parseForOutputClause parses FOR JSON / FOR XML / FOR BROWSE; the current
// token is FOR.
func (p *Parser) parseForOutputClause() (*ast.ForOutputClause, error) {
	p.advance() // FOR
	fo := &ast.ForOutputClause{Kind: strings.ToUpper(p.currentToken.Token.Value)}
	p.advance()
	if fo.Kind == "BROWSE" {
		return fo, nil
	}
	mode := ast.ForOutputModeText(p.currentToken.Token.Value)
	if mode == "" {
		return nil, p.expectedError("PATH, AUTO, RAW or EXPLICIT after FOR " + fo.Kind)
	}
	fo.Mode = strings.ToUpper(mode)
	p.advance()
	if p.isType(models.TokenTypeLParen) {
		arg, err := p.parseForOutputArg()
		if err != nil {
			return nil, err
		}
		fo.ModeArg = arg
	}
	for p.isType(models.TokenTypeComma) {
		p.advance() // ,
		word := strings.ToUpper(p.currentToken.Token.Value)
		switch word {
		case "ELEMENTS":
			p.advance()
			if p.isUnquotedWord("XSINIL") || p.isUnquotedWord("ABSENT") {
				word += " " + strings.ToUpper(p.currentToken.Token.Value)
				p.advance()
			}
		case "BINARY":
			p.advance()
			if !p.isUnquotedWord("BASE64") {
				return nil, p.expectedError("BASE64 after BINARY")
			}
			word = "BINARY BASE64"
			p.advance()
		default:
			if ast.ForOutputOptionText(word) == "" || p.isStringLiteral() {
				return nil, p.expectedError("FOR " + fo.Kind + " option")
			}
			p.advance()
		}
		opt := ast.ForOutputOption{Name: word}
		if p.isType(models.TokenTypeLParen) {
			arg, err := p.parseForOutputArg()
			if err != nil {
				return nil, err
			}
			opt.Arg = arg
		}
		fo.Options = append(fo.Options, opt)
	}
	return fo, nil
}

// parseForOutputArg parses "('name')".
func (p *Parser) parseForOutputArg() (ast.Expression, error) {
	p.advance() // (
	if !p.isStringLiteral() {
		return nil, p.expectedError("string literal")
	}
	arg, err := p.parsePrimaryExpression()
	if err != nil {
		return nil, err
	}
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance()
	return arg, nil
}

// isQueryHintStart reports whether the current tokens are SQL Server
// "OPTION (".
func (p *Parser) isQueryHintStart() bool {
	return p.dialect == string(keywords.DialectSQLServer) && p.isUnquotedWord("OPTION") &&
		p.peekToken().Token.Type == models.TokenTypeLParen
}

// parseQueryHints parses "OPTION (hint [, hint]...)"; the current token is
// OPTION.
func (p *Parser) parseQueryHints() ([]ast.QueryHint, error) {
	p.advance() // OPTION
	p.advance() // (
	var hints []ast.QueryHint
	for {
		h, err := p.parseQueryHint()
		if err != nil {
			return nil, err
		}
		hints = append(hints, h)
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance()
	}
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") after OPTION hints")
	}
	p.advance()
	return hints, nil
}

// isHintWordToken reports whether the current token is a bare word that can
// be part of a query hint name (RECOMPILE, HASH, JOIN, FOR, ...).
func (p *Parser) isHintWordToken() bool {
	switch p.currentToken.Token.Type {
	case models.TokenTypeNumber, models.TokenTypePlaceholder, models.TokenTypeComma,
		models.TokenTypeLParen, models.TokenTypeRParen, models.TokenTypeEq,
		models.TokenTypeEOF, models.TokenTypeDoubleQuotedString:
		return false
	}
	if p.isStringLiteral() {
		return false
	}
	return ast.QueryHintNameText(p.currentToken.Token.Value) != ""
}

// parseQueryHint parses one query hint: words [= value | value] [(args)].
func (p *Parser) parseQueryHint() (ast.QueryHint, error) {
	var h ast.QueryHint
	var words []string
	for p.isHintWordToken() {
		words = append(words, strings.ToUpper(p.currentToken.Token.Value))
		p.advance()
	}
	if len(words) == 0 {
		return h, p.expectedError("query hint")
	}
	h.Name = strings.Join(words, " ")
	if p.isType(models.TokenTypeEq) {
		h.Equals = true
		p.advance()
		v, err := p.parsePrimaryExpression()
		if err != nil {
			return h, err
		}
		h.Value = v
	} else if p.isType(models.TokenTypeNumber) || p.isType(models.TokenTypePlaceholder) || p.isStringLiteral() {
		v, err := p.parsePrimaryExpression()
		if err != nil {
			return h, err
		}
		h.Value = v
	}
	if p.isType(models.TokenTypeLParen) {
		h.HasArgs = true
		p.advance() // (
		for {
			e, err := p.parseExpression()
			if err != nil {
				return h, err
			}
			arg := ast.QueryHintArg{Expr: e}
			if p.isUnquotedWord("UNKNOWN") {
				arg.Unknown = true
				p.advance()
			}
			h.Args = append(h.Args, arg)
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance()
		}
		if !p.isType(models.TokenTypeRParen) {
			return h, p.expectedError(") after query hint arguments")
		}
		p.advance()
	}
	return h, nil
}

// isFormatClauseStart reports whether the current tokens are a ClickHouse
// "FORMAT <name>" output clause.
func (p *Parser) isFormatClauseStart() bool {
	if p.dialect != string(keywords.DialectClickHouse) || !p.isUnquotedWord("FORMAT") {
		return false
	}
	next := p.peekToken().Token
	switch next.Type {
	case models.TokenTypeIdentifier, models.TokenTypeNull, models.TokenTypeValues:
		return ast.FormatNameText(next.Value) != ""
	}
	return false
}

// parseFormatClause parses "FORMAT <name>"; the current token is FORMAT.
func (p *Parser) parseFormatClause() string {
	p.advance() // FORMAT
	name := p.currentToken.Token.Value
	p.advance()
	return name
}

// isSelectTailStart reports whether the current token starts a clause that
// may follow the select list of a SELECT without FROM.
func (p *Parser) isSelectTailStart() bool {
	switch p.currentToken.Token.Type {
	case models.TokenTypeWhere, models.TokenTypeGroup, models.TokenTypeHaving:
		return true
	case models.TokenTypeInto:
		return p.supportsSelectInto()
	case models.TokenTypeFor:
		return p.isForOutputStart()
	case models.TokenTypeIdentifier:
		return p.isFormatClauseStart() || p.isQueryHintStart() || p.isLockInShareMode() ||
			p.isSettingsKeyword() || p.isWindowClauseKeyword() || p.isQualifyKeyword()
	}
	return false
}

// parseSelectTail parses the clauses after the locking clause: SQL Server
// FOR JSON / XML and OPTION (...), ClickHouse FORMAT.
func (p *Parser) parseSelectTail(s *ast.SelectStatement) error {
	if p.isForOutputStart() {
		fo, err := p.parseForOutputClause()
		if err != nil {
			return err
		}
		s.EnsureExtras().ForOutput = fo
	}
	if p.isQueryHintStart() {
		hints, err := p.parseQueryHints()
		if err != nil {
			return err
		}
		s.EnsureExtras().QueryHints = hints
	}
	if p.isFormatClauseStart() {
		s.EnsureExtras().OutputFormat = p.parseFormatClause()
	}
	return nil
}

// parseInterpolate parses ClickHouse "INTERPOLATE [(col [AS expr], ...)]";
// the current token is INTERPOLATE.
func (p *Parser) parseInterpolate() (*ast.InterpolateClause, error) {
	p.advance() // INTERPOLATE
	c := &ast.InterpolateClause{}
	if !p.isType(models.TokenTypeLParen) {
		return c, nil
	}
	p.advance() // (
	if p.isType(models.TokenTypeRParen) {
		p.advance()
		return c, nil
	}
	for {
		if !p.isIdentifier() && !p.isNonReservedKeyword() {
			return nil, p.expectedError("column name in INTERPOLATE")
		}
		item := ast.InterpolateItem{Column: p.currentToken.Token.Value}
		p.advance()
		if p.isType(models.TokenTypeAs) {
			p.advance()
			e, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			item.Expr = e
		}
		c.Items = append(c.Items, item)
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance()
	}
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") after INTERPOLATE list")
	}
	p.advance()
	return c, nil
}

// parseApplyFunctionCall parses the table-valued function on the right of
// CROSS APPLY / OUTER APPLY (STRING_SPLIT(...), sys.dm_exec_sql_text(...))
// in dialects whose FROM clause does not otherwise take function calls.
func (p *Parser) parseApplyFunctionCall(joinType string, ref *ast.TableReference) error {
	if (joinType != "CROSS APPLY" && joinType != "OUTER APPLY") ||
		!p.isType(models.TokenTypeLParen) || p.supportsTableFunction() {
		return nil
	}
	call, err := p.parseFunctionCall(ref.Name)
	if err != nil {
		return err
	}
	call.NameQuote = ref.NameQuote
	ref.TableFunc = call
	return nil
}
