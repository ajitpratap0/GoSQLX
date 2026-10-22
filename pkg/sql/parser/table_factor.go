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

// Package parser - table_factor.go
// Table-factor modifiers of a FROM / JOIN item: PostgreSQL ONLY, Oracle
// @dblink and flashback queries, MySQL PARTITION selection and index hints,
// SQLite INDEXED BY, SQL Server bare table hints and FOR SYSTEM_TIME,
// TABLESAMPLE / SAMPLE, and the VALUES table constructor.

package parser

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// tableModifiers returns ref.Modifiers, allocating it on first use.
func tableModifiers(ref *ast.TableReference) *ast.TableModifiers {
	if ref.Modifiers == nil {
		ref.Modifiers = &ast.TableModifiers{}
	}
	return ref.Modifiers
}

// parseTableOnly consumes the PostgreSQL ONLY modifier before a table name
// (FROM ONLY parent) and reports whether it was present.
func (p *Parser) parseTableOnly() bool {
	if !p.IsPostgreSQL() || !p.isTokenMatch("ONLY") {
		return false
	}
	next := p.peekToken().Token.Type
	if next != models.TokenTypeIdentifier && next != models.TokenTypeDoubleQuotedString {
		return false
	}
	p.advance() // Consume ONLY
	return true
}

// parseOracleDBLink consumes an Oracle database link written right after a
// table name (t@remote_db, t@lnk.example.com). The tokenizer yields the
// "@name" part as a placeholder token.
func (p *Parser) parseOracleDBLink(ref *ast.TableReference) {
	if !p.IsOracle() || !p.isType(models.TokenTypePlaceholder) {
		return
	}
	v := p.currentToken.Token.Value
	if len(v) < 2 || v[0] != '@' {
		return
	}
	link := v[1:]
	p.advance()
	// A dotted link name: @lnk.example.com
	for p.isType(models.TokenTypePeriod) && p.peekToken().Token.Type == models.TokenTypeIdentifier {
		p.advance() // Consume .
		link += "." + p.currentToken.Token.Value
		p.advance()
	}
	tableModifiers(ref).DBLink = link
}

// isForSystemTimeStart reports whether the current token starts a
// FOR SYSTEM_TIME temporal clause (MariaDB, SQL Server).
func (p *Parser) isForSystemTimeStart() bool {
	return (p.IsMariaDB() || p.IsSQLServer()) && p.isType(models.TokenTypeFor) &&
		strings.EqualFold(p.peekToken().Token.Value, "SYSTEM_TIME")
}

// isOracleFlashbackStart reports whether the current token starts an Oracle
// flashback clause: AS OF {SCN | TIMESTAMP} or VERSIONS BETWEEN.
func (p *Parser) isOracleFlashbackStart() bool {
	if !p.IsOracle() {
		return false
	}
	if p.isType(models.TokenTypeAs) {
		return strings.EqualFold(p.peekToken().Token.Value, "OF")
	}
	return p.isTokenMatch("VERSIONS") && p.peekToken().Token.Type == models.TokenTypeBetween
}

// parseOracleFlashback parses AS OF {SCN | TIMESTAMP} expr or
// VERSIONS BETWEEN {SCN | TIMESTAMP} expr AND expr.
func (p *Parser) parseOracleFlashback() (*ast.FlashbackClause, error) {
	clause := &ast.FlashbackClause{Pos: p.currentLocation()}
	if p.isType(models.TokenTypeAs) {
		p.advance() // Consume AS
		p.advance() // Consume OF
	} else {
		clause.Versions = true
		p.advance() // Consume VERSIONS
		p.advance() // Consume BETWEEN
	}
	kind := strings.ToUpper(p.currentToken.Token.Value)
	if kind != "SCN" && kind != "TIMESTAMP" {
		return nil, p.expectedError("SCN or TIMESTAMP")
	}
	clause.Kind = kind
	p.advance()
	if !clause.Versions {
		point, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		clause.Point = point
		return clause, nil
	}
	// The bounds are primary expressions so the AND is not taken as a
	// logical operator (MINVALUE, MAXVALUE, literals, function calls).
	start, err := p.parseFlashbackBound()
	if err != nil {
		return nil, err
	}
	if !p.isType(models.TokenTypeAnd) {
		return nil, p.expectedError("AND in VERSIONS BETWEEN")
	}
	p.advance() // Consume AND
	end, err := p.parseFlashbackBound()
	if err != nil {
		return nil, err
	}
	clause.Start, clause.End = start, end
	return clause, nil
}

// parseFlashbackBound parses a VERSIONS BETWEEN bound: MINVALUE, MAXVALUE
// or a primary expression.
func (p *Parser) parseFlashbackBound() (ast.Expression, error) {
	if p.isTokenMatch("MINVALUE") || p.isTokenMatch("MAXVALUE") {
		id := &ast.Identifier{Name: strings.ToUpper(p.currentToken.Token.Value)}
		p.advance()
		return id, nil
	}
	return p.parseTemporalPointExpression()
}

// isTableSampleStart reports whether the current token starts a SAMPLE /
// TABLESAMPLE clause on a table reference. A ClickHouse SAMPLE followed by a
// number is the SELECT-level sampling clause instead.
func (p *Parser) isTableSampleStart() bool {
	if !p.isSampleKeyword() {
		return false
	}
	return !(p.IsClickHouse() && p.peekToken().Token.Type == models.TokenTypeNumber)
}

// parseTableSample parses a row-sampling clause; the current token is SAMPLE
// or TABLESAMPLE:
//
//	{SAMPLE | TABLESAMPLE} [method] (arg [, arg] [PERCENT | ROWS]) [{REPEATABLE | SEED} (seed)]
//
// The clause is accepted on either side of the table alias. It is recorded
// at the position the dialect documents: before the alias for Oracle, after
// it (SQL standard, PostgreSQL, SQL Server, Snowflake) otherwise.
func (p *Parser) parseTableSample() (*ast.TableSampleClause, error) {
	clause := &ast.TableSampleClause{
		Keyword:    strings.ToUpper(p.currentToken.Token.Value),
		AfterAlias: !p.IsOracle(),
		Pos:        p.currentLocation(),
	}
	p.advance() // Consume SAMPLE / TABLESAMPLE

	// Optional sampling method: BERNOULLI, SYSTEM, BLOCK, ROW or a
	// PostgreSQL extension method name, followed by "(".
	if !p.isType(models.TokenTypeLParen) && p.isWordToken() &&
		p.peekToken().Token.Type == models.TokenTypeLParen {
		clause.Method = strings.ToUpper(p.currentToken.Token.Value)
		p.advance()
	}
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("( after " + clause.Keyword)
	}
	p.advance() // Consume (
	for {
		arg, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		clause.Args = append(clause.Args, arg)
		if p.isTokenMatch("PERCENT") || p.isTokenMatch("ROWS") {
			clause.Unit = strings.ToUpper(p.currentToken.Token.Value)
			p.advance()
			break
		}
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance() // Consume ,
	}
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") after sample size")
	}
	p.advance() // Consume )

	if (p.isTokenMatch("REPEATABLE") || p.isTokenMatch("SEED")) &&
		p.peekToken().Token.Type == models.TokenTypeLParen {
		clause.SeedKeyword = strings.ToUpper(p.currentToken.Token.Value)
		p.advance() // Consume REPEATABLE / SEED
		p.advance() // Consume (
		seed, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		clause.Seed = seed
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(") after " + clause.SeedKeyword)
		}
		p.advance() // Consume )
	}
	return clause, nil
}

// parseTableModifiersBeforeAlias parses the table modifiers that come
// between a table name and its alias: MySQL PARTITION (...), FOR
// SYSTEM_TIME, Snowflake time travel, SAMPLE / TABLESAMPLE and Oracle
// flashback.
func (p *Parser) parseTableModifiersBeforeAlias(ref *ast.TableReference) error {
	if p.isMySQLFamily() && p.isType(models.TokenTypePartition) &&
		p.peekToken().Token.Type == models.TokenTypeLParen {
		p.advance() // Consume PARTITION
		names, err := p.parseParenthesizedWordList("partition name")
		if err != nil {
			return err
		}
		tableModifiers(ref).Partitions = names
	}
	if ref.ForSystemTime == nil && p.isForSystemTimeStart() {
		p.advance() // Consume FOR
		clause, err := p.parseForSystemTimeClause()
		if err != nil {
			return err
		}
		ref.ForSystemTime = clause
	}
	if ref.TimeTravel == nil && p.isSnowflakeTimeTravelStart() {
		tt, err := p.parseSnowflakeTimeTravel()
		if err != nil {
			return err
		}
		ref.TimeTravel = tt
	}
	if ref.TableSample == nil && p.isTableSampleStart() {
		sample, err := p.parseTableSample()
		if err != nil {
			return err
		}
		ref.TableSample = sample
	}
	if ref.Flashback == nil && p.isOracleFlashbackStart() {
		fb, err := p.parseOracleFlashback()
		if err != nil {
			return err
		}
		ref.Flashback = fb
	}
	return nil
}

// isTableModifierAfterAliasStart reports whether the current token starts a
// table modifier that may follow a table alias and must not be taken as the
// alias itself: index hints, SQLite INDEXED BY / NOT INDEXED, Oracle
// flashback, FOR SYSTEM_TIME.
func (p *Parser) isTableModifierAfterAliasStart() bool {
	return p.isIndexHintStart() || p.isSQLiteIndexedStart() || p.isOracleFlashbackStart()
}

// parseTableModifiersAfterAlias parses the table modifiers that follow the
// alias: TABLESAMPLE, ClickHouse FINAL, MySQL index hints, SQLite INDEXED BY
// / NOT INDEXED and SQL Server bare table hints t (NOLOCK).
func (p *Parser) parseTableModifiersAfterAlias(ref *ast.TableReference) error {
	if ref.TableSample == nil && p.isTableSampleStart() {
		sample, err := p.parseTableSample()
		if err != nil {
			return err
		}
		ref.TableSample = sample
	}
	if p.IsClickHouse() && p.isTokenMatch("FINAL") {
		ref.Final = true
		p.advance() // Consume FINAL
	}
	for p.isIndexHintStart() {
		hint, err := p.parseIndexHint()
		if err != nil {
			return err
		}
		m := tableModifiers(ref)
		m.IndexHints = append(m.IndexHints, hint)
		if p.isType(models.TokenTypeComma) && p.peekIsIndexHintStart() {
			p.advance() // Consume , between hints
		}
	}
	if p.isSQLiteIndexedStart() {
		m := tableModifiers(ref)
		if p.isType(models.TokenTypeNot) {
			p.advance() // Consume NOT
			p.advance() // Consume INDEXED
			m.NotIndexed = true
		} else {
			p.advance() // Consume INDEXED
			p.advance() // Consume BY
			if !p.isWordToken() {
				return p.expectedError("index name after INDEXED BY")
			}
			m.IndexedBy = p.currentToken.Token.Value
			p.advance()
		}
	}
	if p.isBareTableHintListStart() && len(ref.TableHints) == 0 {
		p.advance() // Consume (
		for {
			ref.TableHints = append(ref.TableHints, strings.ToUpper(p.currentToken.Token.Value))
			p.advance()
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance() // Consume ,
			if !p.isBareTableHintToken() {
				return p.expectedError("table hint")
			}
		}
		if !p.isType(models.TokenTypeRParen) {
			return p.expectedError(") after table hints")
		}
		p.advance() // Consume )
	}
	return nil
}

// isIndexHintStart reports whether the current token starts a MySQL /
// MariaDB index hint: {USE | FORCE | IGNORE} {INDEX | KEY}.
func (p *Parser) isIndexHintStart() bool {
	if !p.isMySQLFamily() {
		return false
	}
	v := p.currentToken.Token.Value
	if !equalsUpper(v, "USE") && !equalsUpper(v, "FORCE") && !equalsUpper(v, "IGNORE") {
		return false
	}
	next := p.peekToken().Token
	return next.Type == models.TokenTypeIndex || next.Type == models.TokenTypeKey ||
		equalsUpper(next.Value, "INDEX") || equalsUpper(next.Value, "KEY")
}

// peekIsIndexHintStart reports whether the token after the current one
// starts an index hint.
func (p *Parser) peekIsIndexHintStart() bool {
	savedPos, savedTok := p.currentPos, p.currentToken
	p.advance()
	defer func() { p.currentPos, p.currentToken = savedPos, savedTok }()
	return p.isIndexHintStart()
}

// parseIndexHint parses one index hint:
//
//	{USE | FORCE | IGNORE} {INDEX | KEY} [FOR {JOIN | ORDER BY | GROUP BY}] ([index_name, ...])
func (p *Parser) parseIndexHint() (ast.IndexHint, error) {
	hint := ast.IndexHint{Action: strings.ToUpper(p.currentToken.Token.Value)}
	p.advance() // Consume USE / FORCE / IGNORE
	hint.Keyword = strings.ToUpper(p.currentToken.Token.Value)
	p.advance() // Consume INDEX / KEY
	if p.isType(models.TokenTypeFor) {
		p.advance() // Consume FOR
		switch {
		case p.isType(models.TokenTypeJoin):
			hint.For = "JOIN"
			p.advance()
		case p.isType(models.TokenTypeOrder), p.isType(models.TokenTypeGroup):
			hint.For = strings.ToUpper(p.currentToken.Token.Value) + " BY"
			p.advance()
			if !p.isType(models.TokenTypeBy) {
				return hint, p.expectedError("BY")
			}
			p.advance()
		default:
			return hint, p.expectedError("JOIN, ORDER BY or GROUP BY after FOR")
		}
	}
	if !p.isType(models.TokenTypeLParen) {
		return hint, p.expectedError("( after index hint")
	}
	if p.peekToken().Token.Type == models.TokenTypeRParen {
		// USE INDEX (): use no index.
		p.advance()
		p.advance()
		return hint, nil
	}
	names, err := p.parseParenthesizedWordList("index name")
	if err != nil {
		return hint, err
	}
	hint.Names = names
	return hint, nil
}

// parseParenthesizedWordList parses "(name [, name ...])" where each name is
// an identifier or keyword (PRIMARY, partition names).
func (p *Parser) parseParenthesizedWordList(what string) ([]string, error) {
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (
	var names []string
	for {
		if !p.isWordToken() {
			return nil, p.expectedError(what)
		}
		names = append(names, p.currentToken.Token.Value)
		p.advance()
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance() // Consume ,
	}
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )
	return names, nil
}

// isSQLiteIndexedStart reports whether the current token starts SQLite
// INDEXED BY or NOT INDEXED.
func (p *Parser) isSQLiteIndexedStart() bool {
	if !p.IsSQLite() {
		return false
	}
	if p.isType(models.TokenTypeNot) {
		return equalsUpper(p.peekToken().Token.Value, "INDEXED")
	}
	return equalsUpper(p.currentToken.Token.Value, "INDEXED") &&
		p.peekToken().Token.Type == models.TokenTypeBy
}

// sqlServerTableHints are the SQL Server table hints accepted in the legacy
// form without WITH: FROM t (NOLOCK).
var sqlServerTableHints = map[string]bool{
	"NOLOCK": true, "READUNCOMMITTED": true, "READCOMMITTED": true, "READCOMMITTEDLOCK": true,
	"REPEATABLEREAD": true, "SERIALIZABLE": true, "SNAPSHOT": true, "HOLDLOCK": true,
	"UPDLOCK": true, "XLOCK": true, "ROWLOCK": true, "PAGLOCK": true, "TABLOCK": true,
	"TABLOCKX": true, "READPAST": true, "NOWAIT": true, "NOEXPAND": true,
	"FORCESEEK": true, "FORCESCAN": true,
}

// isBareTableHintListStart reports whether the current "(" opens a SQL
// Server table hint list written without WITH, as in FROM t (NOLOCK). Only
// known hint names qualify, so a table-valued function call is not mistaken
// for one.
func (p *Parser) isBareTableHintListStart() bool {
	if !p.IsSQLServer() || !p.isType(models.TokenTypeLParen) {
		return false
	}
	next := p.peekToken().Token
	if next.Quote != 0 || (next.Word != nil && next.Word.QuoteStyle != 0) {
		return false
	}
	return sqlServerTableHints[strings.ToUpper(next.Value)]
}

// parseValuesQuery parses a VALUES table constructor used as a query: in a
// derived table, a CTE body or a set-operation operand. The current token is
// VALUES. MySQL writes each row as ROW(...).
//
//	VALUES (1, 'a'), (2, 'b')
//	VALUES ROW(1, 2), ROW(3, 4)
func (p *Parser) parseValuesQuery() (*ast.Values, error) {
	p.advance() // Consume VALUES
	v := &ast.Values{}
	for {
		if p.IsMySQL() {
			// MySQL 8.0.19+: a table value constructor takes ROW(...) rows.
			if !p.isTokenMatch("ROW") || p.peekToken().Token.Type != models.TokenTypeLParen {
				return nil, p.expectedError("ROW( in VALUES")
			}
			v.RowConstructor = true
			p.advance() // Consume ROW
		}
		if !p.isType(models.TokenTypeLParen) {
			return nil, p.expectedError("( in VALUES")
		}
		p.advance() // Consume (
		var row []ast.Expression
		for {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			row = append(row, expr)
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance() // Consume ,
		}
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(") in VALUES")
		}
		p.advance() // Consume )
		v.Rows = append(v.Rows, row)
		if !p.isType(models.TokenTypeComma) {
			return v, nil
		}
		p.advance() // Consume , between rows
	}
}

// parseTableColumnAliases parses the optional column alias list that follows
// a table alias: (SELECT ...) AS s(a, b), t AS x(a), unnest(arr) AS g(elem).
// PostgreSQL record-returning functions also take column types:
// jsonb_to_recordset(j) AS t(a int, b text).
func (p *Parser) parseTableColumnAliases(ref *ast.TableReference) error {
	if !p.isType(models.TokenTypeLParen) || p.isBareTableHintListStart() {
		return nil
	}
	p.advance() // Consume (
	list := &ast.ColumnAliasList{}
	ref.ColumnAliases = list
	for {
		if !p.isIdentifier() && !p.isNonReservedKeyword() {
			return p.expectedError("column alias in table alias list")
		}
		list.Names = append(list.Names, p.currentToken.Token.Value)
		p.advance()
		// A column type follows only a built-in type keyword, so a
		// missing comma (g(x y)) is still reported.
		if p.IsPostgreSQL() && ref.TableFunc != nil && p.isDataTypeKeyword() {
			typ, err := p.parseDataType()
			if err != nil {
				return err
			}
			for len(list.Types) < len(list.Names)-1 {
				list.Types = append(list.Types, "")
			}
			list.Types = append(list.Types, typ)
		}
		if p.isType(models.TokenTypeComma) {
			p.advance()
			continue
		}
		if !p.isType(models.TokenTypeRParen) {
			return p.expectedError(") after table column aliases")
		}
		p.advance() // Consume )
		if len(list.Types) > 0 {
			for len(list.Types) < len(list.Names) {
				list.Types = append(list.Types, "")
			}
		}
		return nil
	}
}

// parseTableHintArgs parses the arguments of a SQL Server table hint such as
// INDEX(ix_a, ix_b), INDEX(0) or INDEX = ix_a, and returns them normalized
// to "(ix_a, ix_b)". The current token is "(" or "=".
func (p *Parser) parseTableHintArgs() (string, error) {
	var sb strings.Builder
	sb.WriteByte('(')
	if p.isType(models.TokenTypeEq) {
		p.advance() // Consume =
		if !p.isBareTableHintToken() && !p.isType(models.TokenTypeNumber) {
			return "", p.expectedError("index name after =")
		}
		sb.WriteString(p.currentToken.Token.Value)
		p.advance()
		sb.WriteByte(')')
		return sb.String(), nil
	}
	p.advance() // Consume (
	for i := 0; ; i++ {
		if !p.isBareTableHintToken() && !p.isType(models.TokenTypeNumber) {
			return "", p.expectedError("index name in table hint")
		}
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(p.currentToken.Token.Value)
		p.advance()
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance() // Consume ,
	}
	if !p.isType(models.TokenTypeRParen) {
		return "", p.expectedError(") after table hint arguments")
	}
	p.advance() // Consume )
	sb.WriteByte(')')
	return sb.String(), nil
}

// acceptsTableFunctionCall reports whether a "(" after a FROM / JOIN table
// name starts a table-valued function call. Every named dialect has them
// (PostgreSQL unnest, SQL Server STRING_SPLIT / OPENJSON, SQLite json_each,
// Oracle TABLE(...), MySQL JSON_TABLE, ClickHouse numbers, Snowflake
// FLATTEN); the generic dialect keeps the narrower historical gate.
func (p *Parser) acceptsTableFunctionCall() bool {
	if p.supportsTableFunction() {
		return true
	}
	return p.IsSQLServer() || p.IsSQLite() || p.IsOracle() || p.IsMySQL() || p.IsMariaDB() ||
		p.IsRedshift()
}
