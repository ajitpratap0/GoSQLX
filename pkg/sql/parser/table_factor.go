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

// hasTableSample reports whether ref already has a sampling clause.
func hasTableSample(ref *ast.TableReference) bool {
	return ref.Modifiers != nil && ref.Modifiers.TableSample != nil
}

// parseTableOnly consumes the PostgreSQL ONLY modifier before a table name
// (FROM ONLY parent) and reports whether it was present.
func (p *Parser) parseTableOnly() bool {
	if !p.isTokenMatch("ONLY") || !p.IsPostgreSQL() {
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
	if !p.isType(models.TokenTypePlaceholder) || !p.IsOracle() {
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
	return p.isType(models.TokenTypeFor) && (p.IsMariaDB() || p.IsSQLServer()) &&
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
	left, err := p.parseTemporalPointExpression()
	if err != nil {
		return nil, err
	}
	// Arithmetic on the bound: SYSTIMESTAMP - INTERVAL '1' DAY. Only + and -
	// are read, so the AND that follows the first bound is not consumed.
	for p.isType(models.TokenTypePlus) || p.isType(models.TokenTypeMinus) {
		opPos := p.currentLocation()
		op := p.currentToken.Token.Value
		p.advance()
		right, err := p.parseMultiplicativeExpression()
		if err != nil {
			return nil, err
		}
		left = &ast.BinaryExpression{Left: left, Operator: op, Right: right, Pos: opPos}
	}
	return left, nil
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

// atTableModifierBoundary rejects the common table-factor terminators before
// probing dialect-specific modifiers. Word-shaped contextual tokens still take
// the full path, preserving keyword and quoted-name disambiguation.
func (p *Parser) atTableModifierBoundary() bool {
	switch p.currentToken.Token.Type {
	case models.TokenTypeEOF, models.TokenTypeSemicolon, models.TokenTypeComma,
		models.TokenTypeRParen, models.TokenTypeWhere, models.TokenTypeGroup,
		models.TokenTypeHaving, models.TokenTypeOrder, models.TokenTypeLimit,
		models.TokenTypeOffset, models.TokenTypeFetch, models.TokenTypeUnion,
		models.TokenTypeIntersect, models.TokenTypeExcept, models.TokenTypeJoin,
		models.TokenTypeInner, models.TokenTypeLeft, models.TokenTypeRight,
		models.TokenTypeFull, models.TokenTypeCross, models.TokenTypeOn:
		return true
	}
	return false
}

// parseTableModifiersBeforeAlias parses the table modifiers that come
// between a table name and its alias: MySQL PARTITION (...), FOR
// SYSTEM_TIME, Snowflake time travel, SAMPLE / TABLESAMPLE and Oracle
// flashback.
func (p *Parser) parseTableModifiersBeforeAlias(ref *ast.TableReference) error {
	if p.atTableModifierBoundary() {
		return nil
	}
	// Most identifiers here are aliases. Only these token types or contextual
	// words can begin a modifier; leave non-ASCII spellings to the full checks.
	switch p.currentToken.Token.Type {
	case models.TokenTypeWith, models.TokenTypePartition, models.TokenTypeFor, models.TokenTypeAs:
	default:
		v := p.currentToken.Token.Value
		if len(v) < 2 {
			return nil
		}
		if c := v[0] | 0x20; v[0] < 0x80 && c != 'a' && c != 'b' && c != 'c' && c != 's' && c != 't' && c != 'v' {
			return nil
		}
	}
	if p.isOpenJSONSchemaStart(ref) {
		cols, err := p.parseOpenJSONSchema()
		if err != nil {
			return err
		}
		tableModifiers(ref).WithSchema = cols
	}
	if (p.isMySQLFamily() || p.IsOracle()) && p.isType(models.TokenTypePartition) &&
		p.peekToken().Token.Type == models.TokenTypeLParen {
		p.advance() // Consume PARTITION
		names, err := p.parseParenthesizedWordList("partition name")
		if err != nil {
			return err
		}
		tableModifiers(ref).Partitions = names
	}
	if p.IsOracle() && p.isType(models.TokenTypePartition) && p.peekToken().Token.Type == models.TokenTypeFor {
		// Oracle PARTITION FOR (partition key value, ...)
		p.advance() // Consume PARTITION
		p.advance() // Consume FOR
		if !p.isType(models.TokenTypeLParen) {
			return p.expectedError("( after PARTITION FOR")
		}
		p.advance() // Consume (
		for {
			e, err := p.parseExpression()
			if err != nil {
				return err
			}
			m := tableModifiers(ref)
			if m.PartitionFor == nil {
				m.PartitionFor = &ast.PartitionForClause{}
			}
			m.PartitionFor.Values = append(m.PartitionFor.Values, e)
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance() // Consume ,
		}
		if !p.isType(models.TokenTypeRParen) {
			return p.expectedError(") after PARTITION FOR values")
		}
		p.advance() // Consume )
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
	if !hasTableSample(ref) && p.isTableSampleStart() {
		sample, err := p.parseTableSample()
		if err != nil {
			return err
		}
		tableModifiers(ref).TableSample = sample
	}
	if (ref.Modifiers == nil || ref.Modifiers.Flashback == nil) && p.isOracleFlashbackStart() {
		fb, err := p.parseOracleFlashback()
		if err != nil {
			return err
		}
		tableModifiers(ref).Flashback = fb
	}
	return nil
}

// isTableModifierAfterAliasStart reports whether the current token starts a
// table modifier that may follow a table alias and must not be taken as the
// alias itself: index hints, SQLite INDEXED BY / NOT INDEXED, Oracle
// flashback, FOR SYSTEM_TIME.
func (p *Parser) isTableModifierAfterAliasStart() bool {
	switch p.currentToken.Token.Type {
	case models.TokenTypeNot, models.TokenTypeAs:
	default:
		v := p.currentToken.Token.Value
		if len(v) < 3 {
			return false
		}
		if c := v[0] | 0x20; v[0] < 0x80 && c != 'u' && c != 'f' && c != 'i' && c != 'v' {
			return false
		}
	}
	return p.isIndexHintStart() || p.isSQLiteIndexedStart() || p.isOracleFlashbackStart()
}

// parseTableModifiersAfterAlias parses the table modifiers that follow the
// alias: TABLESAMPLE, ClickHouse FINAL, MySQL index hints, SQLite INDEXED BY
// / NOT INDEXED and SQL Server bare table hints t (NOLOCK).
func (p *Parser) parseTableModifiersAfterAlias(ref *ast.TableReference) error {
	if p.atTableModifierBoundary() {
		return nil
	}
	if !hasTableSample(ref) && p.isTableSampleStart() {
		sample, err := p.parseTableSample()
		if err != nil {
			return err
		}
		tableModifiers(ref).TableSample = sample
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
	if !p.isType(models.TokenTypeLParen) || !p.IsSQLServer() {
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
		list.Quotes = nameQuoteList(list.Quotes, len(list.Names), p.currentNameQuote())
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

// isCTENameStart reports whether the current token can name a CTE: any
// token accepted as an alias, so non-reserved keywords work as in dbt's
// WITH source AS (...), final AS (...).
func (p *Parser) isCTENameStart() bool {
	return p.canBeAlias()
}

// parseCTESearchCycle parses the optional SEARCH and CYCLE clauses after a
// CTE's query:
//
//	SEARCH {DEPTH | BREADTH} FIRST BY col [, ...] SET seq_col
//	CYCLE col [, ...] SET mark_col [TO value DEFAULT value] [USING path_col]
func (p *Parser) parseCTESearchCycle(cte *ast.CommonTableExpr) error {
	if p.isTokenMatch("SEARCH") && (equalsUpper(p.peekToken().Token.Value, "DEPTH") ||
		equalsUpper(p.peekToken().Token.Value, "BREADTH")) {
		search := &ast.CTESearchClause{Pos: p.currentLocation()}
		p.advance() // Consume SEARCH
		search.Breadth = equalsUpper(p.currentToken.Token.Value, "BREADTH")
		p.advance() // Consume DEPTH / BREADTH
		if !p.isTokenMatch("FIRST") {
			return p.expectedError("FIRST after SEARCH DEPTH / BREADTH")
		}
		p.advance() // Consume FIRST
		if !p.isType(models.TokenTypeBy) {
			return p.expectedError("BY after SEARCH ... FIRST")
		}
		p.advance() // Consume BY
		cols, err := p.parseCTEClauseColumns()
		if err != nil {
			return err
		}
		search.By = cols
		set, err := p.parseCTEClauseSet()
		if err != nil {
			return err
		}
		search.Set = set
		cte.Search = search
	}
	if p.isTokenMatch("CYCLE") && p.peekToken().Token.Type != models.TokenTypeLParen {
		cycle := &ast.CTECycleClause{Pos: p.currentLocation()}
		p.advance() // Consume CYCLE
		cols, err := p.parseCTEClauseColumns()
		if err != nil {
			return err
		}
		cycle.Columns = cols
		set, err := p.parseCTEClauseSet()
		if err != nil {
			return err
		}
		cycle.Set = set
		if p.isTokenMatch("TO") {
			p.advance() // Consume TO
			to, err := p.parsePrimaryExpression()
			if err != nil {
				return err
			}
			if !p.isType(models.TokenTypeDefault) && !p.isTokenMatch("DEFAULT") {
				return p.expectedError("DEFAULT in CYCLE clause")
			}
			p.advance() // Consume DEFAULT
			def, err := p.parsePrimaryExpression()
			if err != nil {
				return err
			}
			cycle.To, cycle.Default = to, def
		}
		if p.isType(models.TokenTypeUsing) {
			p.advance() // Consume USING
			if !p.isIdentifier() && !p.isNonReservedKeyword() {
				return p.expectedError("path column after USING")
			}
			cycle.Using = p.currentToken.Token.Value
			p.advance()
		}
		cte.Cycle = cycle
	}
	return nil
}

// parseCTEClauseColumns parses "col [, col ...]" of a SEARCH / CYCLE clause.
func (p *Parser) parseCTEClauseColumns() ([]string, error) {
	var cols []string
	for {
		if !p.isIdentifier() && !p.isNonReservedKeyword() {
			return nil, p.expectedError("column name")
		}
		cols = append(cols, p.currentToken.Token.Value)
		p.advance()
		if !p.isType(models.TokenTypeComma) {
			return cols, nil
		}
		p.advance() // Consume ,
	}
}

// parseCTEClauseSet parses "SET column" of a SEARCH / CYCLE clause.
func (p *Parser) parseCTEClauseSet() (string, error) {
	if !p.isType(models.TokenTypeSet) && !p.isTokenMatch("SET") {
		return "", p.expectedError("SET")
	}
	p.advance() // Consume SET
	if !p.isIdentifier() && !p.isNonReservedKeyword() {
		return "", p.expectedError("column name after SET")
	}
	col := p.currentToken.Token.Value
	p.advance()
	return col, nil
}

// parseStagePathSegment consumes one segment of a Snowflake stage path after
// a "/": a word or number, optionally with dotted parts (data.csv,
// part.2024.json). It returns "" when no segment follows (a trailing "/").
func (p *Parser) parseStagePathSegment() string {
	isPart := func() bool {
		return p.isIdentifier() || p.isType(models.TokenTypeKeyword) ||
			p.isType(models.TokenTypeNumber) || (p.isWordToken() && !p.isStringLiteral())
	}
	if !isPart() {
		return ""
	}
	seg := p.currentToken.Token.Value
	p.advance()
	for p.isType(models.TokenTypePeriod) {
		next := p.peekToken().Token
		if next.Type != models.TokenTypeIdentifier && next.Type != models.TokenTypeKeyword &&
			next.Type != models.TokenTypeNumber {
			break
		}
		p.advance() // Consume .
		seg += "." + p.currentToken.Token.Value
		p.advance()
	}
	return seg
}

// parsePivotAggregates parses a PIVOT aggregate list, retaining aliases and
// extra aggregates in the public representation shared with BigQuery.
func (p *Parser) parsePivotAggregates(clause *ast.PivotClause) error {
	expr, err := p.parseExpression()
	if err != nil {
		return err
	}
	clause.AggregateFunction = expr
	if !p.pivotMultiAggregateAllowed() {
		return nil
	}
	alias, err := p.parsePivotAggregateAlias()
	if err != nil {
		return err
	}
	clause.AggregateAlias = alias
	for p.isType(models.TokenTypeComma) {
		p.advance() // consume ,
		expr, err := p.parseExpression()
		if err != nil {
			return err
		}
		alias, err := p.parsePivotAggregateAlias()
		if err != nil {
			return err
		}
		clause.ExtraAggregates = append(clause.ExtraAggregates, ast.PivotAggregate{Function: expr, Alias: alias})
	}
	return nil
}

// parsePivotInSpecial parses a PIVOT IN list that is ANY [ORDER BY ...] or a
// subquery, with the current token after "IN (", through the closing ")" of
// the clause. It reports false when the list is a plain value list.
func (p *Parser) parsePivotInSpecial(clause *ast.PivotClause) (bool, error) {
	switch {
	case p.isType(models.TokenTypeAny):
		clause.InAny = true
		p.advance() // consume ANY
		if p.isType(models.TokenTypeOrder) {
			order, err := p.parseOrderByClause()
			if err != nil {
				return false, err
			}
			clause.InAnyOrderBy = order
		}
	case p.isAnyType(models.TokenTypeSelect, models.TokenTypeWith):
		q, err := p.parseQueryExpression("SELECT in PIVOT IN list")
		if err != nil {
			return false, err
		}
		clause.InSubquery = q
	default:
		return false, nil
	}
	if !p.isType(models.TokenTypeRParen) {
		return false, p.expectedError(") to close PIVOT IN list")
	}
	p.advance() // close IN list )
	if !p.isType(models.TokenTypeRParen) {
		return false, p.expectedError(") to close PIVOT clause")
	}
	p.advance() // close PIVOT )
	return true, nil
}

// parsePivotSuffix parses the PIVOT / UNPIVOT clause of a table reference
// with its alias and optional column alias list. An alias already read for
// the table becomes the clause's source alias: (SELECT ...) s PIVOT (...) p.
func (p *Parser) parsePivotSuffix(ref *ast.TableReference) error {
	if p.isPivotKeyword() {
		pivot, err := p.parsePivotClause()
		if err != nil {
			return err
		}
		pivot.SourceAlias, ref.Alias = ref.Alias, ""
		pivot.SourceAliasQuote, ref.AliasQuote = ref.AliasQuote, 0
		ref.Pivot = pivot
	} else if p.isUnpivotKeyword() {
		unpivot, err := p.parseUnpivotClause()
		if err != nil {
			return err
		}
		unpivot.SourceAlias, ref.Alias = ref.Alias, ""
		unpivot.SourceAliasQuote, ref.AliasQuote = ref.AliasQuote, 0
		ref.Unpivot = unpivot
	} else {
		return nil
	}
	if ref.ColumnAliases != nil {
		// A column list of the source alias has no PIVOT form to keep.
		return p.expectedError("PIVOT or UNPIVOT after a table alias without a column list")
	}
	p.parsePivotAlias(ref)
	if ref.Alias != "" {
		return p.parseTableColumnAliases(ref)
	}
	return nil
}

// isSnowflakePositionalColumn reports whether the current token is a
// Snowflake positional column reference $1, $2, ... (after a qualifier, as in
// t.$1 for a staged file).
func (p *Parser) isSnowflakePositionalColumn() bool {
	if !p.IsSnowflake() || !p.isType(models.TokenTypePlaceholder) {
		return false
	}
	v := p.currentToken.Token.Value
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

// isEmptyNamePart reports whether the current token, right after a ".", is
// another "." that leaves an empty part in a SQL Server qualified name:
// db..t names table t in the default schema of database db.
func (p *Parser) isEmptyNamePart() bool {
	return p.IsSQLServer() && p.isType(models.TokenTypePeriod)
}

// isOpenJSONSchemaStart reports whether the current WITH ( starts the column
// schema of a SQL Server OPENJSON(...) table function rather than table
// hints.
func (p *Parser) isOpenJSONSchemaStart(ref *ast.TableReference) bool {
	return p.isType(models.TokenTypeWith) && ref.TableFunc != nil && p.IsSQLServer() &&
		strings.EqualFold(ref.TableFunc.Name, "OPENJSON") && p.peekToken().Token.Type == models.TokenTypeLParen
}

// parseOpenJSONSchema parses WITH (name type ['$.path'] [AS JSON], ...).
func (p *Parser) parseOpenJSONSchema() ([]ast.OpenJSONColumn, error) {
	p.advance() // Consume WITH
	p.advance() // Consume (
	var cols []ast.OpenJSONColumn
	for {
		if !p.isIdentifier() && !p.isNonReservedKeyword() {
			return nil, p.expectedError("column name in OPENJSON WITH")
		}
		col := ast.OpenJSONColumn{Name: p.currentToken.Token.Value}
		p.advance()
		typ, err := p.parseDataType()
		if err != nil {
			return nil, err
		}
		col.Type = typ
		if p.isStringLiteral() {
			col.Path = p.currentToken.Token.Value
			p.advance()
		}
		if p.isType(models.TokenTypeAs) && equalsUpper(p.peekToken().Token.Value, "JSON") {
			p.advance() // Consume AS
			p.advance() // Consume JSON
			col.AsJSON = true
		}
		cols = append(cols, col)
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance() // Consume ,
	}
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") after OPENJSON WITH columns")
	}
	p.advance() // Consume )
	return cols, nil
}
