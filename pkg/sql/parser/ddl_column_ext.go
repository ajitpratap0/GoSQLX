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

// Package parser - ddl_column_ext.go
// Column data types and the dialect column attributes of CREATE TABLE /
// ALTER TABLE ... ADD COLUMN: multi-word and array types, typeless columns,
// MySQL / T-SQL / Oracle / PostgreSQL / Snowflake / ClickHouse column
// constraints, identity and generated columns.

package parser

import (
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
)

// dialectAllows reports whether syntax that belongs to the listed dialects
// may be parsed: the active dialect is one of them, or no dialect is set (the
// permissive default).
func (p *Parser) dialectAllows(ds ...dialect.Dialect) bool {
	if p.dialectTyped == dialect.Unknown {
		return true
	}
	for _, d := range ds {
		if p.dialectTyped == d {
			return true
		}
	}
	return false
}

// atColumnConstraintStart reports whether the current token begins a column
// constraint that is recognised without looking at the dialect. It decides
// whether a SQLite column has no type and whether CONSTRAINT <name> is
// followed by a name or by the constraint itself.
func (p *Parser) atColumnConstraintStart() bool {
	switch p.currentToken.Token.Type {
	case models.TokenTypePrimary, models.TokenTypeNot, models.TokenTypeNull,
		models.TokenTypeUnique, models.TokenTypeCheck, models.TokenTypeDefault,
		models.TokenTypeReferences, models.TokenTypeConstraint, models.TokenTypeCollate,
		models.TokenTypeAs, models.TokenTypeAutoIncrement:
		return true
	}
	return p.isUnquotedWord("GENERATED")
}

// columnTypeOmitted reports whether the column has no data type: a SQLite
// column may be just a name, a ClickHouse column may start with its DEFAULT /
// MATERIALIZED / ALIAS / EPHEMERAL / CODEC clause, and a SQL Server computed
// column is "name AS expression".
func (p *Parser) columnTypeOmitted() bool {
	switch p.dialectTyped {
	case dialect.SQLite:
		return p.isAnyType(models.TokenTypeComma, models.TokenTypeRParen) || p.atColumnConstraintStart()
	case dialect.ClickHouse:
		return p.isType(models.TokenTypeDefault) ||
			p.isUnquotedWord("MATERIALIZED") || p.isUnquotedWord("ALIAS") ||
			p.isUnquotedWord("EPHEMERAL") ||
			(p.isUnquotedWord("CODEC") && p.peekToken().Token.Type == models.TokenTypeLParen)
	case dialect.SQLServer:
		return p.isType(models.TokenTypeAs)
	}
	return false
}

// intervalFieldAt reports whether the token at offset is an interval field.
func (p *Parser) intervalFieldAt(offset int) bool {
	v := p.peekAt(offset).Token.Value
	for _, f := range [...]string{"YEAR", "MONTH", "DAY", "HOUR", "MINUTE", "SECOND"} {
		if equalsUpper(v, f) {
			return true
		}
	}
	return false
}

// timeZoneClauseLen returns the number of tokens of a WITH / WITHOUT [LOCAL]
// TIME ZONE clause starting at the current token, or 0 when there is none.
func (p *Parser) timeZoneClauseLen() int {
	if !p.isUnquotedWord("WITH") && !p.isUnquotedWord("WITHOUT") {
		return 0
	}
	switch {
	case p.peekValueIs(1, "TIME") && p.peekValueIs(2, "ZONE"):
		return 3
	case p.peekValueIs(1, "LOCAL") && p.peekValueIs(2, "TIME") && p.peekValueIs(3, "ZONE"):
		return 4
	}
	return 0
}

// typeWordFollows reports whether the current word continues a multi-word
// type whose last word is prev (upper case; first is the type's first word).
// Only known sequences continue: DOUBLE PRECISION, CHARACTER VARYING,
// NATIONAL CHARACTER, BINARY LARGE OBJECT, INTERVAL DAY TO SECOND, SQLite's
// UNSIGNED BIG INT / VARYING CHARACTER / NATIVE CHARACTER, and MySQL's
// UNSIGNED / SIGNED / ZEROFILL after a numeric type.
func (p *Parser) typeWordFollows(prev, first string) bool {
	if !p.isWordToken() || p.isQuotedIdentifierToken() {
		return false
	}
	v := p.currentToken.Token.Value
	switch prev {
	case "ZONE":
		return false
	case "DOUBLE":
		if equalsUpper(v, "PRECISION") {
			return true
		}
	case "CHARACTER", "CHAR", "NCHAR", "BIT", "BINARY":
		if equalsUpper(v, "VARYING") {
			return true
		}
		if prev != "BIT" && prev != "NCHAR" && equalsUpper(v, "LARGE") {
			return true
		}
	case "NATIONAL":
		return equalsUpper(v, "CHARACTER") || equalsUpper(v, "CHAR") || equalsUpper(v, "VARCHAR")
	case "LARGE":
		return equalsUpper(v, "OBJECT")
	case "VARYING":
		if first == "VARYING" && equalsUpper(v, "CHARACTER") {
			return true
		}
	case "NATIVE":
		return equalsUpper(v, "CHARACTER")
	case "UNSIGNED":
		if first == "UNSIGNED" && equalsUpper(v, "BIG") {
			return true
		}
	case "BIG":
		return equalsUpper(v, "INT") || equalsUpper(v, "INTEGER")
	case "LONG":
		return equalsUpper(v, "VARCHAR") || equalsUpper(v, "VARBINARY") || equalsUpper(v, "RAW")
	case "INTERVAL":
		return p.intervalFieldAt(0)
	case "YEAR", "MONTH", "DAY", "HOUR", "MINUTE", "SECOND":
		if first == "INTERVAL" && equalsUpper(v, "TO") && p.intervalFieldAt(1) {
			return true
		}
	case "TO":
		return first == "INTERVAL" && p.intervalFieldAt(0)
	}
	// MySQL numeric attributes follow any type, after its arguments too.
	return equalsUpper(v, "UNSIGNED") || equalsUpper(v, "SIGNED") || equalsUpper(v, "ZEROFILL")
}

// parseColumnType parses a column data type: a type name (possibly
// schema-qualified) followed by any of its arguments, the words of a
// multi-word type, a WITH / WITHOUT TIME ZONE clause, MySQL numeric
// attributes (UNSIGNED, ZEROFILL) and PostgreSQL array suffixes (text[],
// int ARRAY[3]). The text is kept as one string, as for the simple types.
//
// Parameterised and nested types such as VARCHAR(100), DECIMAL(10,2),
// Array(Nullable(String)), Map(String, Array(UInt32)), Tuple(a UInt8,
// b String), DateTime64(3, 'UTC') and ReplicatedMergeTree('/path',
// '{replica}') are collected by a depth-tracking token collector that
// round-trips the type string.
func (p *Parser) parseColumnType() (string, error) {
	// Use parseColumnName to accept keyword-based type names such as
	// INTEGER, TEXT, REAL.
	typeName := typeNameTokenSQL(p.currentToken.Token)
	base := p.parseColumnName()
	if base == nil {
		return "", goerrors.ExpectedTokenError(
			"data type",
			p.currentToken.Token.Type.String(),
			p.currentLocation(),
			"",
		)
	}
	typ := typeName
	for p.isType(models.TokenTypePeriod) && p.peekToken().Token.Value != "" &&
		p.peekToken().Token.Type != models.TokenTypeMul {
		p.advance() // Consume .
		typ += "." + typeNameTokenSQL(p.currentToken.Token)
		p.advance()
	}
	first := strings.ToUpper(typ)
	prev := first
	argsLast := false
	for {
		switch {
		case p.isType(models.TokenTypeLParen) && !argsLast:
			args, err := p.parseTypeArgsString()
			if err != nil {
				return "", err
			}
			typ += args
			argsLast = true
			continue
		case p.isType(models.TokenTypeLBracket) && p.dialectAllows(dialect.PostgreSQL, dialect.Redshift):
			suffix, ok := p.parseArraySuffix()
			if !ok {
				return typ, nil
			}
			typ += suffix
			argsLast = true
			continue
		case (prev == "TIME" || prev == "TIMESTAMP") && p.timeZoneClauseLen() > 0:
			for n := p.timeZoneClauseLen(); n > 0; n-- {
				typ += " " + p.currentToken.Token.Value
				p.advance()
			}
			prev, argsLast = "ZONE", true
			continue
		case p.isUnquotedWord("ARRAY") && p.dialectAllows(dialect.PostgreSQL, dialect.Redshift) &&
			(prev != "ARRAY"):
			typ += " " + p.currentToken.Token.Value
			p.advance()
			prev, argsLast = "ARRAY", false
			continue
		case p.typeWordFollows(prev, first):
			typ += " " + p.currentToken.Token.Value
			prev = strings.ToUpper(p.currentToken.Token.Value)
			argsLast = false
			p.advance()
			continue
		}
		return typ, nil
	}
}

// parseArraySuffix consumes one "[]" or "[n]" and returns it. ok is false,
// with nothing consumed, when the brackets are not an array suffix.
func (p *Parser) parseArraySuffix() (string, bool) {
	switch {
	case p.peekTypeAt(1) == models.TokenTypeRBracket:
		p.advance()
		p.advance()
		return "[]", true
	case p.peekTypeAt(1) == models.TokenTypeNumber && p.peekTypeAt(2) == models.TokenTypeRBracket:
		n := p.peekAt(1).Token.Value
		p.advance()
		p.advance()
		p.advance()
		return "[" + n + "]", true
	}
	return "", false
}

// parseClusterKeyword consumes the optional T-SQL CLUSTERED / NONCLUSTERED
// that follows PRIMARY KEY or UNIQUE and returns it upper-cased.
func (p *Parser) parseClusterKeyword() string {
	if !p.dialectAllows(dialect.SQLServer) {
		return ""
	}
	for _, kw := range [...]string{"CLUSTERED", "NONCLUSTERED"} {
		if p.isUnquotedWord(kw) {
			p.advance()
			return kw
		}
	}
	return ""
}

// parseIdentityOptions parses the options of an IDENTITY / AUTOINCREMENT
// column: "(seed, increment)" or Snowflake's "START n INCREMENT m [ORDER |
// NOORDER]". It returns the options as text, or "" when there are none.
func (p *Parser) parseIdentityOptions() (string, error) {
	var parts []string
	if p.isType(models.TokenTypeLParen) {
		args, err := p.parseTypeArgsString()
		if err != nil {
			return "", err
		}
		parts = append(parts, args)
	}
	for {
		switch {
		case p.isUnquotedWord("START") || p.isUnquotedWord("INCREMENT"):
			word := strings.ToUpper(p.currentToken.Token.Value)
			next := p.peekToken().Token
			sign := ""
			if next.Type == models.TokenTypeMinus && p.peekTypeAt(2) == models.TokenTypeNumber {
				sign = "-"
				next = p.peekAt(2).Token
			}
			if next.Type != models.TokenTypeNumber {
				return "", p.expectedError("number after " + word)
			}
			p.advance() // START / INCREMENT
			if sign != "" {
				p.advance() // -
			}
			parts = append(parts, word+" "+sign+p.currentToken.Token.Value)
			p.advance()
		case p.isUnquotedWord("ORDER") || p.isUnquotedWord("NOORDER"):
			parts = append(parts, strings.ToUpper(p.currentToken.Token.Value))
			p.advance()
		default:
			return strings.Join(parts, " "), nil
		}
	}
}

// parseNameText parses a possibly qualified name and returns it as source
// text: quoted parts keep their quotes so the name is written back with the
// same meaning (COLLATE "C", CHARACTER SET utf8mb4, COLLATE pg_catalog."default").
func (p *Parser) parseNameText(what string) (string, error) {
	var sb strings.Builder
	for {
		t := p.currentToken.Token
		switch {
		case t.Type == models.TokenTypeDoubleQuotedString:
			sb.WriteByte('"')
			sb.WriteString(strings.ReplaceAll(t.Value, `"`, `""`))
			sb.WriteByte('"')
		case t.Type == models.TokenTypeString || t.Type == models.TokenTypeSingleQuotedString:
			sb.WriteByte('\'')
			sb.WriteString(strings.ReplaceAll(t.Value, `'`, `''`))
			sb.WriteByte('\'')
		case p.isWordToken() && p.isQuotedIdentifierToken():
			q := byte('"')
			if p.isMySQLFamily() {
				q = '`'
			}
			sb.WriteByte(q)
			sb.WriteString(strings.ReplaceAll(t.Value, string(q), string(q)+string(q)))
			sb.WriteByte(q)
		case p.isWordToken():
			sb.WriteString(t.Value)
		default:
			return "", p.expectedError(what)
		}
		p.advance()
		if p.isType(models.TokenTypePeriod) {
			sb.WriteByte('.')
			p.advance()
			continue
		}
		return sb.String(), nil
	}
}

// parseGeneratedExpression parses the "(expression)" of a generated
// column and the optional STORED / VIRTUAL / PERSISTENT / PERSISTED word.
func (p *Parser) parseGeneratedExpression(c *ast.ColumnConstraint, needParens bool) error {
	if p.isType(models.TokenTypeLParen) {
		pos := p.currentLocation()
		p.advance() // Consume (
		expr, err := p.parseExpression()
		if err != nil {
			return err
		}
		if !p.isType(models.TokenTypeRParen) {
			return p.expectedError(") after generated column expression")
		}
		p.advance() // Consume )
		c.Expr = &ast.ParenthesizedExpression{Expr: expr, Pos: pos}
	} else {
		if needParens {
			return p.expectedError("( for generated column expression")
		}
		expr, err := p.parseExpression()
		if err != nil {
			return err
		}
		c.Expr = expr
	}
	for _, kw := range [...]string{"STORED", "VIRTUAL", "PERSISTENT", "PERSISTED"} {
		if p.isUnquotedWord(kw) {
			c.Keyword = kw
			p.advance()
			break
		}
	}
	return nil
}

// parseGeneratedConstraint parses GENERATED {ALWAYS | BY DEFAULT [ON NULL]}
// AS {IDENTITY [(options)] | (expression) [STORED | VIRTUAL] | ROW START |
// ROW END}. The current token is GENERATED.
func (p *Parser) parseGeneratedConstraint(c *ast.ColumnConstraint) error {
	p.advance() // Consume GENERATED
	always, byDefault, onNull := false, false, false
	switch {
	case p.isUnquotedWord("ALWAYS"):
		always = true
		p.advance()
	case p.isUnquotedWord("BY"):
		p.advance() // Consume BY
		if !p.isType(models.TokenTypeDefault) {
			return p.expectedError("DEFAULT after GENERATED BY")
		}
		p.advance() // Consume DEFAULT
		byDefault = true
		if p.isType(models.TokenTypeOn) && p.peekToken().Token.Type == models.TokenTypeNull {
			p.advance() // Consume ON
			p.advance() // Consume NULL
			onNull = true
		}
	}
	if !p.isType(models.TokenTypeAs) {
		return p.expectedError("AS after GENERATED [ALWAYS]")
	}
	p.advance() // Consume AS
	switch {
	case p.isUnquotedWord("IDENTITY") && (always || byDefault):
		p.advance() // Consume IDENTITY
		switch {
		case always:
			c.Type = "GENERATED ALWAYS AS IDENTITY"
		case onNull:
			c.Type = "GENERATED BY DEFAULT ON NULL AS IDENTITY"
		default:
			c.Type = "GENERATED BY DEFAULT AS IDENTITY"
		}
		if p.isType(models.TokenTypeLParen) {
			args, err := p.parseTypeArgsString()
			if err != nil {
				return err
			}
			c.Args = args
		}
		return nil
	case p.isType(models.TokenTypeRow) && !byDefault:
		// MariaDB system-versioned columns: GENERATED ALWAYS AS ROW START | END.
		p.advance() // Consume ROW
		rowRole := strings.ToUpper(p.currentToken.Token.Value)
		if rowRole != "START" && rowRole != "END" {
			return p.expectedError("START or END after GENERATED [ALWAYS] AS ROW")
		}
		p.advance() // Consume START or END
		c.Type = "GENERATED ALWAYS AS ROW " + rowRole
		return nil
	case p.isType(models.TokenTypeLParen) && (always || byDefault):
		c.Type = "GENERATED ALWAYS AS"
		return p.parseGeneratedExpression(c, true)
	}
	return p.expectedError("IDENTITY, ROW or ( after GENERATED [ALWAYS] AS")
}

// parseColumnConstraintExt parses the constraints beyond the SQL-standard
// ones: COLLATE, ON UPDATE, generated and identity columns, COMMENT,
// CHARACTER SET, INVISIBLE, SRID, DEFERRABLE / INITIALLY, and the ClickHouse
// MATERIALIZED / ALIAS / EPHEMERAL / CODEC / TTL clauses. c is the empty
// constraint to fill. Returns (nil, false, nil) when the current token starts
// none of them.
func (p *Parser) parseColumnConstraintExt(c *ast.ColumnConstraint) (*ast.ColumnConstraint, bool, error) {
	t := p.currentToken.Token
	switch {
	case t.Type == models.TokenTypeCollate:
		p.advance() // Consume COLLATE
		name, err := p.parseNameText("collation name after COLLATE")
		if err != nil {
			return nil, false, err
		}
		c.Type, c.Value = "COLLATE", name
		return c, true, nil

	case t.Type == models.TokenTypeOn && p.peekValueIs(1, "UPDATE") &&
		p.dialectAllows(dialect.MySQL, dialect.MariaDB):
		p.advance() // Consume ON
		p.advance() // Consume UPDATE
		expr, err := p.parseExpression()
		if err != nil {
			return nil, false, err
		}
		c.Type, c.Expr = "ON UPDATE", expr
		return c, true, nil

	case (t.Type == models.TokenTypeWith || p.isUnquotedWord("WITHOUT")) &&
		p.peekValueIs(1, "SYSTEM") && p.peekValueIs(2, "VERSIONING") && p.dialectAllows(dialect.MariaDB):
		// MariaDB: [WITH | WITHOUT] SYSTEM VERSIONING on a column.
		c.Type = strings.ToUpper(t.Value) + " SYSTEM VERSIONING"
		p.advance() // Consume WITH / WITHOUT
		p.advance() // Consume SYSTEM
		p.advance() // Consume VERSIONING
		return c, true, nil

	case t.Type == models.TokenTypeAs:
		// MySQL, MariaDB, SQLite, Oracle: AS (expr) [STORED | VIRTUAL];
		// SQL Server computed column: AS expr [PERSISTED].
		p.advance() // Consume AS
		c.Type = "AS"
		if err := p.parseGeneratedExpression(c, p.dialectTyped != dialect.SQLServer); err != nil {
			return nil, false, err
		}
		return c, true, nil
	}

	if !p.isWordToken() || p.isQuotedIdentifierToken() {
		return nil, false, nil
	}
	switch {
	case p.isUnquotedWord("GENERATED"):
		if err := p.parseGeneratedConstraint(c); err != nil {
			return nil, false, err
		}
		return c, true, nil

	case p.isUnquotedWord("COMMENT") && p.dialectAllows(dialect.MySQL, dialect.MariaDB, dialect.ClickHouse, dialect.Snowflake):
		p.advance() // Consume COMMENT
		if !p.isStringLiteral() {
			return nil, false, p.expectedError("string after COMMENT")
		}
		c.Type, c.Expr = "COMMENT", p.newStringLiteral(p.currentToken.Token.Value)
		p.advance()
		return c, true, nil

	case (p.isUnquotedWord("CHARACTER") && p.peekValueIs(1, "SET") || p.isUnquotedWord("CHARSET")) &&
		p.dialectAllows(dialect.MySQL, dialect.MariaDB):
		if p.isUnquotedWord("CHARSET") {
			c.Keyword = "CHARSET"
		} else {
			p.advance() // Consume CHARACTER
		}
		p.advance() // Consume SET / CHARSET
		if p.isType(models.TokenTypeEq) {
			p.advance()
		}
		name, err := p.parseNameText("character set name")
		if err != nil {
			return nil, false, err
		}
		c.Type, c.Value = "CHARACTER SET", name
		return c, true, nil

	case (p.isUnquotedWord("INVISIBLE") || p.isUnquotedWord("VISIBLE")) &&
		p.dialectAllows(dialect.MySQL, dialect.MariaDB):
		c.Type = strings.ToUpper(t.Value)
		p.advance()
		return c, true, nil

	case p.isUnquotedWord("SRID") && p.peekTypeAt(1) == models.TokenTypeNumber &&
		p.dialectAllows(dialect.MySQL, dialect.MariaDB):
		p.advance() // Consume SRID
		c.Type, c.Value = "SRID", p.currentToken.Token.Value
		p.advance()
		return c, true, nil

	case p.isUnquotedWord("IDENTITY") && p.dialectAllows(dialect.SQLServer, dialect.Snowflake):
		p.advance() // Consume IDENTITY
		args, err := p.parseIdentityOptions()
		if err != nil {
			return nil, false, err
		}
		c.Type, c.Args = "IDENTITY", args
		return c, true, nil

	case p.isUnquotedWord("DEFERRABLE") && p.dialectAllows(dialect.PostgreSQL, dialect.SQLite, dialect.Oracle, dialect.Redshift):
		p.advance()
		c.Type = "DEFERRABLE"
		return c, true, nil

	case p.isUnquotedWord("INITIALLY") && (p.peekValueIs(1, "DEFERRED") || p.peekValueIs(1, "IMMEDIATE")) &&
		p.dialectAllows(dialect.PostgreSQL, dialect.SQLite, dialect.Oracle, dialect.Redshift):
		p.advance() // Consume INITIALLY
		c.Type = "INITIALLY " + strings.ToUpper(p.currentToken.Token.Value)
		p.advance()
		return c, true, nil
	}

	if p.dialectTyped == dialect.ClickHouse {
		return p.parseClickHouseColumnClause(c)
	}
	return nil, false, nil
}

// parseClickHouseColumnClause parses the ClickHouse column clauses that
// follow the type: MATERIALIZED expr, ALIAS expr, EPHEMERAL [expr],
// CODEC(...) and TTL expr. DEFAULT and COMMENT are shared with other dialects
// and handled elsewhere.
func (p *Parser) parseClickHouseColumnClause(c *ast.ColumnConstraint) (*ast.ColumnConstraint, bool, error) {
	switch {
	case p.isUnquotedWord("MATERIALIZED") || p.isUnquotedWord("ALIAS") || p.isUnquotedWord("TTL"):
		c.Type = strings.ToUpper(p.currentToken.Token.Value)
		p.advance()
		expr, err := p.parseExpression()
		if err != nil {
			return nil, false, err
		}
		c.Expr = expr
		return c, true, nil
	case p.isUnquotedWord("EPHEMERAL"):
		c.Type = "EPHEMERAL"
		p.advance()
		if !p.isAnyType(models.TokenTypeComma, models.TokenTypeRParen, models.TokenTypeSemicolon, models.TokenTypeEOF) &&
			!p.isUnquotedWord("CODEC") && !p.isUnquotedWord("COMMENT") && !p.isUnquotedWord("TTL") {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, false, err
			}
			c.Expr = expr
		}
		return c, true, nil
	case p.isUnquotedWord("CODEC") && p.peekToken().Token.Type == models.TokenTypeLParen:
		p.advance() // Consume CODEC
		args, err := p.parseTypeArgsString()
		if err != nil {
			return nil, false, err
		}
		c.Type, c.Args = "CODEC", args
		return c, true, nil
	}
	return nil, false, nil
}

// parseDeferrableClause parses the optional [NOT] DEFERRABLE and INITIALLY
// {DEFERRED | IMMEDIATE} clauses that end a table constraint and returns them
// normalised to upper case, or "".
func (p *Parser) parseDeferrableClause() string {
	if !p.dialectAllows(dialect.PostgreSQL, dialect.SQLite, dialect.Oracle, dialect.Redshift) {
		return ""
	}
	var parts []string
	for {
		switch {
		case p.isUnquotedWord("DEFERRABLE"):
			parts = append(parts, "DEFERRABLE")
			p.advance()
		case p.isType(models.TokenTypeNot) && p.peekValueIs(1, "DEFERRABLE"):
			parts = append(parts, "NOT DEFERRABLE")
			p.advance()
			p.advance()
		case p.isUnquotedWord("INITIALLY") && (p.peekValueIs(1, "DEFERRED") || p.peekValueIs(1, "IMMEDIATE")):
			p.advance()
			parts = append(parts, "INITIALLY "+strings.ToUpper(p.currentToken.Token.Value))
			p.advance()
		default:
			return strings.Join(parts, " ")
		}
	}
}
