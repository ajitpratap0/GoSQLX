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

// utility_grammar.go gives the verbatim GRANT, REVOKE and PostgreSQL COPY
// statements enough grammar to know where they end outside SQL Server, so
// that a statement written after them on the same line without a ';'
// ("GRANT SELECT ON t TO u DROP TABLE t") is an error rather than part of
// their text. The statements are still kept as written.

package parser

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// utilityTailError checks what follows a utility statement whose grammar
// ends before token index end: a ';', the end of the input or, in SQL
// Server, a GO line or the next statement. Elsewhere statements are
// separated by ';', so the next statement is an error unless it is a
// transaction statement on a line of its own (see lineStatementEnd).
func (p *Parser) utilityTailError(end int) error {
	if end >= len(p.tokens) {
		return nil
	}
	switch p.tokens[end].Token.Type {
	case models.TokenTypeSemicolon, models.TokenTypeEOF:
		return nil
	}
	if p.IsSQLServer() {
		if _, ok := p.batchSeparatorEnd(end); ok || p.statementMayEndAt(end) {
			return nil
		}
		p.seek(end)
		return p.expectedError("end of statement")
	}
	return p.lineStatementEnd(end)
}

// parseGrammarStatement parses a utility statement whose end grammarEnd
// finds, as a UtilityStatement of the given kind that keeps its text.
func (p *Parser) parseGrammarStatement(kind string, grammarEnd func(start int) (int, error)) (ast.Statement, bool, error) {
	pos := p.currentLocation()
	start := p.currentPos
	end, err := grammarEnd(start)
	if err != nil {
		return nil, true, err
	}
	if err := p.utilityTailError(end); err != nil {
		return nil, true, err
	}
	text := p.renderTokenRange(start, end)
	p.seek(end)
	return &ast.UtilityStatement{Kind: kind, Text: text, Pos: pos}, true, nil
}

// grantEnd returns the index after the GRANT or REVOKE statement starting
// at token index start:
//
//	GRANT privileges [ON [object type] names] TO grantees [options]
//	REVOKE [GRANT OPTION FOR] privileges [ON ...] FROM grantees [options]
//
// The privilege and object lists are taken as written up to TO / FROM; the
// grantee list and the trailing options are checked, since that is where a
// following statement would be read into the text.
func (p *Parser) grantEnd(start int) (int, error) {
	to := "TO"
	if p.utilityWord(start) == "REVOKE" {
		to = "FROM"
	}
	i, err := p.grantPrincipalsAt(start, to)
	if err != nil {
		return 0, err
	}
	c := txnCursor{p: p, i: i, mask: p.alterMask()}
	if err := c.grantees(); err != nil {
		return 0, err
	}
	if err := c.grantOptions(); err != nil {
		return 0, err
	}
	return c.i, nil
}

// grantPrincipalsAt returns the index after the TO (GRANT) or FROM
// (REVOKE) that starts the grantee list of the statement at token index
// start. The privilege list may name statements (GRANT SELECT, INSERT), so
// only a statement-starting word at the start of a line that does not
// continue a list ends the search.
func (p *Parser) grantPrincipalsAt(start int, to string) (int, error) {
	depth := 0
	for i := start + 1; i < len(p.tokens); i++ {
		switch p.tokens[i].Token.Type {
		case models.TokenTypeLParen:
			depth++
			continue
		case models.TokenTypeRParen:
			depth--
			if depth < 0 {
				p.seek(i)
				return 0, p.expectedError(to)
			}
			continue
		case models.TokenTypeSemicolon, models.TokenTypeEOF:
			if depth == 0 {
				p.seek(i)
				return 0, p.expectedError(to)
			}
			continue
		}
		if depth != 0 {
			continue
		}
		if p.utilityWord(i) == to {
			if i == start+1 {
				p.seek(i)
				return 0, p.expectedError("privilege or role")
			}
			return i + 1, nil
		}
		if i > start+1 && p.tokens[i-1].Token.Type != models.TokenTypeComma &&
			p.startsNewLineStatement(i, start) {
			p.seek(i)
			return 0, p.expectedError(to)
		}
	}
	p.seek(len(p.tokens))
	return 0, p.expectedError(to)
}

// granteeKinds are the words that may precede a grantee name: ROLE r,
// USER u, GROUP g, SHARE s, DATABASE ROLE d.r, APPLICATION ROLE a.
var granteeKinds = map[string]bool{
	"ROLE": true, "USER": true, "GROUP": true, "SHARE": true,
	"DATABASE": true, "APPLICATION": true,
}

// grantees consumes a comma-separated list of grantees: [kind] name, a
// MySQL account ('u'@'h', u@h), or PUBLIC / CURRENT_USER and the like.
// ClickHouse also has ALL [EXCEPT grantees].
func (c *txnCursor) grantees() error {
	for {
		if err := c.grantee(); err != nil {
			return err
		}
		if c.word() == "EXCEPT" && c.p.utilityWord(c.i-1) == "ALL" {
			c.i++
			continue
		}
		if c.typeAt(c.i) != models.TokenTypeComma {
			return nil
		}
		c.i++
	}
}

// grantee consumes one grantee.
func (c *txnCursor) grantee() error {
	p := c.p
	if w := c.word(); granteeKinds[w] && c.granteeNameAt(c.i+1) {
		c.i++
		if w == "DATABASE" || (w == "APPLICATION" && c.p.utilityWord(c.i) == "ROLE") {
			if err := c.expect("ROLE"); err != nil {
				return err
			}
		}
	}
	if !c.granteeNameAt(c.i) {
		return c.fail("grantee")
	}
	switch {
	case c.acceptString(): // 'user'@'host'
	case c.typeAt(c.i) == models.TokenTypeLBracket:
		// [AppUser]: a bracketed name the tokenizer did not read as one
		// outside SQL Server.
		end := c.bracketEnd(c.i)
		if end < 0 {
			return c.fail("]")
		}
		c.i = end
	default:
		c.i = p.nameEnd(c.i)
		if c.typeAt(c.i) == models.TokenTypeLParen {
			// CURRENT_USER(), Snowflake IDENTIFIER('r')
			end := p.groupEnd(c.i)
			if end < 0 {
				return c.fail(")")
			}
			c.i = end
		}
	}
	if c.typeAt(c.i) == models.TokenTypeAtSign {
		c.i++
		if !c.acceptString() {
			if !p.isNamePartAt(c.i) {
				return c.fail("host name")
			}
			c.i = p.nameEnd(c.i)
		}
	} else if c.typeAt(c.i) == models.TokenTypePlaceholder && c.i > 0 &&
		tokensAdjacent(&p.tokens[c.i-1], &p.tokens[c.i]) {
		// u@host read as u followed by the placeholder @host.
		c.i++
	}
	return nil
}

// bracketEnd returns the index after the [ ... ] that opens at token
// index i, or -1 when it does not close on the statement.
func (c *txnCursor) bracketEnd(i int) int {
	for j := i + 1; j < len(c.p.tokens); j++ {
		switch c.typeAt(j) {
		case models.TokenTypeRBracket:
			return j + 1
		case models.TokenTypeSemicolon, models.TokenTypeEOF, models.TokenTypeLBracket:
			return -1
		}
	}
	return -1
}

// granteeNameAt reports whether a grantee name (an identifier, a word or a
// string) starts at token index i.
func (c *txnCursor) granteeNameAt(i int) bool {
	switch c.typeAt(i) {
	case models.TokenTypeString, models.TokenTypeSingleQuotedString, models.TokenTypeLBracket:
		return true
	case models.TokenTypeComma, models.TokenTypeSemicolon, models.TokenTypeEOF:
		return false
	}
	return c.p.isNamePartAt(i)
}

// grantOptions consumes the options after the grantee list:
//
//	WITH {GRANT | ADMIN | HIERARCHY | DELEGATE | REPLACE} OPTION
//	WITH {ADMIN | INHERIT | SET} {OPTION | TRUE | FALSE} [, ...]   (PostgreSQL 16)
//	WITH MAX_QUERIES_PER_HOUR n ...                               (MySQL)
//	GRANTED BY role, CASCADE, RESTRICT, IDENTIFIED BY 'p',
//	REQUIRE ..., AS user [WITH ROLE ...], CONTAINER = ALL | CURRENT,
//	IGNORE UNKNOWN USER, COPY | REVOKE CURRENT GRANTS
func (c *txnCursor) grantOptions() error {
	for {
		switch c.word() {
		case "WITH":
			c.i++
			if err := c.grantWithOption(); err != nil {
				return err
			}
		case "GRANTED":
			c.i++
			if err := c.expect("BY"); err != nil {
				return err
			}
			if err := c.grantee(); err != nil {
				return err
			}
		case "CASCADE", "RESTRICT":
			c.i++
			c.accept("CONSTRAINTS") // Oracle REVOKE ... CASCADE CONSTRAINTS
		case "FORCE":
			c.i++ // Oracle REVOKE ... FORCE
		case "IDENTIFIED":
			c.i++
			if c.accept("VIA") {
				// MariaDB: IDENTIFIED VIA plugin [USING 'x'] [OR plugin ...]
				if err := c.mariadbAuth(); err != nil {
					return err
				}
				continue
			}
			if c.accept("WITH") {
				if !c.p.isNamePartAt(c.i) && !c.acceptString() {
					return c.fail("authentication plugin")
				}
				if c.p.isNamePartAt(c.i) {
					c.i = c.p.nameEnd(c.i)
				}
				if !c.accept("BY") && !c.accept("AS") {
					continue
				}
			} else if err := c.expect("BY"); err != nil {
				return err
			}
			c.accept("PASSWORD")
			if c.accept("RANDOM") {
				if err := c.expect("PASSWORD"); err != nil {
					return err
				}
				continue
			}
			if !c.acceptString() {
				if !c.p.isNamePartAt(c.i) {
					return c.fail("password")
				}
				c.i = c.p.nameEnd(c.i)
			}
		case "REQUIRE":
			c.i++
			if err := c.grantRequire(); err != nil {
				return err
			}
		case "AS":
			c.i++
			if err := c.grantee(); err != nil {
				return err
			}
		case "CONTAINER":
			c.i++
			if c.typeAt(c.i) != models.TokenTypeEq {
				return c.fail("=")
			}
			c.i++
			if !c.accept("ALL") && !c.accept("CURRENT") {
				return c.fail("ALL or CURRENT")
			}
		case "IGNORE":
			if c.p.utilityWord(c.i+1) != "UNKNOWN" {
				return nil
			}
			c.i += 2
			if err := c.expect("USER"); err != nil {
				return err
			}
		case "COPY", "REVOKE":
			if c.p.utilityWord(c.i+1) != "CURRENT" {
				return nil
			}
			c.i += 2
			if err := c.expect("GRANTS"); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

// grantWithOption consumes the words after WITH in a grant option.
func (c *txnCursor) grantWithOption() error {
	for {
		switch w := c.word(); w {
		case "GRANT", "HIERARCHY", "DELEGATE", "REPLACE":
			c.i++
			if err := c.expect("OPTION"); err != nil {
				return err
			}
			if !c.resourceLimit() {
				return nil
			}
			continue // MySQL: WITH GRANT OPTION MAX_QUERIES_PER_HOUR n
		case "ADMIN", "INHERIT", "SET":
			c.i++
			if !c.accept("OPTION") && !c.accept("TRUE") && !c.accept("FALSE") {
				return c.fail("OPTION, TRUE or FALSE")
			}
		case "ROLE":
			// MySQL GRANT ... AS u WITH ROLE {DEFAULT | NONE | ALL | r, ...}
			c.i++
			if err := c.grantees(); err != nil {
				return err
			}
			return nil
		default:
			if !c.resourceLimit() {
				return c.fail("grant option")
			}
			// MySQL: WITH MAX_QUERIES_PER_HOUR n [MAX_... n] ...
			c.i++
			if c.typeAt(c.i) != models.TokenTypeNumber {
				return c.fail("number")
			}
			c.i++
			if c.resourceLimit() {
				continue
			}
			return nil
		}
		if c.typeAt(c.i) != models.TokenTypeComma {
			return nil
		}
		c.i++
	}
}

// grantResourceLimits are MySQL's account resource options (longer than the
// words utilityWord matches).
var grantResourceLimits = []string{
	"MAX_QUERIES_PER_HOUR", "MAX_UPDATES_PER_HOUR", "MAX_CONNECTIONS_PER_HOUR",
	"MAX_USER_CONNECTIONS", "MAX_STATEMENT_TIME",
}

// resourceLimit reports whether the current token is one of
// grantResourceLimits.
func (c *txnCursor) resourceLimit() bool {
	if c.i >= len(c.p.tokens) || c.p.tokens[c.i].Token.Quote != 0 {
		return false
	}
	v := c.p.tokens[c.i].Token.Value
	for _, w := range grantResourceLimits {
		if strings.EqualFold(v, w) {
			return true
		}
	}
	return false
}

// grantRequire consumes MySQL's REQUIRE {NONE | SSL | X509 | {SUBJECT |
// ISSUER | CIPHER} 'text' [[AND] ...]}.
func (c *txnCursor) grantRequire() error {
	switch {
	case c.accept("NONE"), c.accept("SSL"):
		return nil
	case c.i < len(c.p.tokens) && strings.EqualFold(c.p.tokens[c.i].Token.Value, "X509"):
		c.i++
		return nil
	}
	n := 0
	for {
		switch c.word() {
		case "SUBJECT", "ISSUER", "CIPHER":
			c.i++
			if !c.acceptString() {
				return c.fail("string")
			}
			n++
			c.accept("AND")
			continue
		}
		if n == 0 {
			return c.fail("SSL requirement")
		}
		return nil
	}
}

// mariadbAuth consumes plugin [{USING | AS} 'auth'] [OR plugin ...] after
// MariaDB's IDENTIFIED VIA.
func (c *txnCursor) mariadbAuth() error {
	for {
		if !c.p.isNamePartAt(c.i) {
			return c.fail("authentication plugin")
		}
		c.i = c.p.nameEnd(c.i)
		if c.accept("USING") || c.accept("AS") {
			if !c.acceptString() {
				// PASSWORD('x')
				c.i = c.p.nameEnd(c.i)
				if c.typeAt(c.i) != models.TokenTypeLParen {
					return c.fail("string")
				}
				end := c.p.groupEnd(c.i)
				if end < 0 {
					return c.fail(")")
				}
				c.i = end
			}
		}
		if !c.accept("OR") {
			return nil
		}
	}
}

// copyString consumes a COPY file name or option value: a string, an
// escape string (E'...') or a dollar-quoted string.
func (c *txnCursor) copyString() bool {
	switch c.typeAt(c.i) {
	case models.TokenTypeEscapedStringLiteral, models.TokenTypeDollarQuotedString:
		c.i++
		return true
	}
	return c.acceptString()
}

// copyEnd returns the index after the PostgreSQL COPY statement starting at
// token index start:
//
//	COPY {table [(cols)] | (query)} {FROM | TO}
//	     {'file' | PROGRAM 'cmd' | STDIN | STDOUT}
//	     [[WITH] (option [, ...]) | legacy options] [WHERE condition]
func (p *Parser) copyEnd(start int) (int, error) {
	c := txnCursor{p: p, i: start + 1, mask: p.alterMask()}
	if c.typeAt(c.i) == models.TokenTypeLParen {
		end := p.groupEnd(c.i)
		if end < 0 {
			return 0, c.fail(")")
		}
		c.i = end
	} else {
		c.accept("BINARY")
		if !p.isNamePartAt(c.i) {
			return 0, c.fail("table name")
		}
		c.i = p.nameEnd(c.i)
		if e := p.groupEnd(c.i); e > 0 {
			c.i = e
		}
	}
	from := c.accept("FROM")
	if !from && !c.accept("TO") {
		return 0, c.fail("FROM or TO")
	}
	switch {
	case c.accept("PROGRAM"):
		if !c.copyString() {
			return 0, c.fail("command")
		}
	case c.copyString(), c.accept("STDIN"), c.accept("STDOUT"):
	default:
		return 0, c.fail("file name, PROGRAM, STDIN or STDOUT")
	}
	if c.accept("USING") {
		// USING DELIMITERS 'd' (before PostgreSQL 7.3)
		if err := c.expect("DELIMITERS"); err != nil {
			return 0, err
		}
		if !c.copyString() {
			return 0, c.fail("string")
		}
	}
	c.accept("WITH")
	if c.typeAt(c.i) == models.TokenTypeLParen {
		if e := p.groupEnd(c.i); e > 0 {
			c.i = e
		} else {
			return 0, c.fail(")")
		}
	} else if err := c.copyLegacyOptions(); err != nil {
		return 0, err
	}
	if from && c.word() == "WHERE" {
		end, err := p.subParse(c.i+1, true)
		if err != nil {
			return 0, err
		}
		c.i = end
	}
	return c.i, nil
}

// copyLegacyOptions consumes the options of the COPY syntax before
// PostgreSQL 9.0: BINARY, OIDS, FREEZE, CSV, HEADER, DELIMITER [AS] 'd',
// NULL [AS] 'n', QUOTE [AS] 'q', ESCAPE [AS] 'e', ENCODING 'e',
// FORCE QUOTE {cols | *}, FORCE [NOT] NULL cols.
func (c *txnCursor) copyLegacyOptions() error {
	for {
		switch c.word() {
		case "BINARY", "OIDS", "FREEZE", "CSV", "HEADER":
			c.i++
		case "DELIMITER", "DELIMITERS", "NULL", "QUOTE", "ESCAPE", "ENCODING":
			c.i++
			c.accept("AS")
			if !c.copyString() {
				return c.fail("string")
			}
		case "FORCE":
			c.i++
			switch {
			case c.accept("QUOTE"):
				if c.typeAt(c.i) == models.TokenTypeMul || c.typeAt(c.i) == models.TokenTypeAsterisk {
					c.i++
					continue
				}
			case c.accept("NOT"):
				if err := c.expect("NULL"); err != nil {
					return err
				}
			case c.accept("NULL"):
			default:
				return c.fail("QUOTE or NULL")
			}
			if err := c.copyColumns(); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

// copyColumns consumes a comma-separated list of column names.
func (c *txnCursor) copyColumns() error {
	for {
		if !c.p.isNamePartAt(c.i) {
			return c.fail("column name")
		}
		c.i++
		if c.typeAt(c.i) != models.TokenTypeComma {
			return nil
		}
		c.i++
	}
}

// parseAlterDefaultPrivileges parses PostgreSQL's
//
//	ALTER DEFAULT PRIVILEGES [FOR {ROLE | USER} r [, ...]] [IN SCHEMA s [, ...]]
//	      {GRANT ... ON {TABLES | SEQUENCES | ...} TO ... | REVOKE ... FROM ...}
//
// as a UtilityStatement kept as written; the ALTER token has been consumed.
func (p *Parser) parseAlterDefaultPrivileges() (ast.Statement, error) {
	p.seek(p.currentPos - 1)
	stmt, _, err := p.parseGrammarStatement("ALTER DEFAULT PRIVILEGES", p.alterDefaultPrivilegesEnd)
	return stmt, err
}

// alterDefaultPrivilegesEnd returns the index after the ALTER DEFAULT
// PRIVILEGES statement starting at token index start.
func (p *Parser) alterDefaultPrivilegesEnd(start int) (int, error) {
	c := txnCursor{p: p, i: start + 3, mask: p.alterMask()}
	for {
		switch {
		case c.accept("FOR"):
			if !c.accept("ROLE") && !c.accept("USER") {
				return 0, c.fail("ROLE or USER")
			}
		case c.accept("IN"):
			if err := c.expect("SCHEMA"); err != nil {
				return 0, err
			}
		default:
			if w := c.word(); w != "GRANT" && w != "REVOKE" {
				return 0, c.fail("GRANT or REVOKE")
			}
			return p.grantEnd(c.i)
		}
		if err := c.copyColumns(); err != nil {
			return 0, err
		}
	}
}
