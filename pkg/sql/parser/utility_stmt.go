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

// utility_stmt.go parses the utility-statement family: transaction control,
// SET, USE, CALL and the long tail of session, privilege and maintenance
// statements (GRANT, REVOKE, COMMENT ON, VACUUM, LOCK, KILL, PREPARE, T-SQL
// DECLARE / IF / PRINT, ...). parseStatement reaches this code only after its
// type switch found no other statement, so ordinary queries never pay for it.

package parser

import (
	"strings"
	"unicode/utf8"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// maxUtilityWordLen bounds the leading words matched by utilityWord.
const maxUtilityWordLen = 16

// utilityWord returns the upper-cased value of the token at index i when it
// is a bare (unquoted) word that could start or qualify a utility statement,
// and "" otherwise.
func (p *Parser) utilityWord(i int) string {
	if i < 0 || i >= len(p.tokens) {
		return ""
	}
	tok := &p.tokens[i]
	v := tok.Token.Value
	if v == "" || len(v) > maxUtilityWordLen || tok.Token.Quote != 0 || isQuotedSpan(tok) {
		return ""
	}
	switch tok.Token.Type {
	case models.TokenTypeDoubleQuotedString, models.TokenTypeString,
		models.TokenTypeSingleQuotedString, models.TokenTypeDollarQuotedString,
		models.TokenTypeNumber, models.TokenTypePlaceholder:
		return ""
	}
	for j := 0; j < len(v); j++ {
		c := v[j]
		if c != '_' && (c|0x20 < 'a' || c|0x20 > 'z') {
			return ""
		}
	}
	return strings.ToUpper(v)
}

// isQuotedSpan reports whether a token's source span is wider than its value
// on a single line, which is how a delimited identifier (`x`, [x]) whose
// delimiters the tokenizer stripped is recognized.
func isQuotedSpan(tok *models.TokenWithSpan) bool {
	return tok.Start.Line != 0 && tok.Start.Line == tok.End.Line &&
		tok.End.Column-tok.Start.Column > len(tok.Token.Value)
}

// parseUtilityStatement parses a utility statement starting at the current
// token. ok is false when the current token does not start one, in which case
// the parser position is unchanged.
func (p *Parser) parseUtilityStatement() (stmt ast.Statement, ok bool, err error) {
	if !p.atStatementBoundary() {
		return nil, false, nil
	}
	word := p.utilityWord(p.currentPos)
	if word == "" {
		return nil, false, nil
	}
	next := p.utilityWord(p.currentPos + 1)
	switch word {
	case "BEGIN":
		if p.beginIsBlock(next) {
			return p.parseVerbatimStatement("BEGIN")
		}
		return p.parseTransactionStatement("BEGIN")
	case "START":
		if next != "TRANSACTION" {
			return nil, false, nil
		}
		return p.parseTransactionStatement("START TRANSACTION")
	case "COMMIT", "ROLLBACK", "SAVEPOINT":
		return p.parseTransactionStatement(word)
	case "ABORT":
		if p.dialect != string(keywords.DialectPostgreSQL) && p.dialect != "" {
			return nil, false, nil
		}
		return p.parseTransactionStatement("ROLLBACK")
	case "RELEASE":
		return p.parseTransactionStatement("RELEASE SAVEPOINT")
	case "SAVE":
		if p.dialect != string(keywords.DialectSQLServer) || (next != "TRAN" && next != "TRANSACTION") {
			return nil, false, nil
		}
		return p.parseTransactionStatement("SAVEPOINT")
	case "END":
		switch p.dialect {
		case string(keywords.DialectPostgreSQL), string(keywords.DialectSQLite), "":
			// END [WORK | TRANSACTION] commits the current transaction.
			return p.parseTransactionStatement("END")
		case string(keywords.DialectSQLServer):
			// END, END TRY, END CATCH close a T-SQL block.
			return p.parseVerbatimStatement("END")
		}
		return nil, false, nil
	case "SET":
		return p.parseSetStatement()
	case "USE":
		return p.parseUseStatement()
	case "CALL":
		return p.parseCallStatement()
	case "ANALYZE":
		// MariaDB ANALYZE [FORMAT=JSON] <statement> runs and explains it.
		if p.peekStatementAfterOptions() {
			p.advance()
			s, err := p.parseDescribeStatement("ANALYZE")
			return s, true, err
		}
		return p.parseVerbatimStatement(word)
	case "COMMENT":
		if next != "ON" {
			return nil, false, nil
		}
		return p.parseVerbatimStatement(word)
	case "IF", "WHILE", "PRINT", "THROW", "RAISERROR", "WAITFOR", "DBCC", "BULK", "EXEC", "RETURN", "REVERT":
		if p.dialect != string(keywords.DialectSQLServer) {
			return nil, false, nil
		}
		return p.parseVerbatimArgs(word)
	case "EXISTS":
		// ClickHouse EXISTS [TEMPORARY] TABLE | DATABASE | DICTIONARY name.
		if p.dialect != string(keywords.DialectClickHouse) {
			return nil, false, nil
		}
		return p.parseVerbatimArgs(word)
	case "GRANT", "REVOKE", "VACUUM", "LOCK", "UNLOCK", "KILL", "FLUSH", "OPTIMIZE",
		"CHECK", "REPAIR", "CHECKSUM", "LISTEN", "NOTIFY", "UNLISTEN", "PREPARE",
		"EXECUTE", "DEALLOCATE", "DO", "DECLARE", "LOAD", "RENAME", "REINDEX",
		"CLUSTER", "CHECKPOINT", "DISCARD", "RESET", "XA", "BACKUP", "FLASHBACK",
		"PURGE", "UNDROP", "EXCHANGE", "SYSTEM", "ATTACH", "DETACH", "HANDLER",
		"INSTALL", "UNINSTALL", "COPY":
		return p.parseVerbatimArgs(word)
	case "TABLE":
		// TABLE name [ORDER BY ...] [LIMIT ...] (PostgreSQL, MySQL 8).
		if next == "" && !p.isIdentifierAt(p.currentPos+1) {
			return nil, false, nil
		}
		return p.parseVerbatimStatement(word)
	}
	return nil, false, nil
}

// atStatementBoundary reports whether the current token starts the input or
// follows a ';' or a T-SQL utility statement that ended where this one begins
// (see implicitEnd). Statements may follow one another without a semicolon, so
// without this check the tail of a statement the parser stopped short in
// (ALTER ... SET DEFAULT, FROM t USE INDEX) would be taken for a utility
// statement and silently split off.
func (p *Parser) atStatementBoundary() bool {
	return p.currentPos == 0 || p.tokens[p.currentPos-1].Token.Type == models.TokenTypeSemicolon ||
		p.currentPos == p.implicitEnd-1
}

// beginIsBlock reports whether BEGIN opens a procedural block rather than a
// transaction: always in Oracle (PL/SQL), and in SQL Server unless it is
// BEGIN TRAN[SACTION] or BEGIN DISTRIBUTED TRAN[SACTION].
func (p *Parser) beginIsBlock(next string) bool {
	switch p.dialect {
	case string(keywords.DialectOracle):
		return true
	case string(keywords.DialectSQLServer):
		return next != "TRAN" && next != "TRANSACTION" && next != "DISTRIBUTED"
	}
	return false
}

// peekStatementAfterOptions reports whether, after the current keyword, a
// statement follows (possibly after explain-style options such as
// FORMAT=JSON). The parser position is unchanged.
func (p *Parser) peekStatementAfterOptions() bool {
	saved, savedTok := p.currentPos, p.currentToken
	p.advance()
	n := p.explainOptionTokens()
	p.currentPos, p.currentToken = saved, savedTok
	return n >= 0
}

// utilityStatementEnd returns the index of the token that ends the statement
// starting at the current position (a top-level ';' or EOF, or in SQL Server
// the word that starts the next statement), or an error when its parentheses
// do not balance.
func (p *Parser) utilityStatementEnd() (int, error) {
	depth := 0
	i := p.currentPos
	implicit := p.implicitEndAllowed()
	for ; i < len(p.tokens); i++ {
		if implicit && depth == 0 && p.startsNewStatement(i, p.currentPos) {
			p.markImplicitEnd(i)
			return i, nil
		}
		switch p.tokens[i].Token.Type {
		case models.TokenTypeLParen:
			depth++
		case models.TokenTypeRParen:
			depth--
			if depth < 0 {
				p.seek(i)
				return 0, p.expectedError("end of statement")
			}
		case models.TokenTypeSemicolon:
			if depth == 0 {
				return i, nil
			}
		case models.TokenTypeEOF:
			if depth != 0 {
				p.seek(i)
				return 0, p.expectedError(")")
			}
			return i, nil
		}
	}
	if depth != 0 {
		return 0, goerrors.IncompleteStatementError(p.currentLocation(), "")
	}
	return i, nil
}

// consumeUtilityText consumes the rest of the statement and returns its text.
func (p *Parser) consumeUtilityText() (string, error) {
	start := p.currentPos
	end, err := p.utilityStatementEnd()
	if err != nil {
		return "", err
	}
	text := p.renderTokenRange(start, end)
	p.seek(end)
	return text, nil
}

// seek moves the parser to token index i (EOF sentinel past the end).
func (p *Parser) seek(i int) {
	p.currentPos = i
	if i < len(p.tokens) {
		p.currentToken = p.tokens[i]
	} else {
		p.currentToken = models.TokenWithSpan{}
	}
}

// standaloneUtility lists the utility keywords that form a complete
// statement on their own (VACUUM, CHECKPOINT, T-SQL THROW in a CATCH block).
var standaloneUtility = map[string]bool{
	"VACUUM": true, "ANALYZE": true, "REINDEX": true, "CLUSTER": true,
	"CHECKPOINT": true, "THROW": true, "RETURN": true, "REVERT": true,
}

// parseVerbatimArgs is parseVerbatimStatement for a keyword that needs
// arguments unless it is listed in standaloneUtility: GRANT alone is an
// error, not a statement.
func (p *Parser) parseVerbatimArgs(kind string) (ast.Statement, bool, error) {
	if !standaloneUtility[kind] {
		switch p.peekToken().Token.Type {
		case models.TokenTypeSemicolon, models.TokenTypeEOF:
			p.advance()
			return nil, true, p.expectedError("arguments after " + kind)
		}
	}
	return p.parseVerbatimStatement(kind)
}

// parseVerbatimStatement parses the statement starting at the current token
// as a UtilityStatement of the given kind that keeps its text as written.
func (p *Parser) parseVerbatimStatement(kind string) (ast.Statement, bool, error) {
	pos := p.currentLocation()
	start := p.currentPos
	text, err := p.consumeUtilityText()
	if err != nil {
		return nil, true, err
	}
	if err := p.verbatimTailError(start, p.currentPos); err != nil {
		return nil, true, err
	}
	return &ast.UtilityStatement{Kind: kind, Text: text, Pos: pos}, true, nil
}

// parseTransactionStatement parses BEGIN / START TRANSACTION / COMMIT /
// ROLLBACK / SAVEPOINT / RELEASE / END, recording the savepoint name where
// the statement has one.
func (p *Parser) parseTransactionStatement(action string) (ast.Statement, bool, error) {
	stmt := &ast.TransactionStatement{Action: action, Pos: p.currentLocation()}
	start := p.currentPos
	end, err := p.utilityStatementEnd()
	if err != nil {
		return nil, true, err
	}
	savepointExpected := false // ROLLBACK ... TO [SAVEPOINT] name
	switch action {
	case "SAVEPOINT":
		// SAVEPOINT name | SAVE TRAN[SACTION] name
		i := start + 1
		if w := p.utilityWord(i); w == "TRAN" || w == "TRANSACTION" {
			i++
		}
		if i < end {
			stmt.Savepoint = p.tokens[i].Token.Value
		}
	case "RELEASE SAVEPOINT":
		i := start + 1
		if p.utilityWord(i) == "SAVEPOINT" {
			i++
		}
		if i < end {
			stmt.Savepoint = p.tokens[i].Token.Value
		}
	case "ROLLBACK":
		for i := start + 1; i < end; i++ {
			if p.utilityWord(i) != "TO" {
				continue
			}
			savepointExpected = true
			i++
			if p.utilityWord(i) == "SAVEPOINT" {
				i++
			}
			if i < end {
				stmt.Savepoint = p.tokens[i].Token.Value
			}
			break
		}
	}
	if stmt.Savepoint == "" && (action == "SAVEPOINT" || action == "RELEASE SAVEPOINT" || savepointExpected) {
		p.seek(end)
		return nil, true, p.expectedError("savepoint name")
	}
	stmt.Text = p.renderTokenRange(start, end)
	p.seek(end)
	return stmt, true, nil
}

// parseSetStatement parses SET [scope] name ... as a SetStatement that keeps
// its text as written. The scope and the variable name are recorded.
func (p *Parser) parseSetStatement() (ast.Statement, bool, error) {
	stmt := &ast.SetStatement{Pos: p.currentLocation()}
	start := p.currentPos
	end, err := p.utilityStatementEnd()
	if err != nil {
		return nil, true, err
	}
	i := start + 1
	switch w := p.utilityWord(i); w {
	case "GLOBAL", "SESSION", "LOCAL", "PERSIST", "PERSIST_ONLY":
		// SET SESSION = x would assign a variable named session; a scope
		// is always followed by a name.
		if i+1 < end && !isAssignmentToken(p.tokens[i+1].Token.Type) {
			stmt.Scope = w
			i++
		}
	}
	// The name is the run of adjacent tokens up to whitespace or an
	// assignment operator: search_path, @a, @@session.sql_mode, NAMES.
	if i < end && !isAssignmentToken(p.tokens[i].Token.Type) {
		j := i + 1
		for j < end && !isAssignmentToken(p.tokens[j].Token.Type) &&
			p.tokens[j].Token.Type != models.TokenTypeComma &&
			tokensAdjacent(&p.tokens[j-1], &p.tokens[j]) {
			j++
		}
		stmt.Name = p.renderTokenRange(i, j)
	}
	if stmt.Name == "" {
		p.seek(i)
		return nil, true, p.expectedError("variable name after SET")
	}
	if err := p.setValueError(stmt.Name, i, start, end); err != nil {
		return nil, true, err
	}
	stmt.Text = p.renderTokenRange(start, end)
	p.seek(end)
	return stmt, true, nil
}

// isAssignmentToken reports whether t is "=", ":=" or a compound assignment
// operator such as "+=".
func isAssignmentToken(t models.TokenType) bool {
	switch t {
	case models.TokenTypeEq, models.TokenTypeAssignment:
		return true
	}
	return false
}

// parseUseStatement parses USE [WAREHOUSE | DATABASE | SCHEMA | ROLE] name.
func (p *Parser) parseUseStatement() (ast.Statement, bool, error) {
	stmt := &ast.UseStatement{Pos: p.currentLocation()}
	start := p.currentPos
	end, err := p.utilityStatementEnd()
	if err != nil {
		return nil, true, err
	}
	i := start + 1
	if p.dialect == string(keywords.DialectSnowflake) && i+1 < end {
		switch w := p.utilityWord(i); w {
		case "WAREHOUSE", "DATABASE", "SCHEMA", "ROLE":
			stmt.ObjectKind = w
			i++
		case "SECONDARY":
			if p.utilityWord(i+1) == "ROLES" {
				stmt.ObjectKind = "SECONDARY ROLES"
				i += 2
			}
		}
	}
	if i >= end {
		p.seek(i)
		return nil, true, p.expectedError("name after USE")
	}
	p.seek(i)
	if name, err := p.parseQualifiedName(); err == nil && p.currentPos == end {
		stmt.Name = name
	} else if isQualifiedNameTooLong(err) {
		return nil, true, err
	} else {
		// Not a plain name (USE SECONDARY ROLES ALL): keep the words.
		parts := make([]string, 0, end-i)
		for ; i < end; i++ {
			parts = append(parts, p.tokens[i].Token.Value)
		}
		stmt.Name = strings.Join(parts, " ")
	}
	stmt.Text = p.renderTokenRange(start, end)
	p.seek(end)
	return stmt, true, nil
}

// parseCallStatement parses CALL name[(args)]. Arguments are parsed as
// expressions; a call whose arguments the expression parser does not accept
// (named arguments, OUT parameters in some dialects) is kept verbatim.
func (p *Parser) parseCallStatement() (ast.Statement, bool, error) {
	savedPos, savedTok := p.currentPos, p.currentToken
	if stmt, err := p.parseCallStatementStructured(); err == nil {
		return stmt, true, nil
	}
	p.currentPos, p.currentToken = savedPos, savedTok
	return p.parseVerbatimArgs("CALL")
}

func (p *Parser) parseCallStatementStructured() (*ast.CallStatement, error) {
	stmt := &ast.CallStatement{Pos: p.currentLocation()}
	p.advance() // CALL
	name, err := p.parseQualifiedName()
	if err != nil {
		return nil, err
	}
	stmt.Name = name
	if !p.isType(models.TokenTypeLParen) {
		stmt.NoParens = true
	} else {
		p.advance() // (
		for !p.isType(models.TokenTypeRParen) {
			arg, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			stmt.Arguments = append(stmt.Arguments, arg)
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance() // ,
		}
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // )
	}
	if !p.isType(models.TokenTypeSemicolon) && !p.isType(models.TokenTypeEOF) {
		return nil, p.expectedError("end of CALL statement")
	}
	return stmt, nil
}

// parseShowOrUtility parses SHOW. The forms ShowStatement models are
// returned as such; any other SHOW (SHOW VARIABLES LIKE '...', SHOW FULL
// PROCESSLIST, SHOW TABLES IN SCHEMA s, SHOW GRANTS FOR u) is kept verbatim.
func (p *Parser) parseShowOrUtility() (ast.Statement, error) {
	savedPos, savedTok := p.currentPos, p.currentToken
	boundary := p.atStatementBoundary()
	p.advance() // SHOW
	if p.showTailMissing() {
		return nil, p.expectedError("object after SHOW")
	}
	stmt, err := p.parseShowStatement()
	if err == nil && (p.isType(models.TokenTypeSemicolon) || p.isType(models.TokenTypeEOF)) {
		return stmt, nil
	}
	if isQualifiedNameTooLong(err) || !boundary {
		return stmt, err
	}
	if show, ok := stmt.(*ast.ShowStatement); ok {
		ast.PutShowStatement(show)
	}
	p.currentPos, p.currentToken = savedPos, savedTok
	s, _, err := p.parseVerbatimStatement("SHOW")
	return s, err
}

// tokensAdjacent reports whether b starts exactly where a ends in the source,
// i.e. no whitespace or comment separated them. Tokens without position
// information are never adjacent.
func tokensAdjacent(a, b *models.TokenWithSpan) bool {
	return a.End.Line != 0 && a.End == b.Start
}

// renderTokenRange rebuilds the source text of tokens [start, end): each
// token is written in source form (quotes and escapes restored for the
// current dialect) and tokens that were separated in the source are
// separated by one space.
func (p *Parser) renderTokenRange(start, end int) string {
	var sb strings.Builder
	for i := start; i < end && i < len(p.tokens); i++ {
		tok := &p.tokens[i]
		if tok.Token.Type == models.TokenTypeEOF {
			break
		}
		if i > start && p.needsSpaceBefore(&p.tokens[i-1], tok) {
			sb.WriteByte(' ')
		}
		p.writeTokenSource(&sb, tok)
	}
	return sb.String()
}

// needsSpaceBefore decides whether to separate b from the preceding token a.
// With source positions the source layout is followed; without them, a space
// is written except around punctuation that never needs one.
func (p *Parser) needsSpaceBefore(a, b *models.TokenWithSpan) bool {
	if a.End.Line != 0 && b.Start.Line != 0 {
		return a.End != b.Start
	}
	switch b.Token.Type {
	case models.TokenTypeComma, models.TokenTypeRParen, models.TokenTypePeriod,
		models.TokenTypeSemicolon, models.TokenTypeRBracket:
		return false
	}
	switch a.Token.Type {
	case models.TokenTypeLParen, models.TokenTypePeriod, models.TokenTypeLBracket:
		return false
	}
	return true
}

// writeTokenSource writes a token in source form.
func (p *Parser) writeTokenSource(sb *strings.Builder, tok *models.TokenWithSpan) {
	t := tok.Token
	switch t.Type {
	case models.TokenTypeString, models.TokenTypeSingleQuotedString:
		p.writeQuotedLiteral(sb, tok, "")
		return
	case models.TokenTypeNationalStringLiteral:
		p.writeQuotedLiteral(sb, tok, "N")
		return
	case models.TokenTypeEscapedStringLiteral:
		p.writeQuotedLiteral(sb, tok, "E")
		return
	case models.TokenTypeUnicodeStringLiteral:
		p.writeQuotedLiteral(sb, tok, "U&")
		return
	case models.TokenTypeHexStringLiteral:
		p.writeQuotedLiteral(sb, tok, "X")
		return
	case models.TokenTypeByteStringLiteral:
		p.writeQuotedLiteral(sb, tok, "B")
		return
	case models.TokenTypeTripleSingleQuotedString:
		sb.WriteString("'''")
		sb.WriteString(t.Value)
		sb.WriteString("'''")
		return
	case models.TokenTypeTripleDoubleQuotedString:
		sb.WriteString(`"""`)
		sb.WriteString(t.Value)
		sb.WriteString(`"""`)
		return
	case models.TokenTypeDollarQuotedString:
		tag := "$$"
		for n := 0; strings.Contains(t.Value, tag); n++ {
			tag = "$q" + strings.Repeat("q", n) + "$"
		}
		sb.WriteString(tag)
		sb.WriteString(t.Value)
		sb.WriteString(tag)
		return
	case models.TokenTypeDoubleQuotedString:
		writeDelimited(sb, '"', '"', t.Value)
		return
	}
	switch t.Quote {
	case '[':
		writeDelimited(sb, '[', ']', t.Value)
		return
	case '`':
		writeDelimited(sb, '`', '`', t.Value)
		return
	case '"':
		writeDelimited(sb, '"', '"', t.Value)
		return
	case '\'':
		p.writeQuotedLiteral(sb, tok, "")
		return
	}
	if t.Type == models.TokenTypeIdentifier && isQuotedSpan(tok) {
		writeDelimited(sb, '`', '`', t.Value)
		return
	}
	sb.WriteString(t.Value)
}

// writeDelimited writes v between open and close, doubling close inside.
func writeDelimited(sb *strings.Builder, open, close byte, v string) {
	sb.WriteByte(open)
	for i := 0; i < len(v); i++ {
		if v[i] == close {
			sb.WriteByte(close)
		}
		sb.WriteByte(v[i])
	}
	sb.WriteByte(close)
}

// writeQuotedLiteral writes a single-quoted string literal with an optional
// prefix (N, E, X, ...), doubling quotes and escaping backslashes when the
// tokenizer decoded backslash escapes in it (see literalHadBackslashEscapes).
func (p *Parser) writeQuotedLiteral(sb *strings.Builder, tok *models.TokenWithSpan, prefix string) {
	v := tok.Token.Value
	backslash := strings.ContainsAny(v, "\\\n\r\t\x00\x1a") && p.literalHadBackslashEscapes(tok, len(prefix))
	sb.WriteString(prefix)
	sb.WriteByte('\'')
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\'' {
			sb.WriteString("''")
			continue
		}
		if backslash {
			switch c {
			case '\\':
				sb.WriteString(`\\`)
				continue
			case '\n':
				sb.WriteString(`\n`)
				continue
			case '\r':
				sb.WriteString(`\r`)
				continue
			case '\t':
				sb.WriteString(`\t`)
				continue
			case 0:
				sb.WriteString(`\0`)
				continue
			case 0x1a:
				sb.WriteString(`\Z`)
				continue
			}
		}
		sb.WriteByte(c)
	}
	sb.WriteByte('\'')
}

// literalHadBackslashEscapes reports whether the tokenizer decodes backslash
// escapes in a string literal token. When the token sits on one line its
// source width tells directly: a literal read without escapes is exactly as
// wide as its quoted value (a decoded \n makes it narrower and keeps it on
// one line). Otherwise the dialect decides, as in the tokenizer.
func (p *Parser) literalHadBackslashEscapes(tok *models.TokenWithSpan, prefixLen int) bool {
	v := tok.Token.Value
	if tok.Start.Line != 0 && tok.Start.Line == tok.End.Line {
		width := tok.End.Column - tok.Start.Column - prefixLen - 2
		quotes := strings.Count(v, "'")
		return width != len(v)+quotes && width != utf8.RuneCountInString(v)+quotes
	}
	return p.backslashEscapes()
}

// backslashEscapes mirrors the tokenizer: MySQL, MariaDB, PostgreSQL and the
// default dialect decode backslash escapes inside string literals.
func (p *Parser) backslashEscapes() bool {
	switch p.dialect {
	case string(keywords.DialectMySQL), string(keywords.DialectMariaDB),
		string(keywords.DialectPostgreSQL), "":
		return true
	}
	return false
}

// isIdentifierAt reports whether the token at index i is an identifier
// (bare, quoted or delimited).
func (p *Parser) isIdentifierAt(i int) bool {
	if i < 0 || i >= len(p.tokens) {
		return false
	}
	switch p.tokens[i].Token.Type {
	case models.TokenTypeIdentifier, models.TokenTypeDoubleQuotedString:
		return true
	}
	return false
}

// currentIdentQuote returns the opening delimiter of the current token when
// it is a delimited identifier ('"', '`' or '['), and 0 for a bare word.
func (p *Parser) currentIdentQuote() rune {
	if p.isType(models.TokenTypeDoubleQuotedString) {
		return '"'
	}
	switch q := p.currentToken.Token.Quote; q {
	case '`', '[', '"':
		if p.isType(models.TokenTypeIdentifier) {
			return q
		}
	}
	return 0
}

// isAliasAfterAS reports whether the current token can name a select-list
// alias right after AS. Besides identifiers and the non-reserved keywords,
// any keyword spelled as a plain word is accepted (SELECT a AS share,
// AS filter, AS key, AS first, AS final): after AS nothing but a name can
// follow. Words that start a clause or a set operation are still rejected,
// so SELECT a AS FROM t keeps its error.
func (p *Parser) isAliasAfterAS() bool {
	if p.isIdentifier() || p.isNonReservedKeyword() {
		return true
	}
	t := p.currentToken.Token.Type
	if !t.IsKeyword() {
		return false
	}
	switch t {
	case models.TokenTypeFrom, models.TokenTypeWhere, models.TokenTypeGroup,
		models.TokenTypeHaving, models.TokenTypeOrder, models.TokenTypeLimit,
		models.TokenTypeOffset, models.TokenTypeFetch, models.TokenTypeUnion,
		models.TokenTypeExcept, models.TokenTypeIntersect, models.TokenTypeSelect,
		models.TokenTypeInto, models.TokenTypeOn, models.TokenTypeJoin,
		models.TokenTypeInner, models.TokenTypeLeft, models.TokenTypeRight,
		models.TokenTypeFull, models.TokenTypeCross, models.TokenTypeNatural,
		models.TokenTypeWith, models.TokenTypeAs, models.TokenTypeAnd,
		models.TokenTypeOr, models.TokenTypeNot, models.TokenTypeUsing:
		return false
	}
	v := p.currentToken.Token.Value
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c != '_' && (c|0x20 < 'a' || c|0x20 > 'z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// isKeywordColumnName reports whether the current token is a keyword that
// may be written unquoted as a column name in the current dialect
// (SELECT owner, first, key FROM t). The parser reaches it only where an
// operand starts, where none of these words has a keyword meaning: role
// options (OWNER, URL, VALID, ...) are keyword tokens only so the role and
// ALTER statements can match them, and FIRST / LAST / NEXT / FILTER /
// SHARE / SOURCE / TARGET / MATCHED / FINAL are keywords only inside their
// clauses. KEY, INDEX and VIEW are reserved in MySQL, MariaDB, SQL Server
// and Oracle, so there they must stay quoted. A word followed by '(' is not
// taken as a name, so these keywords do not become function names.
func (p *Parser) isKeywordColumnName() bool {
	switch p.currentToken.Token.Type {
	case models.TokenTypeOwner, models.TokenTypeUrl, models.TokenTypeMember,
		models.TokenTypeConnector, models.TokenTypePolicy, models.TokenTypeUntil,
		models.TokenTypeValid, models.TokenTypeDcproperties, models.TokenTypeNologin,
		models.TokenTypeNocreatedb, models.TokenTypeNocreaterole, models.TokenTypeNosuperuser,
		models.TokenTypeFirst, models.TokenTypeLast, models.TokenTypeFilter,
		models.TokenTypeShare, models.TokenTypeSource, models.TokenTypeTarget,
		models.TokenTypeMatched:
		return !p.nextIsLParen()
	case models.TokenTypeNext:
		// NEXT VALUE FOR seq is a sequence expression.
		return !p.nextIsLParen() && !strings.EqualFold(p.peekToken().Token.Value, "VALUE")
	case models.TokenTypeKey, models.TokenTypeIndex, models.TokenTypeView:
		switch p.dialect {
		case string(keywords.DialectMySQL), string(keywords.DialectMariaDB),
			string(keywords.DialectSQLServer), string(keywords.DialectOracle):
			return false
		}
		return !p.nextIsLParen()
	case models.TokenTypeKeyword:
		v := p.currentToken.Token.Value
		return (strings.EqualFold(v, "FINAL") || strings.EqualFold(v, "TEMPORARY")) && !p.nextIsLParen()
	}
	return false
}

// nextIsLParen reports whether the token after the current one is '('.
func (p *Parser) nextIsLParen() bool {
	next := p.currentPos + 1
	return next < len(p.tokens) && p.tokens[next].Token.Type == models.TokenTypeLParen
}
