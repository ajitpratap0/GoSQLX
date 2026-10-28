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

// statement_boundary.go decides where a statement that is not followed by
// ';' ends in scripts written without semicolons. T-SQL never needs ';'
// between statements and separates batches with a GO line, so a COMMIT,
// SET or PRINT that follows an UPDATE starts a new statement. Other dialects
// accept only starts that cannot continue any statement (COMMIT, ROLLBACK,
// START TRANSACTION, ...). Anything else that follows a statement without a
// ';' stays an error ("SELECT 1 FROM t garbage garbage2").

package parser

import (
	"github.com/ajitpratap0/GoSQLX/internal/batch"
	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// batchSeparatorEnd reports whether the token at index i is a T-SQL batch
// separator: the word GO alone on its line, optionally followed by a repeat
// count (GO 5). It returns the index of the first token after the
// separator. Tokens without source positions never form a separator.
func (p *Parser) batchSeparatorEnd(i int) (int, bool) {
	if !p.IsSQLServer() {
		return 0, false
	}
	return batch.End(p.tokens, i)
}

// parseBatchSeparator retains a GO line and marks the next statement boundary.
func (p *Parser) parseBatchSeparator() (*ast.BatchSeparator, bool) {
	if !p.IsSQLServer() {
		return nil, false // batchSeparatorEnd is SQL Server only
	}
	return p.parseBatchSeparatorAt()
}

// parseBatchSeparatorAt is parseBatchSeparator in the SQL Server dialect.
func (p *Parser) parseBatchSeparatorAt() (*ast.BatchSeparator, bool) {
	next, ok := p.batchSeparatorEnd(p.currentPos)
	if !ok {
		return nil, false
	}
	sep := &ast.BatchSeparator{Pos: p.currentLocation()}
	if next > p.currentPos+1 {
		sep.RepeatCount, _ = batch.Count(p.tokens[p.currentPos+1].Token.Value) // validated by batch.End
	}
	p.seek(next)
	p.markImplicitEnd(next)
	return sep, true
}

// batchLineError checks, in SQL Server, the tokens a statement starting at
// token index start ran over (up to the current token when parseErr is set,
// since the statement parser stopped there) for a line holding only GO [n].
// sqlcmd ends the batch at such a line wherever it appears, so a statement
// that runs across it is an error; GO with an invalid repeat count (GO 0,
// GO 1.5) gets an error of its own. It returns parseErr when there is no
// such line, otherwise the index of the GO token and the GO error.
func (p *Parser) batchLineError(start int, parseErr error) (int, error) {
	if !p.IsSQLServer() {
		return -1, parseErr
	}
	last := p.currentPos - 1
	if parseErr != nil {
		last = p.currentPos
	}
	if last >= len(p.tokens) {
		last = len(p.tokens) - 1
	}
	for i := start; i <= last; i++ {
		if t := &p.tokens[i].Token; t.Type != models.TokenTypeIdentifier || len(t.Value) != 2 {
			continue
		}
		if _, valid, ok := batch.Line(p.tokens, i); ok {
			loc := p.tokens[i].Start
			if !valid {
				return i, goerrors.InvalidSyntaxError("invalid GO repeat count: GO takes a positive whole number", loc, "")
			}
			return i, goerrors.InvalidSyntaxError("GO batch separator inside a statement: a line holding only GO ends the batch", loc, "")
		}
	}
	return -1, parseErr
}

// noteStatementEnd is called by the statement loops after a statement was
// parsed. When no ';' follows and the next token unambiguously starts a new
// statement, that token is marked as a statement boundary so that utility
// statements (COMMIT, SET, PRINT, ...) are accepted there.
func (p *Parser) noteStatementEnd() {
	if p.isType(models.TokenTypeSemicolon) || p.isType(models.TokenTypeEOF) {
		return
	}
	if p.implicitStartAt(p.currentPos) {
		p.markImplicitEnd(p.currentPos)
	}
}

// implicitStartAt reports whether the token at index i, which directly
// follows a complete statement, begins the next statement although no ';'
// separates them.
func (p *Parser) implicitStartAt(i int) bool {
	if i <= 0 || i >= len(p.tokens) || p.tokens[i-1].Token.Type == models.TokenTypePeriod {
		return false
	}
	if p.IsSQLServer() {
		if _, ok := p.batchSeparatorEnd(i); ok {
			return true
		}
		word := p.utilityWord(i)
		if !implicitStartWords[word] || !p.startsNewStatement(i, i-1) {
			return false
		}
		if word == "SET" {
			// SET @v = ..., SET NOCOUNT ON; not SET (...) of an ALTER the
			// statement parser stopped short in.
			next := i + 1
			return next < len(p.tokens) && (p.isTableVariableAt(next) ||
				p.tokens[next].Token.Type == models.TokenTypePlaceholder ||
				p.utilityWord(next) != "")
		}
		return true
	}
	// Elsewhere scripts separate statements with ';'; accept only a
	// transaction statement written at the start of its own line. This is
	// reached only where the statement could not take the word: COMMIT and
	// ROLLBACK are non-reserved in every dialect but SQL Server, so where
	// the grammar allows an implicit alias ("SELECT 1\nCOMMIT", "SELECT a
	// FROM t\nrollback") the statement parser has already read the word as
	// the alias, exactly as the database does (PostgreSQL, MySQL, MariaDB,
	// SQLite, Oracle, Snowflake and ClickHouse all accept SELECT 1 commit).
	// After a clause that takes no alias ("... WHERE x = 1\nCOMMIT", "SELECT
	// a AS x\nCOMMIT") it starts the next statement here. END is reserved
	// in PostgreSQL, so there "SELECT 1\nEND" always ends the transaction.
	if prev, cur := &p.tokens[i-1], &p.tokens[i]; cur.Start.Line == 0 || prev.End.Line >= cur.Start.Line {
		return false
	}
	switch p.utilityWord(i) {
	case "COMMIT", "ROLLBACK", "SAVEPOINT":
		return true
	case "END", "ABORT", "RELEASE":
		// END [TRANSACTION] (PostgreSQL, SQLite), ABORT, RELEASE SAVEPOINT.
		return p.isTransactionStartAt(i)
	case "START":
		return p.utilityWord(i+1) == "TRANSACTION"
	case "BEGIN":
		switch p.utilityWord(i + 1) {
		case "TRANSACTION", "WORK":
			return !p.beginIsBlock(p.utilityWord(i + 1))
		}
	}
	return false
}

// statementMayEndAt reports whether a statement may end before the token at
// index i although no ';' follows it: the next statement starts there (see
// implicitStartAt), or in SQL Server the ELSE of an IF whose first branch the
// statement is (IF @x = 1 SELECT 1 ELSE SELECT 2).
func (p *Parser) statementMayEndAt(i int) bool {
	return p.implicitStartAt(i) || (p.IsSQLServer() && p.utilityWord(i) == "ELSE")
}

// tsqlStatementWords are T-SQL reserved words that begin a statement. In
// SQL Server they are never an implicit alias, so "SELECT a FROM t PRINT 'x'"
// is two statements rather than a table aliased print.
var tsqlStatementWords = map[string]bool{
	"PRINT": true, "EXEC": true, "EXECUTE": true, "COMMIT": true, "ROLLBACK": true,
	"SAVE": true, "RAISERROR": true, "WAITFOR": true, "DBCC": true, "DECLARE": true,
	"SET": true, "IF": true, "WHILE": true, "BEGIN": true, "END": true, "ELSE": true,
	"RETURN": true, "USE": true, "GRANT": true, "REVOKE": true, "DENY": true,
	"GOTO": true, "BREAK": true, "CONTINUE": true, "TRUNCATE": true, "MERGE": true,
	"INSERT": true, "UPDATE": true, "DELETE": true, "SELECT": true, "CREATE": true,
	"ALTER": true, "DROP": true,
}

// isTSQLStatementStart reports whether the current token is a T-SQL word
// that begins a statement (or a GO line), which must not be read as an
// implicit alias.
func (p *Parser) isTSQLStatementStart() bool {
	return p.IsSQLServer() && p.isTSQLStatementStartAt()
}

// isTSQLStatementStartAt is isTSQLStatementStart in the SQL Server dialect.
func (p *Parser) isTSQLStatementStartAt() bool {
	if tsqlStatementWords[p.utilityWord(p.currentPos)] {
		return true
	}
	_, ok := p.batchSeparatorEnd(p.currentPos)
	return ok
}

// isTableVariableAt reports whether the token at index i is a T-SQL table
// variable (@name, not a @@ system function) in the SQL Server dialect.
func (p *Parser) isTableVariableAt(i int) bool {
	if !p.IsSQLServer() || i < 0 || i >= len(p.tokens) ||
		p.tokens[i].Token.Type != models.TokenTypePlaceholder {
		return false
	}
	v := p.tokens[i].Token.Value
	return len(v) > 1 && v[0] == '@' && v[1] != '@'
}

// parseTableNameQuoted parses the name of a table in a FROM item or a DML
// target: a possibly qualified name, or in SQL Server a table variable
// (FROM @t, INSERT INTO @t, UPDATE @t, MERGE @t).
func (p *Parser) parseTableNameQuoted() (string, ast.NameQuote, error) {
	if p.isType(models.TokenTypePlaceholder) && p.isTableVariableAt(p.currentPos) {
		name := p.currentToken.Token.Value
		p.advance()
		return name, 0, nil
	}
	return p.parseQualifiedNameQuoted()
}
