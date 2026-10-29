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

// utility_txn.go checks the option grammar of the transaction statements
// (BEGIN, START TRANSACTION, COMMIT, END, ROLLBACK, ABORT, SAVEPOINT,
// RELEASE, SAVE TRAN) per dialect. The grammar is closed, so the statement
// ends where its options end: whatever follows must be a ';', the end of
// the input or the next statement, never more words of this one.

package parser

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Dialect sets of the transaction statements. A parser without a dialect
// (or "generic") accepts the forms of every dialect.
const (
	txnPostgres  = dialectPostgres | dialectRedshift
	txnStartTxn  = txnPostgres | dialectMySQLFamily | dialectSnowflake
	txnEndAbort  = txnPostgres // END and ABORT; SQLite adds END
	txnSavepoint = txnPostgres | dialectMySQLFamily | dialectOracle | dialectSQLite
)

// txnCursor walks the words of a transaction statement.
type txnCursor struct {
	p    *Parser
	i    int
	mask alterDialects
	// savepoint is the savepoint name the statement names, if any.
	savepoint string
}

// in reports whether the parser's dialect is in set.
func (c *txnCursor) in(set alterDialects) bool { return c.mask&set != 0 }

func (c *txnCursor) word() string { return c.p.utilityWord(c.i) }

// accept consumes the current word when it is w.
func (c *txnCursor) accept(w string) bool {
	if c.word() == w {
		c.i++
		return true
	}
	return false
}

// fail returns an "expected ..." error at the current word.
func (c *txnCursor) fail(expected string) error {
	c.p.seek(c.i)
	return c.p.expectedError(expected)
}

// expect consumes w or fails.
func (c *txnCursor) expect(w string) error {
	if c.accept(w) {
		return nil
	}
	return c.fail(w)
}

func (c *txnCursor) typeAt(i int) models.TokenType {
	if i < 0 || i >= len(c.p.tokens) {
		return models.TokenTypeEOF
	}
	return c.p.tokens[i].Token.Type
}

// acceptString consumes a string literal ('x', N'x').
func (c *txnCursor) acceptString() bool {
	switch c.typeAt(c.i) {
	case models.TokenTypeString, models.TokenTypeSingleQuotedString,
		models.TokenTypeNationalStringLiteral:
		c.i++
		return true
	}
	return false
}

// txnNonNames are the words that continue or end a transaction statement
// and so never name a transaction or savepoint.
var txnNonNames = map[string]bool{
	"AND": true, "TO": true, "WITH": true, "WORK": true, "TRAN": true,
	"TRANSACTION": true, "NAME": true, "CHAIN": true, "NO": true, "RELEASE": true,
	"SAVEPOINT": true, "ISOLATION": true, "READ": true, "NOT": true,
	"DEFERRABLE": true, "COMMENT": true, "WRITE": true, "FORCE": true,
	"PREPARED": true, "END": true, "ELSE": true, "ON": true, "MARK": true,
}

// tsqlMoreStatementWords are T-SQL statement words beyond implicitStartWords
// (cursor, flow-control and maintenance statements).
var tsqlMoreStatementWords = map[string]bool{
	"OPEN": true, "CLOSE": true, "FETCH": true, "DEALLOCATE": true, "GOTO": true,
	"BREAK": true, "CONTINUE": true, "SAVE": true, "REVERT": true, "BULK": true,
	"KILL": true, "CHECKPOINT": true, "RECONFIGURE": true, "SHUTDOWN": true,
	"BACKUP": true, "RESTORE": true, "RECEIVE": true, "SEND": true, "GET": true,
	"MOVE": true, "READTEXT": true, "WRITETEXT": true, "UPDATETEXT": true,
	"SETUSER": true, "ENABLE": true, "DISABLE": true, "END": true, "ELSE": true,
}

// name consumes a transaction or savepoint name: an identifier, a word that
// is not part of the statement grammar, or in SQL Server a @variable.
func (c *txnCursor) name() (string, bool) {
	if c.i >= len(c.p.tokens) {
		return "", false
	}
	tok := &c.p.tokens[c.i]
	w := c.word() // "" for a quoted name
	ok := false
	switch tok.Token.Type {
	case models.TokenTypeIdentifier, models.TokenTypeDoubleQuotedString:
		ok = w == "" || (!txnNonNames[w] && !implicitStartWords[w])
	case models.TokenTypePlaceholder:
		ok = c.in(dialectSQLServer)
	default:
		ok = w != "" && !txnNonNames[w] && !implicitStartWords[w]
	}
	if ok && c.in(dialectSQLServer) && c.p.startsLine(c.i) {
		// BEGIN TRAN <newline> OPEN c: the next statement, not a name.
		ok = !tsqlMoreStatementWords[w] && !tsqlStatementWords[w]
	}
	if !ok {
		return "", false
	}
	c.i++
	return tok.Token.Value, true
}

// savepointName consumes a required savepoint name.
func (c *txnCursor) savepointName() error {
	name, ok := c.name()
	if !ok {
		return c.fail("savepoint name")
	}
	c.savepoint = name
	return nil
}

// chain consumes [AND [NO] CHAIN].
func (c *txnCursor) chain() error {
	if !c.accept("AND") {
		return nil
	}
	c.accept("NO")
	return c.expect("CHAIN")
}

// release consumes MySQL's [[NO] RELEASE].
func (c *txnCursor) release() {
	if c.word() == "NO" && c.p.utilityWord(c.i+1) == "RELEASE" {
		c.i += 2
		return
	}
	c.accept("RELEASE")
}

// toSavepoint consumes TO [SAVEPOINT] name when TO follows.
func (c *txnCursor) toSavepoint() (bool, error) {
	if !c.accept("TO") {
		return false, nil
	}
	c.accept("SAVEPOINT")
	return true, c.savepointName()
}

// txnMode consumes one transaction mode: PostgreSQL's ISOLATION LEVEL ...,
// READ WRITE | READ ONLY, [NOT] DEFERRABLE, and (with consistent) MySQL's
// WITH CONSISTENT SNAPSHOT. It reports whether one was there.
func (c *txnCursor) txnMode(postgres, consistent bool) (bool, error) {
	switch c.word() {
	case "ISOLATION":
		if !postgres {
			return false, nil
		}
		c.i++
		if err := c.expect("LEVEL"); err != nil {
			return true, err
		}
		switch {
		case c.accept("SERIALIZABLE"):
		case c.accept("REPEATABLE"):
			return true, c.expect("READ")
		case c.accept("READ"):
			if !c.accept("COMMITTED") && !c.accept("UNCOMMITTED") {
				return true, c.fail("COMMITTED or UNCOMMITTED")
			}
		default:
			return true, c.fail("isolation level")
		}
		return true, nil
	case "READ":
		c.i++
		if !c.accept("WRITE") && !c.accept("ONLY") {
			return true, c.fail("WRITE or ONLY")
		}
		return true, nil
	case "NOT", "DEFERRABLE":
		if !postgres {
			return false, nil
		}
		c.accept("NOT")
		return true, c.expect("DEFERRABLE")
	case "WITH":
		if !consistent || c.p.utilityWord(c.i+1) != "CONSISTENT" {
			return false, nil
		}
		c.i += 2
		return true, c.expect("SNAPSHOT")
	}
	return false, nil
}

// txnModes consumes a list of transaction modes. PostgreSQL separates them
// with commas or blanks, MySQL with commas.
func (c *txnCursor) txnModes(postgres, consistent bool) error {
	ok, err := c.txnMode(postgres, consistent)
	for ok && err == nil {
		if c.typeAt(c.i) == models.TokenTypeComma {
			c.i++
			if ok, err = c.txnMode(postgres, consistent); err == nil && !ok {
				return c.fail("transaction mode")
			}
			continue
		}
		if !postgres {
			return nil
		}
		ok, err = c.txnMode(postgres, consistent)
	}
	return err
}

// snowflakeName consumes Snowflake's [NAME name].
func (c *txnCursor) snowflakeName() error {
	if !c.in(dialectSnowflake) || !c.accept("NAME") {
		return nil
	}
	if _, ok := c.name(); !ok {
		return c.fail("transaction name")
	}
	return nil
}

// begin parses the words after BEGIN.
func (c *txnCursor) begin() error {
	if c.in(dialectSQLServer) {
		// BEGIN [DISTRIBUTED] TRAN[SACTION] [name | @var [WITH MARK ['desc']]]
		distributed := c.accept("DISTRIBUTED")
		if !c.accept("TRAN") && !c.accept("TRANSACTION") {
			if c.mask == dialectSQLServer || distributed {
				return c.fail("TRANSACTION")
			}
		} else if _, ok := c.name(); ok && !distributed && c.word() == "WITH" &&
			c.p.utilityWord(c.i+1) == "MARK" {
			c.i += 2
			c.acceptString()
		}
		if c.mask == dialectSQLServer {
			return nil
		}
	}
	if c.in(dialectSQLite) {
		// BEGIN [DEFERRED | IMMEDIATE | EXCLUSIVE] [TRANSACTION]
		if c.accept("DEFERRED") || c.accept("IMMEDIATE") || c.accept("EXCLUSIVE") {
			c.accept("TRANSACTION")
			return nil
		}
	}
	if !c.in(txnPostgres|dialectSnowflake|dialectClickHouse|dialectBigQuery|dialectSQLite) ||
		!c.accept("TRANSACTION") {
		if c.in(txnPostgres | dialectMySQLFamily | dialectSnowflake) {
			c.accept("WORK")
		}
	}
	if c.in(txnPostgres) {
		if err := c.txnModes(true, c.mask == dialectAll); err != nil {
			return err
		}
	}
	return c.snowflakeName()
}

// startTransaction parses the words after START TRANSACTION.
func (c *txnCursor) startTransaction() error {
	postgres := c.in(txnPostgres)
	if postgres || c.in(dialectMySQLFamily) {
		if err := c.txnModes(postgres, c.in(dialectMySQLFamily)); err != nil {
			return err
		}
	}
	return c.snowflakeName()
}

// commit parses the words after COMMIT, or after END when end is set.
func (c *txnCursor) commit(end bool) error {
	if c.in(dialectSQLServer) && !end {
		// COMMIT [TRAN[SACTION] [name | @var]] [WITH (DELAYED_DURABILITY = ON | OFF)]
		if c.accept("TRAN") || c.accept("TRANSACTION") {
			c.name()
			if err := c.delayedDurability(); err != nil || c.mask == dialectSQLServer {
				return err
			}
		}
	}
	if c.in(txnPostgres) && !end && c.accept("PREPARED") {
		if !c.acceptString() {
			return c.fail("transaction identifier")
		}
		return nil
	}
	c.txnWord(end)
	if c.in(dialectOracle) && !end {
		if done, err := c.oracleCommit(); done || err != nil {
			return err
		}
	}
	if c.in(txnPostgres | dialectMySQLFamily) {
		if err := c.chain(); err != nil {
			return err
		}
	}
	if c.in(dialectMySQLFamily) && !end {
		c.release()
	}
	return nil
}

// txnWord consumes the optional WORK / TRANSACTION after COMMIT, END,
// ROLLBACK or ABORT, as far as the dialect has one.
func (c *txnCursor) txnWord(end bool) {
	switch {
	case c.in(txnPostgres) && (c.accept("WORK") || c.accept("TRANSACTION")):
	case c.in(dialectSQLite|dialectBigQuery) && c.accept("TRANSACTION"):
	case !end && c.in(dialectMySQLFamily|dialectOracle|dialectSnowflake|dialectSQLServer) && c.accept("WORK"):
	}
}

// delayedDurability consumes SQL Server's WITH (DELAYED_DURABILITY = ON | OFF).
func (c *txnCursor) delayedDurability() error {
	if c.word() != "WITH" || c.typeAt(c.i+1) != models.TokenTypeLParen {
		return nil
	}
	c.i += 2
	// DELAYED_DURABILITY is longer than the words utilityWord matches.
	if c.i >= len(c.p.tokens) || !strings.EqualFold(c.p.tokens[c.i].Token.Value, "DELAYED_DURABILITY") {
		return c.fail("DELAYED_DURABILITY")
	}
	c.i++
	if c.typeAt(c.i) != models.TokenTypeEq {
		return c.fail("=")
	}
	c.i++
	if !c.accept("ON") && !c.accept("OFF") {
		return c.fail("ON or OFF")
	}
	if c.typeAt(c.i) != models.TokenTypeRParen {
		return c.fail(")")
	}
	c.i++
	return nil
}

// oracleCommit consumes Oracle's [COMMENT 'text'] [WRITE [WAIT | NOWAIT]
// [IMMEDIATE | BATCH]] or FORCE 'text' [, n]. done is set when FORCE ended
// the statement.
func (c *txnCursor) oracleCommit() (done bool, err error) {
	if c.accept("FORCE") {
		return true, c.oracleForce()
	}
	if c.accept("COMMENT") && !c.acceptString() {
		return true, c.fail("comment text")
	}
	if c.accept("WRITE") {
		_ = c.accept("WAIT") || c.accept("NOWAIT")
		_ = c.accept("IMMEDIATE") || c.accept("BATCH")
	}
	return false, nil
}

// oracleForce consumes the 'text' [, n] after Oracle's FORCE.
func (c *txnCursor) oracleForce() error {
	if !c.acceptString() {
		return c.fail("transaction identifier")
	}
	if c.typeAt(c.i) == models.TokenTypeComma && c.typeAt(c.i+1) == models.TokenTypeNumber {
		c.i += 2
	}
	return nil
}

// rollback parses the words after ROLLBACK, or after ABORT when abort is set.
func (c *txnCursor) rollback(abort bool) error {
	if c.in(dialectSQLServer) && !abort {
		// ROLLBACK [TRAN[SACTION] [name | @var]]
		if c.accept("TRAN") || c.accept("TRANSACTION") {
			c.name()
			if c.mask == dialectSQLServer {
				return nil
			}
		}
	}
	if c.in(txnPostgres) && !abort && c.accept("PREPARED") {
		if !c.acceptString() {
			return c.fail("transaction identifier")
		}
		return nil
	}
	c.txnWord(false)
	if !abort && c.in(txnSavepoint) {
		if to, err := c.toSavepoint(); to || err != nil {
			return err
		}
	}
	if c.in(dialectOracle) && !abort && c.accept("FORCE") {
		return c.oracleForce()
	}
	if c.in(txnPostgres | dialectMySQLFamily) {
		if err := c.chain(); err != nil {
			return err
		}
	}
	if c.in(dialectMySQLFamily) && !abort {
		c.release()
	}
	return nil
}

// transactionEnd checks the grammar of the transaction statement starting at
// token index start and returns the index of the token after it and the
// savepoint it names. ok is false when the statement does not exist in the
// parser's dialect (SAVEPOINT in Snowflake, START TRANSACTION in Oracle).
func (p *Parser) transactionEnd(start int) (end int, savepoint string, ok bool, err error) {
	c := txnCursor{p: p, i: start + 1, mask: p.alterMask()}
	switch p.utilityWord(start) {
	case "BEGIN":
		err = c.begin()
	case "START":
		if !c.in(txnStartTxn) {
			return 0, "", false, nil
		}
		c.i++ // TRANSACTION
		err = c.startTransaction()
	case "COMMIT":
		err = c.commit(false)
	case "END":
		if !c.in(txnEndAbort | dialectSQLite) {
			return 0, "", false, nil
		}
		err = c.commit(true)
	case "ROLLBACK":
		err = c.rollback(false)
	case "ABORT":
		if !c.in(txnEndAbort) {
			return 0, "", false, nil
		}
		err = c.rollback(true)
	case "SAVEPOINT":
		if !c.in(txnSavepoint) {
			return 0, "", false, nil
		}
		err = c.savepointName()
	case "SAVE":
		// SAVE TRAN[SACTION] name | @var (SQL Server)
		c.i++
		err = c.savepointName()
	case "RELEASE":
		if !c.in(txnSavepoint &^ dialectOracle) {
			return 0, "", false, nil
		}
		if !c.accept("SAVEPOINT") && c.mask&^dialectMySQLFamily == 0 {
			return 0, "", true, c.fail("SAVEPOINT")
		}
		err = c.savepointName()
	default:
		return 0, "", false, nil
	}
	if err != nil {
		return 0, "", true, err
	}
	return c.i, c.savepoint, true, nil
}

// transactionTailError checks what follows a transaction statement that
// ends before token index end: a ';', the end of the input, or the next
// statement. In SQL Server that is a statement-starting word (or a GO line,
// or the ELSE of an IF); elsewhere statements are separated by ';', and
// only a statement on a line of its own may follow without one. The next
// statement is marked as starting at a statement boundary.
func (p *Parser) transactionTailError(end int) error {
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
	} else if p.startsLine(end) {
		p.markImplicitEnd(end)
		return nil
	}
	p.seek(end)
	return p.expectedError("end of statement")
}
