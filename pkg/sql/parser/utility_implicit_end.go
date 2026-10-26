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

// utility_implicit_end.go ends a verbatim utility statement at the word that
// starts the next statement. T-SQL does not need ';' between statements, so
// "SET NOCOUNT ON SELECT * FROM t" is two statements; without this the
// SELECT would be swallowed into the text of the SET and never be parsed,
// linted or scanned. Other dialects separate statements with ';', but a
// statement on the next line must not vanish into the text of one without
// it either: it ends the verbatim statement there and is reported (see
// lineEndPolicy).

package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// implicitEndLeaders lists the SQL Server utility statements that end at the
// next statement-starting word when no ';' separates them. Each takes a
// short, closed argument list (a setting, a name, an expression) that never
// contains a bare statement keyword at the top level, so such a word begins
// the next statement. Statements that own a nested body have policies of
// their own (see implicitEndPolicy and parseTSQLConditional), as do GRANT /
// REVOKE / DENY, whose permission lists contain SELECT, INSERT and the like;
// BULK INSERT runs to the next ';'. Transaction statements end with their
// grammar (see transactionEnd).
var implicitEndLeaders = map[string]bool{
	"SET": true, "USE": true,
	"PRINT": true, "EXEC": true, "EXECUTE": true, "THROW": true, "RAISERROR": true,
	"WAITFOR": true, "DBCC": true, "DECLARE": true, "RETURN": true,
}

// implicitStartWords lists the words that begin a statement in T-SQL.
var implicitStartWords = map[string]bool{
	"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true, "MERGE": true,
	"WITH": true, "CREATE": true, "ALTER": true, "DROP": true, "TRUNCATE": true,
	"DECLARE": true, "SET": true, "EXEC": true, "EXECUTE": true, "IF": true,
	"WHILE": true, "BEGIN": true, "PRINT": true, "THROW": true, "RAISERROR": true,
	"WAITFOR": true, "RETURN": true, "USE": true, "DBCC": true, "COMMIT": true,
	"ROLLBACK": true, "GRANT": true, "REVOKE": true, "DENY": true,
}

// implicitPolicy says where a statement kept verbatim may end without a ';'.
type implicitPolicy uint8

const (
	// implicitNone: only ';', the end of input or a GO line end it.
	implicitNone implicitPolicy = iota
	// implicitLeader: a statement in implicitEndLeaders, which ends at the
	// next statement-starting word.
	implicitLeader
	// implicitDDL: a CREATE / ALTER / DROP of an object other than a
	// routine, view or schema. Words that also occur inside such statements
	// (SET, DROP MEMBER, IF EXISTS, AFTER INSERT) only end it where they
	// clearly start a statement (see startsNewDDLStatement).
	implicitDDL
	// implicitSchema: CREATE SCHEMA, like implicitDDL except that its schema
	// elements (CREATE TABLE / VIEW, GRANT, REVOKE, DENY) belong to it.
	implicitSchema
	// implicitAfterBlock: a T-SQL BEGIN ... END block, or an IF or WHILE
	// whose body parseTSQLConditional could not delimit. It may
	// end at the next statement-starting word once a BEGIN ... END block
	// closed at its top level and no ELSE or BEGIN CATCH continues it.
	implicitAfterBlock
	// implicitGrant: GRANT / REVOKE / DENY, whose permission list may name
	// SELECT, INSERT, EXECUTE and the like. It ends at the next
	// statement-starting word once its TO / FROM principal list began.
	implicitGrant
	// implicitLine: outside SQL Server, a utility statement with a closed
	// argument list (SET, USE, CALL, COPY, VACUUM, ...). A word that starts
	// a statement at the start of a line ends it; since these dialects
	// separate statements with ';', the next statement is an error unless
	// it is a transaction statement (see lineStatementEnd).
	implicitLine
	// implicitLineGrant: GRANT / REVOKE outside SQL Server, which ends like
	// implicitLine once its TO / FROM principal list began.
	implicitLineGrant
	// implicitLineDDL: outside SQL Server, a CREATE / ALTER / DROP of an
	// object whose definition holds no statement (a role, a sequence, an
	// extension, ...), which ends like implicitLine at the words of
	// startsNewLineDDL.
	implicitLineDDL
	// implicitLineSchema: CREATE SCHEMA outside SQL Server, like
	// implicitLineDDL except that its schema elements belong to it.
	implicitLineSchema
)

// tsqlRoutineObjects are the objects whose CREATE / ALTER body runs to the
// end of the batch in T-SQL: a following statement belongs to the body.
var tsqlRoutineObjects = map[string]bool{
	"PROCEDURE": true, "PROC": true, "FUNCTION": true, "TRIGGER": true, "VIEW": true,
}

// implicitEndPolicy returns the implicitPolicy of the statement starting at
// token index start.
func (p *Parser) implicitEndPolicy(start int) implicitPolicy {
	if !p.IsSQLServer() {
		return p.lineEndPolicy(start)
	}
	word := p.utilityWord(start)
	switch word {
	case "BEGIN":
		if p.beginIsBlock(p.utilityWord(start + 1)) {
			return implicitAfterBlock
		}
		return implicitNone
	case "IF", "WHILE":
		return implicitAfterBlock
	case "CREATE", "ALTER", "DROP":
		obj := start + 1
		if word == "CREATE" && p.utilityWord(obj) == "OR" {
			obj += 2 // CREATE OR ALTER
		}
		switch w := p.utilityWord(obj); {
		case tsqlRoutineObjects[w]:
			return implicitNone
		case w == "SCHEMA" && word == "CREATE":
			return implicitSchema
		}
		return implicitDDL
	case "GRANT", "REVOKE", "DENY":
		return implicitGrant
	}
	if implicitEndLeaders[word] {
		return implicitLeader
	}
	return implicitNone
}

// implicitEndAt reports whether the statement that began at token index
// start, under policy, ends before the token at index i (which is at the
// top level of the statement: outside parentheses and blocks). grantee is
// set once the principal list of an implicitGrant statement began.
func (p *Parser) implicitEndAt(i, start int, policy implicitPolicy, blk *blockScan, grantee bool) bool {
	switch policy {
	case implicitLeader:
		return p.startsNewStatement(i, start)
	case implicitGrant:
		return grantee && p.startsNewStatement(i, start)
	case implicitLine:
		if p.startsNewLineStatement(i, start) {
			return true
		}
		// SET and USE take a value or a name and nothing that looks
		// like a statement, so one also follows them on the same line.
		switch p.utilityWord(start) {
		case "SET", "USE":
			// Not SET itself (MySQL's SET CHARACTER SET utf8) nor a
			// transaction word (Oracle's SET TRANSACTION USE ROLLBACK
			// SEGMENT s).
			w := p.utilityWord(i)
			_, statement := lineStatementWords[w]
			return statement && w != "SET" && !p.startsLine(i) && p.startsNewStatementAnywhere(i)
		}
		return false
	case implicitLineGrant:
		return grantee && p.startsNewLineStatement(i, start)
	case implicitLineDDL:
		return p.startsNewLineDDL(i, start, false)
	case implicitLineSchema:
		return p.startsNewLineDDL(i, start, true)
	case implicitDDL:
		return p.startsNewDDLStatement(i, start, false)
	case implicitSchema:
		return p.startsNewDDLStatement(i, start, true)
	case implicitAfterBlock:
		if !blk.closed {
			return false
		}
		if p.utilityWord(i) == "BEGIN" && p.utilityWord(i+1) == "CATCH" {
			return false
		}
		return p.startsNewStatement(i, start)
	}
	return false
}

// tsqlDDLObjects are the words after CREATE / ALTER / DROP that make it the
// start of a new DDL statement inside the text of another one; any other
// word (ALTER ROLE r DROP MEMBER u) continues the current statement.
var tsqlDDLObjects = map[string]bool{
	"TABLE": true, "VIEW": true, "INDEX": true, "PROCEDURE": true, "PROC": true,
	"FUNCTION": true, "TRIGGER": true, "SCHEMA": true, "DATABASE": true,
	"USER": true, "ROLE": true, "LOGIN": true, "TYPE": true, "SEQUENCE": true,
	"SYNONYM": true, "STATISTICS": true, "UNIQUE": true, "CLUSTERED": true,
	"NONCLUSTERED": true, "COLUMNSTORE": true, "OR": true, "PARTITION": true,
	"ASSEMBLY": true, "CERTIFICATE": true, "CREDENTIAL": true, "FULLTEXT": true,
	"XML": true, "SPATIAL": true, "DEFAULT": true, "RULE": true, "QUEUE": true,
	"SERVICE": true, "EXTERNAL": true, "SECURITY": true, "MASTER": true,
	"SYMMETRIC": true, "ASYMMETRIC": true, "APPLICATION": true, "EVENT": true,
	"AGGREGATE": true,
}

// startsNewDDLStatement is startsNewStatement for the text of a T-SQL DDL
// statement kept verbatim. schema is set for CREATE SCHEMA, whose schema
// elements continue it.
func (p *Parser) startsNewDDLStatement(i, start int, schema bool) bool {
	if !p.startsNewStatement(i, start) {
		return false
	}
	switch p.utilityWord(i - 1) {
	case "AFTER", "BEFORE", "OF":
		// ADD BLOCK PREDICATE ... AFTER INSERT, INSTEAD OF UPDATE.
		return false
	}
	switch word := p.utilityWord(i); word {
	case "SET":
		// ALTER DATABASE d SET RECOVERY SIMPLE: only a variable
		// assignment certainly starts a statement.
		return i+1 < len(p.tokens) && p.tokens[i+1].Token.Type == models.TokenTypePlaceholder
	case "CREATE", "ALTER", "DROP":
		obj := p.utilityWord(i + 1)
		if schema && word == "CREATE" && (obj == "TABLE" || obj == "VIEW") {
			return false
		}
		return tsqlDDLObjects[obj]
	case "GRANT", "REVOKE", "DENY":
		return !schema
	}
	return true
}

// startsNewStatement reports whether the token at index i, at the top level
// of a utility statement that began at start, begins the next statement
// rather than continuing this one.
func (p *Parser) startsNewStatement(i, start int) bool {
	if i <= start {
		return false
	}
	word := p.utilityWord(i)
	if word == "" || !implicitStartWords[word] {
		return false
	}
	return p.startsStatementInContext(i, word)
}

// startsStatementInContext reports whether word, a statement-starting word
// at token index i of a utility statement, begins the next statement given
// the tokens around it: t.update, UNION SELECT, CURSOR FOR SELECT, DROP
// TABLE IF EXISTS and WITH NOWAIT continue the current one.
func (p *Parser) startsStatementInContext(i int, word string) bool {
	prev := &p.tokens[i-1]
	switch prev.Token.Type {
	case models.TokenTypePeriod, models.TokenTypeEq, models.TokenTypeAssignment:
		// t.update, SET @x = select-like word: a name, not a keyword.
		return false
	}
	switch p.utilityWord(i - 1) {
	case "ALL", "DISTINCT":
		// UNION ALL SELECT; NOCHECK CONSTRAINT ALL ends an ALTER TABLE.
		if word == "SELECT" || word == "WITH" {
			return false
		}
	case "FOR", "AS", "UNION", "EXCEPT", "INTERSECT", "WITH":
		// DECLARE c CURSOR FOR SELECT ..., CURSOR FOR UPDATE, and the
		// set-operation operands of a cursor query (... UNION [ALL]
		// SELECT ...), and WITH GRANT OPTION: the word continues the
		// statement.
		return false
	}
	if word == "IF" {
		// DROP TABLE IF EXISTS t, CREATE ... IF NOT EXISTS: a clause of the
		// statement. The IF statement tests EXISTS (subquery).
		j := i + 1
		if p.utilityWord(j) == "NOT" {
			j++
		}
		if p.utilityWord(j) == "EXISTS" {
			return j+1 < len(p.tokens) && p.tokens[j+1].Token.Type == models.TokenTypeLParen
		}
	}
	if word == "WITH" {
		// A statement-starting WITH opens a CTE (WITH name [(cols)] AS) or
		// WITH XMLNAMESPACES (...); WITH MARK, WITH NOWAIT, WITH RECOMPILE,
		// WITH (DELAYED_DURABILITY = ON) and WITH RESULT SETS (...) are
		// trailing options of the current statement.
		next := p.utilityWord(i + 1)
		switch next {
		case "":
			return false
		case "XMLNAMESPACES", "RECURSIVE":
			return true
		}
		if i+2 >= len(p.tokens) {
			return false
		}
		switch p.tokens[i+2].Token.Type {
		case models.TokenTypeAs, models.TokenTypeLParen:
			return true
		}
		return p.utilityWord(i+2) == "AS"
	}
	return true
}

// markImplicitEnd records that the statement ending at token index end was
// closed by the start of the next one, so that the next statement counts as
// being at a statement boundary (see atStatementBoundary).
func (p *Parser) markImplicitEnd(end int) {
	p.implicitEnd = end + 1
}

// isTransactionStartAt reports whether the token at index i begins a
// transaction statement of the parser's dialect.
func (p *Parser) isTransactionStartAt(i int) bool {
	m := p.alterMask()
	switch p.utilityWord(i) {
	case "COMMIT", "ROLLBACK":
		return true
	case "SAVEPOINT":
		return m&txnSavepoint != 0
	case "RELEASE":
		return m&(txnSavepoint&^dialectOracle) != 0
	case "ABORT":
		return m&txnEndAbort != 0
	case "END":
		return m&(txnEndAbort|dialectSQLite) != 0
	case "START":
		return m&txnStartTxn != 0 && p.utilityWord(i+1) == "TRANSACTION"
	case "BEGIN":
		return !p.beginIsBlock(p.utilityWord(i + 1))
	}
	return false
}

// startsLine reports whether the token at index i is the first token on its
// source line. Tokens without positions never do.
func (p *Parser) startsLine(i int) bool {
	if i <= 0 || i >= len(p.tokens) {
		return false
	}
	cur := p.tokens[i].Start.Line
	return cur != 0 && p.tokens[i-1].End.Line < cur
}

// lineEndLeaders lists the utility statements outside SQL Server whose
// arguments never hold a statement, so that a statement-starting word at
// the start of a line follows them rather than belongs to them.
// Statements with a nested query or body (PREPARE ... AS, DECLARE ... CURSOR
// FOR, CREATE FUNCTION, LOAD DATA ... SET) run to the next ';'.
var lineEndLeaders = map[string]bool{
	"SET": true, "USE": true, "CALL": true, "COPY": true, "VACUUM": true,
	"ANALYZE": true, "LOCK": true, "UNLOCK": true, "DO": true, "KILL": true,
	"FLUSH": true, "OPTIMIZE": true, "CHECK": true, "REPAIR": true,
	"CHECKSUM": true, "LISTEN": true, "NOTIFY": true, "UNLISTEN": true,
	"DEALLOCATE": true, "RENAME": true, "REINDEX": true, "CLUSTER": true,
	"CHECKPOINT": true, "DISCARD": true, "RESET": true, "XA": true,
	"BACKUP": true, "PURGE": true, "UNDROP": true, "EXCHANGE": true,
	"SYSTEM": true, "ATTACH": true, "DETACH": true, "HANDLER": true,
	"INSTALL": true, "UNINSTALL": true, "COMMENT": true, "SHOW": true,
	"TABLE": true, "EXISTS": true, "EXECUTE": true, "PUT": true, "GET": true,
	"LIST": true, "REMOVE": true, "LS": true, "FLASHBACK": true,
}

// lineClosedObjects lists the objects of CREATE / ALTER statements kept
// verbatim whose definition holds no statement (unlike a function, view,
// trigger, event, rule or task).
var lineClosedObjects = map[string]bool{
	"DATABASE": true, "EXTENSION": true, "TYPE": true, "DOMAIN": true,
	"ROLE": true, "USER": true, "SEQUENCE": true, "SYNONYM": true,
	"TABLESPACE": true, "COLLATION": true, "CONVERSION": true, "SERVER": true,
	"PUBLICATION": true, "SUBSCRIPTION": true, "STAGE": true, "WAREHOUSE": true,
	"TAG": true, "LOGIN": true, "DIRECTORY": true, "PROFILE": true,
	"QUOTA": true, "SETTINGS": true, "NETWORK": true, "INTEGRATION": true,
	"SHARE": true, "SECRET": true, "RESOURCE": true, "CATALOG": true,
	"CONTEXT": true, "LIBRARY": true, "CERTIFICATE": true, "CREDENTIAL": true,
	"FILE": true, "POLICY": true, "ROW": true, "STATISTICS": true,
	"ACCESS": true, "TEXT": true, "FOREIGN": true, "NAMED": true,
	"MASKING": true, "INDEX": true, "SESSION": true, "SYSTEM": true,
	"ACCOUNT": true, "PLUGGABLE": true, "STREAM": true, "SCHEMA": true,
}

// lineEndPolicy is implicitEndPolicy outside SQL Server.
func (p *Parser) lineEndPolicy(start int) implicitPolicy {
	switch word := p.utilityWord(start); word {
	case "GRANT", "REVOKE":
		return implicitLineGrant
	case "DROP":
		return implicitLineDDL
	case "CREATE", "ALTER":
		obj := start + 1
		if word == "CREATE" {
			for n := 0; n < 6 && createModifierWords[p.utilityWord(obj)]; n++ {
				obj++
			}
		}
		switch w := p.utilityWord(obj); {
		case w == "SCHEMA" && word == "CREATE":
			return implicitLineSchema
		case lineClosedObjects[w]:
			return implicitLineDDL
		}
		return implicitNone
	default:
		if lineEndLeaders[word] {
			return implicitLine
		}
	}
	return implicitNone
}

// lineStatementWords lists, per word, the dialects other than SQL Server in
// which it begins a statement. Transaction words are decided by
// isTransactionStartAt.
var lineStatementWords = map[string]alterDialects{
	"SELECT": dialectAll, "INSERT": dialectAll, "UPDATE": dialectAll,
	"DELETE": dialectAll, "MERGE": dialectAll, "WITH": dialectAll,
	"CREATE": dialectAll, "ALTER": dialectAll, "DROP": dialectAll,
	"TRUNCATE": dialectAll, "VALUES": dialectAll, "EXPLAIN": dialectAll,
	"SET": dialectAll, "GRANT": dialectAll, "REVOKE": dialectAll,
	"CALL": dialectAll, "SHOW": dialectAll, "DESCRIBE": dialectAll,
	"COMMENT": dialectAll, "PREPARE": dialectAll, "EXECUTE": dialectAll,
	"DEALLOCATE": dialectAll, "DECLARE": dialectAll, "ANALYZE": dialectAll,
	"USE":     dialectMySQLFamily | dialectSnowflake | dialectClickHouse | dialectBigQuery,
	"TABLE":   txnPostgres | dialectMySQLFamily,
	"COPY":    txnPostgres | dialectSnowflake,
	"VACUUM":  txnPostgres | dialectSQLite,
	"LOCK":    txnPostgres | dialectMySQLFamily | dialectOracle,
	"UNLOCK":  dialectMySQLFamily,
	"DO":      txnPostgres | dialectMySQLFamily,
	"REFRESH": txnPostgres,
	"REINDEX": txnPostgres | dialectSQLite, "CLUSTER": txnPostgres,
	"CHECKPOINT": txnPostgres, "DISCARD": txnPostgres, "RESET": txnPostgres,
	"LISTEN": txnPostgres, "NOTIFY": txnPostgres, "UNLISTEN": txnPostgres,
	"REPLACE":  dialectMySQLFamily | dialectSQLite,
	"PRAGMA":   dialectSQLite,
	"ATTACH":   dialectSQLite | dialectClickHouse,
	"DETACH":   dialectSQLite | dialectClickHouse,
	"OPTIMIZE": dialectMySQLFamily | dialectClickHouse,
	"KILL":     dialectMySQLFamily | dialectClickHouse,
	"FLUSH":    dialectMySQLFamily, "RENAME": dialectMySQLFamily | dialectClickHouse,
	"SYSTEM": dialectClickHouse, "UNDROP": dialectSnowflake,
	"PUT": dialectSnowflake, "GET": dialectSnowflake, "LIST": dialectSnowflake,
	"REMOVE": dialectSnowflake,
}

// startsNewLineStatement reports whether the token at index i, at the top
// level of a utility statement that began at start, begins the next
// statement outside SQL Server: a statement-starting word of the dialect
// at the start of a line.
func (p *Parser) startsNewLineStatement(i, start int) bool {
	if i <= start || !p.startsLine(i) {
		return false
	}
	return p.startsNewStatementAnywhere(i)
}

// startsNewStatementAnywhere is startsNewLineStatement without the
// requirement that the word starts a line.
func (p *Parser) startsNewStatementAnywhere(i int) bool {
	word := p.utilityWord(i)
	if word == "" {
		return false
	}
	if m, ok := lineStatementWords[word]; ok {
		if m&p.alterMask() == 0 {
			return false
		}
		switch word {
		case "REPLACE", "INSERT", "TRUNCATE":
			// REPLACE(s, a, b), MySQL's INSERT(s, pos, n, t) and
			// TRUNCATE(x, d) are functions.
			if i+1 < len(p.tokens) && p.tokens[i+1].Token.Type == models.TokenTypeLParen {
				return false
			}
		case "COMMENT":
			return p.utilityWord(i+1) == "ON"
		case "TABLE":
			return p.isIdentifierAt(i + 1)
		}
	} else if !p.isTransactionStartAt(i) {
		return false
	}
	return p.startsStatementInContext(i, word)
}

// lineDDLObjects are the words after CREATE / ALTER / DROP that make it the
// start of a new statement inside the text of a DDL statement outside SQL
// Server; any other word (ALTER DOMAIN d DROP CONSTRAINT c) continues it.
var lineDDLObjects = map[string]bool{
	"TABLE": true, "VIEW": true, "INDEX": true, "SCHEMA": true, "DATABASE": true,
	"USER": true, "ROLE": true, "SEQUENCE": true, "TYPE": true, "FUNCTION": true,
	"PROCEDURE": true, "TRIGGER": true, "EXTENSION": true, "MATERIALIZED": true,
	"UNIQUE": true, "OR": true, "TEMP": true, "TEMPORARY": true, "DOMAIN": true,
	"POLICY": true, "TABLESPACE": true, "WAREHOUSE": true, "STAGE": true,
	"STREAM": true, "TASK": true, "PIPE": true, "EVENT": true, "SERVER": true,
	"PUBLICATION": true, "SUBSCRIPTION": true, "UNLOGGED": true, "FOREIGN": true,
	"EXTERNAL": true, "SYNONYM": true, "PACKAGE": true, "DICTIONARY": true,
	"COLLATION": true, "AGGREGATE": true, "OPERATOR": true, "LOGIN": true,
}

// lineDDLEndWords are the words, besides CREATE / ALTER / DROP and the
// transaction statements, that end a DDL statement kept verbatim outside
// SQL Server. Words that are also options of such statements (SET, RESET,
// RENAME, OWNER) are not among them.
var lineDDLEndWords = map[string]bool{
	"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true,
	"MERGE": true, "WITH": true, "TRUNCATE": true, "GRANT": true,
	"REVOKE": true, "COMMENT": true, "CALL": true, "COPY": true,
	"EXPLAIN": true, "SHOW": true, "USE": true, "VACUUM": true,
	"ANALYZE": true,
}

// startsNewLineDDL is startsNewLineStatement for the text of a DDL
// statement kept verbatim. schema is set for CREATE SCHEMA, whose schema
// elements continue it.
func (p *Parser) startsNewLineDDL(i, start int, schema bool) bool {
	if !p.startsNewLineStatement(i, start) {
		return false
	}
	switch word := p.utilityWord(i); word {
	case "CREATE", "ALTER", "DROP":
		obj := p.utilityWord(i + 1)
		if schema && word == "CREATE" {
			switch obj {
			case "TABLE", "VIEW", "INDEX", "SEQUENCE", "TRIGGER", "UNIQUE":
				return false
			}
		}
		return lineDDLObjects[obj]
	case "GRANT":
		return !schema
	default:
		return lineDDLEndWords[word] || p.isTransactionStartAt(i)
	}
}

// lineStatementEnd handles a utility statement outside SQL Server that
// lineEndPolicy ended before token index i, where the next statement starts
// without a ';' between them. Like any statement there, it is an error
// unless the next one is a transaction statement on its own line (see
// implicitStartAt), which is then marked as starting a statement.
func (p *Parser) lineStatementEnd(i int) error {
	if p.implicitStartAt(i) {
		p.markImplicitEnd(i)
		return nil
	}
	p.seek(i)
	return p.expectedError("semicolon or end of statement")
}
