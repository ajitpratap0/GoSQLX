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
// linted or scanned.

package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// implicitEndLeaders lists the SQL Server utility statements that end at the
// next statement-starting word when no ';' separates them. Each takes a
// short, closed argument list (a setting, a name, an expression) that never
// contains a bare statement keyword at the top level, so such a word begins
// the next statement. Statements that own a nested body have policies of
// their own (see implicitEndPolicy and parseTSQLConditional), as do GRANT /
// REVOKE / DENY, whose permission lists contain SELECT, INSERT and the like;
// BULK INSERT runs to the next ';'.
var implicitEndLeaders = map[string]bool{
	"SET": true, "USE": true, "COMMIT": true, "ROLLBACK": true, "SAVE": true,
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
	// implicitTxn: a transaction statement outside SQL Server (BEGIN,
	// START TRANSACTION, COMMIT, ...). Its options never contain a
	// statement keyword, so a statement-starting word at the start of a
	// line begins the next statement.
	implicitTxn
)

// tsqlRoutineObjects are the objects whose CREATE / ALTER body runs to the
// end of the batch in T-SQL: a following statement belongs to the body.
var tsqlRoutineObjects = map[string]bool{
	"PROCEDURE": true, "PROC": true, "FUNCTION": true, "TRIGGER": true, "VIEW": true,
}

// implicitEndPolicy returns the implicitPolicy of the statement starting at
// token index start. Outside SQL Server only transaction statements end
// without a ';'.
func (p *Parser) implicitEndPolicy(start int) implicitPolicy {
	if !p.IsSQLServer() {
		if p.isTransactionStartAt(start) {
			return implicitTxn
		}
		return implicitNone
	}
	word := p.utilityWord(start)
	switch word {
	case "BEGIN":
		if p.beginIsBlock(p.utilityWord(start + 1)) {
			return implicitAfterBlock
		}
		return implicitLeader
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
	case implicitTxn:
		return p.startsLine(i) && p.startsNewStatement(i, start)
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
		case "XMLNAMESPACES":
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
// transaction statement in a dialect other than SQL Server.
func (p *Parser) isTransactionStartAt(i int) bool {
	switch p.utilityWord(i) {
	case "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE", "ABORT":
		return true
	case "START":
		return p.utilityWord(i+1) == "TRANSACTION"
	case "BEGIN":
		return !p.beginIsBlock(p.utilityWord(i + 1))
	case "END":
		return p.dialect == string(keywords.DialectPostgreSQL) ||
			p.dialect == string(keywords.DialectSQLite) || p.dialect == ""
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
