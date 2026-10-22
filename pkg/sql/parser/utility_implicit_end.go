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
// the next statement. Statements that own a nested body are left out: IF,
// WHILE, a BEGIN block and END (a ';' written after ELSE or BEGIN would
// change the program), as are GRANT / REVOKE / DENY and BULK INSERT, whose
// argument lists contain SELECT, INSERT and the like.
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

// implicitEndAllowed reports whether the statement starting at the current
// token ends at the next statement-starting word: SQL Server only, and only
// for the statements in implicitEndLeaders. BEGIN qualifies only as BEGIN
// TRAN[SACTION] / BEGIN DISTRIBUTED TRAN[SACTION], not as a block opener.
func (p *Parser) implicitEndAllowed() bool {
	if p.dialect != string(keywords.DialectSQLServer) {
		return false
	}
	word := p.utilityWord(p.currentPos)
	if word == "BEGIN" {
		return !p.beginIsBlock(p.utilityWord(p.currentPos + 1))
	}
	return implicitEndLeaders[word]
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
	case "FOR", "AS", "UNION", "EXCEPT", "INTERSECT", "ALL", "DISTINCT":
		// DECLARE c CURSOR FOR SELECT ..., CURSOR FOR UPDATE, and the
		// set-operation operands of a cursor query (... UNION [ALL]
		// SELECT ...): the word continues the statement.
		return false
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
