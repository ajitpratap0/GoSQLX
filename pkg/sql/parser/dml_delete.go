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

// Package parser - dml_delete.go
// DELETE statement parsing.

package parser

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseDeleteStatement parses a DELETE statement:
//
//	DELETE [modifiers] [TOP (n)] FROM [ONLY] target [alias] [OUTPUT ...]
//	       [USING sources [JOIN ...]] [WHERE ...] [ORDER BY ...] [LIMIT n]
//	       [RETURNING ... [INTO ...]]
//	DELETE [modifiers] target [, target] [OUTPUT ...] FROM sources [JOIN ...] ...
//	                                     (MySQL/MariaDB/SQL Server multi-table)
//	DELETE target [alias] WHERE ...      (Oracle / SQL Server: FROM is optional)
func (p *Parser) parseDeleteStatement() (ast.Statement, error) {
	// We've already consumed the DELETE token in matchType
	stmt := &ast.DeleteStatement{}
	// The dialect-specific fields are collected in x and copied to
	// stmt.Extras only when one of them is set.
	var x ast.DMLTargetFields
	q := dmlTargetQuotes{&stmt.TableNameQuote, &stmt.AliasQuote}
	x.Modifiers = p.parseDMLModifiers(dmlDelete)
	top, err := p.parseTopClause()
	if err != nil {
		return nil, err
	}
	x.Top = top

	// MariaDB: DELETE HISTORY FROM t [BEFORE SYSTEM_TIME point]
	if p.isMariaDB() && p.isUnquotedWord("HISTORY") && p.peekToken().Token.Type == models.TokenTypeFrom {
		return p.parseDeleteHistory(stmt, &x)
	}

	sqlServer := p.dialect == string(keywords.DialectSQLServer)
	if p.isType(models.TokenTypeFrom) {
		p.advance() // Consume FROM
		// ONLY is followed by the table name.
		if p.nextIsName() && p.isDMLOnly() {
			x.Only = true
			p.advance() // Consume ONLY
		}
		// MySQL: DELETE FROM t1, t2 USING t1 JOIN t2 ...
		if _, err := p.parseDMLTargets(&stmt.TableName, &stmt.Alias, &q, &x, p.isMySQLFamily(), nil); err != nil {
			return nil, err
		}
		// MySQL names several targets only in the USING form; without it
		// DELETE FROM t1, t2 WHERE ... is a syntax error.
		if p.isMySQLFamily() && len(x.Tables) > 0 && stmt.TableName != "" && !p.isType(models.TokenTypeUsing) {
			return nil, p.expectedError("USING")
		}
	} else {
		multiFrom := p.isMySQLFamily() || sqlServer
		if !multiFrom && p.dialect != string(keywords.DialectOracle) {
			return nil, p.expectedError("FROM")
		}
		// MariaDB: DELETE `history` FROM history deletes the rows of the
		// table history; only the bare word is the HISTORY modifier.
		historyQuote := p.historyTableQuote()
		if _, err := p.parseDMLTargets(&stmt.TableName, &stmt.Alias, &q, &x, p.isMySQLFamily(), nil); err != nil {
			return nil, err
		}
		if historyQuote != 0 && stmt.Alias == "" && strings.EqualFold(stmt.TableName, "history") {
			// Keep the delimiters so the statement is written back as a
			// multi-table delete, not as DELETE HISTORY.
			stmt.TableNameQuote = ast.QuotedName(historyQuote)
		}
		if p.isDMLOutputKeyword() {
			x.Output, x.OutputInto, err = p.parseDMLOutputClause()
			if err != nil {
				return nil, err
			}
		}
		if multiFrom && p.isType(models.TokenTypeFrom) {
			if err := p.parseDeleteSources(&stmt.From, &x.Joins); err != nil {
				return nil, err
			}
		} else if p.isMySQLFamily() || (len(x.Tables) > 0 && stmt.TableName != "") {
			// DELETE t1, t2 needs a FROM clause naming the source tables,
			// and MySQL has no FROM-less DELETE t WHERE ... at all (only
			// Oracle and SQL Server do).
			return nil, p.expectedError("FROM")
		}
	}

	// SQL Server: DELETE FROM t OUTPUT ... [FROM t JOIN ...]
	if len(x.Output) == 0 && p.isDMLOutputKeyword() {
		x.Output, x.OutputInto, err = p.parseDMLOutputClause()
		if err != nil {
			return nil, err
		}
	}
	if sqlServer && len(stmt.From) == 0 && p.isType(models.TokenTypeFrom) {
		if err := p.parseDeleteSources(&stmt.From, &x.Joins); err != nil {
			return nil, err
		}
	}

	// PostgreSQL / Snowflake / MySQL: DELETE FROM t USING s [JOIN ...]
	if len(stmt.From) == 0 && p.isType(models.TokenTypeUsing) {
		if err := p.parseDeleteSources(&stmt.Using, &x.Joins); err != nil {
			return nil, err
		}
	}

	// Parse WHERE clause if present
	if p.isType(models.TokenTypeWhere) {
		p.advance() // Consume WHERE
		stmt.Where, err = p.parseExpression()
		if err != nil {
			return nil, err
		}
	}

	// MySQL / MariaDB / SQLite: ORDER BY ... LIMIT n
	if err := p.parseDMLOrderLimit(&x); err != nil {
		return nil, err
	}

	// Parse RETURNING clause if present (PostgreSQL, SQLite, MariaDB, Oracle INTO)
	if p.isReturningKeyword() {
		stmt.Returning, x.ReturningInto, err = p.parseReturningClause()
		if err != nil {
			return nil, err
		}
	}
	stmt.Extras = finishDMLExtras(&x)
	return stmt, nil
}

// historyTableQuote returns, in MariaDB, the delimiter of a delimited
// first DELETE target named history that FROM follows (DELETE `history`
// FROM history), and 0 otherwise.
func (p *Parser) historyTableQuote() rune {
	if !p.isMariaDB() || !strings.EqualFold(p.currentToken.Token.Value, "history") ||
		p.peekToken().Token.Type != models.TokenTypeFrom || !p.isQuotedIdentifierToken() {
		return 0
	}
	if q := p.currentIdentQuote(); q != 0 {
		return q
	}
	return '`'
}

// parseDeleteSources consumes FROM or USING and parses the source table list
// and its joins into *dst and *joinsDst.
func (p *Parser) parseDeleteSources(dst *[]ast.TableReference, joinsDst *[]ast.JoinClause) error {
	p.advance() // Consume FROM / USING
	prev := p.dmlReturning
	p.dmlReturning = true
	refs, joins, err := p.parseUpdateFromList()
	p.dmlReturning = prev
	if err != nil {
		return err
	}
	*dst = refs
	*joinsDst = joins
	return nil
}

// parseDeleteHistory parses the rest of MariaDB's DELETE HISTORY FROM table
// [PARTITION (partition_list)] [BEFORE SYSTEM_TIME [TIMESTAMP | TRANSACTION] expr];
// the current token is HISTORY. HISTORY is kept as
// a statement modifier.
func (p *Parser) parseDeleteHistory(stmt *ast.DeleteStatement, x *ast.DMLTargetFields) (ast.Statement, error) {
	x.Modifiers = append(x.Modifiers, "HISTORY")
	p.advance() // Consume HISTORY
	p.advance() // Consume FROM
	name, quote, err := p.parseQualifiedNameQuoted()
	if err != nil {
		return nil, err
	}
	stmt.TableName, stmt.TableNameQuote = name, quote
	var history ast.DeleteHistoryOptions
	if p.isType(models.TokenTypePartition) {
		p.advance() // Consume PARTITION
		if !p.matchType(models.TokenTypeLParen) {
			return nil, p.expectedError("(")
		}
		for {
			if !p.isIdentifier() && !p.isNonReservedKeyword() {
				return nil, p.expectedError("partition name")
			}
			partition := p.parseColumnName()
			if partition == nil {
				return nil, p.expectedError("partition name")
			}
			history.Partitions = append(history.Partitions, partition)
			if !p.matchType(models.TokenTypeComma) {
				break
			}
		}
		if !p.matchType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
	}
	if p.isUnquotedWord("BEFORE") && p.peekValueIs(1, "SYSTEM_TIME") {
		p.advance() // Consume BEFORE
		p.advance() // Consume SYSTEM_TIME
		if p.isUnquotedWord("TIMESTAMP") || p.isUnquotedWord("TRANSACTION") {
			history.BeforeSystemTimeUnit = strings.ToUpper(p.currentToken.Token.Value)
			p.advance()
		}
		if stmt.BeforeSystemTime, err = p.parseExpression(); err != nil {
			return nil, err
		}
	}
	if len(history.Partitions) > 0 || history.BeforeSystemTimeUnit != "" {
		x.History = &history
	}
	stmt.Extras = finishDMLExtras(x)
	return stmt, nil
}
