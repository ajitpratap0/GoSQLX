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
	stmt.Modifiers = p.parseDMLModifiers(dmlDelete)
	top, err := p.parseTopClause()
	if err != nil {
		return nil, err
	}
	stmt.Top = top

	// MariaDB: DELETE HISTORY FROM t [BEFORE SYSTEM_TIME point]
	if p.isMariaDB() && p.isUnquotedWord("HISTORY") && p.peekToken().Token.Type == models.TokenTypeFrom {
		return p.parseDeleteHistory(stmt)
	}

	sqlServer := p.dialect == string(keywords.DialectSQLServer)
	if p.isType(models.TokenTypeFrom) {
		p.advance() // Consume FROM
		if p.isDMLOnly() {
			stmt.Only = true
			p.advance() // Consume ONLY
		}
		// MySQL: DELETE FROM t1, t2 USING t1 JOIN t2 ...
		if _, err := p.parseDMLTargets(&stmt.TableName, &stmt.Alias, &stmt.DMLTargetFields, p.isMySQLFamily()); err != nil {
			return nil, err
		}
		// MySQL names several targets only in the USING form; without it
		// DELETE FROM t1, t2 WHERE ... is a syntax error.
		if p.isMySQLFamily() && len(stmt.Tables) > 0 && stmt.TableName != "" && !p.isType(models.TokenTypeUsing) {
			return nil, p.expectedError("USING")
		}
	} else {
		multiFrom := p.isMySQLFamily() || sqlServer
		if !multiFrom && p.dialect != string(keywords.DialectOracle) {
			return nil, p.expectedError("FROM")
		}
		if _, err := p.parseDMLTargets(&stmt.TableName, &stmt.Alias, &stmt.DMLTargetFields, p.isMySQLFamily()); err != nil {
			return nil, err
		}
		if p.isDMLOutputKeyword() {
			stmt.Output, stmt.OutputInto, err = p.parseDMLOutputClause()
			if err != nil {
				return nil, err
			}
		}
		if multiFrom && p.isType(models.TokenTypeFrom) {
			if err := p.parseDeleteSources(&stmt.From, stmt); err != nil {
				return nil, err
			}
		} else if p.isMySQLFamily() || (len(stmt.Tables) > 0 && stmt.TableName != "") {
			// DELETE t1, t2 needs a FROM clause naming the source tables,
			// and MySQL has no FROM-less DELETE t WHERE ... at all (only
			// Oracle and SQL Server do).
			return nil, p.expectedError("FROM")
		}
	}

	// SQL Server: DELETE FROM t OUTPUT ... [FROM t JOIN ...]
	if len(stmt.Output) == 0 && p.isDMLOutputKeyword() {
		stmt.Output, stmt.OutputInto, err = p.parseDMLOutputClause()
		if err != nil {
			return nil, err
		}
	}
	if sqlServer && len(stmt.From) == 0 && p.isType(models.TokenTypeFrom) {
		if err := p.parseDeleteSources(&stmt.From, stmt); err != nil {
			return nil, err
		}
	}

	// PostgreSQL / Snowflake / MySQL: DELETE FROM t USING s [JOIN ...]
	if len(stmt.From) == 0 && p.isType(models.TokenTypeUsing) {
		if err := p.parseDeleteSources(&stmt.Using, stmt); err != nil {
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
	if err := p.parseDMLOrderLimit(&stmt.DMLTargetFields); err != nil {
		return nil, err
	}

	// Parse RETURNING clause if present (PostgreSQL, SQLite, MariaDB, Oracle INTO)
	if p.isReturningKeyword() {
		stmt.Returning, stmt.ReturningInto, err = p.parseReturningClause()
		if err != nil {
			return nil, err
		}
	}
	return stmt, nil
}

// parseDeleteSources consumes FROM or USING and parses the source table list
// and its joins into *dst and stmt.Joins.
func (p *Parser) parseDeleteSources(dst *[]ast.TableReference, stmt *ast.DeleteStatement) error {
	p.advance() // Consume FROM / USING
	prev := p.dmlReturning
	p.dmlReturning = true
	refs, joins, err := p.parseUpdateFromList()
	p.dmlReturning = prev
	if err != nil {
		return err
	}
	*dst = refs
	stmt.Joins = joins
	return nil
}

// parseDeleteHistory parses the rest of MariaDB's DELETE HISTORY FROM table
// [BEFORE SYSTEM_TIME point]; the current token is HISTORY. HISTORY is kept as
// a statement modifier.
func (p *Parser) parseDeleteHistory(stmt *ast.DeleteStatement) (ast.Statement, error) {
	stmt.Modifiers = append(stmt.Modifiers, "HISTORY")
	p.advance() // Consume HISTORY
	p.advance() // Consume FROM
	name, quote, err := p.parseQualifiedNameQuoted()
	if err != nil {
		return nil, err
	}
	stmt.TableName, stmt.TableNameQuote = name, quote
	if p.isUnquotedWord("BEFORE") && p.peekValueIs(1, "SYSTEM_TIME") {
		p.advance() // Consume BEFORE
		p.advance() // Consume SYSTEM_TIME
		if stmt.BeforeSystemTime, err = p.parseTemporalPointExpression(); err != nil {
			return nil, err
		}
	}
	return stmt, nil
}
