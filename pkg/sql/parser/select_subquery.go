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

// Package parser - select_subquery.go
// Derived table and JOIN table reference parsing (subqueries in FROM/JOIN clauses,
// table hints for SQL Server).

package parser

import (
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseFromTableReference parses a single table reference in a FROM clause,
// including derived tables (subqueries), LATERAL, and optional aliases.
func (p *Parser) parseFromTableReference() (ast.TableReference, error) {
	var tableRef ast.TableReference

	// Check for LATERAL keyword (PostgreSQL)
	isLateral := false
	if p.isType(models.TokenTypeLateral) {
		isLateral = true
		p.advance() // Consume LATERAL
	}

	// Check for derived table (subquery in parentheses)
	if p.isType(models.TokenTypeLParen) {
		p.advance() // Consume (

		// Check if this is a subquery (starts with SELECT or WITH)
		if !p.isType(models.TokenTypeSelect) && !p.isType(models.TokenTypeWith) {
			return tableRef, p.expectedError("SELECT in derived table")
		}

		// Consume SELECT token before calling parseSelectStatement
		p.advance() // Consume SELECT

		// Parse the subquery
		subquery, err := p.parseSelectStatement()
		if err != nil {
			return tableRef, err
		}
		selectStmt, ok := subquery.(*ast.SelectStatement)
		if !ok {
			return tableRef, p.expectedError("SELECT statement in derived table")
		}

		// Expect closing parenthesis
		if !p.isType(models.TokenTypeRParen) {
			return tableRef, p.expectedError(")")
		}
		p.advance() // Consume )

		tableRef = ast.TableReference{
			Subquery: selectStmt,
			Lateral:  isLateral,
		}
	} else if p.dialect == string(keywords.DialectSnowflake) &&
		p.isType(models.TokenTypePlaceholder) && strings.HasPrefix(p.currentToken.Token.Value, "@") {
		// Snowflake stage reference: @stage_name or @db.schema.stage/path.
		// Tokenized as PLACEHOLDER; consume as a table name.
		// Gated to Snowflake to avoid misinterpreting @variable in other dialects.
		stageName := p.currentToken.Token.Value
		p.advance()
		// Optional /path suffix — consume tokens joined by / until a space boundary.
		// Slash tokenizes as TokenTypeDiv.
		for p.isType(models.TokenTypeDiv) {
			stageName += "/"
			p.advance()
			if p.isIdentifier() || p.isType(models.TokenTypeKeyword) {
				stageName += p.currentToken.Token.Value
				p.advance()
			}
		}
		tableRef = ast.TableReference{
			Name:    stageName,
			Lateral: isLateral,
		}

		// Stage may be followed by (FILE_FORMAT => ...) args — use the same
		// function-call path as FLATTEN/TABLE(...).
		if p.isType(models.TokenTypeLParen) {
			funcCall, ferr := p.parseFunctionCall(stageName)
			if ferr != nil {
				return tableRef, ferr
			}
			tableRef.TableFunc = funcCall
		}
	} else {
		// Parse regular table name (supports schema.table qualification)
		qualifiedName, err := p.parseQualifiedName()
		if err != nil {
			return tableRef, err
		}

		tableRef = ast.TableReference{
			Name:    qualifiedName,
			Lateral: isLateral,
		}

		// Function-call table reference (Snowflake FLATTEN, TABLE(...),
		// IDENTIFIER(...), PostgreSQL unnest(...), BigQuery UNNEST(...)).
		// If the parsed name is followed by '(' at FROM position, reparse
		// it as a function call. Gated to dialects that actually use this.
		if p.isType(models.TokenTypeLParen) && p.supportsTableFunction() {
			funcCall, ferr := p.parseFunctionCall(qualifiedName)
			if ferr != nil {
				return tableRef, ferr
			}
			tableRef.TableFunc = funcCall
		}

		// Snowflake / ANSI SAMPLE or TABLESAMPLE clause on a table reference:
		//   SAMPLE [BERNOULLI | SYSTEM | BLOCK | ROW] (N [ROWS])
		//   TABLESAMPLE [method] (N [ROWS])
		// Consume permissively — the method and paren block are consumed
		// but not yet modeled on the AST.
		if strings.EqualFold(p.currentToken.Token.Value, "SAMPLE") ||
			strings.EqualFold(p.currentToken.Token.Value, "TABLESAMPLE") {
			p.advance() // SAMPLE / TABLESAMPLE
			// Optional method name
			upper := strings.ToUpper(p.currentToken.Token.Value)
			if upper == "BERNOULLI" || upper == "SYSTEM" || upper == "BLOCK" || upper == "ROW" {
				p.advance()
			}
			// (N [ROWS]) block
			if p.isType(models.TokenTypeLParen) {
				depth := 0
				for {
					t := p.currentToken.Token.Type
					if t == models.TokenTypeEOF {
						break
					}
					if t == models.TokenTypeLParen {
						depth++
					} else if t == models.TokenTypeRParen {
						depth--
						if depth == 0 {
							p.advance()
							break
						}
					}
					p.advance()
				}
			}
		}

		// Snowflake time-travel / change-tracking clauses:
		//   AT (TIMESTAMP => ...)
		//   BEFORE (STATEMENT => ...)
		//   CHANGES (INFORMATION => DEFAULT) AT (...)
		if p.isSnowflakeTimeTravelStart() {
			tt, err := p.parseSnowflakeTimeTravel()
			if err != nil {
				return tableRef, err
			}
			tableRef.TimeTravel = tt
		}
	}

	// Check for table alias (required for derived tables, optional for regular tables).
	// Guard: in MariaDB, CONNECT followed by BY is a hierarchical query clause, not an alias.
	// Similarly, START followed by WITH is a hierarchical query seed, not an alias.
	// Don't consume PIVOT/UNPIVOT as a table alias — they are contextual
	// keywords in SQL Server/Oracle and must reach the pivot-clause parser below.
	if (p.isIdentifier() || p.isType(models.TokenTypeAs)) && !p.isMariaDBClauseStart() && !p.isPivotKeyword() && !p.isUnpivotKeyword() && !p.isQualifyKeyword() && !p.isMinusSetOp() && !p.isSnowflakeTimeTravelStart() && !p.isSampleKeyword() && !p.isMatchRecognizeKeyword() {
		if p.isType(models.TokenTypeAs) {
			p.advance() // Consume AS
			if !p.isIdentifier() {
				return tableRef, p.expectedError("alias after AS")
			}
		}
		if p.isIdentifier() {
			tableRef.Alias = p.currentToken.Token.Value
			p.advance()
		}
	}

	// MariaDB FOR SYSTEM_TIME temporal query (10.3.4+)
	if p.isMariaDB() && p.isType(models.TokenTypeFor) {
		// Only parse as FOR SYSTEM_TIME if next token is SYSTEM_TIME
		next := p.peekToken()
		if strings.EqualFold(next.Token.Value, "SYSTEM_TIME") {
			p.advance() // Consume FOR
			sysTime, err := p.parseForSystemTimeClause()
			if err != nil {
				return tableRef, err
			}
			tableRef.ForSystemTime = sysTime
		}
	}

	// SQL Server table hints: WITH (NOLOCK), WITH (ROWLOCK, UPDLOCK), etc.
	if p.dialect == string(keywords.DialectSQLServer) && p.isType(models.TokenTypeWith) {
		if p.peekToken().Token.Type == models.TokenTypeLParen {
			hints, err := p.parseTableHints()
			if err != nil {
				return tableRef, err
			}
			tableRef.TableHints = hints
		}
	}

	// SQL Server / Oracle PIVOT clause
	if p.isPivotKeyword() {
		pivot, err := p.parsePivotClause()
		if err != nil {
			return tableRef, err
		}
		tableRef.Pivot = pivot
		p.parsePivotAlias(&tableRef)
	}

	// SQL Server / Oracle UNPIVOT clause
	if p.isUnpivotKeyword() {
		unpivot, err := p.parseUnpivotClause()
		if err != nil {
			return tableRef, err
		}
		tableRef.Unpivot = unpivot
		p.parsePivotAlias(&tableRef)
	}

	// Snowflake / Oracle MATCH_RECOGNIZE clause
	if p.isMatchRecognizeKeyword() {
		mr, err := p.parseMatchRecognize()
		if err != nil {
			return tableRef, err
		}
		tableRef.MatchRecognize = mr
		// Optional alias after MATCH_RECOGNIZE (...)
		if p.isType(models.TokenTypeAs) {
			p.advance()
		}
		if p.isIdentifier() {
			tableRef.Alias = p.currentToken.Token.Value
			p.advance()
		}
	}

	return tableRef, nil
}

// parseJoinedTableRef parses the table reference on the right-hand side of a JOIN.
func (p *Parser) parseJoinedTableRef(joinType string) (ast.TableReference, error) {
	var ref ast.TableReference

	// Optional LATERAL (PostgreSQL)
	isLateral := false
	if p.isType(models.TokenTypeLateral) {
		isLateral = true
		p.advance()
	}

	if p.isType(models.TokenTypeLParen) {
		// Derived table (subquery)
		p.advance() // Consume (

		if !p.isType(models.TokenTypeSelect) && !p.isType(models.TokenTypeWith) {
			return ref, p.expectedError("SELECT in derived table")
		}
		p.advance() // Consume SELECT

		subquery, err := p.parseSelectStatement()
		if err != nil {
			return ref, err
		}
		selectStmt, ok := subquery.(*ast.SelectStatement)
		if !ok {
			return ref, p.expectedError("SELECT statement in derived table")
		}

		if !p.isType(models.TokenTypeRParen) {
			return ref, p.expectedError(")")
		}
		p.advance() // Consume )

		ref = ast.TableReference{Subquery: selectStmt, Lateral: isLateral}
	} else {
		joinedName, err := p.parseQualifiedName()
		if err != nil {
			return ref, goerrors.ExpectedTokenError(
				"table name after "+joinType+" JOIN",
				p.currentToken.Token.Type.String(),
				p.currentLocation(),
				"",
			)
		}
		ref = ast.TableReference{Name: joinedName, Lateral: isLateral}
	}

	// Optional alias.
	// Guard: in MariaDB, CONNECT followed by BY is a hierarchical query clause, not an alias.
	// Similarly, START followed by WITH is a hierarchical query seed, not an alias.
	// Don't consume PIVOT/UNPIVOT as a table alias — they are contextual
	// keywords in SQL Server/Oracle and must reach the pivot-clause parser below.
	if (p.isIdentifier() || p.isType(models.TokenTypeAs)) && !p.isMariaDBClauseStart() && !p.isPivotKeyword() && !p.isUnpivotKeyword() && !p.isQualifyKeyword() && !p.isMinusSetOp() && !p.isSnowflakeTimeTravelStart() && !p.isSampleKeyword() && !p.isMatchRecognizeKeyword() {
		if p.isType(models.TokenTypeAs) {
			p.advance()
			if !p.isIdentifier() {
				return ref, p.expectedError("alias after AS")
			}
		}
		if p.isIdentifier() {
			ref.Alias = p.currentToken.Token.Value
			p.advance()
		}
	}

	// MariaDB FOR SYSTEM_TIME temporal query (10.3.4+)
	if p.isMariaDB() && p.isType(models.TokenTypeFor) {
		// Only parse as FOR SYSTEM_TIME if next token is SYSTEM_TIME
		next := p.peekToken()
		if strings.EqualFold(next.Token.Value, "SYSTEM_TIME") {
			p.advance() // Consume FOR
			sysTime, err := p.parseForSystemTimeClause()
			if err != nil {
				return ref, err
			}
			ref.ForSystemTime = sysTime
		}
	}

	// SQL Server table hints
	if p.dialect == string(keywords.DialectSQLServer) && p.isType(models.TokenTypeWith) {
		if p.peekToken().Token.Type == models.TokenTypeLParen {
			hints, err := p.parseTableHints()
			if err != nil {
				return ref, err
			}
			ref.TableHints = hints
		}
	}

	// SQL Server / Oracle PIVOT clause
	if p.isPivotKeyword() {
		pivot, err := p.parsePivotClause()
		if err != nil {
			return ref, err
		}
		ref.Pivot = pivot
		p.parsePivotAlias(&ref)
	}

	// SQL Server / Oracle UNPIVOT clause
	if p.isUnpivotKeyword() {
		unpivot, err := p.parseUnpivotClause()
		if err != nil {
			return ref, err
		}
		ref.Unpivot = unpivot
		p.parsePivotAlias(&ref)
	}

	return ref, nil
}

// parseTableHints parses SQL Server table hints: WITH (NOLOCK), WITH (ROWLOCK, UPDLOCK), etc.
// Called when current token is WITH and peek is LParen.
func (p *Parser) parseTableHints() ([]string, error) {
	p.advance() // Consume WITH
	p.advance() // Consume (

	var hints []string
	for {
		if p.isType(models.TokenTypeRParen) {
			break
		}
		hint := strings.ToUpper(p.currentToken.Token.Value)
		if hint == "" {
			return nil, p.expectedError("table hint inside WITH (...)")
		}
		hints = append(hints, hint)
		p.advance()
		// Consume optional comma between hints
		if p.isType(models.TokenTypeComma) {
			p.advance()
		}
	}
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") after table hints")
	}
	p.advance() // Consume )
	return hints, nil
}
