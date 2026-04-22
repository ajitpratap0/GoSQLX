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

// Package parser - select.go
// Core SELECT statement parsing.
// Related modules:
//   - select_clauses.go  - FROM, WHERE, GROUP BY, HAVING, ORDER BY, LIMIT, FETCH, FOR
//   - select_set_ops.go  - UNION, INTERSECT, EXCEPT
//   - select_subquery.go - derived tables, JOIN table references, table hints

package parser

import (
	"fmt"
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseSelectStatement parses a SELECT statement.
// It delegates each clause to a focused helper method.
func (p *Parser) parseSelectStatement() (ast.Statement, error) {
	// We've already consumed the SELECT token in matchType.

	// DISTINCT / ALL modifier
	isDistinct, distinctOnColumns, err := p.parseDistinctModifier()
	if err != nil {
		return nil, err
	}

	// Reject TOP in dialects that use LIMIT/OFFSET or ROWNUM/FETCH FIRST instead.
	// String comparison is used here because the lexer has no TokenTypeTOP constant;
	// TOP is emitted as an identifier literal (see parseTopClause comment).
	nonTopDialects := map[string]bool{
		string(keywords.DialectMySQL):      true,
		string(keywords.DialectPostgreSQL): true,
		string(keywords.DialectSQLite):     true,
		string(keywords.DialectOracle):     true,
	}
	if nonTopDialects[p.dialect] && strings.ToUpper(p.currentToken.Token.Value) == "TOP" {
		if p.dialect == string(keywords.DialectOracle) {
			return nil, goerrors.UnsupportedFeatureError(
				"TOP clause is not supported in Oracle; use ROWNUM or FETCH FIRST … ROWS ONLY instead",
				p.currentLocation(),
				"",
			)
		}
		return nil, goerrors.UnsupportedFeatureError(
			fmt.Sprintf("TOP clause is not supported in %s; use LIMIT/OFFSET instead", p.dialect),
			p.currentLocation(),
			"",
		)
	}

	// SQL Server TOP clause
	topClause, err := p.parseTopClause()
	if err != nil {
		return nil, err
	}

	// Column list
	columns, err := p.parseSelectColumnList()
	if err != nil {
		return nil, err
	}

	// FROM … JOIN clauses
	tableName, tables, joins, err := p.parseFromClause()
	if err != nil {
		return nil, err
	}

	// Initialise the statement early so clause parsers can check dialect etc.
	selectStmt := &ast.SelectStatement{
		Distinct:          isDistinct,
		DistinctOnColumns: distinctOnColumns,
		Top:               topClause,
		Columns:           columns,
		From:              tables,
		Joins:             joins,
		TableName:         tableName,
	}

	// ClickHouse ARRAY JOIN / LEFT ARRAY JOIN.
	// Migrated from p.dialect == "clickhouse" to Capabilities in Sprint 2.
	// SupportsArrayJoin is true only for ClickHouse in dialect.Capabilities,
	// preserving the exact previous behaviour.
	if p.Capabilities().SupportsArrayJoin {
		if selectStmt.ArrayJoin, err = p.parseArrayJoinClause(); err != nil {
			return nil, err
		}
	}

	// SAMPLE (ClickHouse-specific, specifies sampling rate/size; comes after FROM/FINAL)
	if p.dialect == string(keywords.DialectClickHouse) && p.isTokenMatch("SAMPLE") {
		if selectStmt.Sample, err = p.parseSampleClause(); err != nil {
			return nil, err
		}
	}

	// PREWHERE (ClickHouse-specific, applied before WHERE for early data filtering).
	// Migrated from p.dialect == "clickhouse" to Capabilities in Sprint 2.
	// SupportsPrewhere is true only for ClickHouse in dialect.Capabilities,
	// preserving the exact previous behaviour.
	if p.Capabilities().SupportsPrewhere {
		if selectStmt.PrewhereClause, err = p.parsePrewhereClause(); err != nil {
			return nil, err
		}
	}

	// WHERE
	if selectStmt.Where, err = p.parseWhereClause(); err != nil {
		return nil, err
	}

	// GROUP BY
	if selectStmt.GroupBy, err = p.parseGroupByClause(); err != nil {
		return nil, err
	}

	// HAVING
	if selectStmt.Having, err = p.parseHavingClause(); err != nil {
		return nil, err
	}

	// Snowflake / BigQuery QUALIFY: filters rows after window functions.
	// Appears between HAVING and ORDER BY. Tokenizes as identifier or
	// keyword depending on dialect tables; detect by value.
	// Migrated from p.dialect == "snowflake"/"bigquery" to Capabilities in
	// Sprint 2. SupportsQualify is true only for Snowflake and BigQuery in
	// dialect.Capabilities, preserving the exact previous behaviour.
	if p.Capabilities().SupportsQualify &&
		strings.EqualFold(p.currentToken.Token.Value, "QUALIFY") {
		p.advance() // Consume QUALIFY
		qexpr, qerr := p.parseExpression()
		if qerr != nil {
			return nil, qerr
		}
		selectStmt.Qualify = qexpr
	}

	// Oracle/MariaDB: START WITH ... CONNECT BY hierarchical queries
	if p.isMariaDB() || p.dialect == string(keywords.DialectOracle) {
		if strings.EqualFold(p.currentToken.Token.Value, "START") {
			p.advance() // Consume START
			if !strings.EqualFold(p.currentToken.Token.Value, "WITH") {
				return nil, goerrors.ExpectedTokenError(
					"WITH after START",
					p.currentToken.Token.Value,
					p.currentLocation(),
					"",
				)
			}
			p.advance() // Consume WITH
			startExpr, startErr := p.parseExpression()
			if startErr != nil {
				return nil, startErr
			}
			selectStmt.StartWith = startExpr
		}
		if strings.EqualFold(p.currentToken.Token.Value, "CONNECT") {
			connectPos := p.currentLocation() // position of CONNECT keyword
			p.advance()                       // Consume CONNECT
			if !strings.EqualFold(p.currentToken.Token.Value, "BY") {
				return nil, goerrors.ExpectedTokenError(
					"BY after CONNECT",
					p.currentToken.Token.Value,
					p.currentLocation(),
					"",
				)
			}
			p.advance() // Consume BY
			cb := &ast.ConnectByClause{}
			cb.Pos = connectPos
			if strings.EqualFold(p.currentToken.Token.Value, "NOCYCLE") {
				cb.NoCycle = true
				p.advance() // Consume NOCYCLE
			}
			cond, condErr := p.parseConnectByCondition()
			if condErr != nil {
				return nil, condErr
			}
			if cond == nil {
				return nil, goerrors.InvalidSyntaxError(
					"expected condition after CONNECT BY",
					p.currentLocation(),
					"",
				)
			}
			cb.Condition = cond
			selectStmt.ConnectBy = cb
		}
	}

	// SQL:2003 WINDOW clause: WINDOW w AS (spec), w2 AS (spec2), ...
	// Named window definitions that can be referenced by OVER w.
	if strings.EqualFold(p.currentToken.Token.Value, "WINDOW") {
		p.advance() // Consume WINDOW
		for {
			if !p.isIdentifier() {
				return nil, p.expectedError("window name after WINDOW")
			}
			winName := p.currentToken.Token.Value
			p.advance()
			if !p.isType(models.TokenTypeAs) {
				return nil, p.expectedError("AS after window name")
			}
			p.advance() // Consume AS
			winSpec, winErr := p.parseWindowSpec()
			if winErr != nil {
				return nil, winErr
			}
			winSpec.Name = winName
			selectStmt.Windows = append(selectStmt.Windows, *winSpec)
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance() // Consume comma
		}
	}

	// ORDER BY
	if selectStmt.OrderBy, err = p.parseOrderByClause(); err != nil {
		return nil, err
	}

	// LIMIT / OFFSET
	if selectStmt.Limit, selectStmt.Offset, err = p.parseLimitOffsetClause(); err != nil {
		return nil, err
	}

	// ClickHouse LIMIT BY: `LIMIT N [OFFSET M] BY expr [, expr]...`
	// The LIMIT and OFFSET values were already consumed above; if the next
	// token is BY, consume the BY-expression list (permissive, not modeled).
	if p.dialect == string(keywords.DialectClickHouse) && p.isType(models.TokenTypeBy) {
		p.advance() // Consume BY
		for {
			if _, err := p.parseExpression(); err != nil {
				return nil, err
			}
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance()
		}
	}

	// FETCH FIRST / NEXT
	if p.isType(models.TokenTypeFetch) {
		if selectStmt.Fetch, err = p.parseFetchClause(); err != nil {
			return nil, err
		}
	}

	// FOR UPDATE / SHARE / …
	if p.isType(models.TokenTypeFor) {
		if selectStmt.For, err = p.parseForClause(); err != nil {
			return nil, err
		}
	}

	return selectStmt, nil
}

// parseDistinctModifier parses the optional DISTINCT [ON (...)] or ALL keyword
// immediately after SELECT.
func (p *Parser) parseDistinctModifier() (isDistinct bool, distinctOnColumns []ast.Expression, err error) {
	if p.isType(models.TokenTypeDistinct) {
		isDistinct = true
		p.advance() // Consume DISTINCT

		// PostgreSQL DISTINCT ON (expr, ...)
		if p.isType(models.TokenTypeOn) {
			p.advance() // Consume ON

			if !p.isType(models.TokenTypeLParen) {
				return false, nil, p.expectedError("( after DISTINCT ON")
			}
			p.advance() // Consume (

			for {
				expr, e := p.parseExpression()
				if e != nil {
					return false, nil, e
				}
				distinctOnColumns = append(distinctOnColumns, expr)
				if !p.isType(models.TokenTypeComma) {
					break
				}
				p.advance()
			}

			if !p.isType(models.TokenTypeRParen) {
				return false, nil, p.expectedError(") after DISTINCT ON expression list")
			}
			p.advance() // Consume )
		}
	} else if p.isType(models.TokenTypeAll) {
		p.advance() // ALL is the default; just consume it
	}
	return isDistinct, distinctOnColumns, nil
}

// parseTopClause parses SQL Server's TOP n [PERCENT] [WITH TIES] clause.
// Returns nil when the current dialect is not SQL Server or TOP is absent.
//
// Note: "TOP" is detected via a string comparison rather than a dedicated token-type
// constant because the lexer does not define a TokenTypeTOP - it tokenises TOP as a
// plain identifier/keyword literal.  A future lexer enhancement could introduce
// models.TokenTypeTop and replace the strings.ToUpper check below.
func (p *Parser) parseTopClause() (*ast.TopClause, error) {
	if p.dialect != string(keywords.DialectSQLServer) || strings.ToUpper(p.currentToken.Token.Value) != "TOP" {
		return nil, nil
	}
	p.advance() // Consume TOP

	hasParen := p.isType(models.TokenTypeLParen)
	if hasParen {
		p.advance() // Consume (
	}

	countExpr, err := p.parsePrimaryExpression()
	if err != nil {
		return nil, goerrors.InvalidSyntaxError(
			fmt.Sprintf("expected expression after TOP: %v", err),
			p.currentLocation(),
			"",
		).WithCause(err)
	}

	if hasParen {
		if !p.isType(models.TokenTypeRightParen) {
			return nil, p.expectedError(") after TOP expression")
		}
		p.advance() // Consume )
	}

	topClause := &ast.TopClause{Count: countExpr}

	// Optional PERCENT
	if p.isType(models.TokenTypePercent) ||
		(p.currentToken.Token.Type == models.TokenTypeKeyword && strings.ToUpper(p.currentToken.Token.Value) == "PERCENT") {
		topClause.IsPercent = true
		p.advance()
	}

	// Optional WITH TIES
	if p.isType(models.TokenTypeWith) && p.peekToken().Token.Type == models.TokenTypeTies {
		topClause.WithTies = true
		p.advance() // Consume WITH
		p.advance() // Consume TIES

	}

	return topClause, nil
}

// parseSelectColumnList parses the comma-separated column/expression list in SELECT.
func (p *Parser) parseSelectColumnList() ([]ast.Expression, error) {
	// Guard: SELECT immediately followed by FROM is an error.
	if p.isType(models.TokenTypeFrom) {
		return nil, goerrors.ExpectedTokenError(
			"column expression",
			"FROM",
			p.currentLocation(),
			"SELECT requires at least one column expression before FROM",
		)
	}

	columns := make([]ast.Expression, 0, 8)
	for {
		var expr ast.Expression

		if p.isType(models.TokenTypeAsterisk) || p.isType(models.TokenTypeMul) {
			// Both TokenTypeAsterisk and TokenTypeMul represent '*' in SQL.
			// The tokenizer may produce either depending on context.
			expr = &ast.Identifier{Name: "*"}
			p.advance()
		} else {
			var err error
			expr, err = p.parseExpression()
			if err != nil {
				return nil, err
			}

			// Optional alias: AS name  or  implicit name (non-identifier expressions only)
			if p.isType(models.TokenTypeAs) {
				p.advance() // Consume AS
				if !p.isIdentifier() {
					return nil, p.expectedError("alias name after AS")
				}
				alias := p.currentToken.Token.Value
				p.advance()
				expr = &ast.AliasedExpression{Expr: expr, Alias: alias}
			} else if p.canBeAlias() {
				// Implicit aliasing (SELECT expr alias) is allowed for non-identifier
				// expressions (functions, literals, casts, etc.) and for bare identifiers
				// that are known pseudo-columns (ROWNUM, SYSDATE, LEVEL, etc.) where
				// the alias pattern is idiomatic: SELECT ROWNUM rn FROM ...
				ident, isIdent := expr.(*ast.Identifier)
				allowAlias := !isIdent || (isIdent && ident.Table == "" && p.isOraclePseudoColumn2(ident.Name))
				if allowAlias {
					alias := p.currentToken.Token.Value
					p.advance()
					expr = &ast.AliasedExpression{Expr: expr, Alias: alias}
				}
			}
		}

		columns = append(columns, expr)

		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance() // Consume comma
	}
	return columns, nil
}
