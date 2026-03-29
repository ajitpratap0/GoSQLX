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

// Package parser - select_clauses.go
// SELECT clause parsing: FROM, WHERE, GROUP BY, HAVING, ORDER BY, LIMIT/OFFSET,
// FETCH FIRST, and FOR UPDATE/SHARE locking clauses.

package parser

import (
	"fmt"
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseFromClause parses the FROM clause including comma-separated table references
// and any subsequent JOIN clauses.  Returns the primary table name (for compatibility),
// the full table-reference slice, and the join slice.
func (p *Parser) parseFromClause() (tableName string, tables []ast.TableReference, joins []ast.JoinClause, err error) {
	// FROM is optional (e.g. SELECT 1).  Validate that the next token makes sense.
	if !p.isType(models.TokenTypeFrom) {
		// advance() sets a zero-value sentinel (TokenType == TokenTypeEOF == 0) when
		// currentPos goes past the end of the token slice.  A real EOF token produced by
		// the tokenizer is also TokenTypeEOF but is still within the slice.
		// To replicate the correct behaviour we need to know what the last consumed token
		// was: e.g. SELECT (1,2,3) ends with ')' (FROM is optional) while SELECT *
		// ends with '*' (FROM is required).  When currentPos is past the slice end,
		// inspect the last real token directly instead of relying on currentToken.
		if p.currentPos >= len(p.tokens) {
			// Past end of token stream - check whether the last real token implies
			// that FROM can legitimately be omitted.
			if len(p.tokens) > 0 {
				lastTokType := p.tokens[len(p.tokens)-1].Token.Type
				if lastTokType == models.TokenTypeSemicolon ||
					lastTokType == models.TokenTypeRParen ||
					lastTokType == models.TokenTypeEOF ||
					lastTokType == models.TokenTypeUnion ||
					lastTokType == models.TokenTypeExcept ||
					lastTokType == models.TokenTypeIntersect {
					return "", nil, nil, nil
				}
			}
			return "", nil, nil, p.expectedError("FROM, semicolon, or end of statement")
		}
		// Current token is still within the slice - use the normal token-type check.
		if !p.isType(models.TokenTypeEOF) &&
			!p.isType(models.TokenTypeSemicolon) &&
			!p.isType(models.TokenTypeRParen) &&
			!p.isAnyType(models.TokenTypeUnion, models.TokenTypeExcept, models.TokenTypeIntersect) {
			return "", nil, nil, p.expectedError("FROM, semicolon, or end of statement")
		}
		return "", nil, nil, nil
	}

	p.advance() // Consume FROM

	if p.isType(models.TokenTypeEOF) || p.isType(models.TokenTypeSemicolon) {
		return "", nil, nil, goerrors.ExpectedTokenError(
			"table name",
			p.currentToken.Token.Type.String(),
			p.currentLocation(),
			"FROM clause requires at least one table reference",
		)
	}

	// First table reference
	firstRef, e := p.parseFromTableReference()
	if e != nil {
		return "", nil, nil, e
	}
	tableName = firstRef.Name

	// ClickHouse FINAL modifier — consumed after table reference, before JOINs.
	// NOTE: FINAL only applies to the first (primary) table reference. In ClickHouse,
	// FINAL is a per-table modifier; multi-table FROM with FINAL on a non-first
	// table (e.g. "FROM t1, t2 FINAL") is not supported by this parser.
	if p.dialect == string(keywords.DialectClickHouse) && p.isTokenMatch("FINAL") {
		firstRef.Final = true
		p.advance() // consume FINAL
	}

	tables = []ast.TableReference{firstRef}

	// Additional comma-separated table references (implicit cross joins)
	for p.isType(models.TokenTypeComma) {
		p.advance()
		ref, e2 := p.parseFromTableReference()
		if e2 != nil {
			return "", nil, nil, e2
		}
		tables = append(tables, ref)
	}

	// JOIN clauses
	joins, err = p.parseJoinClauses(firstRef)
	return tableName, tables, joins, err
}

// parseJoinClauses parses zero or more JOIN clauses that follow the FROM table list.
// firstRef is the primary (left-most) table, used for building JoinClause.Left.
func (p *Parser) parseJoinClauses(firstRef ast.TableReference) ([]ast.JoinClause, error) {
	joins := []ast.JoinClause{}

	for p.isJoinKeyword() {
		joinPos := p.currentLocation()
		joinType, isNatural, err := p.parseJoinType()
		if err != nil {
			return nil, err
		}

		// Expect JOIN keyword (APPLY variants skip it)
		isApply := joinType == "CROSS APPLY" || joinType == "OUTER APPLY"
		if !isApply {
			if !p.isType(models.TokenTypeJoin) {
				return nil, goerrors.ExpectedTokenError(
					"JOIN after "+joinType,
					p.currentToken.Token.Type.String(),
					p.currentLocation(),
					"",
				)
			}
			p.advance() // Consume JOIN
		}

		joinedTableRef, err := p.parseJoinedTableRef(joinType)
		if err != nil {
			return nil, err
		}

		joinCondition, err := p.parseJoinCondition(joinType, isNatural, isApply)
		if err != nil {
			return nil, err
		}

		// Build left-side reference (synthetic for chained joins)
		var leftTable ast.TableReference
		if len(joins) == 0 {
			leftTable = firstRef
		} else {
			leftTable = ast.TableReference{
				Name: fmt.Sprintf("(%s_with_%d_joins)", firstRef.Name, len(joins)),
			}
		}

		joins = append(joins, ast.JoinClause{
			Type:      joinType,
			Left:      leftTable,
			Right:     joinedTableRef,
			Condition: joinCondition,
			Pos:       joinPos,
		})
	}
	return joins, nil
}

// parseJoinType parses the optional NATURAL keyword and the join-type keywords
// (LEFT, RIGHT, FULL, INNER, CROSS, OUTER APPLY, …) that precede the JOIN keyword.
// Returns (joinType string, isNatural bool, err).
func (p *Parser) parseJoinType() (string, bool, error) {
	joinType := "INNER"
	isNatural := false
	explicitType := false // tracks whether a join-type keyword was explicitly given

	// ClickHouse GLOBAL JOIN — consume the GLOBAL modifier before the join type.
	// GLOBAL semantics (distributed join) are not preserved in the AST.
	if p.dialect == string(keywords.DialectClickHouse) && p.isTokenMatch("GLOBAL") {
		p.advance() // consume GLOBAL; fall through to standard join parsing
	}

	if p.isType(models.TokenTypeNatural) {
		isNatural = true
		p.advance()
	}

	switch {
	case p.isType(models.TokenTypeLeft):
		joinType = "LEFT"
		explicitType = true
		p.advance()
		if p.isType(models.TokenTypeOuter) {
			p.advance()
		}
	case p.isType(models.TokenTypeRight):
		joinType = "RIGHT"
		explicitType = true
		p.advance()
		if p.isType(models.TokenTypeOuter) {
			p.advance()
		}
	case p.isType(models.TokenTypeFull):
		joinType = "FULL"
		explicitType = true
		p.advance()
		if p.isType(models.TokenTypeOuter) {
			p.advance()
		}
	case p.isType(models.TokenTypeInner):
		joinType = "INNER"
		explicitType = true
		p.advance()
	case p.isType(models.TokenTypeCross):
		joinType = "CROSS"
		explicitType = true
		p.advance()
		if p.dialect == string(keywords.DialectSQLServer) &&
			p.currentToken.Token.Type == models.TokenTypeIdentifier &&
			strings.ToUpper(p.currentToken.Token.Value) == "APPLY" {
			joinType = "CROSS APPLY"
			p.advance()
		}
	case p.isType(models.TokenTypeOuter) && p.dialect == string(keywords.DialectSQLServer):
		p.advance()
		if p.currentToken.Token.Type == models.TokenTypeIdentifier &&
			strings.ToUpper(p.currentToken.Token.Value) == "APPLY" {
			joinType = "OUTER APPLY"
			p.advance()
		} else {
			return "", false, p.expectedError("APPLY after OUTER (SQL Server OUTER APPLY)")
		}
	}

	if isNatural {
		// NATURAL JOIN without an explicit type keyword → just "NATURAL" (SQL standard).
		// NATURAL with an explicit keyword → "NATURAL LEFT", "NATURAL INNER", etc.
		if explicitType {
			joinType = "NATURAL " + joinType
		} else {
			joinType = "NATURAL"
		}
	}
	return joinType, isNatural, nil
}

// parseJoinCondition parses the ON / USING clause that follows a joined table reference.
// CROSS JOIN, APPLY, and NATURAL JOIN variants do not require a condition.
func (p *Parser) parseJoinCondition(joinType string, isNatural, isApply bool) (ast.Expression, error) {
	isCrossJoin := joinType == "CROSS" || isApply
	if isCrossJoin || isNatural {
		return nil, nil
	}

	if p.isType(models.TokenTypeOn) {
		p.advance() // Consume ON
		cond, err := p.parseExpression()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("error parsing ON condition for %s JOIN: %v", joinType, err),
				p.currentLocation(),
				"",
			)
		}
		return cond, nil
	}

	if p.isType(models.TokenTypeUsing) {
		p.advance() // Consume USING
		if !p.isType(models.TokenTypeLParen) {
			return nil, p.expectedError("( after USING")
		}
		p.advance()

		var usingColumns []ast.Expression
		for {
			if !p.isIdentifier() {
				return nil, p.expectedError("column name in USING")
			}
			usingColumns = append(usingColumns, &ast.Identifier{Name: p.currentToken.Token.Value})
			p.advance()
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance()
		}

		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(") after USING column list")
		}
		p.advance()

		if len(usingColumns) == 1 {
			return usingColumns[0], nil
		}
		return &ast.ListExpression{Values: usingColumns}, nil
	}

	return nil, p.expectedError("ON or USING")
}

// parseSampleClause parses the ClickHouse SAMPLE clause that specifies data sampling.
// It is called when the current token is SAMPLE (already verified by caller).
//
// Supported forms:
//
//	SAMPLE 0.1              — ratio (floating-point fraction, e.g., 10%)
//	SAMPLE 1000             — approximate row count (integer)
//	SAMPLE 1/10             — fractional form (numerator/denominator)
//	SAMPLE 1/10 OFFSET 2/10 — fractional with an offset fraction
func (p *Parser) parseSampleClause() (*ast.SampleClause, error) {
	samplePos := p.currentLocation()
	p.advance() // Consume SAMPLE

	if p.isType(models.TokenTypeEOF) || p.isType(models.TokenTypeSemicolon) {
		return nil, goerrors.ExpectedTokenError(
			"sampling size after SAMPLE",
			p.currentToken.Token.Type.String(),
			p.currentLocation(),
			"SAMPLE clause requires a numeric argument",
		)
	}

	clause := &ast.SampleClause{Pos: samplePos}

	// Read the primary sampling value (numerator / whole number / float)
	if !p.isNumericLiteral() {
		return nil, goerrors.ExpectedTokenError(
			"numeric literal after SAMPLE",
			p.currentToken.Token.Type.String(),
			p.currentLocation(),
			"SAMPLE clause requires a numeric argument (ratio, row count, or N/D fraction)",
		)
	}
	clause.Value = p.currentToken.Token.Value
	p.advance()

	// Check for fractional form: SAMPLE N / D
	if p.isType(models.TokenTypeDiv) {
		p.advance() // consume /
		if !p.isNumericLiteral() {
			return nil, goerrors.ExpectedTokenError(
				"denominator after /",
				p.currentToken.Token.Type.String(),
				p.currentLocation(),
				"SAMPLE N/D fraction requires an integer denominator",
			)
		}
		clause.Denominator = p.currentToken.Token.Value
		p.advance()
	}

	// Optional OFFSET N/D
	if p.isTokenMatch("OFFSET") {
		p.advance() // Consume OFFSET
		if !p.isNumericLiteral() {
			return nil, goerrors.ExpectedTokenError(
				"numeric literal after SAMPLE ... OFFSET",
				p.currentToken.Token.Type.String(),
				p.currentLocation(),
				"SAMPLE OFFSET requires a numeric argument",
			)
		}
		clause.Offset = p.currentToken.Token.Value
		p.advance()
		if p.isType(models.TokenTypeDiv) {
			p.advance() // consume /
			if !p.isNumericLiteral() {
				return nil, goerrors.ExpectedTokenError(
					"denominator after OFFSET /",
					p.currentToken.Token.Type.String(),
					p.currentLocation(),
					"SAMPLE OFFSET N/D fraction requires an integer denominator",
				)
			}
			clause.OffsetDenominator = p.currentToken.Token.Value
			p.advance()
		}
	}

	return clause, nil
}

// parsePrewhereClause parses "PREWHERE <expr>" if present (ClickHouse-specific).
// PREWHERE is a ClickHouse optimisation that filters data blocks before reading
// all columns. It is semantically similar to WHERE but executed earlier in the
// query pipeline. Returns nil (no error) when PREWHERE is absent.
func (p *Parser) parsePrewhereClause() (ast.Expression, error) {
	if !p.isTokenMatch("PREWHERE") {
		return nil, nil
	}
	p.advance() // Consume PREWHERE

	// Guard against a PREWHERE keyword with no following expression.
	if p.isType(models.TokenTypeEOF) || p.isType(models.TokenTypeSemicolon) ||
		p.isType(models.TokenTypeWhere) || p.isType(models.TokenTypeGroup) ||
		p.isType(models.TokenTypeOrder) || p.isType(models.TokenTypeLimit) ||
		p.isType(models.TokenTypeHaving) || p.isType(models.TokenTypeUnion) ||
		p.isType(models.TokenTypeExcept) || p.isType(models.TokenTypeIntersect) ||
		p.isType(models.TokenTypeRParen) {
		return nil, goerrors.ExpectedTokenError(
			"expression after PREWHERE",
			p.currentToken.Token.Type.String(),
			p.currentLocation(),
			"PREWHERE clause requires a boolean expression",
		)
	}

	return p.parseExpression()
}

// parseWhereClause parses "WHERE <expr>" if present.
// Returns nil (no error) when WHERE is absent.
func (p *Parser) parseWhereClause() (ast.Expression, error) {
	if !p.isType(models.TokenTypeWhere) {
		return nil, nil
	}
	p.advance() // Consume WHERE

	// Guard against a WHERE keyword with no following expression.
	if p.isType(models.TokenTypeEOF) || p.isType(models.TokenTypeSemicolon) ||
		p.isType(models.TokenTypeGroup) || p.isType(models.TokenTypeOrder) ||
		p.isType(models.TokenTypeLimit) || p.isType(models.TokenTypeHaving) ||
		p.isType(models.TokenTypeUnion) || p.isType(models.TokenTypeExcept) ||
		p.isType(models.TokenTypeIntersect) || p.isType(models.TokenTypeRParen) ||
		p.isType(models.TokenTypeFetch) || p.isType(models.TokenTypeFor) {
		return nil, goerrors.ExpectedTokenError(
			"expression after WHERE",
			p.currentToken.Token.Type.String(),
			p.currentLocation(),
			"WHERE clause requires a boolean expression",
		)
	}

	return p.parseExpression()
}

// parseGroupByClause parses "GROUP BY <expr> [, ...]" including ROLLUP, CUBE,
// GROUPING SETS, and MySQL's trailing WITH ROLLUP / WITH CUBE syntax.
// Returns nil slice (no error) when GROUP BY is absent.
func (p *Parser) parseGroupByClause() ([]ast.Expression, error) {
	if !p.isType(models.TokenTypeGroup) {
		return nil, nil
	}
	p.advance() // Consume GROUP

	if !p.isType(models.TokenTypeBy) {
		return nil, p.expectedError("BY after GROUP")
	}
	p.advance() // Consume BY

	groupByExprs := make([]ast.Expression, 0, 4)
	for {
		var (
			expr ast.Expression
			err  error
		)

		switch {
		case p.isType(models.TokenTypeRollup):
			expr, err = p.parseRollup()
		case p.isType(models.TokenTypeCube):
			expr, err = p.parseCube()
		case p.currentToken.Token.Value == "GROUPING SETS" ||
			(p.isType(models.TokenTypeGrouping) && strings.EqualFold(p.peekToken().Token.Value, "SETS")):
			expr, err = p.parseGroupingSets()
		default:
			expr, err = p.parseExpression()
		}

		if err != nil {
			return nil, err
		}
		groupByExprs = append(groupByExprs, expr)

		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance()
	}

	// MySQL: GROUP BY col1 WITH ROLLUP / WITH CUBE
	if p.isType(models.TokenTypeWith) {
		switch strings.ToUpper(p.peekToken().Token.Value) {
		case "ROLLUP":
			p.advance() // Consume WITH
			p.advance() // Consume ROLLUP
			groupByExprs = []ast.Expression{&ast.RollupExpression{Expressions: groupByExprs}}
		case "CUBE":
			p.advance() // Consume WITH
			p.advance() // Consume CUBE
			groupByExprs = []ast.Expression{&ast.CubeExpression{Expressions: groupByExprs}}
		}
	}

	return groupByExprs, nil
}

// parseHavingClause parses "HAVING <expr>" if present.
// Returns nil (no error) when HAVING is absent.
func (p *Parser) parseHavingClause() (ast.Expression, error) {
	if !p.isType(models.TokenTypeHaving) {
		return nil, nil
	}
	p.advance() // Consume HAVING
	return p.parseExpression()
}

// parseOrderByClause parses "ORDER BY <expr> [ASC|DESC] [NULLS FIRST|LAST] [, ...]".
// Returns nil slice (no error) when ORDER BY is absent.
func (p *Parser) parseOrderByClause() ([]ast.OrderByExpression, error) {
	if !p.isType(models.TokenTypeOrder) {
		return nil, nil
	}
	p.advance() // Consume ORDER

	if !p.isType(models.TokenTypeBy) {
		return nil, p.expectedError("BY")
	}
	p.advance() // Consume BY

	var orderByExprs []ast.OrderByExpression
	for {
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}

		entry := ast.OrderByExpression{
			Expression: expr,
			Ascending:  true,
			NullsFirst: nil,
		}

		if p.isType(models.TokenTypeAsc) {
			entry.Ascending = true
			p.advance()
		} else if p.isType(models.TokenTypeDesc) {
			entry.Ascending = false
			p.advance()
		}

		nullsFirst, err := p.parseNullsClause()
		if err != nil {
			return nil, err
		}
		entry.NullsFirst = nullsFirst

		orderByExprs = append(orderByExprs, entry)

		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance()
	}
	return orderByExprs, nil
}

// parseLimitOffsetClause parses optional LIMIT and/or OFFSET clauses.
// Supports standard "LIMIT n OFFSET m", MySQL "LIMIT offset, count", and
// SQL-99 "OFFSET n ROWS" (ROW/ROWS consumed but value stored).
// Returns (limit, offset, error); either or both pointers may be nil.
func (p *Parser) parseLimitOffsetClause() (limit *int, offset *int, err error) {
	// LIMIT clause
	if p.isType(models.TokenTypeLimit) {
		// Reject LIMIT in SQL Server and Oracle - these dialects use TOP/OFFSET-FETCH or ROWNUM/FETCH FIRST.
		if p.dialect == string(keywords.DialectSQLServer) || p.dialect == string(keywords.DialectOracle) {
			msg := "LIMIT clause is not supported in SQL Server; use TOP or OFFSET/FETCH NEXT instead"
			if p.dialect == string(keywords.DialectOracle) {
				msg = "LIMIT clause is not supported in Oracle; use ROWNUM or FETCH FIRST … ROWS ONLY instead"
			}
			return nil, nil, fmt.Errorf("%s", msg)
		}
		p.advance() // Consume LIMIT

		if !p.isNumericLiteral() {
			return nil, nil, p.expectedError("integer for LIMIT")
		}
		firstVal := 0
		_, _ = fmt.Sscanf(p.currentToken.Token.Value, "%d", &firstVal)
		p.advance()

		// MySQL: LIMIT offset, count
		if p.dialect == "mysql" && p.isType(models.TokenTypeComma) {
			p.advance()
			if !p.isNumericLiteral() {
				return nil, nil, p.expectedError("integer for LIMIT count")
			}
			secondVal := 0
			_, _ = fmt.Sscanf(p.currentToken.Token.Value, "%d", &secondVal)
			p.advance()
			offset = &firstVal
			limit = &secondVal
		} else {
			limit = &firstVal
		}
	}

	// OFFSET clause
	if p.isType(models.TokenTypeOffset) {
		p.advance()

		if !p.isNumericLiteral() {
			return nil, nil, p.expectedError("integer for OFFSET")
		}
		offsetVal := 0
		_, _ = fmt.Sscanf(p.currentToken.Token.Value, "%d", &offsetVal)
		offset = &offsetVal
		p.advance()

		// SQL-99: OFFSET n ROWS
		if p.isAnyType(models.TokenTypeRow, models.TokenTypeRows) {
			p.advance()
		}
	}

	return limit, offset, nil
}

// parseFetchClause parses the SQL-99 FETCH FIRST/NEXT clause (F861, F862).
// Syntax: FETCH {FIRST | NEXT} n [{ROW | ROWS}] [{PERCENT}] {ONLY | WITH TIES}
//
// Examples:
//
//	FETCH FIRST 5 ROWS ONLY
//	FETCH NEXT 10 ROWS ONLY
//	FETCH FIRST 10 PERCENT ROWS WITH TIES
//	FETCH NEXT 20 ROWS WITH TIES
func (p *Parser) parseFetchClause() (*ast.FetchClause, error) {
	fetchClause := &ast.FetchClause{}

	// Consume FETCH keyword (already checked by caller)
	p.advance()

	// Parse FIRST or NEXT
	if p.isType(models.TokenTypeFirst) {
		fetchClause.FetchType = "FIRST"
		p.advance()
	} else if p.isType(models.TokenTypeNext) {
		fetchClause.FetchType = "NEXT"
		p.advance()
	} else {
		return nil, p.expectedError("FIRST or NEXT after FETCH")
	}

	// Parse the count value
	if !p.isNumericLiteral() {
		return nil, p.expectedError("integer for FETCH count")
	}

	// Convert string to int64
	var fetchVal int64
	_, _ = fmt.Sscanf(p.currentToken.Token.Value, "%d", &fetchVal)
	fetchClause.FetchValue = &fetchVal
	p.advance()

	// Check for PERCENT (optional)
	if p.isType(models.TokenTypePercent) {
		fetchClause.IsPercent = true
		p.advance()
	}

	// Check for ROW/ROWS (optional)
	if p.isAnyType(models.TokenTypeRow, models.TokenTypeRows) {
		p.advance() // Consume ROW/ROWS
	}

	// Parse ONLY or WITH TIES
	if p.isType(models.TokenTypeOnly) {
		fetchClause.WithTies = false
		p.advance()
	} else if p.isType(models.TokenTypeWith) {
		p.advance() // Consume WITH
		if !p.isType(models.TokenTypeTies) {
			return nil, p.expectedError("TIES after WITH")
		}
		fetchClause.WithTies = true
		p.advance() // Consume TIES
	} else {
		// If neither ONLY nor WITH TIES, default to ONLY behavior
		fetchClause.WithTies = false
	}

	return fetchClause, nil
}

// parseForClause parses row-level locking clauses in SELECT statements (SQL:2003, PostgreSQL, MySQL).
// Syntax: FOR {UPDATE | SHARE | NO KEY UPDATE | KEY SHARE} [OF table_name [, ...]] [NOWAIT | SKIP LOCKED]
//
// Examples:
//
//	FOR UPDATE
//	FOR SHARE NOWAIT
//	FOR UPDATE OF orders SKIP LOCKED
//	FOR NO KEY UPDATE
//	FOR KEY SHARE
func (p *Parser) parseForClause() (*ast.ForClause, error) {
	forClause := &ast.ForClause{}

	// Consume FOR keyword (already checked by caller)
	p.advance()

	// Parse lock type: UPDATE, SHARE, or compound types (NO KEY UPDATE, KEY SHARE)
	if p.isTokenMatch("UPDATE") {
		forClause.LockType = "UPDATE"
		p.advance()
	} else if p.isTokenMatch("SHARE") {
		forClause.LockType = "SHARE"
		p.advance()
	} else if p.isTokenMatch("NO") {
		// NO KEY UPDATE
		p.advance() // Consume NO
		if !p.isTokenMatch("KEY") {
			return nil, p.expectedError("KEY after NO in FOR clause")
		}
		p.advance() // Consume KEY
		if !p.isTokenMatch("UPDATE") {
			return nil, p.expectedError("UPDATE after NO KEY in FOR clause")
		}
		forClause.LockType = "NO KEY UPDATE"
		p.advance()
	} else if p.isTokenMatch("KEY") {
		// KEY SHARE
		p.advance() // Consume KEY
		if !p.isTokenMatch("SHARE") {
			return nil, p.expectedError("SHARE after KEY in FOR clause")
		}
		forClause.LockType = "KEY SHARE"
		p.advance()
	} else {
		return nil, p.expectedError("UPDATE, SHARE, NO KEY UPDATE, or KEY SHARE after FOR")
	}

	// Parse OF table_name [, ...] if present
	if p.isTokenMatch("OF") {
		p.advance() // Consume OF

		// Parse comma-separated list of table names
		forClause.Tables = make([]string, 0)
		for {
			// Expect an identifier (table name)
			if !p.isIdentifier() {
				return nil, p.expectedError("table name after OF")
			}
			forClause.Tables = append(forClause.Tables, p.currentToken.Token.Value)
			p.advance()

			// Check for comma to continue, otherwise break
			if p.isType(models.TokenTypeComma) {
				p.advance() // Consume comma
			} else {
				break
			}
		}
	}

	// Parse NOWAIT or SKIP LOCKED
	if p.isTokenMatch("NOWAIT") {
		forClause.NoWait = true
		p.advance()
	} else if p.isTokenMatch("SKIP") {
		p.advance() // Consume SKIP
		if !p.isTokenMatch("LOCKED") {
			return nil, p.expectedError("LOCKED after SKIP")
		}
		forClause.SkipLocked = true
		p.advance() // Consume LOCKED
	}

	return forClause, nil
}
