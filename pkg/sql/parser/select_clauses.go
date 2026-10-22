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
	"strconv"
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
			!p.isAnyType(models.TokenTypeUnion, models.TokenTypeExcept, models.TokenTypeIntersect) &&
			!p.isMinusSetOp() &&
			!p.isDMLReturningKeyword() &&
			!p.isAnyType(models.TokenTypeOrder, models.TokenTypeLimit, models.TokenTypeOffset, models.TokenTypeFetch) &&
			!p.isSelectTailStart() &&
			// A DDL tail after a FROM-less query: CREATE ... AS SELECT 1
			// WITH [NO] DATA | WITH CHECK OPTION | WITH READ ONLY.
			!p.isType(models.TokenTypeWith) &&
			// The next statement of a script without semicolons.
			!p.statementMayEndAt(p.currentPos) {
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
			"",
		).WithHint("FROM clause requires at least one table reference")
	}

	// First table reference. A leading parenthesized joined table
	// ("FROM ((a JOIN b ON ...) JOIN c ON ...)") contributes its joins here.
	firstRef, joins, e := p.parseFromItem()
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

	tables, joins, err = p.parseTableListAndJoins(&firstRef, joins)
	if err != nil {
		return "", nil, nil, err
	}
	return tableName, tables, joins, nil
}

// parseTableListAndJoins parses what follows the first table reference of a
// FROM list or of a parenthesized join group: further comma-separated table
// references, then the JOIN clauses, including a comma after an explicit join.
// joins holds the joins already read from a parenthesized group that opened
// the list, or nil.
func (p *Parser) parseTableListAndJoins(first *ast.TableReference, joins []ast.JoinClause) (tables []ast.TableReference, _ []ast.JoinClause, err error) {
	firstRef := *first
	tables = []ast.TableReference{firstRef}

	// Additional comma-separated table references (implicit cross joins)
	for p.isType(models.TokenTypeComma) {
		if len(joins) > 0 {
			// Hoisting the parenthesized joins past a comma would re-bind them
			// to the last comma-separated table and change the query's meaning.
			return nil, nil, goerrors.UnsupportedFeatureError(
				"comma-separated table list after a parenthesized join",
				p.currentLocation(),
				"",
			)
		}
		p.advance()
		ref, e2 := p.parseFromTableReference()
		if e2 != nil {
			return nil, nil, e2
		}
		tables = append(tables, ref)
	}

	// JOIN clauses
	joins, err = p.parseJoinClauses(firstRef, joins)
	if err != nil {
		return nil, nil, err
	}

	// "a JOIN b ON ..., c [JOIN d ...]": a comma after an explicit join
	// adds a cross-joined table; it is kept as a comma when rendered.
	for len(joins) > 0 && p.isType(models.TokenTypeComma) {
		joinPos := p.currentLocation()
		p.advance() // Consume ,
		ref, e2 := p.parseFromTableReference()
		if e2 != nil {
			return nil, nil, e2
		}
		joins = append(joins, ast.JoinClause{
			Type:  "CROSS",
			Comma: true,
			Left: ast.TableReference{
				Name: "(" + firstRef.Name + "_with_" + strconv.Itoa(len(joins)) + "_joins)",
			},
			Right: ref,
			Pos:   joinPos,
		})
		if joins, err = p.parseJoinClauses(firstRef, joins); err != nil {
			return nil, nil, err
		}
	}
	return tables, joins, nil
}

// parseFromItem parses the first item of a FROM clause: either a plain table
// reference (table, derived table, table function, ...) or a parenthesized
// joined table. Joins found inside the parentheses are returned in source
// order so the caller can continue the join chain after them.
func (p *Parser) parseFromItem() (ast.TableReference, []ast.JoinClause, error) {
	if p.isParenthesizedJoinStart() {
		return p.parseParenthesizedJoin()
	}
	ref, err := p.parseFromTableReference()
	return ref, nil, err
}

// isParenthesizedJoinStart reports whether the current '(' opens a
// parenthesized joined table, i.e. "( table_reference [JOIN ...] )" or a
// further nested "((", rather than a derived table "(SELECT ...)".
// A "((" that opens a parenthesized query expression such as
// "((SELECT 1)) t" or "((SELECT 1) UNION (SELECT 2)) t" is a derived table.
// Other tokens after '(' keep the derived-table path and its error message.
func (p *Parser) isParenthesizedJoinStart() bool {
	if !p.isType(models.TokenTypeLParen) {
		return false
	}
	switch p.peekToken().Token.Type {
	case models.TokenTypeIdentifier, models.TokenTypeDoubleQuotedString:
		return true
	case models.TokenTypeLParen:
		return !p.parenOpensQueryExpression()
	}
	return false
}

// parenOpensQueryExpression reports whether the run of '(' starting at the
// current token opens a parenthesized query expression rather than a
// parenthesized join group. It only looks ahead in p.tokens and does not
// change parser state or allocate.
//
// The run of n '(' must end at SELECT or WITH. Level n-1 (the innermost) is
// then a query. Each enclosing level k is classified by the token after the
// first ')' that closes level k+1: another ')' keeps the inner result (the
// level only wraps it), a set operator or ORDER BY / LIMIT / OFFSET / FETCH
// makes it a query, and anything else (an alias, AS, a JOIN keyword, a comma)
// makes it a join group, as in "((SELECT 1) t JOIN u ON ...)".
func (p *Parser) parenOpensQueryExpression() bool {
	start := p.currentPos
	n := 0
	for start+n < len(p.tokens) && p.tokens[start+n].Token.Type == models.TokenTypeLParen {
		n++
		if n > MaxRecursionDepth {
			// Deeper than the parser accepts: the join path reports E2007.
			return false
		}
	}
	first := start + n
	if first >= len(p.tokens) {
		return false
	}
	if t := p.tokens[first].Token.Type; t != models.TokenTypeSelect && t != models.TokenTypeWith {
		return false
	}

	// Level d is the d-th '(' of the run (counting from 0, outermost first).
	// closeAt[d] is the index of the ')' that closes level d, i.e. the first
	// ')' that brings the depth down to d.
	var closeAt [MaxRecursionDepth + 1]int
	depth, minDepth := n, n
	for j := first; depth > 0; j++ {
		if j >= len(p.tokens) {
			return false
		}
		switch p.tokens[j].Token.Type {
		case models.TokenTypeEOF:
			return false
		case models.TokenTypeLParen:
			depth++
		case models.TokenTypeRParen:
			depth--
			if depth < minDepth {
				minDepth = depth
				closeAt[depth] = j
			}
		}
	}

	isQuery := true
	for k := n - 2; k >= 0; k-- {
		next := closeAt[k+1] + 1
		if next >= len(p.tokens) {
			return false
		}
		tok := p.tokens[next].Token
		switch tok.Type {
		case models.TokenTypeRParen:
			// Level k only wraps level k+1: keep its classification.
		case models.TokenTypeUnion, models.TokenTypeExcept, models.TokenTypeIntersect,
			models.TokenTypeOrder, models.TokenTypeLimit, models.TokenTypeOffset, models.TokenTypeFetch:
			isQuery = true
		default:
			isQuery = p.isMinusSetOpToken(tok)
		}
	}
	return isQuery
}

// parseParenthesizedJoin parses "( from_item [join_clause ...] )" as used by
// MySQL view definitions and allowed by SQL-92 <joined table>:
//
//	FROM ((a JOIN b ON ...) JOIN c ON ...) JOIN d ON ...
//
// Only the left-most position may be parenthesized here, and a left-nested
// join group has exactly the meaning of the same joins written without
// parentheses (joins associate to the left), so the group is flattened into
// the enclosing join chain. The returned reference is the group's left-most
// table and the joins are in source order.
func (p *Parser) parseParenthesizedJoin() (ast.TableReference, []ast.JoinClause, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > MaxRecursionDepth {
		return ast.TableReference{}, nil, goerrors.RecursionDepthLimitError(
			p.depth, MaxRecursionDepth, p.currentLocation(), "")
	}

	p.advance() // Consume (

	first, joins, err := p.parseFromItem()
	if err != nil {
		return ast.TableReference{}, nil, err
	}
	if p.isType(models.TokenTypeComma) {
		return ast.TableReference{}, nil, goerrors.UnsupportedFeatureError(
			"comma-separated table list inside a parenthesized join",
			p.currentLocation(),
			"",
		)
	}
	joins, err = p.parseJoinClauses(first, joins)
	if err != nil {
		return ast.TableReference{}, nil, err
	}
	if !p.isType(models.TokenTypeRParen) {
		return ast.TableReference{}, nil, p.expectedError(") or JOIN")
	}
	p.advance() // Consume )

	// The group is flattened into its left-most table, so a modifier written
	// after ")" has nothing correct to attach to: FINAL would silently apply
	// to the first table only, and an alias would name the first table.
	if p.dialect == string(keywords.DialectClickHouse) && p.isTokenMatch("FINAL") {
		return ast.TableReference{}, nil, goerrors.UnsupportedFeatureError(
			"FINAL after a parenthesized join group",
			p.currentLocation(),
			"",
		)
	}
	if p.isType(models.TokenTypeAs) || p.isIdentifier() {
		return ast.TableReference{}, nil, goerrors.UnsupportedFeatureError(
			"alias after a parenthesized join group",
			p.currentLocation(),
			"",
		)
	}
	return first, joins, nil
}

// parseJoinClauses parses zero or more JOIN clauses that follow the FROM table list
// and appends them to joins (the joins already parsed from a parenthesized
// group, or nil). firstRef is the primary (left-most) table, used for building
// JoinClause.Left.
func (p *Parser) parseJoinClauses(firstRef ast.TableReference, joins []ast.JoinClause) ([]ast.JoinClause, error) {
	if joins == nil {
		joins = []ast.JoinClause{}
	}

	for p.isJoinKeyword() {
		joinPos := p.currentLocation()
		var jc ast.JoinClause
		joinType, isNatural, err := p.parseJoinType(&jc)
		if err != nil {
			return nil, err
		}

		// Expect JOIN keyword (APPLY variants and STRAIGHT_JOIN skip it)
		isApply := joinType == "CROSS APPLY" || joinType == "OUTER APPLY"
		if !isApply && jc.Hint != "STRAIGHT_JOIN" {
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

		// Snowflake ASOF JOIN t MATCH_CONDITION (expr) ON ...
		if jc.Strictness == "ASOF" && p.dialect == string(keywords.DialectSnowflake) {
			if !p.isUnquotedWord("MATCH_CONDITION") {
				return nil, p.expectedError("MATCH_CONDITION after ASOF JOIN table")
			}
			p.advance() // MATCH_CONDITION
			if !p.isType(models.TokenTypeLParen) {
				return nil, p.expectedError("( after MATCH_CONDITION")
			}
			p.advance() // (
			if jc.MatchCondition, err = p.parseExpression(); err != nil {
				return nil, err
			}
			if !p.isType(models.TokenTypeRParen) {
				return nil, p.expectedError(") after MATCH_CONDITION")
			}
			p.advance() // )
		}

		var joinCondition ast.Expression
		var joinUsing []ast.Expression
		// MySQL / MariaDB / SQLite: [INNER] JOIN without ON is a cross join.
		if !p.joinConditionOptional(joinType, &jc) || p.isType(models.TokenTypeOn) || p.isType(models.TokenTypeUsing) {
			if joinCondition, joinUsing, err = p.parseJoinCondition(joinType, isNatural, isApply); err != nil {
				return nil, err
			}
		}

		// Build left-side reference (synthetic for chained joins)
		var leftTable ast.TableReference
		if len(joins) == 0 {
			leftTable = firstRef
		} else {
			leftTable = ast.TableReference{
				Name: "(" + firstRef.Name + "_with_" + strconv.Itoa(len(joins)) + "_joins)",
			}
		}

		if cap(joins) == 0 {
			joins = make([]ast.JoinClause, 0, 2)
		}
		jc.Type = joinType
		jc.Left = leftTable
		jc.Right = joinedTableRef
		jc.Condition = joinCondition
		jc.Using = joinUsing
		jc.Pos = joinPos
		joins = append(joins, jc)
	}
	return joins, nil
}

// joinConditionOptional reports whether a join of this type may omit ON /
// USING: MySQL, MariaDB and SQLite treat [INNER] JOIN and STRAIGHT_JOIN
// without a condition as a cross join, and a Snowflake ASOF JOIN needs only
// its MATCH_CONDITION.
func (p *Parser) joinConditionOptional(joinType string, jc *ast.JoinClause) bool {
	if jc.MatchCondition != nil {
		return true
	}
	if jc.Strictness != "" || joinType != "INNER" {
		return false
	}
	return p.isMySQLFamily() || p.dialect == string(keywords.DialectSQLite)
}

// isApplyDialect reports whether CROSS APPLY / OUTER APPLY are accepted
// (SQL Server, Oracle 12c+).
func (p *Parser) isApplyDialect() bool {
	return p.dialect == string(keywords.DialectSQLServer) || p.dialect == string(keywords.DialectOracle)
}

// isExtJoinStart reports whether the current token starts a join written
// with a dialect word that isJoinKeyword does not know: ClickHouse ASOF /
// SEMI / ANTI, Snowflake ASOF, MySQL STRAIGHT_JOIN, Oracle OUTER APPLY.
func (p *Parser) isExtJoinStart() bool {
	switch p.dialect {
	case string(keywords.DialectClickHouse), string(keywords.DialectSnowflake):
		return p.isJoinStrictnessStart()
	case string(keywords.DialectMySQL), string(keywords.DialectMariaDB):
		return p.isUnquotedWord("STRAIGHT_JOIN")
	case string(keywords.DialectOracle):
		return p.isType(models.TokenTypeOuter) && equalsUpper(p.peekToken().Token.Value, "APPLY")
	}
	return false
}

// parseJoinStrictness consumes a ClickHouse join strictness (ANY, ALL,
// ASOF, SEMI, ANTI) or Snowflake ASOF into jc when one is present.
func (p *Parser) parseJoinStrictness(jc *ast.JoinClause) {
	if jc.Strictness != "" {
		return
	}
	switch p.dialect {
	case string(keywords.DialectClickHouse):
		if p.isType(models.TokenTypeAny) || p.isType(models.TokenTypeAll) {
			jc.Strictness = strings.ToUpper(p.currentToken.Token.Value)
			p.advance()
			return
		}
		if p.currentToken.Token.Type == models.TokenTypeIdentifier && !p.isQuotedIdentifierToken() {
			v := p.currentToken.Token.Value
			if equalsUpper(v, "ASOF") || equalsUpper(v, "SEMI") || equalsUpper(v, "ANTI") {
				jc.Strictness = strings.ToUpper(v)
				p.advance()
			}
		}
	case string(keywords.DialectSnowflake):
		if p.isJoinStrictnessStart() {
			jc.Strictness = "ASOF"
			p.advance()
		}
	}
}

// parseJoinType parses the optional NATURAL keyword and the join-type keywords
// (LEFT, RIGHT, FULL, INNER, CROSS, OUTER APPLY, …) that precede the JOIN keyword.
// Returns (joinType string, isNatural bool, err).
func (p *Parser) parseJoinType(jc *ast.JoinClause) (string, bool, error) {
	joinType := "INNER"
	isNatural := false
	explicitType := false // tracks whether a join-type keyword was explicitly given

	// ClickHouse GLOBAL JOIN (distributed join).
	if p.dialect == string(keywords.DialectClickHouse) && p.isTokenMatch("GLOBAL") {
		jc.Global = true
		p.advance()
	}

	// ClickHouse ANY / ALL / ASOF / SEMI / ANTI and Snowflake ASOF written
	// before the join kind: ANY LEFT JOIN, ASOF JOIN.
	p.parseJoinStrictness(jc)

	// MySQL / MariaDB STRAIGHT_JOIN: an inner join that reads the left table first.
	if p.isMySQLFamily() && p.isUnquotedWord("STRAIGHT_JOIN") {
		jc.Hint = "STRAIGHT_JOIN"
		p.advance()
		return joinType, false, nil
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
		if p.isApplyDialect() &&
			p.currentToken.Token.Type == models.TokenTypeIdentifier &&
			strings.ToUpper(p.currentToken.Token.Value) == "APPLY" {
			joinType = "CROSS APPLY"
			p.advance()
		}
	case p.isType(models.TokenTypeOuter) && p.isApplyDialect():
		p.advance()
		if p.currentToken.Token.Type == models.TokenTypeIdentifier &&
			strings.ToUpper(p.currentToken.Token.Value) == "APPLY" {
			joinType = "OUTER APPLY"
			p.advance()
		} else {
			return "", false, p.expectedError("APPLY after OUTER (SQL Server OUTER APPLY)")
		}
	}

	// ClickHouse strictness after the kind: LEFT SEMI JOIN, LEFT ANY JOIN.
	if explicitType {
		p.parseJoinStrictness(jc)
	}

	// SQL Server join hints after an explicit kind: INNER HASH JOIN,
	// LEFT OUTER LOOP JOIN, FULL MERGE JOIN, INNER REMOTE JOIN.
	if explicitType && p.dialect == string(keywords.DialectSQLServer) &&
		p.peekToken().Token.Type == models.TokenTypeJoin {
		if h := ast.JoinHintText(p.currentToken.Token.Value); h != "" {
			jc.Hint = strings.ToUpper(h)
			p.advance()
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
// It returns the ON expression, or for USING (col, ...) a nil expression and
// the column list, one *ast.Identifier per column.
func (p *Parser) parseJoinCondition(joinType string, isNatural, isApply bool) (ast.Expression, []ast.Expression, error) {
	isCrossJoin := joinType == "CROSS" || isApply
	if isCrossJoin || isNatural {
		return nil, nil, nil
	}

	if p.isType(models.TokenTypeOn) {
		p.advance() // Consume ON
		cond, err := p.parseExpression()
		if err != nil {
			return nil, nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("error parsing ON condition for %s JOIN: %v", joinType, err),
				p.currentLocation(),
				"",
			)
		}
		return cond, nil, nil
	}

	if p.isType(models.TokenTypeUsing) {
		p.advance() // Consume USING
		if !p.isType(models.TokenTypeLParen) {
			return nil, nil, p.expectedError("( after USING")
		}
		p.advance()

		var usingColumns []ast.Expression
		for {
			if !p.isIdentifier() {
				return nil, nil, p.expectedError("column name in USING")
			}
			usingColumns = append(usingColumns, p.currentColumnIdent())
			p.advance()
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance()
		}

		if !p.isType(models.TokenTypeRParen) {
			return nil, nil, p.expectedError(") after USING column list")
		}
		p.advance()

		return nil, usingColumns, nil
	}

	return nil, nil, p.expectedError("ON or USING")
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
			"",
		).WithHint("SAMPLE clause requires a numeric argument")
	}

	clause := &ast.SampleClause{Pos: samplePos}

	// Read the primary sampling value (numerator / whole number / float)
	if !p.isNumericLiteral() {
		return nil, goerrors.ExpectedTokenError(
			"numeric literal after SAMPLE",
			p.currentToken.Token.Type.String(),
			p.currentLocation(),
			"",
		).WithHint("SAMPLE clause requires a numeric argument (ratio, row count, or N/D fraction)")
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
				"",
			).WithHint("SAMPLE N/D fraction requires an integer denominator")
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
				"",
			).WithHint("SAMPLE OFFSET requires a numeric argument")
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
					"",
				).WithHint("SAMPLE OFFSET N/D fraction requires an integer denominator")
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
			"",
		).WithHint("PREWHERE clause requires a boolean expression")
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
			"",
		).WithHint("WHERE clause requires a boolean expression")
	}

	return p.parseExpression()
}

// parseGroupByClause parses "GROUP BY <expr> [, ...]" including ROLLUP, CUBE,
// GROUPING SETS, GROUP BY ALL, and the trailing WITH ROLLUP / WITH CUBE /
// WITH TOTALS modifiers, which are stored on stmt.GroupByModifiers.
// Returns nil slice (no error) when GROUP BY is absent.
func (p *Parser) parseGroupByClause(stmt *ast.SelectStatement) ([]ast.Expression, error) {
	if !p.isType(models.TokenTypeGroup) {
		return nil, nil
	}
	p.advance() // Consume GROUP

	if !p.isType(models.TokenTypeBy) {
		return nil, p.expectedError("BY after GROUP")
	}
	p.advance() // Consume BY

	// Snowflake / ClickHouse / BigQuery GROUP BY ALL: group by every
	// non-aggregate select item.
	if p.isType(models.TokenTypeAll) && p.supportsGroupByAll() {
		p.advance() // Consume ALL
		stmt.GroupByModifiers.All = true
		p.parseGroupByWithModifiers(stmt)
		return nil, nil
	}

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

	// MySQL / SQL Server / ClickHouse: GROUP BY col1 WITH ROLLUP / WITH CUBE / WITH TOTALS
	p.parseGroupByWithModifiers(stmt)

	return groupByExprs, nil
}

// supportsGroupByAll reports whether GROUP BY ALL is accepted.
func (p *Parser) supportsGroupByAll() bool {
	switch p.dialect {
	case string(keywords.DialectSnowflake), string(keywords.DialectClickHouse),
		string(keywords.DialectBigQuery):
		return true
	}
	return false
}

// parseGroupByWithModifiers parses the trailing GROUP BY modifiers
// WITH ROLLUP, WITH CUBE and (ClickHouse) WITH TOTALS. They are kept as
// written: MySQL and MariaDB reject the equivalent ROLLUP(...) form.
func (p *Parser) parseGroupByWithModifiers(stmt *ast.SelectStatement) {
	for p.isType(models.TokenTypeWith) {
		next := p.peekToken().Token.Value
		switch {
		case equalsUpper(next, "ROLLUP") && !stmt.GroupByModifiers.WithCube:
			stmt.GroupByModifiers.WithRollup = true
		case equalsUpper(next, "CUBE") && !stmt.GroupByModifiers.WithRollup:
			stmt.GroupByModifiers.WithCube = true
		case equalsUpper(next, "TOTALS"):
			stmt.GroupByModifiers.WithTotals = true
		default:
			return
		}
		p.advance() // Consume WITH
		p.advance() // Consume ROLLUP / CUBE / TOTALS
	}
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
	return p.parseOrderByList()
}

// parseOrderByList parses "BY <expr> [ASC|DESC] ... [, ...]"; the current
// token is BY.
func (p *Parser) parseOrderByList() ([]ast.OrderByExpression, error) {
	if !p.isType(models.TokenTypeBy) {
		return nil, p.expectedError("BY")
	}
	p.advance() // Consume BY

	var orderByExprs []ast.OrderByExpression
	for {
		var expr ast.Expression
		if p.isOrderByAll() {
			// ClickHouse ORDER BY ALL: sort by every selected column.
			expr = &ast.Identifier{Name: p.currentToken.Token.Value, Pos: p.currentLocation()}
			p.advance() // Consume ALL
		} else {
			var err error
			if expr, err = p.parseExpression(); err != nil {
				return nil, err
			}
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
		} else if p.isType(models.TokenTypeUsing) && p.dialect == string(keywords.DialectPostgreSQL) {
			// PostgreSQL ORDER BY expr USING <op>
			op := ast.OrderUsingOperatorText(p.peekToken().Token.Value)
			if op == "" {
				p.advance() // USING
				return nil, p.expectedError("sort operator after USING")
			}
			p.advance() // USING
			p.advance() // operator
			entry.UsingOperator = op
		}

		nullsFirst, err := p.parseNullsClause()
		if err != nil {
			return nil, err
		}
		entry.NullsFirst = nullsFirst

		// ClickHouse WITH FILL per-entry tail:
		//   ORDER BY expr [ASC|DESC] WITH FILL [FROM x] [TO y] [STEP z]
		if p.dialect == string(keywords.DialectClickHouse) &&
			p.isType(models.TokenTypeWith) &&
			strings.EqualFold(p.peekToken().Token.Value, "FILL") {
			fill, err := p.parseClickHouseWithFill()
			if err != nil {
				return nil, err
			}
			entry.WithFill = fill
		}

		orderByExprs = append(orderByExprs, entry)

		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance()
	}
	return orderByExprs, nil
}

// parseClickHouseWithFill consumes "WITH FILL [FROM x] [TO y] [STEP z]" and
// models it into a *ast.WithFillClause so it can round-trip.
func (p *Parser) parseClickHouseWithFill() (*ast.WithFillClause, error) {
	pos := p.currentLocation()
	p.advance() // WITH
	p.advance() // FILL
	fill := &ast.WithFillClause{Pos: pos}
	for {
		v := p.currentToken.Token.Value
		switch {
		case equalsUpper(v, "FROM"):
			p.advance()
			e, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			fill.From = e
		case equalsUpper(v, "TO"):
			p.advance()
			e, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			fill.To = e
		case equalsUpper(v, "STEP"):
			p.advance()
			e, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			fill.Step = e
		default:
			return fill, nil
		}
	}
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

	// Parse the count value: optional (FETCH FIRST ROW ONLY), a plain
	// integer, or an expression (FETCH NEXT @n ROWS ONLY).
	if !p.isAnyType(models.TokenTypeRow, models.TokenTypeRows) {
		n, e, err := p.parseRowCountValue()
		if err != nil {
			return nil, err
		}
		if n != nil {
			fetchVal := int64(*n)
			fetchClause.FetchValue = &fetchVal
		}
		fetchClause.FetchExpr = e
	}

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

	// Parse NOWAIT, WAIT n (Oracle / MariaDB) or SKIP LOCKED
	if p.isTokenMatch("NOWAIT") || p.isUnquotedWord("WAIT") {
		if err := p.parseLockWaitOption(forClause); err != nil {
			return nil, err
		}
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

// parseArrayJoinClause parses ClickHouse [LEFT] ARRAY JOIN expr [AS alias], ...
// Returns nil if the current token is not ARRAY (or LEFT ARRAY).
func (p *Parser) parseArrayJoinClause() (*ast.ArrayJoinClause, error) {
	isLeft := false

	// Detect LEFT ARRAY JOIN
	if p.isType(models.TokenTypeLeft) && p.peekToken().Token.Type == models.TokenTypeArray {
		isLeft = true
	}

	if !p.isType(models.TokenTypeArray) && !isLeft {
		return nil, nil
	}

	pos := p.currentLocation()
	if isLeft {
		p.advance() // Consume LEFT
	}

	// Must be ARRAY
	if !p.isType(models.TokenTypeArray) {
		return nil, nil
	}
	p.advance() // Consume ARRAY

	// Must be JOIN
	if !p.isType(models.TokenTypeJoin) {
		return nil, p.expectedError("JOIN after ARRAY")
	}
	p.advance() // Consume JOIN

	clause := &ast.ArrayJoinClause{Left: isLeft, Pos: pos}
	for {
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		elem := ast.ArrayJoinElement{Expr: expr}
		// Optional alias: AS name or bare name
		if p.isType(models.TokenTypeAs) {
			p.advance() // Consume AS
			if !p.isIdentifier() {
				return nil, p.expectedError("alias after AS in ARRAY JOIN")
			}
			elem.Alias = p.currentToken.Token.Value
			p.advance()
		} else if p.canBeAlias() {
			elem.Alias = p.currentToken.Token.Value
			p.advance()
		}
		clause.Elements = append(clause.Elements, elem)
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance() // Consume comma
	}
	return clause, nil
}

// isOrderByAll reports whether the current token is the ALL of ClickHouse's
// ORDER BY ALL (sort by all selected columns), as opposed to the start of an
// expression: it is followed by ASC, DESC, NULLS, a comma or the end of the
// clause.
func (p *Parser) isOrderByAll() bool {
	if !p.isType(models.TokenTypeAll) || p.dialect != string(keywords.DialectClickHouse) {
		return false
	}
	switch p.peekToken().Token.Type {
	case models.TokenTypeAsc, models.TokenTypeDesc, models.TokenTypeComma, models.TokenTypeSemicolon,
		models.TokenTypeEOF, models.TokenTypeRParen, models.TokenTypeLimit, models.TokenTypeOffset:
		return true
	}
	return equalsUpper(p.peekToken().Token.Value, "NULLS")
}
