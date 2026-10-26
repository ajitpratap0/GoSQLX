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

		// Check if this is a subquery (starts with SELECT, WITH, VALUES or
		// a nested parenthesized query)
		if !p.isDerivedTableQueryStart() {
			return tableRef, p.expectedError("SELECT in derived table")
		}

		// Parse the subquery: a full query expression (set operations,
		// WITH, nested parentheses)
		subquery, err := p.parseDerivedTableQuery()
		if err != nil {
			return tableRef, err
		}

		// Expect closing parenthesis
		if !p.isType(models.TokenTypeRParen) {
			return tableRef, p.expectedError(")")
		}
		p.advance() // Consume )

		tableRef = ast.TableReference{Lateral: isLateral}
		if err := p.setDerivedQuery(&tableRef, subquery); err != nil {
			return tableRef, err
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
			stageName += p.parseStagePathSegment()
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
	} else if p.IsSnowflake() && p.isType(models.TokenTypeValues) &&
		p.peekToken().Token.Type == models.TokenTypeLParen {
		// Snowflake: FROM VALUES (1, 'a'), (2, 'b') AS v (id, name)
		values, err := p.parseValuesQuery()
		if err != nil {
			return tableRef, err
		}
		tableRef = ast.TableReference{Lateral: isLateral, Modifiers: &ast.TableModifiers{Values: values}}
	} else if p.isClickHouseKeywordTableFunction() {
		// ClickHouse table function named by a keyword token: url(...),
		// merge(...), values(...), null(...).
		funcName := p.currentToken.Token.Value
		p.advance() // Consume the function name
		funcCall, ferr := p.parseFunctionCall(funcName)
		if ferr != nil {
			return tableRef, ferr
		}
		tableRef = ast.TableReference{
			Name:      funcName,
			Lateral:   isLateral,
			TableFunc: funcCall,
		}
	} else {
		only := p.parseTableOnly()
		// Parse regular table name (supports schema.table qualification)
		qualifiedName, nameQuote, err := p.parseTableNameQuoted()
		if err != nil {
			return tableRef, err
		}

		tableRef = ast.TableReference{
			Name:      qualifiedName,
			NameQuote: nameQuote,
			Lateral:   isLateral,
			Only:      only,
		}
		p.parseOracleDBLink(&tableRef)

		// Function-call table reference (Snowflake FLATTEN, TABLE(...),
		// IDENTIFIER(...), PostgreSQL unnest(...), BigQuery UNNEST(...),
		// ClickHouse numbers(...), remote(...)).
		// If the parsed name is followed by '(' at FROM position, reparse
		// it as a function call. Gated to dialects that actually use this.
		if err := p.parseTableFunctionCall(&tableRef); err != nil {
			return tableRef, err
		}
	}

	// Nothing else belongs to the reference at a table-reference end.
	if p.atTableRefEnd() {
		return tableRef, nil
	}

	// Modifiers between the table and its alias: PARTITION (...), FOR
	// SYSTEM_TIME, Snowflake AT / BEFORE / CHANGES, SAMPLE / TABLESAMPLE,
	// Oracle flashback.
	if err := p.parseTableModifiersBeforeAlias(&tableRef); err != nil {
		return tableRef, err
	}

	// Check for table alias (required for derived tables, optional for regular tables).
	// Guard: in MariaDB, CONNECT followed by BY is a hierarchical query clause, not an alias.
	// Similarly, START followed by WITH is a hierarchical query seed, not an alias.
	// Don't consume PIVOT/UNPIVOT as a table alias — they are contextual
	// keywords in SQL Server/Oracle and must reach the pivot-clause parser below.
	if (p.isIdentifier() || p.isType(models.TokenTypeAs)) && !p.isMariaDBClauseStart() && !p.isPivotKeyword() && !p.isUnpivotKeyword() && !p.isQualifyKeyword() && !p.isMinusSetOp() && !p.isSnowflakeTimeTravelStart() && !p.isSampleKeyword() && !p.isMatchRecognizeKeyword() && !p.isWindowClauseKeyword() && !p.isSettingsKeyword() && !p.isDMLReturningKeyword() && !p.isSelectExtClauseStart() && !p.isTableModifierAfterAliasStart() && !p.isTSQLStatementStart() {
		if p.isType(models.TokenTypeAs) {
			p.advance() // Consume AS
			if !p.isIdentifier() {
				return tableRef, p.expectedError("alias after AS")
			}
		}
		if p.isIdentifier() {
			tableRef.Alias = p.currentToken.Token.Value
			tableRef.AliasQuote = p.currentNameQuote()
			p.advance()
			if err := p.parseTableColumnAliases(&tableRef); err != nil {
				return tableRef, err
			}
		}
	}

	if p.atTableRefEnd() {
		return tableRef, nil
	}

	// Modifiers after the alias: TABLESAMPLE, FINAL, index hints, INDEXED
	// BY, SQL Server (NOLOCK).
	if err := p.parseTableModifiersAfterAlias(&tableRef); err != nil {
		return tableRef, err
	}

	// FOR SYSTEM_TIME after the alias (accepted for compatibility; MariaDB
	// and SQL Server write it before the alias).
	if tableRef.ForSystemTime == nil && p.isForSystemTimeStart() {
		p.advance() // Consume FOR
		sysTime, err := p.parseForSystemTimeClause()
		if err != nil {
			return tableRef, err
		}
		tableRef.ForSystemTime = sysTime
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

	// SQL Server / Oracle / Snowflake PIVOT or UNPIVOT clause
	if err := p.parsePivotSuffix(&tableRef); err != nil {
		return tableRef, err
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
			tableRef.AliasQuote = p.currentNameQuote()
			p.advance()
		}
	}

	return tableRef, nil
}

// parseDerivedTableQuery parses the query of a derived table (the current
// token is SELECT, WITH or a nested "(") one recursion level deeper, so
// nested derived tables are bounded by MaxRecursionDepth. This path does not
// pass through parseExpression, which guards other nesting.
func (p *Parser) parseDerivedTableQuery() (ast.Statement, error) {
	// A derived table is a nested scope: the INSERT-source RETURNING stop
	// does not apply inside it (#610).
	prev := p.dmlReturning
	p.dmlReturning = false
	defer func() { p.dmlReturning = prev }()
	err := p.enterRecursion()
	defer p.leaveRecursion()
	if err != nil {
		return nil, err
	}
	return p.parseQueryExpression("SELECT in derived table")
}

// setDerivedQuery stores a derived-table query on ref: a single SELECT in
// Subquery, a set operation in SetSubquery.
func (p *Parser) setDerivedQuery(ref *ast.TableReference, q ast.Statement) error {
	switch s := q.(type) {
	case *ast.SelectStatement:
		ref.Subquery = s
	case *ast.SetOperation:
		ref.SetSubquery = s
	case *ast.Values:
		ref.EnsureModifiers().Values = s
	default:
		return p.expectedError("SELECT statement in derived table")
	}
	return nil
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

	if !isLateral && p.isParenthesizedJoinStart() {
		// Parenthesized joined table as a join operand: a JOIN (b JOIN c ON
		// ...) ON ..., t1 LEFT JOIN (t2, t3) ON ...
		return p.parseJoinGroup()
	}

	if p.isType(models.TokenTypeLParen) {
		// Derived table (subquery)
		p.advance() // Consume (

		if !p.isDerivedTableQueryStart() {
			return ref, p.expectedError("SELECT in derived table")
		}

		subquery, err := p.parseDerivedTableQuery()
		if err != nil {
			return ref, err
		}

		if !p.isType(models.TokenTypeRParen) {
			return ref, p.expectedError(")")
		}
		p.advance() // Consume )

		ref = ast.TableReference{Lateral: isLateral}
		if err := p.setDerivedQuery(&ref, subquery); err != nil {
			return ref, err
		}
	} else {
		only := p.parseTableOnly()
		joinedName, joinedQuote, err := p.parseTableNameQuoted()
		if isQualifiedNameTooLong(err) {
			return ref, err
		}
		if err != nil {
			return ref, goerrors.ExpectedTokenError(
				"table name after "+joinType+" JOIN",
				p.currentToken.Token.Type.String(),
				p.currentLocation(),
				"",
			)
		}
		ref = ast.TableReference{Name: joinedName, NameQuote: joinedQuote, Lateral: isLateral, Only: only}
		p.parseOracleDBLink(&ref)
		if err := p.parseApplyFunctionCall(joinType, &ref); err != nil {
			return ref, err
		}
		if err := p.parseTableFunctionCall(&ref); err != nil {
			return ref, err
		}
	}

	// Nothing else belongs to the reference at a table-reference end.
	if p.atTableRefEnd() {
		return ref, nil
	}

	if err := p.parseTableModifiersBeforeAlias(&ref); err != nil {
		return ref, err
	}

	// Optional alias.
	// Guard: in MariaDB, CONNECT followed by BY is a hierarchical query clause, not an alias.
	// Similarly, START followed by WITH is a hierarchical query seed, not an alias.
	// Don't consume PIVOT/UNPIVOT as a table alias — they are contextual
	// keywords in SQL Server/Oracle and must reach the pivot-clause parser below.
	if (p.isIdentifier() || p.isType(models.TokenTypeAs)) && !p.isMariaDBClauseStart() && !p.isPivotKeyword() && !p.isUnpivotKeyword() && !p.isQualifyKeyword() && !p.isMinusSetOp() && !p.isSnowflakeTimeTravelStart() && !p.isSampleKeyword() && !p.isMatchRecognizeKeyword() && !p.isWindowClauseKeyword() && !p.isSettingsKeyword() && !p.isDMLReturningKeyword() && !p.isSelectExtClauseStart() && !p.isTableModifierAfterAliasStart() && !p.isTSQLStatementStart() {
		if p.isType(models.TokenTypeAs) {
			p.advance()
			if !p.isIdentifier() {
				return ref, p.expectedError("alias after AS")
			}
		}
		if p.isIdentifier() {
			ref.Alias = p.currentToken.Token.Value
			ref.AliasQuote = p.currentNameQuote()
			p.advance()
			if err := p.parseTableColumnAliases(&ref); err != nil {
				return ref, err
			}
		}
	}

	if p.atTableRefEnd() {
		return ref, nil
	}

	// Modifiers after the alias: TABLESAMPLE, FINAL, index hints, INDEXED
	// BY, SQL Server (NOLOCK).
	if err := p.parseTableModifiersAfterAlias(&ref); err != nil {
		return ref, err
	}

	// FOR SYSTEM_TIME after the alias (accepted for compatibility; MariaDB
	// and SQL Server write it before the alias).
	if ref.ForSystemTime == nil && p.isForSystemTimeStart() {
		p.advance() // Consume FOR
		sysTime, err := p.parseForSystemTimeClause()
		if err != nil {
			return ref, err
		}
		ref.ForSystemTime = sysTime
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

	// SQL Server / Oracle / Snowflake PIVOT or UNPIVOT clause
	if err := p.parsePivotSuffix(&ref); err != nil {
		return ref, err
	}

	return ref, nil
}

// parseTableFunctionCall keeps FROM and JOIN function-call references under
// the same dialect gate and preserves their arguments for AST consumers.
func (p *Parser) parseTableFunctionCall(ref *ast.TableReference) error {
	if !p.isType(models.TokenTypeLParen) || !p.acceptsTableFunctionCall() || p.isBareTableHintListStart() {
		return nil
	}
	call, err := p.parseFunctionCall(ref.Name)
	if err != nil {
		return err
	}
	call.NameQuote = ref.NameQuote
	ref.TableFunc = call
	// PostgreSQL: unnest(arr) WITH ORDINALITY. The other table-function
	// dialects have no such modifier (BigQuery spells it WITH OFFSET after
	// the alias), so it stays PostgreSQL-only.
	if p.IsPostgreSQL() && p.isType(models.TokenTypeWith) &&
		strings.EqualFold(p.peekToken().Token.Value, "ORDINALITY") {
		p.advance() // Consume WITH
		p.advance() // Consume ORDINALITY
		ref.WithOrdinality = true
	}
	return nil
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
		// Only bare-word hints (NOLOCK, ROWLOCK, ...) are accepted. Quoted,
		// bracketed or string-literal tokens lose their delimiters in the
		// token value, and operators such as INDEX = ix do not fit the
		// []string representation, so rendering them back would not
		// reproduce the source (and could inject SQL).
		if !p.isBareTableHintToken() {
			return nil, p.expectedError("table hint inside WITH (...)")
		}
		hint := strings.ToUpper(p.currentToken.Token.Value)
		p.advance()
		if p.isAnyType(models.TokenTypeLParen, models.TokenTypeEq) {
			// INDEX(ix [, ix]), INDEX = ix, FORCESEEK(ix): stored as "INDEX(ix)".
			args, err := p.parseTableHintArgs()
			if err != nil {
				return nil, err
			}
			hint += args
		}
		hints = append(hints, hint)
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

// isBareTableHintToken reports whether the current token is an unquoted
// identifier or keyword spelled [A-Za-z_][A-Za-z0-9_]*.
func (p *Parser) isBareTableHintToken() bool {
	tok := p.currentToken.Token
	if tok.Quote != 0 || (tok.Word != nil && tok.Word.QuoteStyle != 0) {
		return false
	}
	if p.isStringLiteral() || p.isType(models.TokenTypeDoubleQuotedString) {
		return false
	}
	v := tok.Value
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// parseJoinGroup parses a parenthesized joined table that is the operand of a
// JOIN, with the current token at "(":
//
//	a JOIN (b JOIN c ON b.id = c.b_id) ON a.id = b.a_id
//	t1 LEFT JOIN (t2, t3) ON t1.id = t2.id
//
// Unlike a group at the left-most position of a FROM clause, which
// parseParenthesizedJoin flattens, the group is kept whole: the ON condition
// after it may only see the group as a unit, and outer joins inside and
// outside it do not associate freely. It takes no alias.
func (p *Parser) parseJoinGroup() (ast.TableReference, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > MaxRecursionDepth {
		return ast.TableReference{}, goerrors.RecursionDepthLimitError(
			p.depth, MaxRecursionDepth, p.currentLocation(), "")
	}

	p.advance() // Consume (
	first, joins, err := p.parseFromItem()
	if err != nil {
		return ast.TableReference{}, err
	}
	tables, joins, err := p.parseTableListAndJoins(&first, joins)
	if err != nil {
		return ast.TableReference{}, err
	}
	if !p.isType(models.TokenTypeRParen) {
		return ast.TableReference{}, p.expectedError(") or JOIN")
	}
	p.advance() // Consume )

	if p.isType(models.TokenTypeAs) || p.isIdentifier() && !p.isJoinKeyword() {
		return ast.TableReference{}, goerrors.UnsupportedFeatureError(
			"alias after a parenthesized join group",
			p.currentLocation(),
			"",
		)
	}
	return ast.TableReference{Modifiers: &ast.TableModifiers{
		Group: &ast.JoinGroup{Tables: tables, Joins: joins},
	}}, nil
}
