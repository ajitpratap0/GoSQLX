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

// Package parser - cte.go
// Common Table Expression (CTE) parsing with recursive CTE support.

package parser

import (
	"fmt"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// WITH summary(region, total) AS (SELECT region, SUM(amount) FROM sales GROUP BY region) SELECT * FROM summary
func (p *Parser) parseWithStatement() (ast.Statement, error) {
	withPos := p.currentLocation()
	// Consume WITH
	p.advance()

	// Check for RECURSIVE keyword
	recursive := false
	if p.isType(models.TokenTypeRecursive) {
		recursive = true
		p.advance()
	}

	// Parse Common Table Expressions
	ctes := []*ast.CommonTableExpr{}

	for {
		cte, err := p.parseCommonTableExpr()
		if err != nil {
			return nil, goerrors.InvalidCTEError(
				fmt.Sprintf("error parsing CTE definition: %v", err),
				p.currentLocation(),
				"",
			)
		}
		ctes = append(ctes, cte)

		// Check for more CTEs (comma-separated)
		if p.isType(models.TokenTypeComma) {
			p.advance() // Consume comma
			continue
		}
		break
	}

	// Create WITH clause
	withClause := &ast.WithClause{
		Recursive: recursive,
		CTEs:      ctes,
		Pos:       withPos,
	}

	// A parenthesized query after the WITH clause: WITH c AS (...) (A UNION B)
	// INTERSECT C. The clause scopes over the whole query expression.
	if p.isType(models.TokenTypeLParen) {
		return p.parseWithParenthesizedQuery(withClause)
	}

	// Parse the main statement that follows the WITH clause
	mainStmt, err := p.parseMainStatementAfterWith()
	if err != nil {
		return nil, goerrors.InvalidCTEError(
			fmt.Sprintf("error parsing statement after WITH clause: %v", err),
			p.currentLocation(),
			"",
		)
	}

	// Attach WITH clause to the main statement
	switch stmt := mainStmt.(type) {
	case *ast.SelectStatement:
		stmt.With = withClause
		return stmt, nil
	case *ast.SetOperation:
		// For set operations, attach WITH to the leftmost SELECT. Chained
		// operators (A UNION B UNION C) nest as ((A UNION B) UNION C), so walk
		// down the Left links to the first operand.
		left := stmt.Left
		for {
			inner, ok := left.(*ast.SetOperation)
			if !ok {
				break
			}
			left = inner.Left
		}
		if leftSelect, ok := left.(*ast.SelectStatement); ok {
			leftSelect.With = withClause
		}
		return stmt, nil
	case *ast.InsertStatement:
		stmt.With = withClause
		return stmt, nil
	case *ast.UpdateStatement:
		stmt.With = withClause
		return stmt, nil
	case *ast.DeleteStatement:
		stmt.With = withClause
		return stmt, nil
	default:
		return nil, goerrors.InvalidCTEError(
			fmt.Sprintf("WITH clause not supported with statement type: %T", stmt),
			p.currentLocation(),
			"",
		)
	}
}

// parseCommonTableExpr parses a single Common Table Expression.
// It handles CTE name, optional column list, AS keyword, and the CTE query in parentheses.
//
// Syntax: cte_name [(column_list)] AS (query)
func (p *Parser) parseCommonTableExpr() (*ast.CommonTableExpr, error) {
	// Check recursion depth to prevent stack overflow in recursive CTEs
	// This is critical since CTEs can call parseStatement which leads back to more CTEs
	p.depth++
	defer func() { p.depth-- }()

	if p.depth > MaxRecursionDepth {
		return nil, goerrors.InvalidCTEError(
			fmt.Sprintf("maximum recursion depth exceeded (%d) - CTE too deeply nested", MaxRecursionDepth),
			p.currentLocation(),
			"",
		)
	}

	// ClickHouse scalar CTE: WITH <expr> AS <name>, ...
	// Detected when the token after WITH is not an identifier, or is an
	// identifier not followed by AS/( (which would be a standard CTE).
	if p.dialect == string(keywords.DialectClickHouse) && !p.isIdentifier() && !p.isCTENameStart() {
		scalarExpr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		if !p.isType(models.TokenTypeAs) {
			return nil, p.expectedError("AS after scalar CTE expression")
		}
		p.advance() // Consume AS
		if !p.isIdentifier() {
			return nil, p.expectedError("name after AS in scalar CTE")
		}
		scalarName := p.currentToken.Token.Value
		scalarPos := p.currentLocation()
		scalarQuote := p.currentNameQuote()
		p.advance()
		return &ast.CommonTableExpr{
			Name:       scalarName,
			ScalarExpr: scalarExpr,
			Pos:        scalarPos,
			NameQuote:  scalarQuote,
		}, nil
	}

	// Parse CTE name (supports double-quoted identifiers and keywords
	// used as names: WITH source AS (...), WITH final AS (...))
	if !p.isIdentifier() && !p.isCTENameStart() {
		return nil, p.expectedError("CTE name")
	}
	cteNamePos := p.currentLocation()
	name := p.currentToken.Token.Value
	nameQuote := p.currentNameQuote()
	p.advance()

	// Parse optional column list
	var columns []string
	var columnQuotes []ast.NameQuote
	if p.isType(models.TokenTypeLParen) {
		// "name (SELECT ...)" is a CTE missing its AS keyword, not a column
		// list; report the missing AS instead of "expected column name" (#537).
		if next := p.peekToken().Token.Type; next == models.TokenTypeSelect || next == models.TokenTypeWith {
			return nil, p.expectedError("AS")
		}
		p.advance() // Consume (

		for {
			if !p.isIdentifier() {
				return nil, p.expectedError("column name")
			}
			columnQuotes = nameQuoteList(columnQuotes, len(columns), p.currentNameQuote())
			columns = append(columns, p.currentToken.Token.Value)
			p.advance()

			if p.isType(models.TokenTypeComma) {
				p.advance() // Consume comma
				continue
			}
			break
		}

		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
	}

	// Parse AS keyword
	if !p.isType(models.TokenTypeAs) {
		return nil, p.expectedError("AS")
	}
	p.advance()

	// Parse optional MATERIALIZED / NOT MATERIALIZED
	// Syntax: AS [NOT] MATERIALIZED (query)
	var materialized *bool
	if p.isType(models.TokenTypeNot) {
		p.advance() // Consume NOT
		if !p.isType(models.TokenTypeMaterialized) {
			return nil, p.expectedError("MATERIALIZED after NOT")
		}
		p.advance() // Consume MATERIALIZED
		notMaterialized := false
		materialized = &notMaterialized
	} else if p.isType(models.TokenTypeMaterialized) {
		p.advance() // Consume MATERIALIZED
		isMaterialized := true
		materialized = &isMaterialized
	}

	// Parse the CTE query (must be in parentheses)
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("( before CTE query")
	}
	p.advance() // Consume (

	// A CTE body is a nested scope: the INSERT-source RETURNING stop does not
	// apply inside it (#610).
	prevReturning := p.dmlReturning
	p.dmlReturning = false
	defer func() { p.dmlReturning = prevReturning }()

	// Parse the inner statement - handle SELECT with set operations support
	var stmt ast.Statement
	var err error

	if p.isType(models.TokenTypeSelect) {
		// For SELECT statements, use parseSelectWithSetOperations to support UNION, EXCEPT, INTERSECT
		p.advance() // Consume SELECT
		stmt, err = p.parseSelectWithSetOperations()
	} else if p.isAnyType(models.TokenTypeValues, models.TokenTypeLParen) {
		// VALUES body or a parenthesized query expression:
		// WITH c AS (VALUES (1), (2)), WITH c AS ((SELECT 1) UNION SELECT 2)
		stmt, err = p.parseQueryExpression("CTE query")
	} else {
		// For other statement types (INSERT, UPDATE, DELETE, WITH), use parseStatement
		stmt, err = p.parseStatement()
	}

	if err != nil {
		return nil, goerrors.InvalidCTEError(
			fmt.Sprintf("error parsing CTE subquery: %v", err),
			p.currentLocation(),
			"",
		)
	}

	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") after CTE query")
	}
	p.advance() // Consume )

	cte := &ast.CommonTableExpr{
		Name:         name,
		Columns:      columns,
		Statement:    stmt,
		Materialized: materialized,
		Pos:          cteNamePos,
		NameQuote:    nameQuote,
		ColumnQuotes: columnQuotes,
	}
	// SQL:1999 SEARCH / CYCLE clauses of a recursive CTE.
	if err := p.parseCTESearchCycle(cte); err != nil {
		return nil, err
	}
	return cte, nil
}

// parseMainStatementAfterWith parses the main statement after WITH clause.
// It supports SELECT, INSERT, UPDATE, and DELETE statements, routing them to the appropriate
// parsers while preserving set operation support for SELECT statements.
func (p *Parser) parseMainStatementAfterWith() (ast.Statement, error) {
	if p.isType(models.TokenTypeSelect) {
		p.advance() // Consume SELECT
		return p.parseSelectWithSetOperations()
	} else if p.isType(models.TokenTypeInsert) {
		p.advance() // Consume INSERT
		return p.parseInsertStatement()
	} else if p.isType(models.TokenTypeUpdate) {
		p.advance() // Consume UPDATE
		return p.parseUpdateStatement()
	} else if p.isType(models.TokenTypeDelete) {
		p.advance() // Consume DELETE
		return p.parseDeleteStatement()
	}
	return nil, p.expectedError("SELECT, INSERT, UPDATE, or DELETE after WITH")
}

// parseWithParenthesizedQuery parses the query expression after a WITH clause
// when it starts with "(", as in
//
//	WITH c AS (SELECT 1 AS a) (SELECT a FROM c UNION SELECT a FROM c) INTERSECT SELECT a FROM c
//
// The WITH clause is attached to the first SELECT of the query expression, as
// for an unparenthesized one, and the set operation that owns the
// parenthesized operand records that the clause was written outside the
// parentheses (SetOperation.LeftWithHoisted), so that renderers keep it in
// scope of the other operands. A first SELECT that has a WITH clause of its
// own is rejected.
func (p *Parser) parseWithParenthesizedQuery(with *ast.WithClause) (ast.Statement, error) {
	wrap := func(err error) error {
		return goerrors.InvalidCTEError(
			fmt.Sprintf("error parsing statement after WITH clause: %v", err),
			p.currentLocation(),
			"",
		)
	}
	q, err := p.parseParenthesizedQuery("SELECT after WITH")
	if err != nil {
		return nil, wrap(err)
	}
	stmt, err := p.parseSetOperationChain(q, true)
	if err != nil {
		return nil, wrap(err)
	}

	// The first SELECT of the whole expression takes the WITH clause.
	var first ast.Statement = stmt
	for {
		op, ok := first.(*ast.SetOperation)
		if !ok || op == nil {
			break
		}
		first = op.Left
	}
	sel, ok := first.(*ast.SelectStatement)
	if !ok || sel == nil || sel.With != nil {
		return nil, goerrors.UnsupportedFeatureError(
			"WITH clause before a parenthesized query that is not a SELECT or already has its own WITH clause",
			p.currentLocation(),
			"",
		)
	}
	sel.With = with

	// The operation whose left operand is the parenthesized query is the
	// innermost one of the left spine that was written with parentheses.
	for cur := stmt; ; {
		op, ok := cur.(*ast.SetOperation)
		if !ok || op == nil {
			break
		}
		if op.LeftParenthesized {
			op.LeftWithHoisted = true
			break
		}
		cur = op.Left
	}
	return stmt, nil
}
