// Package parser - cte.go
// Common Table Expression (CTE) parsing with recursive CTE support.

package parser

import (
	"fmt"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// WITH summary(region, total) AS (SELECT region, SUM(amount) FROM sales GROUP BY region) SELECT * FROM summary
func (p *Parser) parseWithStatement() (ast.Statement, error) {
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
				models.Location{},
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
	}

	// Parse the main statement that follows the WITH clause
	mainStmt, err := p.parseMainStatementAfterWith()
	if err != nil {
		return nil, goerrors.InvalidCTEError(
			fmt.Sprintf("error parsing statement after WITH clause: %v", err),
			models.Location{},
			"",
		)
	}

	// Attach WITH clause to the main statement
	switch stmt := mainStmt.(type) {
	case *ast.SelectStatement:
		stmt.With = withClause
		return stmt, nil
	case *ast.SetOperation:
		// For set operations, attach WITH to the left statement if it's a SELECT
		if leftSelect, ok := stmt.Left.(*ast.SelectStatement); ok {
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
			models.Location{},
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
			models.Location{},
			"",
		)
	}

	// Parse CTE name (supports double-quoted identifiers and non-reserved keywords)
	if !p.isIdentifier() && !p.isNonReservedKeyword() {
		return nil, p.expectedError("CTE name")
	}
	name := p.currentToken.Literal
	p.advance()

	// Parse optional column list
	var columns []string
	if p.isType(models.TokenTypeLParen) {
		p.advance() // Consume (

		for {
			if !p.isIdentifier() {
				return nil, p.expectedError("column name")
			}
			columns = append(columns, p.currentToken.Literal)
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

	// Parse the inner statement - handle SELECT with set operations support
	var stmt ast.Statement
	var err error

	if p.isType(models.TokenTypeSelect) {
		// For SELECT statements, use parseSelectWithSetOperations to support UNION, EXCEPT, INTERSECT
		p.advance() // Consume SELECT
		stmt, err = p.parseSelectWithSetOperations()
	} else {
		// For other statement types (INSERT, UPDATE, DELETE, WITH), use parseStatement
		stmt, err = p.parseStatement()
	}

	if err != nil {
		return nil, goerrors.InvalidCTEError(
			fmt.Sprintf("error parsing CTE subquery: %v", err),
			models.Location{},
			"",
		)
	}

	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") after CTE query")
	}
	p.advance() // Consume )

	return &ast.CommonTableExpr{
		Name:         name,
		Columns:      columns,
		Statement:    stmt,
		Materialized: materialized,
	}, nil
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
