// Package parser - grouping.go
// SQL-99 advanced grouping operations: GROUPING SETS, ROLLUP, CUBE.

package parser

import (
	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// used by ROLLUP and CUBE. Returns error if the list is empty.
func (p *Parser) parseGroupingExpressionList(keyword string) ([]ast.Expression, error) {
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("( after " + keyword)
	}
	p.advance() // Consume (

	// Check for empty list - not allowed for ROLLUP/CUBE
	if p.isType(models.TokenTypeRParen) {
		// TODO: Add position tracking to parser for accurate error locations
		return nil, goerrors.InvalidSyntaxError(
			keyword+" requires at least one expression",
			models.Location{}, // TODO: Track token positions in parser
			"",                // TODO: Preserve original SQL in parser
		)
	}

	// Parse comma-separated expressions
	expressions := make([]ast.Expression, 0)
	for {
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		expressions = append(expressions, expr)

		// Check for comma (more expressions) or closing paren
		if p.isType(models.TokenTypeRParen) {
			break
		}
		if !p.isType(models.TokenTypeComma) {
			return nil, p.expectedError(", or ) in " + keyword)
		}
		p.advance() // Consume comma
	}
	p.advance() // Consume )

	return expressions, nil
}

// parseRollup parses ROLLUP(col1, col2, ...) in GROUP BY clause
// ROLLUP generates hierarchical grouping sets from right to left
// Example: ROLLUP(a, b, c) generates: (a, b, c), (a, b), (a), ()
func (p *Parser) parseRollup() (*ast.RollupExpression, error) {
	p.advance() // Consume ROLLUP

	expressions, err := p.parseGroupingExpressionList("ROLLUP")
	if err != nil {
		return nil, err
	}

	return &ast.RollupExpression{
		Expressions: expressions,
	}, nil
}

// parseCube parses CUBE(col1, col2, ...) in GROUP BY clause
// CUBE generates all possible combinations of grouping sets
// Example: CUBE(a, b) generates: (a, b), (a), (b), ()
func (p *Parser) parseCube() (*ast.CubeExpression, error) {
	p.advance() // Consume CUBE

	expressions, err := p.parseGroupingExpressionList("CUBE")
	if err != nil {
		return nil, err
	}

	return &ast.CubeExpression{
		Expressions: expressions,
	}, nil
}

// parseGroupingSets parses GROUPING SETS(...) in GROUP BY clause
// Allows explicit specification of grouping sets
// Example: GROUPING SETS((a, b), (a), ()) generates exactly those three grouping sets
func (p *Parser) parseGroupingSets() (*ast.GroupingSetsExpression, error) {
	// Handle both "GROUPING SETS" as compound keyword or separate tokens
	if p.currentToken.Literal == "GROUPING SETS" {
		p.advance() // Consume "GROUPING SETS" compound token
	} else if p.isType(models.TokenTypeGrouping) {
		p.advance() // Consume GROUPING
		// Check for SETS - using literal comparison as fallback since SETS is not a standalone token type
		if p.currentToken.Literal != "SETS" && p.currentToken.Type != "SETS" {
			return nil, p.expectedError("SETS after GROUPING")
		}
		p.advance() // Consume SETS
	}

	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("( after GROUPING SETS")
	}
	p.advance() // Consume (

	// Parse comma-separated grouping sets
	sets := make([][]ast.Expression, 0)
	for {
		// Each set is either:
		// 1. A parenthesized list: (col1, col2)
		// 2. An empty set: ()
		// 3. A single column without parens: col1 (treated as (col1))

		var set []ast.Expression
		if p.isType(models.TokenTypeLParen) {
			p.advance() // Consume (
			// Parse expressions in this set
			set = make([]ast.Expression, 0)
			// Handle empty set: ()
			if !p.isType(models.TokenTypeRParen) {
				for {
					expr, err := p.parseExpression()
					if err != nil {
						return nil, err
					}
					set = append(set, expr)

					if p.isType(models.TokenTypeRParen) {
						break
					}
					if !p.isType(models.TokenTypeComma) {
						return nil, p.expectedError(", or ) in grouping set")
					}
					p.advance() // Consume comma
				}
			}
			p.advance() // Consume )
		} else {
			// Single column without parens
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			set = []ast.Expression{expr}
		}
		sets = append(sets, set)

		// Check for comma (more sets) or closing paren
		if p.isType(models.TokenTypeRParen) {
			break
		}
		if !p.isType(models.TokenTypeComma) {
			return nil, p.expectedError(", or ) in GROUPING SETS")
		}
		p.advance() // Consume comma
	}
	p.advance() // Consume )

	return &ast.GroupingSetsExpression{
		Sets: sets,
	}, nil
}
