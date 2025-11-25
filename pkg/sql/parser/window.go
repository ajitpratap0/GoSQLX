// Package parser - window.go
// Window function parsing for the SQL parser.
// Includes OVER clause, PARTITION BY, ORDER BY, and frame specifications.

package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// SUM(salary) OVER (PARTITION BY dept ORDER BY date ROWS UNBOUNDED PRECEDING) -> window function with frame
func (p *Parser) parseFunctionCall(funcName string) (*ast.FunctionCall, error) {
	// Expect opening parenthesis
	if p.currentToken.Type != "(" {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	// Parse function arguments
	var arguments []ast.Expression
	var distinct bool

	// Check for DISTINCT keyword
	if p.currentToken.Type == "DISTINCT" {
		distinct = true
		p.advance()
	}

	// Parse arguments if not empty
	if p.currentToken.Type != ")" {
		for {
			arg, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			arguments = append(arguments, arg)

			// Check for comma or end of arguments
			if p.currentToken.Type == "," {
				p.advance() // Consume comma
			} else if p.currentToken.Type == ")" {
				break
			} else {
				return nil, p.expectedError(", or )")
			}
		}
	}

	// Expect closing parenthesis
	if p.currentToken.Type != ")" {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )

	// Create function call
	funcCall := &ast.FunctionCall{
		Name:      funcName,
		Arguments: arguments,
		Distinct:  distinct,
	}

	// Check for OVER clause (window function)
	if p.currentToken.Type == "OVER" {
		p.advance() // Consume OVER

		windowSpec, err := p.parseWindowSpec()
		if err != nil {
			return nil, err
		}
		funcCall.Over = windowSpec
	}

	return funcCall, nil
}

// parseWindowSpec parses a window specification (PARTITION BY, ORDER BY, frame clause)
func (p *Parser) parseWindowSpec() (*ast.WindowSpec, error) {
	// Expect opening parenthesis
	if p.currentToken.Type != "(" {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	windowSpec := &ast.WindowSpec{}

	// Parse PARTITION BY clause
	if p.currentToken.Type == "PARTITION" {
		p.advance() // Consume PARTITION
		if p.currentToken.Type != "BY" {
			return nil, p.expectedError("BY after PARTITION")
		}
		p.advance() // Consume BY

		// Parse partition expressions
		for {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			windowSpec.PartitionBy = append(windowSpec.PartitionBy, expr)

			if p.currentToken.Type == "," {
				p.advance() // Consume comma
			} else {
				break
			}
		}
	}

	// Parse ORDER BY clause
	if p.currentToken.Type == "ORDER" {
		p.advance() // Consume ORDER
		if p.currentToken.Type != "BY" {
			return nil, p.expectedError("BY after ORDER")
		}
		p.advance() // Consume BY

		// Parse order expressions
		for {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}

			// Create OrderByExpression with defaults
			orderByExpr := ast.OrderByExpression{
				Expression: expr,
				Ascending:  true, // Default to ASC
				NullsFirst: nil,  // Default behavior (database-specific)
			}

			// Check for ASC/DESC after the expression
			if p.currentToken.Type == "ASC" {
				orderByExpr.Ascending = true
				p.advance() // Consume ASC
			} else if p.currentToken.Type == "DESC" {
				orderByExpr.Ascending = false
				p.advance() // Consume DESC
			}

			// Check for NULLS FIRST/LAST
			nullsFirst, err := p.parseNullsClause()
			if err != nil {
				return nil, err
			}
			orderByExpr.NullsFirst = nullsFirst

			windowSpec.OrderBy = append(windowSpec.OrderBy, orderByExpr)

			if p.currentToken.Type == "," {
				p.advance() // Consume comma
			} else {
				break
			}
		}
	}

	// Parse frame clause (ROWS/RANGE with bounds)
	if p.currentToken.Type == "ROWS" || p.currentToken.Type == "RANGE" {
		frameType := p.currentToken.Literal
		p.advance() // Consume ROWS/RANGE

		frameClause, err := p.parseWindowFrame(frameType)
		if err != nil {
			return nil, err
		}
		windowSpec.FrameClause = frameClause
	}

	// Expect closing parenthesis
	if p.currentToken.Type != ")" {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )

	return windowSpec, nil
}

// parseWindowFrame parses a window frame clause
func (p *Parser) parseWindowFrame(frameType string) (*ast.WindowFrame, error) {
	frame := &ast.WindowFrame{
		Type: frameType,
	}

	// Parse frame bounds
	if p.currentToken.Type == "BETWEEN" {
		p.advance() // Consume BETWEEN

		// Parse start bound
		startBound, err := p.parseFrameBound()
		if err != nil {
			return nil, err
		}
		frame.Start = *startBound

		// Expect AND
		if p.currentToken.Type != "AND" {
			return nil, p.expectedError("AND")
		}
		p.advance() // Consume AND

		// Parse end bound
		endBound, err := p.parseFrameBound()
		if err != nil {
			return nil, err
		}
		frame.End = endBound
	} else {
		// Single bound (implies CURRENT ROW as end)
		startBound, err := p.parseFrameBound()
		if err != nil {
			return nil, err
		}
		frame.Start = *startBound
		// End is nil for single bound
	}

	return frame, nil
}

// parseFrameBound parses a window frame bound
func (p *Parser) parseFrameBound() (*ast.WindowFrameBound, error) {
	bound := &ast.WindowFrameBound{}

	if p.currentToken.Type == "UNBOUNDED" {
		p.advance() // Consume UNBOUNDED
		if p.currentToken.Type == "PRECEDING" {
			bound.Type = "UNBOUNDED PRECEDING"
			p.advance() // Consume PRECEDING
		} else if p.currentToken.Type == "FOLLOWING" {
			bound.Type = "UNBOUNDED FOLLOWING"
			p.advance() // Consume FOLLOWING
		} else {
			return nil, p.expectedError("PRECEDING or FOLLOWING after UNBOUNDED")
		}
	} else if p.currentToken.Type == "CURRENT" {
		p.advance() // Consume CURRENT
		if p.currentToken.Type != "ROW" {
			return nil, p.expectedError("ROW after CURRENT")
		}
		bound.Type = "CURRENT ROW"
		p.advance() // Consume ROW
	} else {
		// Numeric bound
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		bound.Value = expr

		if p.currentToken.Type == "PRECEDING" {
			bound.Type = "PRECEDING"
			p.advance() // Consume PRECEDING
		} else if p.currentToken.Type == "FOLLOWING" {
			bound.Type = "FOLLOWING"
			p.advance() // Consume FOLLOWING
		} else {
			return nil, p.expectedError("PRECEDING or FOLLOWING after numeric value")
		}
	}

	return bound, nil
}

// parseNullsClause parses the optional NULLS FIRST/LAST clause in ORDER BY expressions.
// Returns a pointer to bool indicating null ordering: true for NULLS FIRST, false for NULLS LAST, nil if not specified.
func (p *Parser) parseNullsClause() (*bool, error) {
	if p.currentToken.Type == "NULLS" {
		p.advance() // Consume NULLS
		if p.currentToken.Type == "FIRST" {
			t := true
			p.advance() // Consume FIRST
			return &t, nil
		} else if p.currentToken.Type == "LAST" {
			f := false
			p.advance() // Consume LAST
			return &f, nil
		} else {
			return nil, p.expectedError("FIRST or LAST after NULLS")
		}
	}
	return nil, nil
}

// parseGroupingExpressionList parses a parenthesized, comma-separated list of expressions
