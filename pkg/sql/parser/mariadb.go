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

package parser

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// isMariaDB is a convenience helper used throughout the parser.
func (p *Parser) isMariaDB() bool {
	return p.dialect == string(keywords.DialectMariaDB)
}

// parseCreateSequenceStatement parses:
//
//	CREATE [OR REPLACE] SEQUENCE [IF NOT EXISTS] name [options...]
//
// The caller has already consumed CREATE and SEQUENCE.
func (p *Parser) parseCreateSequenceStatement(orReplace bool) (*ast.CreateSequenceStatement, error) {
	stmt := ast.NewCreateSequenceStatement()
	stmt.OrReplace = orReplace

	// IF NOT EXISTS
	if strings.EqualFold(p.currentToken.Token.Value, "IF") {
		p.advance()
		if !strings.EqualFold(p.currentToken.Token.Value, "NOT") {
			return nil, p.expectedError("NOT")
		}
		p.advance()
		if !strings.EqualFold(p.currentToken.Token.Value, "EXISTS") {
			return nil, p.expectedError("EXISTS")
		}
		p.advance()
		stmt.IfNotExists = true
	}

	name := p.parseIdent()
	if name == nil || name.Name == "" {
		return nil, p.expectedError("sequence name")
	}
	stmt.Name = name

	opts, err := p.parseSequenceOptions()
	if err != nil {
		return nil, err
	}
	stmt.Options = opts
	return stmt, nil
}

// parseDropSequenceStatement parses: DROP SEQUENCE [IF EXISTS | IF NOT EXISTS] name
// The caller has already consumed DROP and SEQUENCE.
func (p *Parser) parseDropSequenceStatement() (*ast.DropSequenceStatement, error) {
	stmt := ast.NewDropSequenceStatement()

	if strings.EqualFold(p.currentToken.Token.Value, "IF") {
		p.advance()
		if strings.EqualFold(p.currentToken.Token.Value, "NOT") {
			// IF NOT EXISTS — treated as "no error if absent" (same semantics as IF EXISTS)
			p.advance()
			if !strings.EqualFold(p.currentToken.Token.Value, "EXISTS") {
				return nil, p.expectedError("EXISTS")
			}
			p.advance()
			stmt.IfExists = true
		} else if strings.EqualFold(p.currentToken.Token.Value, "EXISTS") {
			p.advance()
			stmt.IfExists = true
		} else {
			return nil, p.expectedError("EXISTS or NOT EXISTS")
		}
	}

	name := p.parseIdent()
	if name == nil || name.Name == "" {
		return nil, p.expectedError("sequence name")
	}
	stmt.Name = name
	return stmt, nil
}

// parseAlterSequenceStatement parses: ALTER SEQUENCE [IF EXISTS] name [options...]
// The caller has already consumed ALTER and SEQUENCE.
func (p *Parser) parseAlterSequenceStatement() (*ast.AlterSequenceStatement, error) {
	stmt := ast.NewAlterSequenceStatement()

	if strings.EqualFold(p.currentToken.Token.Value, "IF") {
		p.advance()
		if !strings.EqualFold(p.currentToken.Token.Value, "EXISTS") {
			return nil, p.expectedError("EXISTS")
		}
		p.advance()
		stmt.IfExists = true
	}

	name := p.parseIdent()
	if name == nil || name.Name == "" {
		return nil, p.expectedError("sequence name")
	}
	stmt.Name = name

	opts, err := p.parseSequenceOptions()
	if err != nil {
		return nil, err
	}
	stmt.Options = opts
	return stmt, nil
}

// parseSequenceOptions parses sequence option keywords until no more are found.
func (p *Parser) parseSequenceOptions() (ast.SequenceOptions, error) {
	var opts ast.SequenceOptions
	for {
		if p.isType(models.TokenTypeSemicolon) || p.isType(models.TokenTypeEOF) {
			break
		}

		word := strings.ToUpper(p.currentToken.Token.Value)
		switch word {
		case "START":
			p.advance()
			if strings.EqualFold(p.currentToken.Token.Value, "WITH") {
				p.advance()
			}
			lit, err := p.parseNumericLit()
			if err != nil {
				return opts, err
			}
			opts.StartWith = lit
		case "INCREMENT":
			p.advance()
			if strings.EqualFold(p.currentToken.Token.Value, "BY") {
				p.advance()
			}
			lit, err := p.parseNumericLit()
			if err != nil {
				return opts, err
			}
			opts.IncrementBy = lit
		case "MINVALUE":
			p.advance()
			lit, err := p.parseNumericLit()
			if err != nil {
				return opts, err
			}
			opts.MinValue = lit
		case "MAXVALUE":
			p.advance()
			lit, err := p.parseNumericLit()
			if err != nil {
				return opts, err
			}
			opts.MaxValue = lit
		case "NO":
			p.advance()
			sub := strings.ToUpper(p.currentToken.Token.Value)
			p.advance()
			switch sub {
			case "MINVALUE":
				opts.MinValue = nil
			case "MAXVALUE":
				opts.MaxValue = nil
			case "CYCLE":
				opts.NoCycle = true
			case "CACHE":
				opts.Cache = nil
			default:
				return opts, fmt.Errorf("unexpected token after NO in SEQUENCE options: %s", sub)
			}
		case "CYCLE":
			p.advance()
			opts.Cycle = true
		case "NOCYCLE":
			p.advance()
			opts.NoCycle = true
		case "CACHE":
			p.advance()
			lit, err := p.parseNumericLit()
			if err != nil {
				return opts, err
			}
			opts.Cache = lit
		case "NOCACHE":
			p.advance()
			opts.NoCache = true
		case "RESTART":
			p.advance()
			if strings.EqualFold(p.currentToken.Token.Value, "WITH") {
				p.advance()
				lit, err := p.parseNumericLit()
				if err != nil {
					return opts, err
				}
				opts.RestartWith = lit
			} else {
				opts.Restart = true
			}
		default:
			return opts, nil
		}
	}
	return opts, nil
}

// parseNumericLit reads a numeric literal token and returns a LiteralValue.
func (p *Parser) parseNumericLit() (*ast.LiteralValue, error) {
	if !p.isNumericLiteral() {
		return nil, p.expectedError("numeric literal")
	}
	value := p.currentToken.Token.Value
	litType := "int"
	if strings.ContainsAny(value, ".eE") {
		litType = "float"
	}
	p.advance()
	return &ast.LiteralValue{Value: value, Type: litType}, nil
}

// parseForSystemTimeClause parses the FOR SYSTEM_TIME clause that follows a table reference.
// The caller has already consumed FOR.
func (p *Parser) parseForSystemTimeClause() (*ast.ForSystemTimeClause, error) {
	if !strings.EqualFold(p.currentToken.Token.Value, "SYSTEM_TIME") {
		return nil, fmt.Errorf("expected SYSTEM_TIME after FOR, got %q", p.currentToken.Token.Value)
	}
	p.advance()

	clause := &ast.ForSystemTimeClause{}
	word := strings.ToUpper(p.currentToken.Token.Value)

	switch word {
	case "AS":
		p.advance()
		if !strings.EqualFold(p.currentToken.Token.Value, "OF") {
			return nil, fmt.Errorf("expected OF after AS, got %q", p.currentToken.Token.Value)
		}
		p.advance()
		expr, err := p.parseTemporalPointExpression()
		if err != nil {
			return nil, err
		}
		clause.Type = ast.SystemTimeAsOf
		clause.Point = expr
	case "BETWEEN":
		p.advance()
		// Use parsePrimaryExpression to avoid consuming AND as a binary logical operator.
		start, err := p.parseTemporalPointExpression()
		if err != nil {
			return nil, err
		}
		if !strings.EqualFold(p.currentToken.Token.Value, "AND") {
			return nil, fmt.Errorf("expected AND in FOR SYSTEM_TIME BETWEEN, got %q", p.currentToken.Token.Value)
		}
		p.advance()
		end, err := p.parseTemporalPointExpression()
		if err != nil {
			return nil, err
		}
		clause.Type = ast.SystemTimeBetween
		clause.Start = start
		clause.End = end
	case "FROM":
		p.advance()
		start, err := p.parseTemporalPointExpression()
		if err != nil {
			return nil, err
		}
		if !strings.EqualFold(p.currentToken.Token.Value, "TO") {
			return nil, fmt.Errorf("expected TO in FOR SYSTEM_TIME FROM, got %q", p.currentToken.Token.Value)
		}
		p.advance()
		end, err := p.parseTemporalPointExpression()
		if err != nil {
			return nil, err
		}
		clause.Type = ast.SystemTimeFromTo
		clause.Start = start
		clause.End = end
	case "ALL":
		p.advance()
		clause.Type = ast.SystemTimeAll
	default:
		return nil, fmt.Errorf("expected AS OF, BETWEEN, FROM, or ALL after FOR SYSTEM_TIME, got %q", word)
	}
	return clause, nil
}

// parseTemporalPointExpression parses a temporal point expression for FOR SYSTEM_TIME clauses.
// Handles typed string literals like TIMESTAMP '2024-01-01' and DATE '2024-01-01',
// as well as plain string literals and other primary expressions.
func (p *Parser) parseTemporalPointExpression() (ast.Expression, error) {
	// Handle TIMESTAMP 'str', DATE 'str', TIME 'str' typed literals.
	word := strings.ToUpper(p.currentToken.Token.Value)
	if word == "TIMESTAMP" || word == "DATE" || word == "TIME" {
		typeKeyword := p.currentToken.Token.Value
		p.advance()
		if !p.isStringLiteral() {
			return nil, fmt.Errorf("expected string literal after %s, got %q", typeKeyword, p.currentToken.Token.Value)
		}
		// The tokenizer strips surrounding single quotes from string literal tokens,
		// so p.currentToken.Token.Value is the raw string content (e.g. "2023-01-01 00:00:00").
		// We reconstruct the canonical form: TYPE 'value'.
		value := typeKeyword + " '" + p.currentToken.Token.Value + "'"
		p.advance()
		return &ast.LiteralValue{Value: value, Type: "timestamp"}, nil
	}
	// Fall back to primary expression (handles plain string literals, numbers, identifiers).
	return p.parsePrimaryExpression()
}

// parseConnectByCondition parses the condition expression for CONNECT BY.
// It handles the PRIOR prefix operator in either position:
//
//	CONNECT BY PRIOR id = parent_id   (PRIOR on left)
//	CONNECT BY id = PRIOR parent_id   (PRIOR on right)
//
// PRIOR references the value from the parent row in the hierarchy.
// It is modeled as UnaryExpression{Operator: ast.Prior, Expr: <column>}.
func (p *Parser) parseConnectByCondition() (ast.Expression, error) {
	// Case 1: PRIOR col op col
	if strings.EqualFold(p.currentToken.Token.Value, "PRIOR") {
		p.advance()
		priorIdent := p.parseIdent()
		if priorIdent == nil || priorIdent.Name == "" {
			return nil, p.expectedError("column name after PRIOR")
		}
		priorExpr := &ast.UnaryExpression{Operator: ast.Prior, Expr: priorIdent}

		if p.isType(models.TokenTypeEq) || p.isType(models.TokenTypeNeq) ||
			p.isType(models.TokenTypeLt) || p.isType(models.TokenTypeGt) ||
			p.isType(models.TokenTypeLtEq) || p.isType(models.TokenTypeGtEq) {
			op := p.currentToken.Token.Value
			p.advance()
			right, err := p.parsePrimaryExpression()
			if err != nil {
				return nil, err
			}
			return &ast.BinaryExpression{Left: priorExpr, Operator: op, Right: right}, nil
		}
		return priorExpr, nil
	}

	// Case 2: col op PRIOR col  (PRIOR on the right-hand side)
	left, err := p.parsePrimaryExpression()
	if err != nil {
		return nil, err
	}
	if p.isType(models.TokenTypeEq) || p.isType(models.TokenTypeNeq) ||
		p.isType(models.TokenTypeLt) || p.isType(models.TokenTypeGt) ||
		p.isType(models.TokenTypeLtEq) || p.isType(models.TokenTypeGtEq) {
		op := p.currentToken.Token.Value
		p.advance()
		// Check for PRIOR on the right side
		if strings.EqualFold(p.currentToken.Token.Value, "PRIOR") {
			p.advance()
			priorIdent := p.parseIdent()
			if priorIdent == nil || priorIdent.Name == "" {
				return nil, p.expectedError("column name after PRIOR")
			}
			priorExpr := &ast.UnaryExpression{Operator: ast.Prior, Expr: priorIdent}
			return &ast.BinaryExpression{Left: left, Operator: op, Right: priorExpr}, nil
		}
		right, err := p.parsePrimaryExpression()
		if err != nil {
			return nil, err
		}
		return &ast.BinaryExpression{Left: left, Operator: op, Right: right}, nil
	}
	return left, nil
}

// parsePeriodDefinition parses: PERIOD FOR name (start_col, end_col)
// The caller positions the parser at the PERIOD keyword; this function advances past it.
func (p *Parser) parsePeriodDefinition() (*ast.PeriodDefinition, error) {
	// current token is PERIOD; advance past it
	p.advance()
	if !strings.EqualFold(p.currentToken.Token.Value, "FOR") {
		return nil, p.expectedError("FOR")
	}
	p.advance()

	name := p.parseIdent()
	if name == nil || name.Name == "" {
		return nil, p.expectedError("period name")
	}

	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("(")
	}
	p.advance()

	startCol := p.parseIdent()
	if startCol == nil || startCol.Name == "" {
		return nil, p.expectedError("start column name")
	}

	if !p.isType(models.TokenTypeComma) {
		return nil, p.expectedError(",")
	}
	p.advance()

	endCol := p.parseIdent()
	if endCol == nil || endCol.Name == "" {
		return nil, p.expectedError("end column name")
	}

	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance()

	return &ast.PeriodDefinition{Name: name, StartCol: startCol, EndCol: endCol}, nil
}
