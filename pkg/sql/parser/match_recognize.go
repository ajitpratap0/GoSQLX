// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

// Package parser - match_recognize.go
// SQL:2016 MATCH_RECOGNIZE clause for row-pattern recognition (Snowflake, Oracle).

package parser

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// isMatchRecognizeKeyword returns true if the current token is the contextual
// MATCH_RECOGNIZE keyword in a dialect that supports it.
//
// Migrated from p.dialect == "snowflake"/"oracle" to Capabilities in
// Sprint 2. SupportsMatchRecognize is true only for Oracle and Snowflake
// in dialect.Capabilities, preserving the exact previous behaviour.
func (p *Parser) isMatchRecognizeKeyword() bool {
	if !p.Capabilities().SupportsMatchRecognize {
		return false
	}
	return strings.EqualFold(p.currentToken.Token.Value, "MATCH_RECOGNIZE")
}

// parseMatchRecognize parses the MATCH_RECOGNIZE clause. The current token
// must be MATCH_RECOGNIZE.
//
// Grammar:
//
//	MATCH_RECOGNIZE (
//	    [PARTITION BY expr, ...]
//	    [ORDER BY expr [ASC|DESC], ...]
//	    [MEASURES measure_expr AS alias, ...]
//	    [ONE ROW PER MATCH | ALL ROWS PER MATCH]
//	    [AFTER MATCH SKIP ...]
//	    PATTERN ( pattern_regex )
//	    DEFINE var AS condition, ...
//	)
func (p *Parser) parseMatchRecognize() (*ast.MatchRecognizeClause, error) {
	pos := p.currentLocation()
	p.advance() // Consume MATCH_RECOGNIZE

	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("( after MATCH_RECOGNIZE")
	}
	p.advance() // Consume (

	clause := &ast.MatchRecognizeClause{Pos: pos}

	// Parse sub-clauses in order. Each is optional except PATTERN and DEFINE.
	// PARTITION BY
	if p.isType(models.TokenTypePartition) {
		p.advance() // PARTITION
		if p.isType(models.TokenTypeBy) {
			p.advance() // BY
		}
		for {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			clause.PartitionBy = append(clause.PartitionBy, expr)
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance()
		}
	}

	// ORDER BY
	if p.isType(models.TokenTypeOrder) {
		p.advance() // ORDER
		if p.isType(models.TokenTypeBy) {
			p.advance() // BY
		}
		for {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			entry := ast.OrderByExpression{Expression: expr, Ascending: true}
			if p.isType(models.TokenTypeAsc) {
				p.advance()
			} else if p.isType(models.TokenTypeDesc) {
				entry.Ascending = false
				p.advance()
			}
			clause.OrderBy = append(clause.OrderBy, entry)
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance()
		}
	}

	// MEASURES
	if strings.EqualFold(p.currentToken.Token.Value, "MEASURES") {
		p.advance() // MEASURES
		for {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			alias := ""
			if p.isType(models.TokenTypeAs) {
				p.advance() // AS
				alias = p.currentToken.Token.Value
				p.advance() // alias name
			}
			clause.Measures = append(clause.Measures, ast.MeasureDef{
				Expr:  expr,
				Alias: alias,
			})
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance()
		}
	}

	// ONE ROW PER MATCH / ALL ROWS PER MATCH
	if strings.EqualFold(p.currentToken.Token.Value, "ONE") {
		clause.RowsPerMatch = "ONE ROW PER MATCH"
		p.advance() // ONE
		p.advance() // ROW
		p.advance() // PER
		p.advance() // MATCH
	} else if p.isType(models.TokenTypeAll) {
		clause.RowsPerMatch = "ALL ROWS PER MATCH"
		p.advance() // ALL
		p.advance() // ROWS
		p.advance() // PER
		p.advance() // MATCH
	}

	// AFTER MATCH SKIP ... — consume as raw text until PATTERN or DEFINE
	if strings.EqualFold(p.currentToken.Token.Value, "AFTER") {
		var parts []string
		for {
			val := strings.ToUpper(p.currentToken.Token.Value)
			if val == "PATTERN" || val == "DEFINE" {
				break
			}
			if p.isType(models.TokenTypeEOF) || p.isType(models.TokenTypeRParen) {
				break
			}
			parts = append(parts, p.currentToken.Token.Value)
			p.advance()
		}
		clause.AfterMatch = strings.Join(parts, " ")
	}

	// PATTERN ( regex )
	if strings.EqualFold(p.currentToken.Token.Value, "PATTERN") {
		p.advance() // PATTERN
		if !p.isType(models.TokenTypeLParen) {
			return nil, p.expectedError("( after PATTERN")
		}
		p.advance() // Consume (

		// Collect pattern tokens as raw text until the matching ')'
		var patParts []string
		depth := 1
		for depth > 0 {
			if p.isType(models.TokenTypeEOF) {
				return nil, p.expectedError(") to close PATTERN")
			}
			if p.isType(models.TokenTypeLParen) {
				depth++
				patParts = append(patParts, "(")
			} else if p.isType(models.TokenTypeRParen) {
				depth--
				if depth > 0 {
					patParts = append(patParts, ")")
				}
			} else {
				patParts = append(patParts, p.currentToken.Token.Value)
			}
			p.advance()
		}
		clause.Pattern = strings.Join(patParts, " ")
	}

	// DEFINE var AS condition, ...
	if strings.EqualFold(p.currentToken.Token.Value, "DEFINE") {
		p.advance() // DEFINE
		for {
			if p.isType(models.TokenTypeRParen) || p.isType(models.TokenTypeEOF) {
				break
			}
			name := p.currentToken.Token.Value
			p.advance() // variable name

			if !p.isType(models.TokenTypeAs) {
				return nil, p.expectedError("AS after pattern variable " + name)
			}
			p.advance() // AS

			cond, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			clause.Definitions = append(clause.Definitions, ast.PatternDef{
				Name:      name,
				Condition: cond,
			})
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance()
		}
	}

	// Expect closing )
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") to close MATCH_RECOGNIZE")
	}
	p.advance() // Consume )

	return clause, nil
}
