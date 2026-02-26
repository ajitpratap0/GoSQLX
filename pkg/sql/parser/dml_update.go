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

// Package parser - dml_update.go
// UPDATE statement parsing.

package parser

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseUpdateStatement parses an UPDATE statement
func (p *Parser) parseUpdateStatement() (ast.Statement, error) {
	// We've already consumed the UPDATE token in matchType

	// Parse table name (supports schema.table qualification and double-quoted identifiers)
	tableName, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.expectedError("table name")
	}

	// Parse SET
	if !p.isType(models.TokenTypeSet) {
		return nil, p.expectedError("SET")
	}
	p.advance() // Consume SET

	// Parse assignments
	updates := make([]ast.UpdateExpression, 0)
	for {
		// Parse column name (supports double-quoted identifiers)
		if !p.isIdentifier() {
			return nil, p.expectedError("column name")
		}
		columnName := p.currentToken.Token.Value
		p.advance()

		if !p.isType(models.TokenTypeEq) {
			return nil, p.expectedError("=")
		}
		p.advance() // Consume =

		// Parse value expression
		var expr ast.Expression
		if p.isStringLiteral() {
			expr = &ast.LiteralValue{Value: p.currentToken.Token.Value, Type: "string"}
			p.advance()
		} else if p.isNumericLiteral() {
			litType := "int"
			if strings.ContainsAny(p.currentToken.Token.Value, ".eE") {
				litType = "float"
			}
			expr = &ast.LiteralValue{Value: p.currentToken.Token.Value, Type: litType}
			p.advance()
		} else if p.isBooleanLiteral() {
			expr = &ast.LiteralValue{Value: p.currentToken.Token.Value, Type: "bool"}
			p.advance()
		} else {
			var err error
			expr, err = p.parseExpression()
			if err != nil {
				return nil, err
			}
		}

		// Create update expression
		columnExpr := &ast.Identifier{Name: columnName}
		updateExpr := ast.UpdateExpression{
			Column: columnExpr,
			Value:  expr,
		}
		updates = append(updates, updateExpr)

		// Check if there are more assignments
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance() // Consume comma
	}

	// Parse WHERE clause if present
	var whereClause ast.Expression
	if p.isType(models.TokenTypeWhere) {
		p.advance() // Consume WHERE
		var err error
		whereClause, err = p.parseExpression()
		if err != nil {
			return nil, err
		}
	}

	// Parse LIMIT clause if present (MySQL)
	if p.isType(models.TokenTypeLimit) {
		p.advance() // Consume LIMIT
		if p.isNumericLiteral() {
			p.advance() // Consume limit value (MySQL UPDATE LIMIT)
		}
	}

	// Parse RETURNING clause if present (PostgreSQL)
	var returning []ast.Expression
	if p.isType(models.TokenTypeReturning) || p.currentToken.Token.Value == "RETURNING" {
		p.advance() // Consume RETURNING
		var err error
		returning, err = p.parseReturningColumns()
		if err != nil {
			return nil, err
		}
	}

	// Create UPDATE statement
	return &ast.UpdateStatement{
		TableName:   tableName,
		Assignments: updates,
		Where:       whereClause,
		Returning:   returning,
	}, nil
}
