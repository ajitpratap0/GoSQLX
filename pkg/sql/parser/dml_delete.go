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

// Package parser - dml_delete.go
// DELETE statement parsing.

package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseDeleteStatement parses a DELETE statement
func (p *Parser) parseDeleteStatement() (ast.Statement, error) {
	// We've already consumed the DELETE token in matchType

	// Parse FROM
	if !p.isType(models.TokenTypeFrom) {
		return nil, p.expectedError("FROM")
	}
	p.advance() // Consume FROM

	// Parse table name (supports schema.table qualification and double-quoted identifiers)
	tableName, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.expectedError("table name")
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
			p.advance() // Consume limit value
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

	// Create DELETE statement
	return &ast.DeleteStatement{
		TableName: tableName,
		Where:     whereClause,
		Returning: returning,
	}, nil
}
