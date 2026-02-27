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

// Package parser - ddl_index.go
// CREATE INDEX parsing.

package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseCreateIndex parses CREATE [UNIQUE] INDEX statement
func (p *Parser) parseCreateIndex(unique bool) (*ast.CreateIndexStatement, error) {
	stmt := &ast.CreateIndexStatement{
		Unique: unique,
	}

	// Check for IF NOT EXISTS
	if p.isType(models.TokenTypeIf) {
		p.advance() // Consume IF
		if !p.isType(models.TokenTypeNot) {
			return nil, p.expectedError("NOT after IF")
		}
		p.advance() // Consume NOT
		if !p.isType(models.TokenTypeExists) {
			return nil, p.expectedError("EXISTS after NOT")
		}
		p.advance() // Consume EXISTS
		stmt.IfNotExists = true
	}

	// Parse index name (supports schema.index qualification and double-quoted identifiers)
	indexName, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.expectedError("index name")
	}
	stmt.Name = indexName

	// Expect ON
	if !p.isType(models.TokenTypeOn) {
		return nil, p.expectedError("ON")
	}
	p.advance() // Consume ON

	// Parse table name (supports schema.table qualification and double-quoted identifiers)
	indexTableName, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.expectedError("table name")
	}
	stmt.Table = indexTableName

	// Parse optional USING
	if p.isType(models.TokenTypeUsing) {
		p.advance() // Consume USING
		if !p.isIdentifier() {
			return nil, p.expectedError("index method")
		}
		stmt.Using = p.currentToken.Token.Value
		p.advance()
	}

	// Expect opening parenthesis
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	// Parse column list
	for {
		col := ast.IndexColumn{}
		if !p.isIdentifier() {
			return nil, p.expectedError("column name")
		}
		col.Column = p.currentToken.Token.Value
		p.advance()

		// Parse optional direction
		if p.isType(models.TokenTypeAsc) {
			col.Direction = "ASC"
			p.advance()
		} else if p.isType(models.TokenTypeDesc) {
			col.Direction = "DESC"
			p.advance()
		}

		// Parse optional NULLS LAST
		if p.isType(models.TokenTypeNulls) {
			p.advance() // Consume NULLS
			if p.isType(models.TokenTypeLast) {
				col.NullsLast = true
				p.advance()
			} else if p.isType(models.TokenTypeFirst) {
				p.advance()
			}
		}

		stmt.Columns = append(stmt.Columns, col)

		if p.isType(models.TokenTypeComma) {
			p.advance() // Consume comma
			continue
		}
		break
	}

	// Expect closing parenthesis
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )

	// Parse optional WHERE clause (partial index)
	if p.isType(models.TokenTypeWhere) {
		p.advance() // Consume WHERE
		whereClause, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		stmt.Where = whereClause
	}

	return stmt, nil
}
