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

// parseCreateIndex parses CREATE [UNIQUE] [kind] INDEX after the INDEX
// keyword:
//
//	[CONCURRENTLY] [IF NOT EXISTS] [name] ON [ONLY] table [USING method]
//	(element [, ...]) [INCLUDE (cols)] [options] [WHERE predicate] [options]
//
// where an element is a column or an expression with optional COLLATE,
// operator class, ASC | DESC and NULLS FIRST | LAST.
func (p *Parser) parseCreateIndex(unique bool) (*ast.CreateIndexStatement, error) {
	stmt := &ast.CreateIndexStatement{
		Unique: unique,
	}

	if p.wordAt(0) == "CONCURRENTLY" {
		p.advance()
		stmt.Concurrently = true
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

	// Parse index name (supports schema.index qualification and double-quoted
	// identifiers). PostgreSQL allows the name to be omitted.
	if !p.isType(models.TokenTypeOn) || stmt.IfNotExists {
		indexName, indexQuote, err := p.parseQualifiedNameQuoted()
		if err != nil {
			return nil, p.qualifiedNameError(err, "index name")
		}
		stmt.Name = indexName
		stmt.NameQuote = indexQuote
	}

	// Expect ON
	if !p.isType(models.TokenTypeOn) {
		return nil, p.expectedError("ON")
	}
	p.advance() // Consume ON
	if p.isType(models.TokenTypeOnly) {
		p.advance()
		stmt.Only = true
	}

	// Parse table name (supports schema.table qualification and double-quoted identifiers)
	indexTableName, indexTableQuote, err := p.parseQualifiedNameQuoted()
	if err != nil {
		return nil, p.qualifiedNameError(err, "table name")
	}
	stmt.Table = indexTableName
	stmt.TableQuote = indexTableQuote

	// Parse optional USING method (hash is a keyword)
	if p.isType(models.TokenTypeUsing) {
		p.advance() // Consume USING
		if p.wordAt(0) == "" && !p.isIdentifier() {
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

	// Parse the index elements
	for {
		col, err := p.parseIndexElement()
		if err != nil {
			return nil, err
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

	// INCLUDE (cols): PostgreSQL / SQL Server covering columns
	if p.wordAt(0) == "INCLUDE" && p.peekToken().Token.Type == models.TokenTypeLParen {
		p.advance() // INCLUDE
		p.advance() // (
		for {
			name := p.parseColumnName()
			if name == nil {
				return nil, p.expectedError("column name")
			}
			stmt.IncludeQuotes = nameQuoteList(stmt.IncludeQuotes, len(stmt.Include), name.Quotes)
			stmt.Include = append(stmt.Include, name.Name)
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance()
		}
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance()
	}

	if stmt.Options, err = p.parseTableOptions(indexOptionSpecs, stmt.Options); err != nil {
		return nil, err
	}
	stmt.OptionsBeforeWhere = len(stmt.Options)

	// Parse optional WHERE clause (partial index)
	if p.isType(models.TokenTypeWhere) {
		p.advance() // Consume WHERE
		whereClause, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		stmt.Where = whereClause
		if stmt.Options, err = p.parseTableOptions(indexOptionSpecs, stmt.Options); err != nil {
			return nil, err
		}
	}

	return stmt, nil
}

// parseIndexElement parses one CREATE INDEX element: a column or an
// expression, then [COLLATE c] [opclass] [ASC | DESC] [NULLS FIRST | LAST].
func (p *Parser) parseIndexElement() (ast.IndexColumn, error) {
	col := ast.IndexColumn{}
	if p.isIdentifier() && p.isIndexElementEnd(1) {
		col.Column = p.currentToken.Token.Value
		col.ColumnQuote = p.currentNameQuote()
		p.advance()
	} else {
		e, err := p.parseExpression()
		if err != nil {
			return col, err
		}
		if id, ok := e.(*ast.Identifier); ok && id.Table == "" && !id.Quoted {
			col.Column = id.Name
			col.ColumnQuote = id.Quotes
		} else {
			col.Expr = e
		}
	}

	// Parse optional COLLATE (SQLite, PostgreSQL): col COLLATE NOCASE
	if p.isType(models.TokenTypeCollate) {
		p.advance() // Consume COLLATE
		if !p.isIdentifier() && !p.isNonReservedKeyword() && p.wordAt(0) == "" {
			return col, p.expectedError("collation name")
		}
		col.Collate = p.currentToken.Token.Value
		col.CollateQuoted = p.isType(models.TokenTypeDoubleQuotedString)
		p.advance()
	}

	// PostgreSQL operator class: (attrs jsonb_path_ops)
	if p.isIdentifier() && !p.isQuotedIdentifierToken() && p.isIndexElementEnd(1) {
		col.OpClass = p.currentToken.Token.Value
		p.advance()
	}

	// Parse optional direction
	if p.isType(models.TokenTypeAsc) {
		col.Direction = "ASC"
		p.advance()
	} else if p.isType(models.TokenTypeDesc) {
		col.Direction = "DESC"
		p.advance()
	}

	// Parse optional NULLS FIRST / NULLS LAST
	if p.isType(models.TokenTypeNulls) {
		p.advance() // Consume NULLS
		if p.isType(models.TokenTypeLast) {
			col.NullsLast = true
			p.advance()
		} else if p.isType(models.TokenTypeFirst) {
			col.NullsFirst = true
			p.advance()
		} else {
			return col, p.expectedError("FIRST or LAST after NULLS")
		}
	}
	return col, nil
}

// isIndexElementEnd reports whether the token n positions ahead ends an
// index element's leading column or operator class.
func (p *Parser) isIndexElementEnd(n int) bool {
	switch p.tokenAt(n).Token.Type {
	case models.TokenTypeComma, models.TokenTypeRParen, models.TokenTypeAsc,
		models.TokenTypeDesc, models.TokenTypeNulls, models.TokenTypeCollate:
		return true
	case models.TokenTypeIdentifier:
		// column followed by an operator class
		next := p.tokenAt(n + 1).Token.Type
		return n == 1 && (next == models.TokenTypeComma || next == models.TokenTypeRParen ||
			next == models.TokenTypeAsc || next == models.TokenTypeDesc || next == models.TokenTypeNulls)
	}
	return false
}
