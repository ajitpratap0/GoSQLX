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

// Package parser - ddl_view.go
// CREATE VIEW and CREATE MATERIALIZED VIEW parsing (including REFRESH).

package parser

import (
	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseCreateView parses CREATE [OR REPLACE] [TEMPORARY] VIEW statement
func (p *Parser) parseCreateView(orReplace, temporary bool) (*ast.CreateViewStatement, error) {
	stmt := &ast.CreateViewStatement{
		OrReplace: orReplace,
		Temporary: temporary,
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

	// Parse view name (supports schema.view qualification and double-quoted identifiers)
	viewName, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.expectedError("view name")
	}
	stmt.Name = viewName

	// Parse optional column list
	if p.isType(models.TokenTypeLParen) {
		p.advance() // Consume (
		for {
			if !p.isIdentifier() {
				return nil, p.expectedError("column name")
			}
			stmt.Columns = append(stmt.Columns, p.currentToken.Token.Value)
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

	// Expect AS
	if !p.isType(models.TokenTypeAs) {
		return nil, p.expectedError("AS")
	}
	p.advance() // Consume AS

	// Parse the SELECT statement
	if !p.isType(models.TokenTypeSelect) {
		return nil, p.expectedError("SELECT")
	}
	p.advance() // Consume SELECT

	query, err := p.parseSelectWithSetOperations()
	if err != nil {
		return nil, goerrors.WrapError(
			goerrors.ErrCodeInvalidSyntax,
			"error parsing view query",
			models.Location{}, // Location not available in current parser implementation
			"",                // SQL not available in current parser implementation
			err,
		)
	}
	stmt.Query = query

	// Parse optional WITH CHECK OPTION
	if p.isType(models.TokenTypeWith) {
		p.advance() // Consume WITH
		if p.isType(models.TokenTypeCheck) {
			p.advance() // Consume CHECK
			if p.isTokenMatch("OPTION") {
				p.advance() // Consume OPTION
				stmt.WithOption = "CHECK OPTION"
			}
		} else if p.isTokenMatch("CASCADED") {
			p.advance() // Consume CASCADED
			if p.isType(models.TokenTypeCheck) {
				p.advance() // Consume CHECK
				if p.isTokenMatch("OPTION") {
					p.advance() // Consume OPTION
					stmt.WithOption = "CASCADED CHECK OPTION"
				}
			}
		} else if p.isTokenMatch("LOCAL") {
			p.advance() // Consume LOCAL
			if p.isType(models.TokenTypeCheck) {
				p.advance() // Consume CHECK
				if p.isTokenMatch("OPTION") {
					p.advance() // Consume OPTION
					stmt.WithOption = "LOCAL CHECK OPTION"
				}
			}
		}
	}

	return stmt, nil
}

// parseCreateMaterializedView parses CREATE MATERIALIZED VIEW statement
func (p *Parser) parseCreateMaterializedView() (*ast.CreateMaterializedViewStatement, error) {
	stmt := &ast.CreateMaterializedViewStatement{}

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

	// Parse view name (supports schema.view qualification and double-quoted identifiers)
	matViewName, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.expectedError("materialized view name")
	}
	stmt.Name = matViewName

	// Parse optional column list
	if p.isType(models.TokenTypeLParen) {
		p.advance() // Consume (
		for {
			if !p.isIdentifier() {
				return nil, p.expectedError("column name")
			}
			stmt.Columns = append(stmt.Columns, p.currentToken.Token.Value)
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

	// Parse optional TABLESPACE
	if p.isTokenMatch("TABLESPACE") {
		p.advance() // Consume TABLESPACE
		if !p.isIdentifier() {
			return nil, p.expectedError("tablespace name")
		}
		stmt.Tablespace = p.currentToken.Token.Value
		p.advance()
	}

	// ClickHouse: optional TO <table> before ENGINE/AS
	if p.dialect == string(keywords.DialectClickHouse) && p.isType(models.TokenTypeTo) {
		p.advance() // Consume TO
		toName, toErr := p.parseQualifiedName()
		if toErr != nil {
			return nil, p.expectedError("target table after TO")
		}
		stmt.Tablespace = toName // reuse Tablespace for ClickHouse TO
	}

	// ClickHouse: optional ENGINE = ... ORDER BY ... before AS SELECT
	if p.dialect == string(keywords.DialectClickHouse) {
		for p.isTokenMatch("ENGINE") || p.isType(models.TokenTypeOrder) || p.isTokenMatch("PRIMARY") || p.isTokenMatch("PARTITION") || p.isTokenMatch("SETTINGS") {
			// Consume all engine clauses token-by-token until AS
			for !p.isType(models.TokenTypeAs) && !p.isType(models.TokenTypeEOF) && !p.isType(models.TokenTypeSemicolon) {
				p.advance()
			}
		}
	}

	// Expect AS
	if !p.isType(models.TokenTypeAs) {
		return nil, p.expectedError("AS")
	}
	p.advance() // Consume AS

	// Parse the SELECT statement
	if !p.isType(models.TokenTypeSelect) {
		return nil, p.expectedError("SELECT")
	}
	p.advance() // Consume SELECT

	query, err := p.parseSelectWithSetOperations()
	if err != nil {
		return nil, goerrors.WrapError(
			goerrors.ErrCodeInvalidSyntax,
			"error parsing materialized view query",
			models.Location{}, // Location not available in current parser implementation
			"",                // SQL not available in current parser implementation
			err,
		)
	}
	stmt.Query = query

	// Parse optional WITH [NO] DATA
	// Note: DATA and NO may be tokenized as IDENT since they're common identifiers
	if p.isType(models.TokenTypeWith) {
		p.advance() // Consume WITH
		if p.isTokenMatch("NO") {
			p.advance() // Consume NO
			if !p.isTokenMatch("DATA") {
				return nil, p.expectedError("DATA after NO")
			}
			p.advance() // Consume DATA
			withData := false
			stmt.WithData = &withData
		} else if p.isTokenMatch("DATA") {
			p.advance() // Consume DATA
			withData := true
			stmt.WithData = &withData
		}
	}

	return stmt, nil
}

// parseRefreshStatement parses REFRESH MATERIALIZED VIEW statement
func (p *Parser) parseRefreshStatement() (*ast.RefreshMaterializedViewStatement, error) {
	// Expect MATERIALIZED
	if !p.isType(models.TokenTypeMaterialized) {
		return nil, p.expectedError("MATERIALIZED after REFRESH")
	}
	p.advance() // Consume MATERIALIZED

	// Expect VIEW
	if !p.isType(models.TokenTypeView) {
		return nil, p.expectedError("VIEW after MATERIALIZED")
	}
	p.advance() // Consume VIEW

	stmt := &ast.RefreshMaterializedViewStatement{}

	// Check for CONCURRENTLY
	if p.isTokenMatch("CONCURRENTLY") {
		stmt.Concurrently = true
		p.advance()
	}

	// Parse view name (supports schema.view qualification and double-quoted identifiers)
	refreshViewName, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.expectedError("materialized view name")
	}
	stmt.Name = refreshViewName

	// Parse optional WITH [NO] DATA
	// Note: DATA and NO may be tokenized as IDENT since they're common identifiers
	if p.isType(models.TokenTypeWith) {
		p.advance() // Consume WITH
		if p.isTokenMatch("NO") {
			p.advance() // Consume NO
			if !p.isTokenMatch("DATA") {
				return nil, p.expectedError("DATA after NO")
			}
			p.advance() // Consume DATA
			withData := false
			stmt.WithData = &withData
		} else if p.isTokenMatch("DATA") {
			p.advance() // Consume DATA
			withData := true
			stmt.WithData = &withData
		}
	}

	return stmt, nil
}
