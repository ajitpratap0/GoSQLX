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

// Package parser - pragma.go
// SQLite PRAGMA statement parsing.

package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parsePragmaStatement parses a SQLite PRAGMA statement.
// Handles: PRAGMA name | PRAGMA name(arg) | PRAGMA name = value
//
// Examples:
//
//	PRAGMA table_info(users)
//	PRAGMA journal_mode = WAL
//	PRAGMA integrity_check
func (p *Parser) parsePragmaStatement() (*ast.PragmaStatement, error) {
	stmt := &ast.PragmaStatement{}

	// The PRAGMA keyword has already been consumed by the caller.
	// Current token should be the pragma name (identifier or non-reserved keyword).
	if !p.isIdentifier() && !p.isNonReservedKeyword() && !p.isType(models.TokenTypeKeyword) {
		return nil, p.expectedError("PRAGMA name")
	}
	stmt.Name = p.currentToken.Token.Value
	p.advance()

	switch {
	case p.isType(models.TokenTypeLParen):
		p.advance() // consume (
		if !p.isType(models.TokenTypeEOF) && !p.isType(models.TokenTypeRParen) {
			stmt.Arg = p.currentToken.Token.Value
			p.advance()
		}
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // consume )
	case p.isType(models.TokenTypeEq) || p.isType(models.TokenTypeAssignment):
		p.advance() // consume =
		if !p.isType(models.TokenTypeEOF) && !p.isType(models.TokenTypeSemicolon) {
			stmt.Value = p.currentToken.Token.Value
			p.advance()
		}
	}

	return stmt, nil
}
