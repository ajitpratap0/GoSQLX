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

// Package parser - dml_replace.go
// MySQL / MariaDB / SQLite REPLACE statement parsing.

package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseReplaceStatement parses a REPLACE statement (the REPLACE token has
// been consumed):
//
//	REPLACE [INTO] t [(cols)] VALUES (...), ... [RETURNING ...]
//	REPLACE [INTO] t [(cols)] SELECT ...         [RETURNING ...]
//	REPLACE [INTO] t SET col = expr, ...         [RETURNING ...]
//
// INTO is optional in MySQL and MariaDB; RETURNING is MariaDB 10.5+.
func (p *Parser) parseReplaceStatement() (ast.Statement, error) {
	if p.isType(models.TokenTypeInto) {
		p.advance() // Consume INTO
	} else if !p.isMySQLFamily() {
		return nil, p.expectedError("INTO")
	}

	tableName, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.qualifiedNameError(err, "table name")
	}

	var columns []ast.Expression
	if p.isType(models.TokenTypeLParen) && !p.isInsertQueryParenStart() {
		columns, err = p.parseInsertColumnList()
		if err != nil {
			return nil, err
		}
	}

	var (
		values    [][]ast.Expression
		query     ast.QueryExpression
		setSyntax bool
	)
	switch {
	case p.isType(models.TokenTypeValues):
		p.advance() // Consume VALUES
		values, err = p.parseInsertValueRows()
	case p.isType(models.TokenTypeSelect), p.isType(models.TokenTypeWith), p.isInsertQueryParenStart():
		query, err = p.parseInsertQuery()
	case p.isType(models.TokenTypeSet) && len(columns) == 0:
		p.advance() // Consume SET
		var row []ast.Expression
		columns, row, err = p.parseInsertSetList()
		values = [][]ast.Expression{row}
		setSyntax = true
	default:
		return nil, p.expectedError("VALUES, SELECT, or SET")
	}
	if err != nil {
		return nil, err
	}

	var returning []ast.Expression
	if p.isReturningKeyword() {
		var into []ast.Expression
		returning, into, err = p.parseReturningClause()
		if err != nil {
			return nil, err
		}
		if len(into) > 0 {
			return nil, p.expectedError("end of RETURNING list")
		}
	}

	replStmt := ast.GetReplaceStatement()
	replStmt.TableName = tableName
	replStmt.Columns = append(replStmt.Columns, columns...)
	replStmt.Values = append(replStmt.Values, values...)
	replStmt.Query = query
	replStmt.SetSyntax = setSyntax
	replStmt.Returning = append(replStmt.Returning, returning...)
	return replStmt, nil
}
