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

// Package parser - dml_insert_multi.go
// Oracle multi-table INSERT ALL / INSERT FIRST.

package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseMultiTableInsert parses an Oracle multi-table insert; the current
// token is ALL or FIRST:
//
//	INSERT ALL INTO t [(cols)] [VALUES (...)] ... subquery
//	INSERT {ALL | FIRST} WHEN cond THEN INTO ... [WHEN ...] [ELSE INTO ...] subquery
func (p *Parser) parseMultiTableInsert(stmt *ast.InsertStatement) (ast.Statement, error) {
	m := &ast.MultiTableInsert{First: p.isTokenMatch("FIRST")}
	p.advance() // Consume ALL / FIRST

	if p.isType(models.TokenTypeWhen) {
		for p.isType(models.TokenTypeWhen) {
			p.advance() // Consume WHEN
			cond, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			if !p.isType(models.TokenTypeThen) {
				return nil, p.expectedError("THEN")
			}
			p.advance() // Consume THEN
			into, err := p.parseMultiInsertIntos()
			if err != nil {
				return nil, err
			}
			m.Branches = append(m.Branches, ast.MultiInsertBranch{When: cond, Into: into})
		}
		if p.isType(models.TokenTypeElse) {
			p.advance() // Consume ELSE
			into, err := p.parseMultiInsertIntos()
			if err != nil {
				return nil, err
			}
			m.Branches = append(m.Branches, ast.MultiInsertBranch{Else: true, Into: into})
		}
	} else {
		if m.First {
			return nil, p.expectedError("WHEN after INSERT FIRST")
		}
		into, err := p.parseMultiInsertIntos()
		if err != nil {
			return nil, err
		}
		m.Branches = append(m.Branches, ast.MultiInsertBranch{Into: into})
	}

	if !p.isType(models.TokenTypeSelect) && !p.isType(models.TokenTypeWith) && !p.isInsertQueryParenStart() {
		return nil, p.expectedError("SELECT")
	}
	qe, err := p.parseInsertQuery()
	if err != nil {
		return nil, err
	}
	stmt.Query = qe
	stmt.MultiTable = m
	return stmt, nil
}

// parseMultiInsertIntos parses one or more "INTO t [(cols)] [VALUES (...)]".
func (p *Parser) parseMultiInsertIntos() ([]ast.MultiInsertInto, error) {
	var intos []ast.MultiInsertInto
	for p.isType(models.TokenTypeInto) {
		p.advance() // Consume INTO
		name, err := p.parseQualifiedName()
		if err != nil {
			return nil, p.qualifiedNameError(err, "table name")
		}
		in := ast.MultiInsertInto{Table: name}
		if p.isType(models.TokenTypeLParen) {
			cols, err := p.parseInsertColumnList()
			if err != nil {
				return nil, err
			}
			in.Columns = cols
		}
		if p.isType(models.TokenTypeValues) {
			p.advance() // Consume VALUES
			rows, err := p.parseInsertValueRows()
			if err != nil {
				return nil, err
			}
			if len(rows) != 1 {
				return nil, p.expectedError("one VALUES row per INTO clause")
			}
			in.Values = rows[0]
		}
		intos = append(intos, in)
	}
	if len(intos) == 0 {
		return nil, p.expectedError("INTO")
	}
	return intos, nil
}
