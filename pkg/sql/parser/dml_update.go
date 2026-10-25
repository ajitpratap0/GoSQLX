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
	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseUpdateStatement parses an UPDATE statement:
//
//	UPDATE [modifiers] [TOP (n)] [ONLY] target [alias] [, target ...] [JOIN ...]
//	SET assignments [OUTPUT ...] [FROM ...] [WHERE ...]
//	[ORDER BY ...] [LIMIT n] [RETURNING ... [INTO ...]]
func (p *Parser) parseUpdateStatement() (ast.Statement, error) {
	// We've already consumed the UPDATE token in matchType
	stmt := &ast.UpdateStatement{}
	stmt.Modifiers = p.parseDMLModifiers(dmlUpdate)
	top, err := p.parseTopClause()
	if err != nil {
		return nil, err
	}
	stmt.Top = top
	if p.isDMLOnly() {
		stmt.Only = true
		p.advance() // Consume ONLY
	}

	// Target(s). MySQL/MariaDB allow a multi-table target list with JOINs.
	if p.isMySQLFamily() {
		if err := p.parseMultiTableUpdateTargets(stmt); err != nil {
			return nil, err
		}
	} else if _, err := p.parseDMLTargets(&stmt.TableName, &stmt.Alias, &stmt.DMLTargetFields, false, nil); err != nil {
		return nil, err
	}

	// Parse SET
	if !p.isType(models.TokenTypeSet) {
		return nil, p.expectedError("SET")
	}
	p.advance() // Consume SET

	stmt.Assignments, err = p.parseAssignments("SET")
	if err != nil {
		return nil, err
	}

	// SQL Server: OUTPUT precedes FROM and WHERE.
	if p.isDMLOutputKeyword() {
		stmt.Output, stmt.OutputInto, err = p.parseDMLOutputClause()
		if err != nil {
			return nil, err
		}
	}

	// PostgreSQL / SQL Server / SQLite: UPDATE t SET ... FROM s [, ...] (#610).
	if p.isType(models.TokenTypeFrom) {
		if len(stmt.Joins) > 0 {
			return nil, goerrors.UnsupportedFeatureError("FROM after a joined UPDATE target", p.currentLocation(), "")
		}
		p.advance() // Consume FROM
		prev := p.dmlReturning
		p.dmlReturning = true
		stmt.From, stmt.Joins, err = p.parseUpdateFromList()
		p.dmlReturning = prev
		if err != nil {
			return nil, err
		}
	}

	// Parse WHERE clause if present
	if p.isType(models.TokenTypeWhere) {
		p.advance() // Consume WHERE
		stmt.Where, err = p.parseExpression()
		if err != nil {
			return nil, err
		}
	}

	// MySQL / MariaDB / SQLite: ORDER BY ... LIMIT n
	if err := p.parseDMLOrderLimit(&stmt.DMLTargetFields); err != nil {
		return nil, err
	}

	// Parse RETURNING clause if present (PostgreSQL, SQLite, Oracle INTO)
	if p.isReturningKeyword() {
		stmt.Returning, stmt.ReturningInto, err = p.parseReturningClause()
		if err != nil {
			return nil, err
		}
	}
	return stmt, nil
}

// parseMultiTableUpdateTargets parses the MySQL / MariaDB UPDATE target
// list: comma-separated targets, then JOIN clauses joined to the first one.
func (p *Parser) parseMultiTableUpdateTargets(stmt *ast.UpdateStatement) error {
	var first ast.TableReference
	isParen, err := p.parseDMLTargets(&stmt.TableName, &stmt.Alias, &stmt.DMLTargetFields, true, &first)
	if err != nil {
		return err
	}
	if p.isJoinKeyword() {
		if !isParen {
			first = ast.TableReference{Name: stmt.TableName, NameQuote: stmt.TableNameQuote, Alias: stmt.Alias, AliasQuote: stmt.AliasQuote}
		}
		joins, err := p.parseJoinClauses(first, nil)
		if err != nil {
			return err
		}
		stmt.Joins = joins
	}
	return nil
}

// parseUpdateFromList parses the comma-separated table references of
// UPDATE ... FROM and the JOIN clauses that follow them (SQL Server,
// PostgreSQL).
func (p *Parser) parseUpdateFromList() ([]ast.TableReference, []ast.JoinClause, error) {
	var refs []ast.TableReference
	for {
		ref, err := p.parseFromTableReference()
		if err != nil {
			return nil, nil, err
		}
		refs = append(refs, ref)
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance() // Consume comma
	}
	if !p.isJoinKeyword() {
		return refs, nil, nil
	}
	joins, err := p.parseJoinClauses(refs[len(refs)-1], nil)
	if err != nil {
		return nil, nil, err
	}
	return refs, joins, nil
}
