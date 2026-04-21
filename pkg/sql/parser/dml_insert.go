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

// Package parser - dml_insert.go
// INSERT statement parsing: INSERT, ON CONFLICT, ON DUPLICATE KEY UPDATE, RETURNING, OUTPUT.

package parser

import (
	"fmt"
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseInsertStatement parses an INSERT statement
func (p *Parser) parseInsertStatement() (ast.Statement, error) {
	// We've already consumed the INSERT token in matchType

	// Parse INTO
	if !p.isType(models.TokenTypeInto) {
		return nil, p.expectedError("INTO")
	}
	p.advance() // Consume INTO

	// Parse table name (supports schema.table qualification and double-quoted identifiers)
	tableName, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.expectedError("table name")
	}

	// Parse column list if present
	columns := make([]ast.Expression, 0)
	if p.isType(models.TokenTypeLParen) {
		p.advance() // Consume (

		for {
			// Parse column name (supports double-quoted identifiers)
			if !p.isIdentifier() {
				return nil, p.expectedError("column name")
			}
			columns = append(columns, &ast.Identifier{Name: p.currentToken.Token.Value})
			p.advance()

			// Check if there are more columns
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance() // Consume comma
		}

		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
	}

	// Parse SQL Server OUTPUT clause (between column list and VALUES).
	// Accept OUTPUT regardless of dialect — the keyword is unambiguous here
	// and allows dialect-agnostic parsing of T-SQL INSERT statements.
	var outputCols []ast.Expression
	if strings.ToUpper(p.currentToken.Token.Value) == "OUTPUT" {
		p.advance() // Consume OUTPUT
		var err error
		outputCols, err = p.parseOutputColumns()
		if err != nil {
			return nil, err
		}
	}

	// Parse VALUES or SELECT
	var values [][]ast.Expression
	var query ast.QueryExpression

	// ClickHouse-only: INSERT INTO t [(cols)] FORMAT <name> with the data
	// payload being external (network / file). Short-circuit here — there is
	// no VALUES or SELECT to follow.
	if p.dialect == string(keywords.DialectClickHouse) &&
		strings.EqualFold(p.currentToken.Token.Value, "FORMAT") {
		p.advance() // Consume FORMAT
		if p.isIdentifier() || p.isType(models.TokenTypeKeyword) {
			p.advance() // Consume format name
		}
		return &ast.InsertStatement{
			TableName: tableName,
			Columns:   columns,
		}, nil
	}

	switch {
	case p.isType(models.TokenTypeSelect):
		// INSERT ... SELECT syntax
		p.advance() // Consume SELECT
		stmt, err := p.parseSelectWithSetOperations()
		if err != nil {
			return nil, err
		}
		qe, ok := stmt.(ast.QueryExpression)
		if !ok {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("expected SELECT or set operation in INSERT ... SELECT, got %T", stmt),
				p.currentLocation(),
				"",
			).WithCause(ErrUnexpectedStatement)
		}
		query = qe
	case p.isType(models.TokenTypeValues):
		p.advance() // Consume VALUES

		// Parse value rows - supports multi-row INSERT: VALUES (a, b), (c, d), (e, f)
		values = make([][]ast.Expression, 0)
		for {
			if !p.isType(models.TokenTypeLParen) {
				if len(values) == 0 {
					return nil, p.expectedError("(")
				}
				break
			}
			p.advance() // Consume (

			// Parse one row of values
			row := make([]ast.Expression, 0)
			for {
				// Parse value using parseExpression to support all expression types
				// including function calls like NOW(), UUID(), etc.
				expr, err := p.parseExpression()
				if err != nil {
					return nil, goerrors.InvalidSyntaxError(
						fmt.Sprintf("failed to parse value at position %d in VALUES row %d: %v", len(row)+1, len(values)+1, err),
						p.currentLocation(),
						"",
					).WithCause(err)
				}
				row = append(row, expr)

				// Check if there are more values in this row
				if !p.isType(models.TokenTypeComma) {
					break
				}
				p.advance() // Consume comma
			}

			if !p.isType(models.TokenTypeRParen) {
				return nil, p.expectedError(")")
			}
			p.advance() // Consume )

			values = append(values, row)

			// Check if there are more rows (comma after closing paren)
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance() // Consume comma between rows
		}
	default:
		return nil, p.expectedError("VALUES or SELECT")
	}

	// Parse ON CONFLICT clause (PostgreSQL) or ON DUPLICATE KEY UPDATE (MySQL)
	var onConflict *ast.OnConflict
	var onDuplicateKey *ast.UpsertClause
	if p.isType(models.TokenTypeOn) {
		nextLit := strings.ToUpper(p.peekToken().Token.Value)
		if nextLit == "CONFLICT" {
			p.advance() // Consume ON
			p.advance() // Consume CONFLICT
			var err error
			onConflict, err = p.parseOnConflictClause()
			if err != nil {
				return nil, err
			}
		} else if nextLit == "DUPLICATE" {
			p.advance() // Consume ON
			p.advance() // Consume DUPLICATE
			// Expect KEY
			if strings.ToUpper(p.currentToken.Token.Value) != "KEY" && !p.isType(models.TokenTypeKey) {
				return nil, p.expectedError("KEY")
			}
			p.advance() // Consume KEY
			// Expect UPDATE
			if !p.isType(models.TokenTypeUpdate) {
				return nil, p.expectedError("UPDATE")
			}
			p.advance() // Consume UPDATE
			var err error
			onDuplicateKey, err = p.parseOnDuplicateKeyUpdateClause()
			if err != nil {
				return nil, err
			}
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

	// ClickHouse INSERT ... VALUES (...) FORMAT <name> trailing format hint.
	// Parse-only; the trailing payload is not consumed.
	if p.dialect == string(keywords.DialectClickHouse) &&
		strings.EqualFold(p.currentToken.Token.Value, "FORMAT") {
		p.advance() // Consume FORMAT
		if p.isIdentifier() || p.isType(models.TokenTypeKeyword) ||
			p.isType(models.TokenTypeValues) {
			p.advance() // Consume format name (may tokenize as VALUES keyword)
		}
	}

	// Create INSERT statement
	return &ast.InsertStatement{
		TableName:      tableName,
		Columns:        columns,
		Output:         outputCols,
		Values:         values,
		Query:          query,
		OnConflict:     onConflict,
		OnDuplicateKey: onDuplicateKey,
		Returning:      returning,
	}, nil
}

// parseReturningColumns parses the columns in a RETURNING clause
// Supports: column names, *, qualified names (table.column), expressions
func (p *Parser) parseReturningColumns() ([]ast.Expression, error) {
	var columns []ast.Expression

	for {
		// Check for * (return all columns)
		if p.isType(models.TokenTypeMul) {
			columns = append(columns, &ast.Identifier{Name: "*"})
			p.advance()
		} else {
			// Parse expression (can be column name, qualified name, or expression)
			expr, err := p.parseExpression()
			if err != nil {
				return nil, goerrors.InvalidSyntaxError(
					fmt.Sprintf("failed to parse RETURNING column: %v", err),
					p.currentLocation(),
					"",
				).WithCause(err)
			}
			columns = append(columns, expr)
		}

		// Check for comma to continue parsing more columns
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance() // Consume comma
	}

	return columns, nil
}

// parseOnConflictClause parses the ON CONFLICT clause (PostgreSQL UPSERT)
// Syntax: ON CONFLICT [(columns)] | ON CONSTRAINT name DO NOTHING | DO UPDATE SET ...
func (p *Parser) parseOnConflictClause() (*ast.OnConflict, error) {
	onConflict := &ast.OnConflict{}

	// Parse optional conflict target: (column_list) or ON CONSTRAINT constraint_name
	if p.isType(models.TokenTypeLParen) {
		p.advance() // Consume (
		var targets []ast.Expression

		for {
			if !p.isIdentifier() {
				return nil, p.expectedError("column name in ON CONFLICT target")
			}
			targets = append(targets, &ast.Identifier{Name: p.currentToken.Token.Value})
			p.advance()

			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance() // Consume comma
		}

		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
		onConflict.Target = targets
	} else if p.isType(models.TokenTypeOn) && p.peekToken().Token.Value == "CONSTRAINT" {
		// ON CONSTRAINT constraint_name
		p.advance() // Consume ON
		p.advance() // Consume CONSTRAINT
		if !p.isIdentifier() {
			return nil, p.expectedError("constraint name")
		}
		onConflict.Constraint = p.currentToken.Token.Value
		p.advance()
	}

	// Parse DO keyword
	if p.currentToken.Token.Value != "DO" {
		return nil, p.expectedError("DO")
	}
	p.advance() // Consume DO

	// Parse action: NOTHING or UPDATE
	if p.currentToken.Token.Value == "NOTHING" {
		onConflict.Action = ast.OnConflictAction{DoNothing: true}
		p.advance() // Consume NOTHING
	} else if p.isType(models.TokenTypeUpdate) {
		p.advance() // Consume UPDATE

		// Parse SET keyword
		if !p.isType(models.TokenTypeSet) {
			return nil, p.expectedError("SET")
		}
		p.advance() // Consume SET

		// Parse update assignments
		var updates []ast.UpdateExpression
		for {
			if !p.isIdentifier() {
				return nil, p.expectedError("column name")
			}
			columnName := p.currentToken.Token.Value
			p.advance()

			if !p.isType(models.TokenTypeEq) {
				return nil, p.expectedError("=")
			}
			p.advance() // Consume =

			// Parse value expression (supports EXCLUDED.column references)
			value, err := p.parseExpression()
			if err != nil {
				return nil, goerrors.InvalidSyntaxError(
					fmt.Sprintf("failed to parse ON CONFLICT UPDATE value: %v", err),
					p.currentLocation(),
					"",
				).WithCause(err)
			}

			updates = append(updates, ast.UpdateExpression{
				Column: &ast.Identifier{Name: columnName},
				Value:  value,
			})

			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance() // Consume comma
		}
		onConflict.Action.DoUpdate = updates

		// Parse optional WHERE clause
		if p.isType(models.TokenTypeWhere) {
			p.advance() // Consume WHERE
			where, err := p.parseExpression()
			if err != nil {
				return nil, goerrors.InvalidSyntaxError(
					fmt.Sprintf("failed to parse ON CONFLICT WHERE clause: %v", err),
					p.currentLocation(),
					"",
				).WithCause(err)
			}
			onConflict.Action.Where = where
		}
	} else {
		return nil, p.expectedError("NOTHING or UPDATE")
	}

	return onConflict, nil
}

// parseOutputColumns parses comma-separated OUTPUT column expressions
// e.g., INSERTED.id, INSERTED.name, DELETED.*, inserted.*
func (p *Parser) parseOutputColumns() ([]ast.Expression, error) {
	var cols []ast.Expression
	for {
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		cols = append(cols, expr)
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance() // Consume comma
	}
	return cols, nil
}

// parseOnDuplicateKeyUpdateClause parses the assignments in ON DUPLICATE KEY UPDATE
func (p *Parser) parseOnDuplicateKeyUpdateClause() (*ast.UpsertClause, error) {
	upsert := &ast.UpsertClause{}
	for {
		if !p.isIdentifier() {
			return nil, p.expectedError("column name in ON DUPLICATE KEY UPDATE")
		}
		columnName := p.currentToken.Token.Value
		p.advance()

		if !p.isType(models.TokenTypeEq) {
			return nil, p.expectedError("=")
		}
		p.advance()

		value, err := p.parseExpression()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse ON DUPLICATE KEY UPDATE value: %v", err),
				p.currentLocation(),
				"",
			).WithCause(err)
		}

		upsert.Updates = append(upsert.Updates, ast.UpdateExpression{
			Column: &ast.Identifier{Name: columnName},
			Value:  value,
		})

		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance() // Consume comma
	}
	return upsert, nil
}
