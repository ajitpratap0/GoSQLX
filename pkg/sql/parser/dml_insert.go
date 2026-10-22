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

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseInsertStatement parses an INSERT statement
func (p *Parser) parseInsertStatement() (ast.Statement, error) {
	// We've already consumed the INSERT token in matchType
	stmt := &ast.InsertStatement{}

	// Oracle multi-table insert: INSERT ALL ... / INSERT FIRST ...
	if p.dialect == string(keywords.DialectOracle) &&
		(p.isType(models.TokenTypeAll) || p.isTokenMatch("FIRST")) {
		return p.parseMultiTableInsert(stmt)
	}

	stmt.Modifiers = p.parseDMLModifiers(dmlInsert)

	// Parse INTO. SQL Server, MySQL and MariaDB make it optional.
	if p.isType(models.TokenTypeInto) {
		p.advance() // Consume INTO
	} else if p.dialect != string(keywords.DialectSQLServer) && !p.isMySQLFamily() {
		return nil, p.expectedError("INTO")
	}

	// ClickHouse: INSERT INTO FUNCTION table_function(...)
	if p.dialect == string(keywords.DialectClickHouse) && p.isTokenMatch("FUNCTION") &&
		p.peekToken().Token.Type != models.TokenTypeLParen {
		p.advance() // Consume FUNCTION
		name := p.currentToken.Token.Value
		if !p.isWordToken() {
			return nil, p.expectedError("table function name")
		}
		p.advance()
		if !p.isType(models.TokenTypeLParen) {
			return nil, p.expectedError("(")
		}
		fn, err := p.parseFunctionCall(name)
		if err != nil {
			return nil, err
		}
		stmt.TableFunction = fn
	} else {
		// Parse table name (supports schema.table qualification and double-quoted identifiers)
		tableName, tableQuote, err := p.parseQualifiedNameQuoted()
		if err != nil {
			return nil, p.qualifiedNameError(err, "table name")
		}
		stmt.TableName = tableName
		stmt.TableNameQuote = tableQuote
	}

	// Parse column list if present
	stmt.Columns = make([]ast.Expression, 0)
	if p.isType(models.TokenTypeLParen) && !p.isInsertQueryParenStart() {
		cols, err := p.parseInsertColumnList()
		if err != nil {
			return nil, err
		}
		stmt.Columns = cols
	}

	// Parse SQL Server OUTPUT clause (between column list and VALUES).
	// Accept OUTPUT regardless of dialect — the keyword is unambiguous here
	// and allows dialect-agnostic parsing of T-SQL INSERT statements.
	if equalsUpper(p.currentToken.Token.Value, "OUTPUT") {
		var err error
		stmt.Output, stmt.OutputInto, err = p.parseDMLOutputClause()
		if err != nil {
			return nil, err
		}
	}

	if p.dialect == string(keywords.DialectClickHouse) {
		// ClickHouse: INSERT INTO t [(cols)] SETTINGS k = v, ... VALUES ...
		if p.isSettingsKeyword() {
			settings, err := p.parseInsertSettings()
			if err != nil {
				return nil, err
			}
			stmt.Settings = settings
		}
		// ClickHouse-only: INSERT INTO t [(cols)] FORMAT <name> with the
		// data payload being external (network / file). There is no VALUES
		// or SELECT to follow.
		if p.isTokenMatch("FORMAT") {
			if err := p.parseInsertFormat(stmt); err != nil {
				return nil, err
			}
			return stmt, nil
		}
	}

	// PostgreSQL: OVERRIDING {SYSTEM | USER} VALUE
	if p.isTokenMatch("OVERRIDING") {
		p.advance() // Consume OVERRIDING
		switch {
		case p.isTokenMatch("SYSTEM"):
			stmt.Overriding = "SYSTEM"
		case p.isTokenMatch("USER"):
			stmt.Overriding = "USER"
		default:
			return nil, p.expectedError("SYSTEM or USER")
		}
		p.advance()
		if !p.isTokenMatch("VALUE") {
			return nil, p.expectedError("VALUE")
		}
		p.advance() // Consume VALUE
	}

	switch {
	case p.isType(models.TokenTypeSelect), p.isType(models.TokenTypeWith), p.isInsertQueryParenStart():
		// INSERT ... SELECT, INSERT ... WITH cte AS (...) SELECT (#537), or a
		// parenthesized query INSERT INTO t [(cols)] (SELECT ...) (#610).
		qe, err := p.parseInsertQuery()
		if err != nil {
			return nil, err
		}
		stmt.Query = qe
	case p.isType(models.TokenTypeValues):
		p.advance() // Consume VALUES
		values, err := p.parseInsertValueRows()
		if err != nil {
			return nil, err
		}
		stmt.Values = values
	case p.isType(models.TokenTypeDefault) && p.peekToken().Token.Type == models.TokenTypeValues:
		// INSERT INTO t DEFAULT VALUES (PostgreSQL, SQL Server, SQLite).
		if len(stmt.Columns) > 0 {
			return nil, goerrors.InvalidSyntaxError(
				"DEFAULT VALUES cannot follow a column list",
				p.currentLocation(),
				"",
			)
		}
		p.advance() // Consume DEFAULT
		p.advance() // Consume VALUES
		stmt.DefaultValues = true
	case p.isType(models.TokenTypeSet) && p.isMySQLFamily():
		// MySQL/MariaDB INSERT INTO t SET col = expr, ... - stored as
		// Columns plus one Values row; SetSyntax keeps the source form.
		if len(stmt.Columns) > 0 {
			return nil, p.expectedError("VALUES or SELECT after a column list")
		}
		p.advance() // Consume SET
		cols, row, err := p.parseInsertSetList()
		if err != nil {
			return nil, err
		}
		stmt.Columns = cols
		stmt.Values = [][]ast.Expression{row}
		stmt.SetSyntax = true
	default:
		return nil, p.expectedError("VALUES, SELECT, or WITH")
	}

	// MySQL 8.0.19+: VALUES (...) AS row_alias [(col_alias, ...)]
	if p.isType(models.TokenTypeAs) && p.isMySQLFamily() && stmt.Query == nil {
		if err := p.parseInsertRowAlias(stmt); err != nil {
			return nil, err
		}
	}

	// Parse ON CONFLICT clause (PostgreSQL) or ON DUPLICATE KEY UPDATE (MySQL)
	if p.isType(models.TokenTypeOn) {
		next := p.peekToken().Token.Value
		if equalsUpper(next, "CONFLICT") {
			p.advance() // Consume ON
			p.advance() // Consume CONFLICT
			var err error
			stmt.OnConflict, err = p.parseOnConflictClause()
			if err != nil {
				return nil, err
			}
		} else if equalsUpper(next, "DUPLICATE") {
			p.advance() // Consume ON
			p.advance() // Consume DUPLICATE
			// Expect KEY
			if !p.isTokenMatch("KEY") && !p.isType(models.TokenTypeKey) {
				return nil, p.expectedError("KEY")
			}
			p.advance() // Consume KEY
			// Expect UPDATE
			if !p.isType(models.TokenTypeUpdate) {
				return nil, p.expectedError("UPDATE")
			}
			p.advance() // Consume UPDATE
			var err error
			stmt.OnDuplicateKey, err = p.parseOnDuplicateKeyUpdateClause()
			if err != nil {
				return nil, err
			}
		}
	}

	// Parse RETURNING clause if present (PostgreSQL, SQLite, MariaDB, Oracle INTO)
	if p.isReturningKeyword() {
		var err error
		stmt.Returning, stmt.ReturningInto, err = p.parseReturningClause()
		if err != nil {
			return nil, err
		}
	}

	// ClickHouse INSERT ... VALUES (...) FORMAT <name> trailing format hint.
	if p.dialect == string(keywords.DialectClickHouse) && p.isTokenMatch("FORMAT") {
		if err := p.parseInsertFormat(stmt); err != nil {
			return nil, err
		}
	}
	return stmt, nil
}

// parseInsertSettings parses the ClickHouse "SETTINGS name = expr, ..." of
// an INSERT; the current token must be SETTINGS. Unlike the SELECT settings
// list it leaves a following FORMAT clause to the caller, which stores it.
func (p *Parser) parseInsertSettings() ([]ast.QuerySetting, error) {
	p.advance() // Consume SETTINGS
	var settings []ast.QuerySetting
	for {
		if !p.isQuerySettingName() {
			return nil, p.expectedError("setting name")
		}
		pos := p.currentLocation()
		name := p.currentToken.Token.Value
		p.advance()
		if !p.isType(models.TokenTypeEq) {
			return nil, p.expectedError("=")
		}
		p.advance() // Consume =
		value, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		settings = append(settings, ast.QuerySetting{Name: name, Value: value, Pos: pos})
		if !p.isType(models.TokenTypeComma) {
			return settings, nil
		}
		p.advance() // Consume ,
	}
}

// parseInsertFormat parses the ClickHouse "FORMAT name" of an INSERT; the
// current token must be FORMAT. The name may tokenize as a keyword (Values).
func (p *Parser) parseInsertFormat(stmt *ast.InsertStatement) error {
	p.advance() // Consume FORMAT
	if !p.isWordToken() {
		return p.expectedError("format name after FORMAT")
	}
	stmt.DataFormat = p.currentToken.Token.Value
	p.advance()
	return nil
}

// parseInsertQuery parses the query source of INSERT ... SELECT.
func (p *Parser) parseInsertQuery() (ast.QueryExpression, error) {
	stmt, err := p.parseInsertSourceQuery()
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
	return qe, nil
}

// parseInsertColumnList parses "(col, ...)" of an INSERT (or an OUTPUT INTO
// target, a REPLACE, a multi-table INTO). The current token must be '('.
// An empty list "()" (MySQL) is accepted. Keyword words are accepted as
// column names, since a column list holds only names.
func (p *Parser) parseInsertColumnList() ([]ast.Expression, error) {
	p.advance() // Consume (
	columns := make([]ast.Expression, 0)
	if p.isType(models.TokenTypeRParen) && p.isMySQLFamily() {
		p.advance() // Consume )
		return columns, nil
	}
	for {
		if !p.isWordToken() {
			return nil, p.expectedError("column name")
		}
		columns = append(columns, p.currentColumnIdent())
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
	return columns, nil
}

// parseInsertValueRows parses the rows after VALUES: (a, b), (c, d), ...
// Items may be DEFAULT; an empty row "()" (MySQL) is accepted.
func (p *Parser) parseInsertValueRows() ([][]ast.Expression, error) {
	values := make([][]ast.Expression, 0)
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
		if !(p.isType(models.TokenTypeRParen) && p.isMySQLFamily()) {
			for {
				// Parse value using parseExpression to support all expression types
				// including function calls like NOW(), UUID(), etc.
				expr, err := p.parseDMLValue()
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
	return values, nil
}

// parseInsertSetList parses the MySQL "col = expr, ..." list of INSERT/REPLACE
// ... SET; the current token is the first column.
func (p *Parser) parseInsertSetList() ([]ast.Expression, []ast.Expression, error) {
	var columns []ast.Expression
	row := make([]ast.Expression, 0)
	for {
		if !p.isWordToken() {
			return nil, nil, p.expectedError("column name")
		}
		columns = append(columns, p.currentColumnIdent())
		p.advance()
		if !p.isType(models.TokenTypeEq) {
			return nil, nil, p.expectedError("=")
		}
		p.advance() // Consume =
		expr, err := p.parseDMLValue()
		if err != nil {
			return nil, nil, err
		}
		row = append(row, expr)
		if !p.isType(models.TokenTypeComma) {
			return columns, row, nil
		}
		p.advance() // Consume comma
	}
}

// parseInsertRowAlias parses the MySQL row alias "AS name [(cols)]"; the
// current token must be AS.
func (p *Parser) parseInsertRowAlias(stmt *ast.InsertStatement) error {
	p.advance() // Consume AS
	if !p.isWordToken() {
		return p.expectedError("row alias after AS")
	}
	stmt.RowAlias = p.currentToken.Token.Value
	p.advance()
	if !p.isType(models.TokenTypeLParen) {
		return nil
	}
	p.advance() // Consume (
	for {
		if !p.isWordToken() {
			return p.expectedError("column alias")
		}
		stmt.RowAliasColumns = append(stmt.RowAliasColumns, p.currentToken.Token.Value)
		p.advance()
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance() // Consume ,
	}
	if !p.isType(models.TokenTypeRParen) {
		return p.expectedError(")")
	}
	p.advance() // Consume )
	return nil
}

// isInsertQueryParenStart reports whether the current '(' opens a
// parenthesized query source - INSERT INTO t [(cols)] (SELECT ...) - rather
// than a column list. A column list never starts with SELECT, WITH or '('.
func (p *Parser) isInsertQueryParenStart() bool {
	if !p.isType(models.TokenTypeLParen) {
		return false
	}
	switch p.peekToken().Token.Type {
	case models.TokenTypeSelect, models.TokenTypeWith, models.TokenTypeLParen:
		return true
	}
	return false
}

// parseInsertSourceQuery parses the query source of INSERT ... SELECT,
// optionally wrapped in parentheses. RETURNING is not accepted as an implicit
// alias inside the source, so INSERT ... SELECT ... FROM s RETURNING id keeps
// its RETURNING clause (#610).
func (p *Parser) parseInsertSourceQuery() (ast.Statement, error) {
	open := 0
	for p.isType(models.TokenTypeLParen) {
		p.advance() // Consume (
		open++
	}
	prev := p.dmlReturning
	p.dmlReturning = true
	stmt, err := p.parseQuerySource()
	p.dmlReturning = prev
	if err != nil {
		return nil, err
	}
	for ; open > 0; open-- {
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
	}
	return stmt, nil
}

// parseOnConflictClause parses the ON CONFLICT clause (PostgreSQL / SQLite UPSERT)
// Syntax: ON CONFLICT [(target, ...) [WHERE pred] | ON CONSTRAINT name]
// DO NOTHING | DO UPDATE SET ... [WHERE ...]. A target is a column or an
// index expression such as lower(email).
func (p *Parser) parseOnConflictClause() (*ast.OnConflict, error) {
	onConflict := &ast.OnConflict{}

	// Parse optional conflict target: (column_list) or ON CONSTRAINT constraint_name
	if p.isType(models.TokenTypeLParen) {
		p.advance() // Consume (
		var targets []ast.Expression

		for {
			var target ast.Expression
			if p.isWordToken() && !p.isType(models.TokenTypeDefault) {
				switch p.peekToken().Token.Type {
				case models.TokenTypeComma, models.TokenTypeRParen:
					// A plain column name (which may be a keyword: key, value).
					target = p.currentColumnIdent()
					p.advance()
				}
			}
			if target == nil {
				expr, err := p.parseExpression()
				if err != nil {
					return nil, goerrors.InvalidSyntaxError(
						fmt.Sprintf("failed to parse ON CONFLICT target: %v", err),
						p.currentLocation(),
						"",
					).WithCause(err)
				}
				target = expr
			}
			targets = append(targets, target)

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

		// Partial-index predicate: ON CONFLICT (a) WHERE b > 0 DO ...
		if p.isType(models.TokenTypeWhere) {
			p.advance() // Consume WHERE
			where, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			onConflict.TargetWhere = where
		}
	} else if p.isType(models.TokenTypeOn) && equalsUpper(p.peekToken().Token.Value, "CONSTRAINT") {
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
	if !p.isTokenMatch("DO") {
		return nil, p.expectedError("DO")
	}
	p.advance() // Consume DO

	// Parse action: NOTHING or UPDATE
	if p.isTokenMatch("NOTHING") {
		onConflict.Action = ast.OnConflictAction{DoNothing: true}
		p.advance() // Consume NOTHING
	} else if p.isType(models.TokenTypeUpdate) {
		p.advance() // Consume UPDATE

		// Parse SET keyword
		if !p.isType(models.TokenTypeSet) {
			return nil, p.expectedError("SET")
		}
		p.advance() // Consume SET

		updates, err := p.parseAssignments("ON CONFLICT UPDATE")
		if err != nil {
			return nil, err
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

// parseOnDuplicateKeyUpdateClause parses the assignments in ON DUPLICATE KEY UPDATE
func (p *Parser) parseOnDuplicateKeyUpdateClause() (*ast.UpsertClause, error) {
	updates, err := p.parseAssignments("ON DUPLICATE KEY UPDATE")
	if err != nil {
		return nil, err
	}
	return &ast.UpsertClause{Updates: updates}, nil
}
