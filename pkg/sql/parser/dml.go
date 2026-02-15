// Package parser - dml.go
// DML statement parsing: INSERT, UPDATE, DELETE, MERGE (SQL:2003).

package parser

import (
	"fmt"
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
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
			columns = append(columns, &ast.Identifier{Name: p.currentToken.Literal})
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

	// Parse VALUES or SELECT
	var values [][]ast.Expression
	var query ast.QueryExpression

	if p.isType(models.TokenTypeSelect) {
		// INSERT ... SELECT syntax
		p.advance() // Consume SELECT
		stmt, err := p.parseSelectWithSetOperations()
		if err != nil {
			return nil, err
		}
		qe, ok := stmt.(ast.QueryExpression)
		if !ok {
			return nil, fmt.Errorf("expected SELECT or set operation in INSERT ... SELECT, got %T", stmt)
		}
		query = qe
	} else if p.isType(models.TokenTypeValues) {
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
					return nil, fmt.Errorf("failed to parse value at position %d in VALUES row %d: %w", len(row)+1, len(values)+1, err)
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
	} else {
		return nil, p.expectedError("VALUES or SELECT")
	}

	// Parse ON CONFLICT clause if present (PostgreSQL UPSERT)
	var onConflict *ast.OnConflict
	if p.isType(models.TokenTypeOn) {
		// Peek ahead to check for CONFLICT
		if p.peekToken().Literal == "CONFLICT" {
			p.advance() // Consume ON
			p.advance() // Consume CONFLICT
			var err error
			onConflict, err = p.parseOnConflictClause()
			if err != nil {
				return nil, err
			}
		}
	}

	// Parse RETURNING clause if present (PostgreSQL)
	var returning []ast.Expression
	if p.isType(models.TokenTypeReturning) || p.currentToken.Literal == "RETURNING" {
		p.advance() // Consume RETURNING
		var err error
		returning, err = p.parseReturningColumns()
		if err != nil {
			return nil, err
		}
	}

	// Create INSERT statement
	return &ast.InsertStatement{
		TableName:  tableName,
		Columns:    columns,
		Values:     values,
		Query:      query,
		OnConflict: onConflict,
		Returning:  returning,
	}, nil
}

// parseUpdateStatement parses an UPDATE statement
func (p *Parser) parseUpdateStatement() (ast.Statement, error) {
	// We've already consumed the UPDATE token in matchType

	// Parse table name (supports schema.table qualification and double-quoted identifiers)
	tableName, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.expectedError("table name")
	}

	// Parse SET
	if !p.isType(models.TokenTypeSet) {
		return nil, p.expectedError("SET")
	}
	p.advance() // Consume SET

	// Parse assignments
	updates := make([]ast.UpdateExpression, 0)
	for {
		// Parse column name (supports double-quoted identifiers)
		if !p.isIdentifier() {
			return nil, p.expectedError("column name")
		}
		columnName := p.currentToken.Literal
		p.advance()

		if !p.isType(models.TokenTypeEq) {
			return nil, p.expectedError("=")
		}
		p.advance() // Consume =

		// Parse value expression
		var expr ast.Expression
		if p.isStringLiteral() {
			expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "string"}
			p.advance()
		} else if p.isNumericLiteral() {
			litType := "int"
			if strings.ContainsAny(p.currentToken.Literal, ".eE") {
				litType = "float"
			}
			expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: litType}
			p.advance()
		} else if p.isBooleanLiteral() {
			expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "bool"}
			p.advance()
		} else {
			var err error
			expr, err = p.parseExpression()
			if err != nil {
				return nil, err
			}
		}

		// Create update expression
		columnExpr := &ast.Identifier{Name: columnName}
		updateExpr := ast.UpdateExpression{
			Column: columnExpr,
			Value:  expr,
		}
		updates = append(updates, updateExpr)

		// Check if there are more assignments
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance() // Consume comma
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

	// Parse RETURNING clause if present (PostgreSQL)
	var returning []ast.Expression
	if p.isType(models.TokenTypeReturning) || p.currentToken.Literal == "RETURNING" {
		p.advance() // Consume RETURNING
		var err error
		returning, err = p.parseReturningColumns()
		if err != nil {
			return nil, err
		}
	}

	// Create UPDATE statement
	return &ast.UpdateStatement{
		TableName:   tableName,
		Assignments: updates,
		Where:       whereClause,
		Returning:   returning,
	}, nil
}

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

	// Parse RETURNING clause if present (PostgreSQL)
	var returning []ast.Expression
	if p.isType(models.TokenTypeReturning) || p.currentToken.Literal == "RETURNING" {
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

// parseMergeStatement parses a MERGE statement (SQL:2003 F312)
// Syntax: MERGE INTO target [AS alias] USING source [AS alias] ON condition
//
//	WHEN MATCHED [AND condition] THEN UPDATE/DELETE
//	WHEN NOT MATCHED [AND condition] THEN INSERT
//	WHEN NOT MATCHED BY SOURCE [AND condition] THEN UPDATE/DELETE
func (p *Parser) parseMergeStatement() (ast.Statement, error) {
	stmt := &ast.MergeStatement{}

	// Parse INTO (optional)
	if p.isType(models.TokenTypeInto) {
		p.advance() // Consume INTO
	}

	// Parse target table
	tableRef, err := p.parseTableReference()
	if err != nil {
		return nil, goerrors.WrapError(goerrors.ErrCodeInvalidSyntax, "error parsing MERGE target table", models.Location{}, "", err)
	}
	stmt.TargetTable = *tableRef

	// Parse optional target alias (AS alias or just alias)
	if p.isType(models.TokenTypeAs) {
		p.advance() // Consume AS
		if !p.isIdentifier() && !p.isNonReservedKeyword() {
			return nil, p.expectedError("target alias after AS")
		}
		stmt.TargetAlias = p.currentToken.Literal
		p.advance()
	} else if p.canBeAlias() && !p.isType(models.TokenTypeUsing) && p.currentToken.Literal != "USING" {
		stmt.TargetAlias = p.currentToken.Literal
		p.advance()
	}

	// Parse USING
	if !p.isType(models.TokenTypeUsing) && p.currentToken.Literal != "USING" {
		return nil, p.expectedError("USING")
	}
	p.advance() // Consume USING

	// Parse source table (could be a table or subquery)
	sourceRef, err := p.parseTableReference()
	if err != nil {
		return nil, goerrors.WrapError(goerrors.ErrCodeInvalidSyntax, "error parsing MERGE source", models.Location{}, "", err)
	}
	stmt.SourceTable = *sourceRef

	// Parse optional source alias
	if p.isType(models.TokenTypeAs) {
		p.advance() // Consume AS
		if !p.isIdentifier() && !p.isNonReservedKeyword() {
			return nil, p.expectedError("source alias after AS")
		}
		stmt.SourceAlias = p.currentToken.Literal
		p.advance()
	} else if p.canBeAlias() && !p.isType(models.TokenTypeOn) && p.currentToken.Literal != "ON" {
		stmt.SourceAlias = p.currentToken.Literal
		p.advance()
	}

	// Parse ON condition
	if !p.isType(models.TokenTypeOn) {
		return nil, p.expectedError("ON")
	}
	p.advance() // Consume ON

	onCondition, err := p.parseExpression()
	if err != nil {
		return nil, goerrors.WrapError(goerrors.ErrCodeInvalidSyntax, "error parsing MERGE ON condition", models.Location{}, "", err)
	}
	stmt.OnCondition = onCondition

	// Parse WHEN clauses
	for p.isType(models.TokenTypeWhen) {
		whenClause, err := p.parseMergeWhenClause()
		if err != nil {
			return nil, err
		}
		stmt.WhenClauses = append(stmt.WhenClauses, whenClause)
	}

	if len(stmt.WhenClauses) == 0 {
		return nil, goerrors.MissingClauseError("WHEN", models.Location{}, "")
	}

	return stmt, nil
}

// parseMergeWhenClause parses a WHEN clause in a MERGE statement
func (p *Parser) parseMergeWhenClause() (*ast.MergeWhenClause, error) {
	clause := &ast.MergeWhenClause{}

	p.advance() // Consume WHEN

	// Determine clause type: MATCHED, NOT MATCHED, NOT MATCHED BY SOURCE
	if p.isType(models.TokenTypeMatched) || p.currentToken.Literal == "MATCHED" {
		clause.Type = "MATCHED"
		p.advance() // Consume MATCHED
	} else if p.isType(models.TokenTypeNot) {
		p.advance() // Consume NOT
		if !p.isType(models.TokenTypeMatched) && p.currentToken.Literal != "MATCHED" {
			return nil, p.expectedError("MATCHED after NOT")
		}
		p.advance() // Consume MATCHED

		// Check for BY SOURCE
		if p.isType(models.TokenTypeBy) {
			p.advance() // Consume BY
			if !p.isType(models.TokenTypeSource) && p.currentToken.Literal != "SOURCE" {
				return nil, p.expectedError("SOURCE after BY")
			}
			p.advance() // Consume SOURCE
			clause.Type = "NOT_MATCHED_BY_SOURCE"
		} else {
			clause.Type = "NOT_MATCHED"
		}
	} else {
		return nil, p.expectedError("MATCHED or NOT MATCHED")
	}

	// Parse optional AND condition
	if p.isType(models.TokenTypeAnd) {
		p.advance() // Consume AND
		condition, err := p.parseExpression()
		if err != nil {
			return nil, goerrors.WrapError(goerrors.ErrCodeInvalidSyntax, "error parsing WHEN condition", models.Location{}, "", err)
		}
		clause.Condition = condition
	}

	// Parse THEN
	if !p.isType(models.TokenTypeThen) {
		return nil, p.expectedError("THEN")
	}
	p.advance() // Consume THEN

	// Parse action (UPDATE, INSERT, DELETE)
	action, err := p.parseMergeAction(clause.Type)
	if err != nil {
		return nil, err
	}
	clause.Action = action

	return clause, nil
}

// parseMergeAction parses the action in a WHEN clause
func (p *Parser) parseMergeAction(clauseType string) (*ast.MergeAction, error) {
	action := &ast.MergeAction{}

	if p.isType(models.TokenTypeUpdate) {
		action.ActionType = "UPDATE"
		p.advance() // Consume UPDATE

		// Parse SET
		if !p.isType(models.TokenTypeSet) {
			return nil, p.expectedError("SET after UPDATE")
		}
		p.advance() // Consume SET

		// Parse SET clauses
		for {
			if !p.isIdentifier() && !p.canBeAlias() {
				return nil, p.expectedError("column name")
			}
			// Handle qualified column names (e.g., t.name)
			columnName := p.currentToken.Literal
			p.advance()

			// Check for qualified name (table.column)
			if p.isType(models.TokenTypePeriod) {
				p.advance() // Consume .
				if !p.isIdentifier() && !p.canBeAlias() {
					return nil, p.expectedError("column name after .")
				}
				columnName = columnName + "." + p.currentToken.Literal
				p.advance()
			}

			setClause := ast.SetClause{Column: columnName}

			if !p.isType(models.TokenTypeEq) {
				return nil, p.expectedError("=")
			}
			p.advance() // Consume =

			value, err := p.parseExpression()
			if err != nil {
				return nil, goerrors.WrapError(goerrors.ErrCodeInvalidSyntax, "error parsing SET value", models.Location{}, "", err)
			}
			setClause.Value = value
			action.SetClauses = append(action.SetClauses, setClause)

			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance() // Consume comma
		}
	} else if p.isType(models.TokenTypeInsert) {
		if clauseType == "MATCHED" || clauseType == "NOT_MATCHED_BY_SOURCE" {
			return nil, goerrors.InvalidSyntaxError(fmt.Sprintf("INSERT not allowed in WHEN %s clause", clauseType), models.Location{}, "")
		}
		action.ActionType = "INSERT"
		p.advance() // Consume INSERT

		// Parse optional column list
		if p.isType(models.TokenTypeLParen) {
			p.advance() // Consume (
			for {
				if !p.isIdentifier() {
					return nil, p.expectedError("column name")
				}
				action.Columns = append(action.Columns, p.currentToken.Literal)
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
		}

		// Parse VALUES or DEFAULT VALUES
		if p.isType(models.TokenTypeDefault) {
			p.advance() // Consume DEFAULT
			if !p.isType(models.TokenTypeValues) {
				return nil, p.expectedError("VALUES after DEFAULT")
			}
			p.advance() // Consume VALUES
			action.DefaultValues = true
		} else if p.isType(models.TokenTypeValues) {
			p.advance() // Consume VALUES
			if !p.isType(models.TokenTypeLParen) {
				return nil, p.expectedError("(")
			}
			p.advance() // Consume (

			for {
				value, err := p.parseExpression()
				if err != nil {
					return nil, goerrors.WrapError(goerrors.ErrCodeInvalidSyntax, "error parsing INSERT value", models.Location{}, "", err)
				}
				action.Values = append(action.Values, value)

				if !p.isType(models.TokenTypeComma) {
					break
				}
				p.advance() // Consume comma
			}

			if !p.isType(models.TokenTypeRParen) {
				return nil, p.expectedError(")")
			}
			p.advance() // Consume )
		} else {
			return nil, p.expectedError("VALUES or DEFAULT VALUES")
		}
	} else if p.isType(models.TokenTypeDelete) {
		if clauseType == "NOT_MATCHED" {
			return nil, goerrors.InvalidSyntaxError("DELETE not allowed in WHEN NOT MATCHED clause", models.Location{}, "")
		}
		action.ActionType = "DELETE"
		p.advance() // Consume DELETE
	} else {
		return nil, p.expectedError("UPDATE, INSERT, or DELETE")
	}

	return action, nil
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
				return nil, fmt.Errorf("failed to parse RETURNING column: %w", err)
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
			targets = append(targets, &ast.Identifier{Name: p.currentToken.Literal})
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
	} else if p.isType(models.TokenTypeOn) && p.peekToken().Literal == "CONSTRAINT" {
		// ON CONSTRAINT constraint_name
		p.advance() // Consume ON
		p.advance() // Consume CONSTRAINT
		if !p.isIdentifier() {
			return nil, p.expectedError("constraint name")
		}
		onConflict.Constraint = p.currentToken.Literal
		p.advance()
	}

	// Parse DO keyword
	if p.currentToken.Literal != "DO" {
		return nil, p.expectedError("DO")
	}
	p.advance() // Consume DO

	// Parse action: NOTHING or UPDATE
	if p.currentToken.Literal == "NOTHING" {
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
			columnName := p.currentToken.Literal
			p.advance()

			if !p.isType(models.TokenTypeEq) {
				return nil, p.expectedError("=")
			}
			p.advance() // Consume =

			// Parse value expression (supports EXCLUDED.column references)
			value, err := p.parseExpression()
			if err != nil {
				return nil, fmt.Errorf("failed to parse ON CONFLICT UPDATE value: %w", err)
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
				return nil, fmt.Errorf("failed to parse ON CONFLICT WHERE clause: %w", err)
			}
			onConflict.Action.Where = where
		}
	} else {
		return nil, p.expectedError("NOTHING or UPDATE")
	}

	return onConflict, nil
}

// parseTableReference parses a simple table reference (table name)
// Returns a TableReference with the Name field populated
