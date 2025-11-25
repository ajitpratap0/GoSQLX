// Package parser - dml.go
// DML statement parsing: INSERT, UPDATE, DELETE, MERGE (SQL:2003).

package parser

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// parseInsertStatement parses an INSERT statement
func (p *Parser) parseInsertStatement() (ast.Statement, error) {
	// We've already consumed the INSERT token in matchToken

	// Parse INTO
	if p.currentToken.Type != "INTO" {
		return nil, p.expectedError("INTO")
	}
	p.advance() // Consume INTO

	// Parse table name
	if p.currentToken.Type != "IDENT" {
		return nil, p.expectedError("table name")
	}
	tableName := p.currentToken.Literal
	p.advance()

	// Parse column list if present
	columns := make([]ast.Expression, 0)
	if p.currentToken.Type == "(" {
		p.advance() // Consume (

		for {
			// Parse column name
			if p.currentToken.Type != "IDENT" {
				return nil, p.expectedError("column name")
			}
			columns = append(columns, &ast.Identifier{Name: p.currentToken.Literal})
			p.advance()

			// Check if there are more columns
			if p.currentToken.Type != "," {
				break
			}
			p.advance() // Consume comma
		}

		if p.currentToken.Type != ")" {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
	}

	// Parse VALUES
	if p.currentToken.Type != "VALUES" {
		return nil, p.expectedError("VALUES")
	}
	p.advance() // Consume VALUES

	// Parse value list
	values := make([]ast.Expression, 0)
	if p.currentToken.Type == "(" {
		p.advance() // Consume (

		for {
			// Parse value
			var expr ast.Expression
			switch p.currentToken.Type {
			case "STRING":
				expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "string"}
				p.advance()
			case "INT":
				expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "int"}
				p.advance()
			case "FLOAT":
				expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "float"}
				p.advance()
			case token.TRUE, token.FALSE:
				expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "bool"}
				p.advance()
			default:
				return nil, fmt.Errorf("unexpected token for value: %s", p.currentToken.Type)
			}
			values = append(values, expr)

			// Check if there are more values
			if p.currentToken.Type != "," {
				break
			}
			p.advance() // Consume comma
		}

		if p.currentToken.Type != ")" {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
	}

	// Create INSERT statement
	return &ast.InsertStatement{
		TableName: tableName,
		Columns:   columns,
		Values:    values,
	}, nil
}

// parseUpdateStatement parses an UPDATE statement
func (p *Parser) parseUpdateStatement() (ast.Statement, error) {
	// We've already consumed the UPDATE token in matchToken

	// Parse table name
	if p.currentToken.Type != "IDENT" {
		return nil, p.expectedError("table name")
	}
	tableName := p.currentToken.Literal
	p.advance()

	// Parse SET
	if p.currentToken.Type != "SET" {
		return nil, p.expectedError("SET")
	}
	p.advance() // Consume SET

	// Parse assignments
	updates := make([]ast.UpdateExpression, 0)
	for {
		// Parse column name
		if p.currentToken.Type != "IDENT" {
			return nil, p.expectedError("column name")
		}
		columnName := p.currentToken.Literal
		p.advance()

		if p.currentToken.Type != "=" {
			return nil, p.expectedError("=")
		}
		p.advance() // Consume =

		// Parse value expression
		var expr ast.Expression
		switch p.currentToken.Type {
		case "STRING":
			expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "string"}
			p.advance()
		case "INT":
			expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "int"}
			p.advance()
		case "FLOAT":
			expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "float"}
			p.advance()
		case "TRUE", "FALSE":
			expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "bool"}
			p.advance()
		default:
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
		if p.currentToken.Type != "," {
			break
		}
		p.advance() // Consume comma
	}

	// Parse WHERE clause if present
	var whereClause ast.Expression
	if p.currentToken.Type == "WHERE" {
		p.advance() // Consume WHERE
		var err error
		whereClause, err = p.parseExpression()
		if err != nil {
			return nil, err
		}
	}

	// Create UPDATE statement
	return &ast.UpdateStatement{
		TableName: tableName,
		Updates:   updates,
		Where:     whereClause,
	}, nil
}

// parseDeleteStatement parses a DELETE statement
func (p *Parser) parseDeleteStatement() (ast.Statement, error) {
	// We've already consumed the DELETE token in matchToken

	// Parse FROM
	if p.currentToken.Type != "FROM" {
		return nil, p.expectedError("FROM")
	}
	p.advance() // Consume FROM

	// Parse table name
	if p.currentToken.Type != "IDENT" {
		return nil, p.expectedError("table name")
	}
	tableName := p.currentToken.Literal
	p.advance()

	// Parse WHERE clause if present
	var whereClause ast.Expression
	if p.currentToken.Type == "WHERE" {
		p.advance() // Consume WHERE
		var err error
		whereClause, err = p.parseExpression()
		if err != nil {
			return nil, err
		}
	}

	// Create DELETE statement
	return &ast.DeleteStatement{
		TableName: tableName,
		Where:     whereClause,
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
	if p.currentToken.Type == "INTO" {
		p.advance() // Consume INTO
	}

	// Parse target table
	tableRef, err := p.parseTableReference()
	if err != nil {
		return nil, fmt.Errorf("error parsing MERGE target table: %w", err)
	}
	stmt.TargetTable = *tableRef

	// Parse optional target alias (AS alias or just alias)
	if p.currentToken.Type == "AS" {
		p.advance() // Consume AS
		if p.currentToken.Type != "IDENT" && !p.isNonReservedKeyword() {
			return nil, p.expectedError("target alias after AS")
		}
		stmt.TargetAlias = p.currentToken.Literal
		p.advance()
	} else if p.canBeAlias() && p.currentToken.Type != "USING" && p.currentToken.Literal != "USING" {
		stmt.TargetAlias = p.currentToken.Literal
		p.advance()
	}

	// Parse USING
	if p.currentToken.Type != "USING" && p.currentToken.Literal != "USING" {
		return nil, p.expectedError("USING")
	}
	p.advance() // Consume USING

	// Parse source table (could be a table or subquery)
	sourceRef, err := p.parseTableReference()
	if err != nil {
		return nil, fmt.Errorf("error parsing MERGE source: %w", err)
	}
	stmt.SourceTable = *sourceRef

	// Parse optional source alias
	if p.currentToken.Type == "AS" {
		p.advance() // Consume AS
		if p.currentToken.Type != "IDENT" && !p.isNonReservedKeyword() {
			return nil, p.expectedError("source alias after AS")
		}
		stmt.SourceAlias = p.currentToken.Literal
		p.advance()
	} else if p.canBeAlias() && p.currentToken.Type != "ON" && p.currentToken.Literal != "ON" {
		stmt.SourceAlias = p.currentToken.Literal
		p.advance()
	}

	// Parse ON condition
	if p.currentToken.Type != "ON" {
		return nil, p.expectedError("ON")
	}
	p.advance() // Consume ON

	onCondition, err := p.parseExpression()
	if err != nil {
		return nil, fmt.Errorf("error parsing MERGE ON condition: %w", err)
	}
	stmt.OnCondition = onCondition

	// Parse WHEN clauses
	for p.currentToken.Type == "WHEN" {
		whenClause, err := p.parseMergeWhenClause()
		if err != nil {
			return nil, err
		}
		stmt.WhenClauses = append(stmt.WhenClauses, whenClause)
	}

	if len(stmt.WhenClauses) == 0 {
		return nil, fmt.Errorf("MERGE statement requires at least one WHEN clause")
	}

	return stmt, nil
}

// parseMergeWhenClause parses a WHEN clause in a MERGE statement
func (p *Parser) parseMergeWhenClause() (*ast.MergeWhenClause, error) {
	clause := &ast.MergeWhenClause{}

	p.advance() // Consume WHEN

	// Determine clause type: MATCHED, NOT MATCHED, NOT MATCHED BY SOURCE
	if p.currentToken.Type == "MATCHED" || p.currentToken.Literal == "MATCHED" {
		clause.Type = "MATCHED"
		p.advance() // Consume MATCHED
	} else if p.currentToken.Type == "NOT" {
		p.advance() // Consume NOT
		if p.currentToken.Type != "MATCHED" && p.currentToken.Literal != "MATCHED" {
			return nil, p.expectedError("MATCHED after NOT")
		}
		p.advance() // Consume MATCHED

		// Check for BY SOURCE
		if p.currentToken.Type == "BY" {
			p.advance() // Consume BY
			if p.currentToken.Type != "SOURCE" && p.currentToken.Literal != "SOURCE" {
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
	if p.currentToken.Type == "AND" {
		p.advance() // Consume AND
		condition, err := p.parseExpression()
		if err != nil {
			return nil, fmt.Errorf("error parsing WHEN condition: %w", err)
		}
		clause.Condition = condition
	}

	// Parse THEN
	if p.currentToken.Type != "THEN" {
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

	switch p.currentToken.Type {
	case "UPDATE":
		action.ActionType = "UPDATE"
		p.advance() // Consume UPDATE

		// Parse SET
		if p.currentToken.Type != "SET" {
			return nil, p.expectedError("SET after UPDATE")
		}
		p.advance() // Consume SET

		// Parse SET clauses
		for {
			if p.currentToken.Type != "IDENT" && !p.canBeAlias() {
				return nil, p.expectedError("column name")
			}
			// Handle qualified column names (e.g., t.name)
			columnName := p.currentToken.Literal
			p.advance()

			// Check for qualified name (table.column)
			if p.currentToken.Type == "." {
				p.advance() // Consume .
				if p.currentToken.Type != "IDENT" && !p.canBeAlias() {
					return nil, p.expectedError("column name after .")
				}
				columnName = columnName + "." + p.currentToken.Literal
				p.advance()
			}

			setClause := ast.SetClause{Column: columnName}

			if p.currentToken.Type != "=" {
				return nil, p.expectedError("=")
			}
			p.advance() // Consume =

			value, err := p.parseExpression()
			if err != nil {
				return nil, fmt.Errorf("error parsing SET value: %w", err)
			}
			setClause.Value = value
			action.SetClauses = append(action.SetClauses, setClause)

			if p.currentToken.Type != "," {
				break
			}
			p.advance() // Consume comma
		}

	case "INSERT":
		if clauseType == "MATCHED" || clauseType == "NOT_MATCHED_BY_SOURCE" {
			return nil, fmt.Errorf("INSERT not allowed in WHEN %s clause", clauseType)
		}
		action.ActionType = "INSERT"
		p.advance() // Consume INSERT

		// Parse optional column list
		if p.currentToken.Type == "(" {
			p.advance() // Consume (
			for {
				if p.currentToken.Type != "IDENT" {
					return nil, p.expectedError("column name")
				}
				action.Columns = append(action.Columns, p.currentToken.Literal)
				p.advance()

				if p.currentToken.Type != "," {
					break
				}
				p.advance() // Consume comma
			}
			if p.currentToken.Type != ")" {
				return nil, p.expectedError(")")
			}
			p.advance() // Consume )
		}

		// Parse VALUES or DEFAULT VALUES
		if p.currentToken.Type == "DEFAULT" {
			p.advance() // Consume DEFAULT
			if p.currentToken.Type != "VALUES" {
				return nil, p.expectedError("VALUES after DEFAULT")
			}
			p.advance() // Consume VALUES
			action.DefaultValues = true
		} else if p.currentToken.Type == "VALUES" {
			p.advance() // Consume VALUES
			if p.currentToken.Type != "(" {
				return nil, p.expectedError("(")
			}
			p.advance() // Consume (

			for {
				value, err := p.parseExpression()
				if err != nil {
					return nil, fmt.Errorf("error parsing INSERT value: %w", err)
				}
				action.Values = append(action.Values, value)

				if p.currentToken.Type != "," {
					break
				}
				p.advance() // Consume comma
			}

			if p.currentToken.Type != ")" {
				return nil, p.expectedError(")")
			}
			p.advance() // Consume )
		} else {
			return nil, p.expectedError("VALUES or DEFAULT VALUES")
		}

	case "DELETE":
		if clauseType == "NOT_MATCHED" {
			return nil, fmt.Errorf("DELETE not allowed in WHEN NOT MATCHED clause")
		}
		action.ActionType = "DELETE"
		p.advance() // Consume DELETE

	default:
		return nil, p.expectedError("UPDATE, INSERT, or DELETE")
	}

	return action, nil
}

// parseTableReference parses a simple table reference (table name)
// Returns a TableReference with the Name field populated
