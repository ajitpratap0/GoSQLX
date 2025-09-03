// Package parser provides a recursive descent SQL parser that converts tokens into an Abstract Syntax Tree (AST).
// It supports standard SQL statements including SELECT, INSERT, UPDATE, DELETE, and various DDL operations.
package parser

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// Parser represents a SQL parser
type Parser struct {
	tokens       []token.Token
	currentPos   int
	currentToken token.Token
}

// Parse parses the tokens into an AST
func (p *Parser) Parse(tokens []token.Token) (*ast.AST, error) {
	p.tokens = tokens
	p.currentPos = 0
	if len(tokens) > 0 {
		p.currentToken = tokens[0]
	}

	// Get a pre-allocated AST from the pool
	result := ast.NewAST()

	// Pre-allocate statements slice based on a reasonable estimate
	estimatedStmts := 1 // Most SQL queries have just one statement
	if len(tokens) > 100 {
		estimatedStmts = 2 // For larger inputs, allocate more
	}
	result.Statements = make([]ast.Statement, 0, estimatedStmts)

	// Parse statements
	for p.currentPos < len(tokens) && p.currentToken.Type != "EOF" {
		stmt, err := p.parseStatement()
		if err != nil {
			// Clean up the AST on error
			ast.ReleaseAST(result)
			return nil, err
		}
		result.Statements = append(result.Statements, stmt)
	}

	return result, nil
}

// Release releases any resources held by the parser
func (p *Parser) Release() {
	// Reset internal state to avoid memory leaks
	p.tokens = nil
	p.currentPos = 0
	p.currentToken = token.Token{}
}

// parseStatement parses a single SQL statement
func (p *Parser) parseStatement() (ast.Statement, error) {
	// TODO: PHASE 2 - Add WITH statement parsing for Common Table Expressions (CTEs)
	// case "WITH":
	//     p.advance() // Consume WITH
	//     return p.parseWithStatement() // Needs implementation
	switch p.currentToken.Type {
	case "SELECT":
		p.advance() // Consume SELECT
		return p.parseSelectStatement()
	case "INSERT":
		p.advance() // Consume INSERT
		return p.parseInsertStatement()
	case "UPDATE":
		p.advance() // Consume UPDATE
		return p.parseUpdateStatement()
	case "DELETE":
		p.advance() // Consume DELETE
		return p.parseDeleteStatement()
	case "ALTER":
		p.advance() // Consume ALTER
		return p.parseAlterTableStmt()
	default:
		return nil, p.expectedError("statement")
	}
}

// NewParser creates a new parser
func NewParser() *Parser {
	return &Parser{}
}

// matchToken checks if the current token matches the expected type
func (p *Parser) matchToken(expected token.Type) bool {
	// Convert both to strings for comparison
	expectedStr := string(expected)
	currentStr := string(p.currentToken.Type)
	if currentStr == expectedStr {
		p.advance()
		return true
	}
	return false
}

// advance moves to the next token
func (p *Parser) advance() {
	p.currentPos++
	if p.currentPos < len(p.tokens) {
		p.currentToken = p.tokens[p.currentPos]
	}
}

// expectedError returns an error for unexpected token
func (p *Parser) expectedError(expected string) error {
	return fmt.Errorf("expected %s, got %s", expected, p.currentToken.Type)
}

// parseIdent parses an identifier
func (p *Parser) parseIdent() *ast.Identifier {
	if p.currentToken.Type != token.IDENT && p.currentToken.Type != "IDENT" {
		return nil
	}
	ident := &ast.Identifier{Name: p.currentToken.Literal}
	p.advance()
	return ident
}

// parseIdentAsString parses an identifier and returns its name as a string
func (p *Parser) parseIdentAsString() string {
	ident := p.parseIdent()
	if ident == nil {
		return ""
	}
	return ident.Name
}

// parseObjectName parses an object name (possibly qualified)
func (p *Parser) parseObjectName() ast.ObjectName {
	ident := p.parseIdent()
	if ident == nil {
		return ast.ObjectName{}
	}
	return ast.ObjectName{Name: ident.Name}
}

// parseStringLiteral parses a string literal
func (p *Parser) parseStringLiteral() string {
	if p.currentToken.Type != token.STRING && p.currentToken.Type != "STRING" {
		return ""
	}
	value := p.currentToken.Literal
	p.advance()
	return value
}

// parseExpression parses an expression
func (p *Parser) parseExpression() (ast.Expression, error) {
	// Parse the left side of the expression
	var left ast.Expression

	switch p.currentToken.Type {
	case "IDENT":
		// Handle identifiers
		ident := &ast.Identifier{Name: p.currentToken.Literal}
		p.advance()

		// Check for qualified identifier (table.column)
		if p.currentToken.Type == "." {
			p.advance() // Consume .
			if p.currentToken.Type != "IDENT" {
				return nil, p.expectedError("identifier after .")
			}
			// Create a qualified identifier
			ident = &ast.Identifier{
				Table: ident.Name,
				Name:  p.currentToken.Literal,
			}
			p.advance()
		}

		left = ident

	case "STRING":
		// Handle string literals
		left = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "string"}
		p.advance()

	case "INT":
		// Handle integer literals
		left = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "int"}
		p.advance()

	case "FLOAT":
		// Handle float literals
		left = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "float"}
		p.advance()

	case "TRUE", "FALSE":
		// Handle boolean literals
		left = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "bool"}
		p.advance()

	default:
		return nil, fmt.Errorf("unexpected token: %s", p.currentToken.Type)
	}

	// Check if this is a binary expression
	if p.currentToken.Type == "=" || p.currentToken.Type == "<" ||
		p.currentToken.Type == ">" || p.currentToken.Type == "!=" {
		// Save the operator
		operator := p.currentToken.Literal
		p.advance()

		// Parse the right side of the expression
		right, err := p.parseExpression()
		if err != nil {
			return nil, err
		}

		// Create a binary expression
		return &ast.BinaryExpression{
			Left:     left,
			Operator: operator,
			Right:    right,
		}, nil
	}

	return left, nil
}

// parseColumnDef parses a column definition
func (p *Parser) parseColumnDef() (*ast.ColumnDef, error) {
	name := p.parseIdent()
	if name == nil {
		return nil, fmt.Errorf("expected column name")
	}

	dataType := p.parseIdent()
	if dataType == nil {
		return nil, fmt.Errorf("expected data type")
	}

	colDef := &ast.ColumnDef{
		Name: name.Name,
		Type: dataType.Name,
	}

	return colDef, nil
}

// parseTableConstraint parses a table constraint
func (p *Parser) parseTableConstraint() (*ast.TableConstraint, error) {
	name := p.parseIdent()
	if name == nil {
		return nil, fmt.Errorf("expected constraint name")
	}

	constraint := &ast.TableConstraint{
		Name: name.Name,
	}

	return constraint, nil
}

// parseSelectStatement parses a SELECT statement
func (p *Parser) parseSelectStatement() (ast.Statement, error) {
	// We've already consumed the SELECT token in matchToken

	// Parse columns
	columns := make([]ast.Expression, 0)
	for {
		// Handle * as a special case
		if p.currentToken.Type == "*" {
			columns = append(columns, &ast.Identifier{Name: "*"})
			p.advance()
		} else if p.currentToken.Type == "IDENT" {
			// Parse column identifier
			ident := &ast.Identifier{Name: p.currentToken.Literal}
			p.advance()

			// Check for qualified column (table.column)
			if p.currentToken.Type == "." {
				p.advance() // Consume .
				if p.currentToken.Type != "IDENT" {
					return nil, p.expectedError("identifier after .")
				}
				// Create a qualified identifier
				ident = &ast.Identifier{
					Table: ident.Name,
					Name:  p.currentToken.Literal,
				}
				p.advance()
			}

			columns = append(columns, ident)
		} else {
			// Parse other expression types
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			columns = append(columns, expr)
		}

		// Check if there are more columns
		if p.currentToken.Type != "," {
			break
		}
		p.advance() // Consume comma
	}

	// Parse FROM clause
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

	// Create table reference
	tableRef := ast.TableReference{
		Name: tableName,
	}

	// Check for table alias
	if p.currentToken.Type == "IDENT" || p.currentToken.Type == "AS" {
		if p.currentToken.Type == "AS" {
			p.advance() // Consume AS
			if p.currentToken.Type != "IDENT" {
				return nil, p.expectedError("alias after AS")
			}
		}
		if p.currentToken.Type == "IDENT" {
			tableRef.Alias = p.currentToken.Literal
			p.advance()
		}
	}

	// Create tables list for FROM clause
	tables := []ast.TableReference{tableRef}

	// Parse JOIN clauses if present
	joins := []ast.JoinClause{}
	for p.isJoinKeyword() {
		// Determine JOIN type
		joinType := "INNER" // Default

		if p.currentToken.Type == "LEFT" {
			joinType = "LEFT"
			p.advance()
			if p.currentToken.Type == "OUTER" {
				p.advance() // Optional OUTER keyword
			}
		} else if p.currentToken.Type == "RIGHT" {
			joinType = "RIGHT"
			p.advance()
			if p.currentToken.Type == "OUTER" {
				p.advance() // Optional OUTER keyword
			}
		} else if p.currentToken.Type == "FULL" {
			joinType = "FULL"
			p.advance()
			if p.currentToken.Type == "OUTER" {
				p.advance() // Optional OUTER keyword
			}
		} else if p.currentToken.Type == "INNER" {
			joinType = "INNER"
			p.advance()
		} else if p.currentToken.Type == "CROSS" {
			joinType = "CROSS"
			p.advance()
		}

		// Expect JOIN keyword
		if p.currentToken.Type != "JOIN" {
			return nil, fmt.Errorf("expected JOIN after %s, got %s", joinType, p.currentToken.Type)
		}
		p.advance() // Consume JOIN

		// Parse joined table name
		if p.currentToken.Type != "IDENT" {
			return nil, fmt.Errorf("expected table name after %s JOIN, got %s", joinType, p.currentToken.Type)
		}
		joinedTableName := p.currentToken.Literal
		p.advance()

		// Create joined table reference
		joinedTableRef := ast.TableReference{
			Name: joinedTableName,
		}

		// Check for table alias
		if p.currentToken.Type == "IDENT" || p.currentToken.Type == "AS" {
			if p.currentToken.Type == "AS" {
				p.advance() // Consume AS
				if p.currentToken.Type != "IDENT" {
					return nil, p.expectedError("alias after AS")
				}
			}
			if p.currentToken.Type == "IDENT" {
				joinedTableRef.Alias = p.currentToken.Literal
				p.advance()
			}
		}

		// Parse join condition (ON or USING)
		var joinCondition ast.Expression

		// CROSS JOIN doesn't require ON clause
		if joinType != "CROSS" {
			if p.currentToken.Type == "ON" {
				p.advance() // Consume ON

				// Parse join condition
				cond, err := p.parseExpression()
				if err != nil {
					return nil, fmt.Errorf("error parsing ON condition for %s JOIN: %v", joinType, err)
				}
				joinCondition = cond
			} else if p.currentToken.Type == "USING" {
				p.advance() // Consume USING

				// Parse column list in parentheses
				if p.currentToken.Type != "(" {
					return nil, p.expectedError("( after USING")
				}
				p.advance()

				// TODO: LIMITATION - Currently only supports single column in USING clause
				// Future enhancement needed for multi-column support like USING (col1, col2, col3)
				// This requires parsing comma-separated column list and storing as []Expression
				// Priority: Medium (Phase 2 enhancement)
				if p.currentToken.Type != "IDENT" {
					return nil, p.expectedError("column name in USING")
				}
				joinCondition = &ast.Identifier{Name: p.currentToken.Literal}
				p.advance()

				if p.currentToken.Type != ")" {
					return nil, p.expectedError(") after USING column")
				}
				p.advance()
			} else if joinType != "NATURAL" {
				return nil, p.expectedError("ON or USING")
			}
		}

		// Create join clause with proper tree relationships
		// For SQL: FROM A JOIN B JOIN C (equivalent to (A JOIN B) JOIN C)
		var leftTable ast.TableReference
		if len(joins) == 0 {
			// First join: A JOIN B
			leftTable = tableRef
		} else {
			// Subsequent joins: (previous result) JOIN C
			// We represent this by using a synthetic table reference that indicates
			// the left side is the result of previous joins
			leftTable = ast.TableReference{
				Name:  fmt.Sprintf("(%s_with_%d_joins)", tableRef.Name, len(joins)),
				Alias: "",
			}
		}

		joinClause := ast.JoinClause{
			Type:      joinType,
			Left:      leftTable,
			Right:     joinedTableRef,
			Condition: joinCondition,
		}

		// Add join clause to joins list
		joins = append(joins, joinClause)

		// Note: We don't update tableRef here as each JOIN in the list
		// represents a join with the accumulated result set
	}

	// Initialize SELECT statement
	selectStmt := &ast.SelectStatement{
		Columns:   columns,
		From:      tables,
		Joins:     joins,
		TableName: tableName, // Add this for compatibility with tests
	}

	// Parse WHERE clause if present
	if p.currentToken.Type == "WHERE" {
		p.advance() // Consume WHERE

		// Parse WHERE condition
		whereClause, err := p.parseExpression()
		if err != nil {
			return nil, err
		}

		// Add WHERE clause to SELECT statement
		selectStmt.Where = whereClause
	}

	// Parse ORDER BY clause if present
	if p.currentToken.Type == "ORDER" {
		p.advance() // Consume ORDER

		if p.currentToken.Type != "BY" {
			return nil, p.expectedError("BY")
		}
		p.advance() // Consume BY

		// Parse ORDER BY expression
		orderByExpr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}

		// Check for direction (ASC/DESC)
		// Note: Direction is handled separately in the actual implementation
		if p.currentToken.Type == "DESC" {
			p.advance() // Consume DESC
		} else if p.currentToken.Type == "ASC" {
			p.advance() // Consume ASC
		}

		// Add ORDER BY to SELECT statement
		selectStmt.OrderBy = []ast.Expression{orderByExpr}
	}

	// Parse LIMIT clause if present
	if p.currentToken.Type == "LIMIT" {
		p.advance() // Consume LIMIT

		// Parse LIMIT value
		if p.currentToken.Type != "INT" {
			return nil, p.expectedError("integer for LIMIT")
		}

		// Convert string to int
		limitVal := 0
		_, _ = fmt.Sscanf(p.currentToken.Literal, "%d", &limitVal)

		// Add LIMIT to SELECT statement
		selectStmt.Limit = &limitVal
		p.advance()
	}

	// Parse OFFSET clause if present
	if p.currentToken.Type == "OFFSET" {
		p.advance() // Consume OFFSET

		// Parse OFFSET value
		if p.currentToken.Type != "INT" {
			return nil, p.expectedError("integer for OFFSET")
		}

		// Convert string to int
		offsetVal := 0
		_, _ = fmt.Sscanf(p.currentToken.Literal, "%d", &offsetVal)

		// Add OFFSET to SELECT statement
		selectStmt.Offset = &offsetVal
		p.advance()
	}

	return selectStmt, nil
}

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

// parseAlterTableStmt is a simplified version for the parser implementation
// It delegates to the more comprehensive parseAlterStatement in alter.go
func (p *Parser) parseAlterTableStmt() (ast.Statement, error) {
	// We've already consumed the ALTER token in matchToken
	// This is just a placeholder that delegates to the main implementation
	return p.parseAlterStatement()
}

// isJoinKeyword checks if current token is a JOIN-related keyword
func (p *Parser) isJoinKeyword() bool {
	switch p.currentToken.Type {
	case "JOIN", "INNER", "LEFT", "RIGHT", "FULL", "CROSS":
		return true
	default:
		return false
	}
}
