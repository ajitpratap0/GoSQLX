package parser

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseMatchAgainst parses MySQL MATCH(...) AGAINST('text' [IN NATURAL LANGUAGE MODE | IN BOOLEAN MODE | WITH QUERY EXPANSION])
func (p *Parser) parseMatchAgainst(matchFunc *ast.FunctionCall) (ast.Expression, error) {
	p.advance() // Consume AGAINST
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	// Parse search expression (just the primary — not full expression, to avoid IN being eaten)
	searchExpr, err := p.parsePrimaryExpression()
	if err != nil {
		return nil, fmt.Errorf("failed to parse AGAINST expression: %w", err)
	}

	// Consume optional mode keywords until we hit )
	mode := ""
	for !p.isType(models.TokenTypeRParen) && !p.isType(models.TokenTypeEOF) {
		mode += " " + p.currentToken.Literal
		p.advance()
	}

	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )

	// Represent as a binary expression: MATCH(cols) AGAINST(expr)
	// Store the search expr and mode as a function call named "AGAINST"
	againstFunc := &ast.FunctionCall{
		Name:      "AGAINST",
		Arguments: []ast.Expression{searchExpr},
	}
	if mode != "" {
		againstFunc.Arguments = append(againstFunc.Arguments, &ast.LiteralValue{
			Value: strings.TrimSpace(mode),
			Type:  "STRING",
		})
	}

	return &ast.BinaryExpression{
		Left:     matchFunc,
		Operator: "AGAINST",
		Right:    againstFunc,
	}, nil
}

// parseShowStatement parses MySQL SHOW commands:
//   - SHOW TABLES
//   - SHOW DATABASES
//   - SHOW CREATE TABLE name
//   - SHOW COLUMNS FROM name
//   - SHOW INDEX FROM name
func (p *Parser) parseShowStatement() (ast.Statement, error) {
	show := &ast.ShowStatement{}

	upper := strings.ToUpper(p.currentToken.Literal)

	switch upper {
	case "TABLES":
		show.ShowType = "TABLES"
		p.advance()
		// Optional FROM database
		if p.isType(models.TokenTypeFrom) {
			p.advance()
			show.From = p.currentToken.Literal
			p.advance()
		}
	case "DATABASES":
		show.ShowType = "DATABASES"
		p.advance()
	case "CREATE":
		p.advance() // Consume CREATE
		if p.isType(models.TokenTypeTable) {
			show.ShowType = "CREATE TABLE"
			p.advance() // Consume TABLE
			name, err := p.parseQualifiedName()
			if err != nil {
				return nil, p.expectedError("table name")
			}
			show.ObjectName = name
		} else {
			show.ShowType = "CREATE " + strings.ToUpper(p.currentToken.Literal)
			p.advance()
			name, err := p.parseQualifiedName()
			if err != nil {
				return nil, p.expectedError("object name")
			}
			show.ObjectName = name
		}
	case "COLUMNS":
		show.ShowType = "COLUMNS"
		p.advance()
		if p.isType(models.TokenTypeFrom) {
			p.advance()
			name, err := p.parseQualifiedName()
			if err != nil {
				return nil, p.expectedError("table name")
			}
			show.ObjectName = name
		}
	case "INDEX", "INDEXES", "KEYS":
		show.ShowType = upper
		p.advance()
		if p.isType(models.TokenTypeFrom) {
			p.advance()
			name, err := p.parseQualifiedName()
			if err != nil {
				return nil, p.expectedError("table name")
			}
			show.ObjectName = name
		}
	case "STATUS", "VARIABLES":
		show.ShowType = upper
		p.advance()
	default:
		// Generic: SHOW <whatever>
		show.ShowType = upper
		p.advance()
	}

	return show, nil
}

// parseDescribeStatement parses DESCRIBE/DESC/EXPLAIN table_name
func (p *Parser) parseDescribeStatement() (ast.Statement, error) {
	// For EXPLAIN SELECT ..., defer to parseStatement for the SELECT
	// For DESCRIBE table_name, just parse the table name
	if p.isType(models.TokenTypeSelect) {
		// EXPLAIN SELECT ... — treat as describe with the query text
		// For now, just skip to parse the select
		p.advance()
		stmt, err := p.parseSelectWithSetOperations()
		if err != nil {
			return nil, err
		}
		// Wrap in a describe
		_ = stmt
		return &ast.DescribeStatement{TableName: "SELECT"}, nil
	}

	name, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.expectedError("table name")
	}
	return &ast.DescribeStatement{TableName: name}, nil
}

// parseReplaceStatement parses MySQL REPLACE INTO statement
func (p *Parser) parseReplaceStatement() (ast.Statement, error) {
	// Expect INTO
	if !p.isType(models.TokenTypeInto) {
		return nil, p.expectedError("INTO")
	}
	p.advance()

	// Parse table name
	tableName, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.expectedError("table name")
	}

	// Parse column list if present
	columns := make([]ast.Expression, 0)
	if p.isType(models.TokenTypeLParen) {
		p.advance()
		for {
			if !p.isIdentifier() {
				return nil, p.expectedError("column name")
			}
			columns = append(columns, &ast.Identifier{Name: p.currentToken.Literal})
			p.advance()
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance()
		}
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance()
	}

	// Parse VALUES
	if !p.isType(models.TokenTypeValues) {
		return nil, p.expectedError("VALUES")
	}
	p.advance()

	values := make([][]ast.Expression, 0)
	for {
		if !p.isType(models.TokenTypeLParen) {
			if len(values) == 0 {
				return nil, p.expectedError("(")
			}
			break
		}
		p.advance()

		row := make([]ast.Expression, 0)
		for {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, fmt.Errorf("failed to parse value in REPLACE: %w", err)
			}
			row = append(row, expr)
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance()
		}
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance()
		values = append(values, row)

		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance()
	}

	return &ast.ReplaceStatement{
		TableName: tableName,
		Columns:   columns,
		Values:    values,
	}, nil
}
