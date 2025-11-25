// Package parser - ddl.go
// DDL statement parsing: CREATE, DROP, REFRESH for views, materialized views, tables, and indexes.

package parser

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// isTokenMatch checks if the current token matches the given keyword
// This handles both keyword tokens and identifier tokens with matching literal values
// (needed because some keywords like DATA, NO may be tokenized as identifiers)
func (p *Parser) isTokenMatch(keyword string) bool {
	upperKeyword := strings.ToUpper(keyword)
	// Check if token type matches the keyword directly
	if strings.ToUpper(string(p.currentToken.Type)) == upperKeyword {
		return true
	}
	// Check if it's an identifier with matching literal (case-insensitive)
	if p.currentToken.Type == "IDENT" && strings.ToUpper(p.currentToken.Literal) == upperKeyword {
		return true
	}
	return false
}

// parseCreateStatement parses CREATE statements (TABLE, VIEW, MATERIALIZED VIEW, INDEX)
func (p *Parser) parseCreateStatement() (ast.Statement, error) {
	// Check for modifiers: OR REPLACE, TEMPORARY, TEMP
	orReplace := false
	temporary := false

	for {
		if p.currentToken.Type == "OR" {
			p.advance() // Consume OR
			if p.currentToken.Type != "REPLACE" {
				return nil, p.expectedError("REPLACE after OR")
			}
			p.advance() // Consume REPLACE
			orReplace = true
		} else if p.currentToken.Type == "TEMPORARY" || p.isTokenMatch("TEMP") {
			p.advance() // Consume TEMPORARY/TEMP
			temporary = true
		} else {
			break
		}
	}

	// Determine object type
	switch p.currentToken.Type {
	case "MATERIALIZED":
		p.advance() // Consume MATERIALIZED
		if p.currentToken.Type != "VIEW" {
			return nil, p.expectedError("VIEW after MATERIALIZED")
		}
		p.advance() // Consume VIEW
		return p.parseCreateMaterializedView()

	case "VIEW":
		p.advance() // Consume VIEW
		return p.parseCreateView(orReplace, temporary)

	case "TABLE":
		p.advance() // Consume TABLE
		return p.parseCreateTable(temporary)

	case "INDEX":
		p.advance()                      // Consume INDEX
		return p.parseCreateIndex(false) // Not unique

	case "UNIQUE":
		p.advance() // Consume UNIQUE
		if p.currentToken.Type != "INDEX" {
			return nil, p.expectedError("INDEX after UNIQUE")
		}
		p.advance()                     // Consume INDEX
		return p.parseCreateIndex(true) // Unique

	default:
		return nil, p.expectedError("TABLE, VIEW, MATERIALIZED VIEW, or INDEX after CREATE")
	}
}

// parseCreateView parses CREATE [OR REPLACE] [TEMPORARY] VIEW statement
func (p *Parser) parseCreateView(orReplace, temporary bool) (*ast.CreateViewStatement, error) {
	stmt := &ast.CreateViewStatement{
		OrReplace: orReplace,
		Temporary: temporary,
	}

	// Check for IF NOT EXISTS
	if p.currentToken.Type == "IF" {
		p.advance() // Consume IF
		if p.currentToken.Type != "NOT" {
			return nil, p.expectedError("NOT after IF")
		}
		p.advance() // Consume NOT
		if p.currentToken.Type != "EXISTS" {
			return nil, p.expectedError("EXISTS after NOT")
		}
		p.advance() // Consume EXISTS
		stmt.IfNotExists = true
	}

	// Parse view name
	if p.currentToken.Type != "IDENT" {
		return nil, p.expectedError("view name")
	}
	stmt.Name = p.currentToken.Literal
	p.advance()

	// Parse optional column list
	if p.currentToken.Type == "(" {
		p.advance() // Consume (
		for {
			if p.currentToken.Type != "IDENT" {
				return nil, p.expectedError("column name")
			}
			stmt.Columns = append(stmt.Columns, p.currentToken.Literal)
			p.advance()

			if p.currentToken.Type == "," {
				p.advance() // Consume comma
				continue
			}
			break
		}
		if p.currentToken.Type != ")" {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
	}

	// Expect AS
	if p.currentToken.Type != "AS" {
		return nil, p.expectedError("AS")
	}
	p.advance() // Consume AS

	// Parse the SELECT statement
	if p.currentToken.Type != "SELECT" {
		return nil, p.expectedError("SELECT")
	}
	p.advance() // Consume SELECT

	query, err := p.parseSelectWithSetOperations()
	if err != nil {
		return nil, fmt.Errorf("error parsing view query: %v", err)
	}
	stmt.Query = query

	// Parse optional WITH CHECK OPTION
	if p.currentToken.Type == "WITH" {
		p.advance() // Consume WITH
		if p.currentToken.Type == "CHECK" {
			p.advance() // Consume CHECK
			if p.currentToken.Type == "OPTION" {
				p.advance() // Consume OPTION
				stmt.WithOption = "CHECK OPTION"
			}
		} else if p.currentToken.Type == "CASCADED" {
			p.advance() // Consume CASCADED
			if p.currentToken.Type == "CHECK" {
				p.advance() // Consume CHECK
				if p.currentToken.Type == "OPTION" {
					p.advance() // Consume OPTION
					stmt.WithOption = "CASCADED CHECK OPTION"
				}
			}
		} else if p.currentToken.Type == "LOCAL" {
			p.advance() // Consume LOCAL
			if p.currentToken.Type == "CHECK" {
				p.advance() // Consume CHECK
				if p.currentToken.Type == "OPTION" {
					p.advance() // Consume OPTION
					stmt.WithOption = "LOCAL CHECK OPTION"
				}
			}
		}
	}

	return stmt, nil
}

// parseCreateMaterializedView parses CREATE MATERIALIZED VIEW statement
func (p *Parser) parseCreateMaterializedView() (*ast.CreateMaterializedViewStatement, error) {
	stmt := &ast.CreateMaterializedViewStatement{}

	// Check for IF NOT EXISTS
	if p.currentToken.Type == "IF" {
		p.advance() // Consume IF
		if p.currentToken.Type != "NOT" {
			return nil, p.expectedError("NOT after IF")
		}
		p.advance() // Consume NOT
		if p.currentToken.Type != "EXISTS" {
			return nil, p.expectedError("EXISTS after NOT")
		}
		p.advance() // Consume EXISTS
		stmt.IfNotExists = true
	}

	// Parse view name
	if p.currentToken.Type != "IDENT" {
		return nil, p.expectedError("materialized view name")
	}
	stmt.Name = p.currentToken.Literal
	p.advance()

	// Parse optional column list
	if p.currentToken.Type == "(" {
		p.advance() // Consume (
		for {
			if p.currentToken.Type != "IDENT" {
				return nil, p.expectedError("column name")
			}
			stmt.Columns = append(stmt.Columns, p.currentToken.Literal)
			p.advance()

			if p.currentToken.Type == "," {
				p.advance() // Consume comma
				continue
			}
			break
		}
		if p.currentToken.Type != ")" {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
	}

	// Parse optional TABLESPACE
	if p.currentToken.Type == "TABLESPACE" {
		p.advance() // Consume TABLESPACE
		if p.currentToken.Type != "IDENT" {
			return nil, p.expectedError("tablespace name")
		}
		stmt.Tablespace = p.currentToken.Literal
		p.advance()
	}

	// Expect AS
	if p.currentToken.Type != "AS" {
		return nil, p.expectedError("AS")
	}
	p.advance() // Consume AS

	// Parse the SELECT statement
	if p.currentToken.Type != "SELECT" {
		return nil, p.expectedError("SELECT")
	}
	p.advance() // Consume SELECT

	query, err := p.parseSelectWithSetOperations()
	if err != nil {
		return nil, fmt.Errorf("error parsing materialized view query: %v", err)
	}
	stmt.Query = query

	// Parse optional WITH [NO] DATA
	// Note: DATA and NO may be tokenized as IDENT since they're common identifiers
	if p.currentToken.Type == "WITH" {
		p.advance() // Consume WITH
		if p.isTokenMatch("NO") {
			p.advance() // Consume NO
			if !p.isTokenMatch("DATA") {
				return nil, p.expectedError("DATA after NO")
			}
			p.advance() // Consume DATA
			withData := false
			stmt.WithData = &withData
		} else if p.isTokenMatch("DATA") {
			p.advance() // Consume DATA
			withData := true
			stmt.WithData = &withData
		}
	}

	return stmt, nil
}

// parseCreateTable parses CREATE TABLE statement with partitioning support
func (p *Parser) parseCreateTable(temporary bool) (*ast.CreateTableStatement, error) {
	stmt := &ast.CreateTableStatement{
		Temporary: temporary,
	}

	// Check for IF NOT EXISTS
	if p.currentToken.Type == "IF" {
		p.advance() // Consume IF
		if p.currentToken.Type != "NOT" {
			return nil, p.expectedError("NOT after IF")
		}
		p.advance() // Consume NOT
		if p.currentToken.Type != "EXISTS" {
			return nil, p.expectedError("EXISTS after NOT")
		}
		p.advance() // Consume EXISTS
		stmt.IfNotExists = true
	}

	// Parse table name
	if p.currentToken.Type != "IDENT" {
		return nil, p.expectedError("table name")
	}
	stmt.Name = p.currentToken.Literal
	p.advance()

	// Expect opening parenthesis for column definitions
	if p.currentToken.Type != "(" {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	// Parse column definitions and constraints
	for {
		// Check for table-level constraints
		if p.currentToken.Type == "PRIMARY" || p.currentToken.Type == "FOREIGN" ||
			p.currentToken.Type == "UNIQUE" || p.currentToken.Type == "CHECK" ||
			p.currentToken.Type == "CONSTRAINT" {
			constraint, err := p.parseTableConstraint()
			if err != nil {
				return nil, err
			}
			stmt.Constraints = append(stmt.Constraints, *constraint)
		} else {
			// Parse column definition
			colDef, err := p.parseColumnDef()
			if err != nil {
				return nil, err
			}
			stmt.Columns = append(stmt.Columns, *colDef)
		}

		// Check for more definitions
		if p.currentToken.Type == "," {
			p.advance() // Consume comma
			continue
		}
		break
	}

	// Expect closing parenthesis
	if p.currentToken.Type != ")" {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )

	// Parse optional PARTITION BY clause
	if p.currentToken.Type == "PARTITION" {
		p.advance() // Consume PARTITION
		if p.currentToken.Type != "BY" {
			return nil, p.expectedError("BY after PARTITION")
		}
		p.advance() // Consume BY

		partitionBy, err := p.parsePartitionByClause()
		if err != nil {
			return nil, err
		}
		stmt.PartitionBy = partitionBy

		// Parse partition definitions if present
		if p.currentToken.Type == "(" {
			p.advance() // Consume (
			for {
				partDef, err := p.parsePartitionDefinition()
				if err != nil {
					return nil, err
				}
				stmt.Partitions = append(stmt.Partitions, *partDef)

				if p.currentToken.Type == "," {
					p.advance() // Consume comma
					continue
				}
				break
			}
			if p.currentToken.Type != ")" {
				return nil, p.expectedError(")")
			}
			p.advance() // Consume )
		}
	}

	// Parse optional table options
	for p.currentToken.Type == "ENGINE" || p.currentToken.Type == "CHARSET" ||
		p.currentToken.Type == "COLLATE" || p.currentToken.Type == "COMMENT" {
		opt := ast.TableOption{Name: p.currentToken.Literal}
		p.advance()
		if p.currentToken.Type == "=" {
			p.advance() // Consume =
		}
		if p.currentToken.Type == "IDENT" || p.currentToken.Type == "STRING" {
			opt.Value = p.currentToken.Literal
			p.advance()
		}
		stmt.Options = append(stmt.Options, opt)
	}

	return stmt, nil
}

// parsePartitionByClause parses PARTITION BY RANGE/LIST/HASH (columns)
func (p *Parser) parsePartitionByClause() (*ast.PartitionBy, error) {
	partitionBy := &ast.PartitionBy{}

	// Parse partition type
	switch p.currentToken.Type {
	case "RANGE":
		partitionBy.Type = "RANGE"
		p.advance()
	case "LIST":
		partitionBy.Type = "LIST"
		p.advance()
	case "HASH":
		partitionBy.Type = "HASH"
		p.advance()
	default:
		return nil, p.expectedError("RANGE, LIST, or HASH")
	}

	// Expect opening parenthesis
	if p.currentToken.Type != "(" {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	// Parse column list
	for {
		if p.currentToken.Type != "IDENT" {
			return nil, p.expectedError("column name")
		}
		partitionBy.Columns = append(partitionBy.Columns, p.currentToken.Literal)
		p.advance()

		if p.currentToken.Type == "," {
			p.advance() // Consume comma
			continue
		}
		break
	}

	// Expect closing parenthesis
	if p.currentToken.Type != ")" {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )

	return partitionBy, nil
}

// parsePartitionDefinition parses a single partition definition
func (p *Parser) parsePartitionDefinition() (*ast.PartitionDefinition, error) {
	partDef := &ast.PartitionDefinition{}

	// Expect PARTITION keyword
	if p.currentToken.Type != "PARTITION" {
		return nil, p.expectedError("PARTITION")
	}
	p.advance() // Consume PARTITION

	// Parse partition name
	if p.currentToken.Type != "IDENT" {
		return nil, p.expectedError("partition name")
	}
	partDef.Name = p.currentToken.Literal
	p.advance()

	// Parse VALUES clause
	if p.currentToken.Type != "VALUES" {
		return nil, p.expectedError("VALUES")
	}
	p.advance() // Consume VALUES

	// Parse value specification
	if p.currentToken.Type == "LESS" {
		p.advance() // Consume LESS
		if p.currentToken.Type != "THAN" {
			return nil, p.expectedError("THAN after LESS")
		}
		p.advance() // Consume THAN
		partDef.Type = "LESS THAN"

		// Parse value or MAXVALUE
		if p.currentToken.Type == "(" {
			p.advance() // Consume (
			if p.currentToken.Type == "MAXVALUE" {
				partDef.LessThan = &ast.Identifier{Name: "MAXVALUE"}
				p.advance()
			} else {
				expr, err := p.parseExpression()
				if err != nil {
					return nil, err
				}
				partDef.LessThan = expr
			}
			if p.currentToken.Type != ")" {
				return nil, p.expectedError(")")
			}
			p.advance() // Consume )
		} else if p.currentToken.Type == "MAXVALUE" {
			partDef.LessThan = &ast.Identifier{Name: "MAXVALUE"}
			p.advance()
		}
	} else if p.currentToken.Type == "IN" {
		p.advance() // Consume IN
		partDef.Type = "IN"

		// Parse value list
		if p.currentToken.Type != "(" {
			return nil, p.expectedError("(")
		}
		p.advance() // Consume (

		for {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			partDef.InValues = append(partDef.InValues, expr)

			if p.currentToken.Type == "," {
				p.advance() // Consume comma
				continue
			}
			break
		}

		if p.currentToken.Type != ")" {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
	} else if p.currentToken.Type == "FROM" {
		p.advance() // Consume FROM
		partDef.Type = "FROM TO"

		// Parse FROM value
		if p.currentToken.Type != "(" {
			return nil, p.expectedError("(")
		}
		p.advance() // Consume (
		fromExpr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		partDef.From = fromExpr
		if p.currentToken.Type != ")" {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )

		// Expect TO
		if p.currentToken.Type != "TO" {
			return nil, p.expectedError("TO")
		}
		p.advance() // Consume TO

		// Parse TO value
		if p.currentToken.Type != "(" {
			return nil, p.expectedError("(")
		}
		p.advance() // Consume (
		toExpr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		partDef.To = toExpr
		if p.currentToken.Type != ")" {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
	}

	// Parse optional TABLESPACE
	if p.currentToken.Type == "TABLESPACE" {
		p.advance() // Consume TABLESPACE
		if p.currentToken.Type != "IDENT" {
			return nil, p.expectedError("tablespace name")
		}
		partDef.Tablespace = p.currentToken.Literal
		p.advance()
	}

	return partDef, nil
}

// parseCreateIndex parses CREATE [UNIQUE] INDEX statement
func (p *Parser) parseCreateIndex(unique bool) (*ast.CreateIndexStatement, error) {
	stmt := &ast.CreateIndexStatement{
		Unique: unique,
	}

	// Check for IF NOT EXISTS
	if p.currentToken.Type == "IF" {
		p.advance() // Consume IF
		if p.currentToken.Type != "NOT" {
			return nil, p.expectedError("NOT after IF")
		}
		p.advance() // Consume NOT
		if p.currentToken.Type != "EXISTS" {
			return nil, p.expectedError("EXISTS after NOT")
		}
		p.advance() // Consume EXISTS
		stmt.IfNotExists = true
	}

	// Parse index name
	if p.currentToken.Type != "IDENT" {
		return nil, p.expectedError("index name")
	}
	stmt.Name = p.currentToken.Literal
	p.advance()

	// Expect ON
	if p.currentToken.Type != "ON" {
		return nil, p.expectedError("ON")
	}
	p.advance() // Consume ON

	// Parse table name
	if p.currentToken.Type != "IDENT" {
		return nil, p.expectedError("table name")
	}
	stmt.Table = p.currentToken.Literal
	p.advance()

	// Parse optional USING
	if p.currentToken.Type == "USING" {
		p.advance() // Consume USING
		if p.currentToken.Type != "IDENT" {
			return nil, p.expectedError("index method")
		}
		stmt.Using = p.currentToken.Literal
		p.advance()
	}

	// Expect opening parenthesis
	if p.currentToken.Type != "(" {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	// Parse column list
	for {
		col := ast.IndexColumn{}
		if p.currentToken.Type != "IDENT" {
			return nil, p.expectedError("column name")
		}
		col.Column = p.currentToken.Literal
		p.advance()

		// Parse optional direction
		if p.currentToken.Type == "ASC" {
			col.Direction = "ASC"
			p.advance()
		} else if p.currentToken.Type == "DESC" {
			col.Direction = "DESC"
			p.advance()
		}

		// Parse optional NULLS LAST
		if p.currentToken.Type == "NULLS" {
			p.advance() // Consume NULLS
			if p.currentToken.Type == "LAST" {
				col.NullsLast = true
				p.advance()
			} else if p.currentToken.Type == "FIRST" {
				p.advance()
			}
		}

		stmt.Columns = append(stmt.Columns, col)

		if p.currentToken.Type == "," {
			p.advance() // Consume comma
			continue
		}
		break
	}

	// Expect closing parenthesis
	if p.currentToken.Type != ")" {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )

	// Parse optional WHERE clause (partial index)
	if p.currentToken.Type == "WHERE" {
		p.advance() // Consume WHERE
		whereClause, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		stmt.Where = whereClause
	}

	return stmt, nil
}

// parseDropStatement parses DROP statements (TABLE, VIEW, MATERIALIZED VIEW, INDEX)
func (p *Parser) parseDropStatement() (*ast.DropStatement, error) {
	stmt := &ast.DropStatement{}

	// Determine object type
	switch p.currentToken.Type {
	case "MATERIALIZED":
		p.advance() // Consume MATERIALIZED
		if p.currentToken.Type != "VIEW" {
			return nil, p.expectedError("VIEW after MATERIALIZED")
		}
		p.advance() // Consume VIEW
		stmt.ObjectType = "MATERIALIZED VIEW"

	case "VIEW":
		p.advance() // Consume VIEW
		stmt.ObjectType = "VIEW"

	case "TABLE":
		p.advance() // Consume TABLE
		stmt.ObjectType = "TABLE"

	case "INDEX":
		p.advance() // Consume INDEX
		stmt.ObjectType = "INDEX"

	default:
		return nil, p.expectedError("TABLE, VIEW, MATERIALIZED VIEW, or INDEX after DROP")
	}

	// Check for IF EXISTS
	if p.currentToken.Type == "IF" {
		p.advance() // Consume IF
		if p.currentToken.Type != "EXISTS" {
			return nil, p.expectedError("EXISTS after IF")
		}
		p.advance() // Consume EXISTS
		stmt.IfExists = true
	}

	// Parse object names (can be comma-separated)
	for {
		if p.currentToken.Type != "IDENT" {
			return nil, p.expectedError("object name")
		}
		stmt.Names = append(stmt.Names, p.currentToken.Literal)
		p.advance()

		if p.currentToken.Type == "," {
			p.advance() // Consume comma
			continue
		}
		break
	}

	// Parse optional CASCADE/RESTRICT
	if p.currentToken.Type == "CASCADE" {
		stmt.CascadeType = "CASCADE"
		p.advance()
	} else if p.currentToken.Type == "RESTRICT" {
		stmt.CascadeType = "RESTRICT"
		p.advance()
	}

	return stmt, nil
}

// parseRefreshStatement parses REFRESH MATERIALIZED VIEW statement
func (p *Parser) parseRefreshStatement() (*ast.RefreshMaterializedViewStatement, error) {
	// Expect MATERIALIZED
	if p.currentToken.Type != "MATERIALIZED" {
		return nil, p.expectedError("MATERIALIZED after REFRESH")
	}
	p.advance() // Consume MATERIALIZED

	// Expect VIEW
	if p.currentToken.Type != "VIEW" {
		return nil, p.expectedError("VIEW after MATERIALIZED")
	}
	p.advance() // Consume VIEW

	stmt := &ast.RefreshMaterializedViewStatement{}

	// Check for CONCURRENTLY
	if p.currentToken.Type == "CONCURRENTLY" {
		stmt.Concurrently = true
		p.advance()
	}

	// Parse view name
	if p.currentToken.Type != "IDENT" {
		return nil, p.expectedError("materialized view name")
	}
	stmt.Name = p.currentToken.Literal
	p.advance()

	// Parse optional WITH [NO] DATA
	// Note: DATA and NO may be tokenized as IDENT since they're common identifiers
	if p.currentToken.Type == "WITH" {
		p.advance() // Consume WITH
		if p.isTokenMatch("NO") {
			p.advance() // Consume NO
			if !p.isTokenMatch("DATA") {
				return nil, p.expectedError("DATA after NO")
			}
			p.advance() // Consume DATA
			withData := false
			stmt.WithData = &withData
		} else if p.isTokenMatch("DATA") {
			p.advance() // Consume DATA
			withData := true
			stmt.WithData = &withData
		}
	}

	return stmt, nil
}
