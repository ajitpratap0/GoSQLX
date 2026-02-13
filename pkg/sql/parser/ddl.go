// Package parser - ddl.go
// DDL statement parsing: CREATE, DROP, REFRESH for views, materialized views, tables, and indexes.

package parser

import (
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// isTokenMatch checks if the current token matches the given keyword
// This handles both keyword tokens and identifier tokens with matching literal values
// (needed because some keywords like DATA, NO may be tokenized as identifiers)
func (p *Parser) isTokenMatch(keyword string) bool {
	upperKeyword := strings.ToUpper(keyword)
	// Check if token literal matches the keyword (case-insensitive)
	if strings.ToUpper(p.currentToken.Literal) == upperKeyword {
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
		if p.isType(models.TokenTypeOr) {
			p.advance() // Consume OR
			if !p.isType(models.TokenTypeReplace) {
				return nil, p.expectedError("REPLACE after OR")
			}
			p.advance() // Consume REPLACE
			orReplace = true
		} else if p.isTokenMatch("TEMPORARY") || p.isTokenMatch("TEMP") {
			p.advance() // Consume TEMPORARY/TEMP
			temporary = true
		} else {
			break
		}
	}

	// Determine object type
	if p.isType(models.TokenTypeMaterialized) {
		p.advance() // Consume MATERIALIZED
		if !p.isType(models.TokenTypeView) {
			return nil, p.expectedError("VIEW after MATERIALIZED")
		}
		p.advance() // Consume VIEW
		return p.parseCreateMaterializedView()
	} else if p.isType(models.TokenTypeView) {
		p.advance() // Consume VIEW
		return p.parseCreateView(orReplace, temporary)
	} else if p.isType(models.TokenTypeTable) {
		p.advance() // Consume TABLE
		return p.parseCreateTable(temporary)
	} else if p.isType(models.TokenTypeIndex) {
		p.advance()                      // Consume INDEX
		return p.parseCreateIndex(false) // Not unique
	} else if p.isType(models.TokenTypeUnique) {
		p.advance() // Consume UNIQUE
		if !p.isType(models.TokenTypeIndex) {
			return nil, p.expectedError("INDEX after UNIQUE")
		}
		p.advance()                     // Consume INDEX
		return p.parseCreateIndex(true) // Unique
	}
	return nil, p.expectedError("TABLE, VIEW, MATERIALIZED VIEW, or INDEX after CREATE")
}

// parseCreateView parses CREATE [OR REPLACE] [TEMPORARY] VIEW statement
func (p *Parser) parseCreateView(orReplace, temporary bool) (*ast.CreateViewStatement, error) {
	stmt := &ast.CreateViewStatement{
		OrReplace: orReplace,
		Temporary: temporary,
	}

	// Check for IF NOT EXISTS
	if p.isType(models.TokenTypeIf) {
		p.advance() // Consume IF
		if !p.isType(models.TokenTypeNot) {
			return nil, p.expectedError("NOT after IF")
		}
		p.advance() // Consume NOT
		if !p.isType(models.TokenTypeExists) {
			return nil, p.expectedError("EXISTS after NOT")
		}
		p.advance() // Consume EXISTS
		stmt.IfNotExists = true
	}

	// Parse view name (supports schema.view qualification and double-quoted identifiers)
	viewName, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.expectedError("view name")
	}
	stmt.Name = viewName

	// Parse optional column list
	if p.isType(models.TokenTypeLParen) {
		p.advance() // Consume (
		for {
			if !p.isIdentifier() {
				return nil, p.expectedError("column name")
			}
			stmt.Columns = append(stmt.Columns, p.currentToken.Literal)
			p.advance()

			if p.isType(models.TokenTypeComma) {
				p.advance() // Consume comma
				continue
			}
			break
		}
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
	}

	// Expect AS
	if !p.isType(models.TokenTypeAs) {
		return nil, p.expectedError("AS")
	}
	p.advance() // Consume AS

	// Parse the SELECT statement
	if !p.isType(models.TokenTypeSelect) {
		return nil, p.expectedError("SELECT")
	}
	p.advance() // Consume SELECT

	query, err := p.parseSelectWithSetOperations()
	if err != nil {
		return nil, goerrors.WrapError(
			goerrors.ErrCodeInvalidSyntax,
			"error parsing view query",
			models.Location{}, // Location not available in current parser implementation
			"",                // SQL not available in current parser implementation
			err,
		)
	}
	stmt.Query = query

	// Parse optional WITH CHECK OPTION
	if p.isType(models.TokenTypeWith) {
		p.advance() // Consume WITH
		if p.isType(models.TokenTypeCheck) {
			p.advance() // Consume CHECK
			if p.isTokenMatch("OPTION") {
				p.advance() // Consume OPTION
				stmt.WithOption = "CHECK OPTION"
			}
		} else if p.isTokenMatch("CASCADED") {
			p.advance() // Consume CASCADED
			if p.isType(models.TokenTypeCheck) {
				p.advance() // Consume CHECK
				if p.isTokenMatch("OPTION") {
					p.advance() // Consume OPTION
					stmt.WithOption = "CASCADED CHECK OPTION"
				}
			}
		} else if p.isTokenMatch("LOCAL") {
			p.advance() // Consume LOCAL
			if p.isType(models.TokenTypeCheck) {
				p.advance() // Consume CHECK
				if p.isTokenMatch("OPTION") {
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
	if p.isType(models.TokenTypeIf) {
		p.advance() // Consume IF
		if !p.isType(models.TokenTypeNot) {
			return nil, p.expectedError("NOT after IF")
		}
		p.advance() // Consume NOT
		if !p.isType(models.TokenTypeExists) {
			return nil, p.expectedError("EXISTS after NOT")
		}
		p.advance() // Consume EXISTS
		stmt.IfNotExists = true
	}

	// Parse view name (supports schema.view qualification and double-quoted identifiers)
	matViewName, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.expectedError("materialized view name")
	}
	stmt.Name = matViewName

	// Parse optional column list
	if p.isType(models.TokenTypeLParen) {
		p.advance() // Consume (
		for {
			if !p.isIdentifier() {
				return nil, p.expectedError("column name")
			}
			stmt.Columns = append(stmt.Columns, p.currentToken.Literal)
			p.advance()

			if p.isType(models.TokenTypeComma) {
				p.advance() // Consume comma
				continue
			}
			break
		}
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
	}

	// Parse optional TABLESPACE
	if p.isTokenMatch("TABLESPACE") {
		p.advance() // Consume TABLESPACE
		if !p.isIdentifier() {
			return nil, p.expectedError("tablespace name")
		}
		stmt.Tablespace = p.currentToken.Literal
		p.advance()
	}

	// Expect AS
	if !p.isType(models.TokenTypeAs) {
		return nil, p.expectedError("AS")
	}
	p.advance() // Consume AS

	// Parse the SELECT statement
	if !p.isType(models.TokenTypeSelect) {
		return nil, p.expectedError("SELECT")
	}
	p.advance() // Consume SELECT

	query, err := p.parseSelectWithSetOperations()
	if err != nil {
		return nil, goerrors.WrapError(
			goerrors.ErrCodeInvalidSyntax,
			"error parsing materialized view query",
			models.Location{}, // Location not available in current parser implementation
			"",                // SQL not available in current parser implementation
			err,
		)
	}
	stmt.Query = query

	// Parse optional WITH [NO] DATA
	// Note: DATA and NO may be tokenized as IDENT since they're common identifiers
	if p.isType(models.TokenTypeWith) {
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
	if p.isType(models.TokenTypeIf) {
		p.advance() // Consume IF
		if !p.isType(models.TokenTypeNot) {
			return nil, p.expectedError("NOT after IF")
		}
		p.advance() // Consume NOT
		if !p.isType(models.TokenTypeExists) {
			return nil, p.expectedError("EXISTS after NOT")
		}
		p.advance() // Consume EXISTS
		stmt.IfNotExists = true
	}

	// Parse table name (supports schema.table qualification and double-quoted identifiers)
	createTableName, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.expectedError("table name")
	}
	stmt.Name = createTableName

	// Expect opening parenthesis for column definitions
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	// Parse column definitions and constraints
	for {
		// Check for table-level constraints
		if p.isAnyType(models.TokenTypePrimary, models.TokenTypeForeign,
			models.TokenTypeUnique, models.TokenTypeCheck, models.TokenTypeConstraint) {
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
		if p.isType(models.TokenTypeComma) {
			p.advance() // Consume comma
			continue
		}
		break
	}

	// Expect closing parenthesis
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )

	// Parse optional PARTITION BY clause
	if p.isType(models.TokenTypePartition) {
		p.advance() // Consume PARTITION
		if !p.isType(models.TokenTypeBy) {
			return nil, p.expectedError("BY after PARTITION")
		}
		p.advance() // Consume BY

		partitionBy, err := p.parsePartitionByClause()
		if err != nil {
			return nil, err
		}
		stmt.PartitionBy = partitionBy

		// Parse partition definitions if present
		if p.isType(models.TokenTypeLParen) {
			p.advance() // Consume (
			for {
				partDef, err := p.parsePartitionDefinition()
				if err != nil {
					return nil, err
				}
				stmt.Partitions = append(stmt.Partitions, *partDef)

				if p.isType(models.TokenTypeComma) {
					p.advance() // Consume comma
					continue
				}
				break
			}
			if !p.isType(models.TokenTypeRParen) {
				return nil, p.expectedError(")")
			}
			p.advance() // Consume )
		}
	}

	// Parse optional table options
	for p.isTokenMatch("ENGINE") || p.isTokenMatch("CHARSET") ||
		p.isType(models.TokenTypeCollate) || p.isTokenMatch("COMMENT") {
		opt := ast.TableOption{Name: p.currentToken.Literal}
		p.advance()
		if p.isType(models.TokenTypeEq) {
			p.advance() // Consume =
		}
		if p.isIdentifier() || p.isType(models.TokenTypeString) {
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
	if p.isType(models.TokenTypeRange) {
		partitionBy.Type = "RANGE"
		p.advance()
	} else if p.isTokenMatch("LIST") {
		partitionBy.Type = "LIST"
		p.advance()
	} else if p.isTokenMatch("HASH") {
		partitionBy.Type = "HASH"
		p.advance()
	} else {
		return nil, p.expectedError("RANGE, LIST, or HASH")
	}

	// Expect opening parenthesis
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	// Parse column list
	for {
		if !p.isIdentifier() {
			return nil, p.expectedError("column name")
		}
		partitionBy.Columns = append(partitionBy.Columns, p.currentToken.Literal)
		p.advance()

		if p.isType(models.TokenTypeComma) {
			p.advance() // Consume comma
			continue
		}
		break
	}

	// Expect closing parenthesis
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )

	return partitionBy, nil
}

// parsePartitionDefinition parses a single partition definition
func (p *Parser) parsePartitionDefinition() (*ast.PartitionDefinition, error) {
	partDef := &ast.PartitionDefinition{}

	// Expect PARTITION keyword
	if !p.isType(models.TokenTypePartition) {
		return nil, p.expectedError("PARTITION")
	}
	p.advance() // Consume PARTITION

	// Parse partition name (supports double-quoted identifiers)
	if !p.isIdentifier() {
		return nil, p.expectedError("partition name")
	}
	partDef.Name = p.currentToken.Literal
	p.advance()

	// Parse VALUES clause
	if !p.isType(models.TokenTypeValues) {
		return nil, p.expectedError("VALUES")
	}
	p.advance() // Consume VALUES

	// Parse value specification
	if p.isTokenMatch("LESS") {
		p.advance() // Consume LESS
		if !p.isTokenMatch("THAN") {
			return nil, p.expectedError("THAN after LESS")
		}
		p.advance() // Consume THAN
		partDef.Type = "LESS THAN"

		// Parse value or MAXVALUE
		if p.isType(models.TokenTypeLParen) {
			p.advance() // Consume (
			if p.isTokenMatch("MAXVALUE") {
				partDef.LessThan = &ast.Identifier{Name: "MAXVALUE"}
				p.advance()
			} else {
				expr, err := p.parseExpression()
				if err != nil {
					return nil, err
				}
				partDef.LessThan = expr
			}
			if !p.isType(models.TokenTypeRParen) {
				return nil, p.expectedError(")")
			}
			p.advance() // Consume )
		} else if p.isTokenMatch("MAXVALUE") {
			partDef.LessThan = &ast.Identifier{Name: "MAXVALUE"}
			p.advance()
		}
	} else if p.isType(models.TokenTypeIn) {
		p.advance() // Consume IN
		partDef.Type = "IN"

		// Parse value list
		if !p.isType(models.TokenTypeLParen) {
			return nil, p.expectedError("(")
		}
		p.advance() // Consume (

		for {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			partDef.InValues = append(partDef.InValues, expr)

			if p.isType(models.TokenTypeComma) {
				p.advance() // Consume comma
				continue
			}
			break
		}

		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
	} else if p.isType(models.TokenTypeFrom) {
		p.advance() // Consume FROM
		partDef.Type = "FROM TO"

		// Parse FROM value
		if !p.isType(models.TokenTypeLParen) {
			return nil, p.expectedError("(")
		}
		p.advance() // Consume (
		fromExpr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		partDef.From = fromExpr
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )

		// Expect TO
		if !p.isType(models.TokenTypeTo) {
			return nil, p.expectedError("TO")
		}
		p.advance() // Consume TO

		// Parse TO value
		if !p.isType(models.TokenTypeLParen) {
			return nil, p.expectedError("(")
		}
		p.advance() // Consume (
		toExpr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		partDef.To = toExpr
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
	}

	// Parse optional TABLESPACE
	if p.isTokenMatch("TABLESPACE") {
		p.advance() // Consume TABLESPACE
		if !p.isIdentifier() {
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
	if p.isType(models.TokenTypeIf) {
		p.advance() // Consume IF
		if !p.isType(models.TokenTypeNot) {
			return nil, p.expectedError("NOT after IF")
		}
		p.advance() // Consume NOT
		if !p.isType(models.TokenTypeExists) {
			return nil, p.expectedError("EXISTS after NOT")
		}
		p.advance() // Consume EXISTS
		stmt.IfNotExists = true
	}

	// Parse index name (supports schema.index qualification and double-quoted identifiers)
	indexName, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.expectedError("index name")
	}
	stmt.Name = indexName

	// Expect ON
	if !p.isType(models.TokenTypeOn) {
		return nil, p.expectedError("ON")
	}
	p.advance() // Consume ON

	// Parse table name (supports schema.table qualification and double-quoted identifiers)
	indexTableName, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.expectedError("table name")
	}
	stmt.Table = indexTableName

	// Parse optional USING
	if p.isType(models.TokenTypeUsing) {
		p.advance() // Consume USING
		if !p.isIdentifier() {
			return nil, p.expectedError("index method")
		}
		stmt.Using = p.currentToken.Literal
		p.advance()
	}

	// Expect opening parenthesis
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	// Parse column list
	for {
		col := ast.IndexColumn{}
		if !p.isIdentifier() {
			return nil, p.expectedError("column name")
		}
		col.Column = p.currentToken.Literal
		p.advance()

		// Parse optional direction
		if p.isType(models.TokenTypeAsc) {
			col.Direction = "ASC"
			p.advance()
		} else if p.isType(models.TokenTypeDesc) {
			col.Direction = "DESC"
			p.advance()
		}

		// Parse optional NULLS LAST
		if p.isType(models.TokenTypeNulls) {
			p.advance() // Consume NULLS
			if p.isType(models.TokenTypeLast) {
				col.NullsLast = true
				p.advance()
			} else if p.isType(models.TokenTypeFirst) {
				p.advance()
			}
		}

		stmt.Columns = append(stmt.Columns, col)

		if p.isType(models.TokenTypeComma) {
			p.advance() // Consume comma
			continue
		}
		break
	}

	// Expect closing parenthesis
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )

	// Parse optional WHERE clause (partial index)
	if p.isType(models.TokenTypeWhere) {
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
	if p.isType(models.TokenTypeMaterialized) {
		p.advance() // Consume MATERIALIZED
		if !p.isType(models.TokenTypeView) {
			return nil, p.expectedError("VIEW after MATERIALIZED")
		}
		p.advance() // Consume VIEW
		stmt.ObjectType = "MATERIALIZED VIEW"
	} else if p.isType(models.TokenTypeView) {
		p.advance() // Consume VIEW
		stmt.ObjectType = "VIEW"
	} else if p.isType(models.TokenTypeTable) {
		p.advance() // Consume TABLE
		stmt.ObjectType = "TABLE"
	} else if p.isType(models.TokenTypeIndex) {
		p.advance() // Consume INDEX
		stmt.ObjectType = "INDEX"
	} else {
		return nil, p.expectedError("TABLE, VIEW, MATERIALIZED VIEW, or INDEX after DROP")
	}

	// Check for IF EXISTS
	if p.isType(models.TokenTypeIf) {
		p.advance() // Consume IF
		if !p.isType(models.TokenTypeExists) {
			return nil, p.expectedError("EXISTS after IF")
		}
		p.advance() // Consume EXISTS
		stmt.IfExists = true
	}

	// Parse object names (can be comma-separated, supports schema.name qualification)
	for {
		dropName, err := p.parseQualifiedName()
		if err != nil {
			return nil, p.expectedError("object name")
		}
		stmt.Names = append(stmt.Names, dropName)

		if p.isType(models.TokenTypeComma) {
			p.advance() // Consume comma
			continue
		}
		break
	}

	// Parse optional CASCADE/RESTRICT
	if p.isType(models.TokenTypeCascade) {
		stmt.CascadeType = "CASCADE"
		p.advance()
	} else if p.isType(models.TokenTypeRestrict) {
		stmt.CascadeType = "RESTRICT"
		p.advance()
	}

	return stmt, nil
}

// parseRefreshStatement parses REFRESH MATERIALIZED VIEW statement
func (p *Parser) parseRefreshStatement() (*ast.RefreshMaterializedViewStatement, error) {
	// Expect MATERIALIZED
	if !p.isType(models.TokenTypeMaterialized) {
		return nil, p.expectedError("MATERIALIZED after REFRESH")
	}
	p.advance() // Consume MATERIALIZED

	// Expect VIEW
	if !p.isType(models.TokenTypeView) {
		return nil, p.expectedError("VIEW after MATERIALIZED")
	}
	p.advance() // Consume VIEW

	stmt := &ast.RefreshMaterializedViewStatement{}

	// Check for CONCURRENTLY
	if p.isTokenMatch("CONCURRENTLY") {
		stmt.Concurrently = true
		p.advance()
	}

	// Parse view name (supports schema.view qualification and double-quoted identifiers)
	refreshViewName, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.expectedError("materialized view name")
	}
	stmt.Name = refreshViewName

	// Parse optional WITH [NO] DATA
	// Note: DATA and NO may be tokenized as IDENT since they're common identifiers
	if p.isType(models.TokenTypeWith) {
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

// parseTruncateStatement parses TRUNCATE TABLE statement
// Syntax: TRUNCATE [TABLE] table_name [, table_name ...] [RESTART IDENTITY | CONTINUE IDENTITY] [CASCADE | RESTRICT]
func (p *Parser) parseTruncateStatement() (*ast.TruncateStatement, error) {
	stmt := &ast.TruncateStatement{}

	// Optional TABLE keyword
	if p.isType(models.TokenTypeTable) {
		p.advance() // Consume TABLE
	}

	// Parse table names (can be comma-separated, supports schema.table qualification)
	for {
		truncTableName, err := p.parseQualifiedName()
		if err != nil {
			return nil, p.expectedError("table name")
		}
		stmt.Tables = append(stmt.Tables, truncTableName)

		if p.isType(models.TokenTypeComma) {
			p.advance() // Consume comma
			continue
		}
		break
	}

	// Parse optional RESTART IDENTITY / CONTINUE IDENTITY
	if p.isTokenMatch("RESTART") {
		p.advance() // Consume RESTART
		if !p.isTokenMatch("IDENTITY") {
			return nil, p.expectedError("IDENTITY after RESTART")
		}
		p.advance() // Consume IDENTITY
		stmt.RestartIdentity = true
	} else if p.isTokenMatch("CONTINUE") {
		p.advance() // Consume CONTINUE
		if !p.isTokenMatch("IDENTITY") {
			return nil, p.expectedError("IDENTITY after CONTINUE")
		}
		p.advance() // Consume IDENTITY
		stmt.ContinueIdentity = true
	}

	// Parse optional CASCADE/RESTRICT
	if p.isType(models.TokenTypeCascade) {
		stmt.CascadeType = "CASCADE"
		p.advance()
	} else if p.isType(models.TokenTypeRestrict) {
		stmt.CascadeType = "RESTRICT"
		p.advance()
	}

	return stmt, nil
}
