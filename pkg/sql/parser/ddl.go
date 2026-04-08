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

// Package parser - ddl.go
// DDL statement parsing: CREATE TABLE core, DROP, TRUNCATE.
// Related modules:
//   - ddl_columns.go  - column definitions and table constraints
//   - ddl_index.go    - CREATE INDEX
//   - ddl_view.go     - CREATE VIEW, CREATE MATERIALIZED VIEW, REFRESH

package parser

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// isTokenMatch checks if the current token matches the given keyword
// This handles both keyword tokens and identifier tokens with matching literal values
// (needed because some keywords like DATA, NO may be tokenized as identifiers)
func (p *Parser) isTokenMatch(keyword string) bool {
	// Check if token literal matches the keyword (case-insensitive)
	return strings.EqualFold(p.currentToken.Token.Value, keyword)
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
	} else if p.isMariaDB() && p.isTokenMatch("SEQUENCE") {
		seqPos := p.currentLocation() // position of SEQUENCE token
		p.advance()                   // Consume SEQUENCE
		stmt, err := p.parseCreateSequenceStatement(orReplace)
		if err != nil {
			return nil, err
		}
		if stmt.Pos.IsZero() {
			stmt.Pos = seqPos
		}
		return stmt, nil
	}
	return nil, p.expectedError("TABLE, VIEW, MATERIALIZED VIEW, or INDEX after CREATE")
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
		// MariaDB: PERIOD FOR name (start_col, end_col) — application-time or system-time period
		if p.isMariaDB() && p.isTokenMatch("PERIOD") {
			periodPos := p.currentLocation() // position of PERIOD keyword
			pd, err := p.parsePeriodDefinition()
			if err != nil {
				return nil, err
			}
			pd.Pos = periodPos
			stmt.PeriodDefinitions = append(stmt.PeriodDefinitions, pd)
		} else if p.isAnyType(models.TokenTypePrimary, models.TokenTypeForeign,
			models.TokenTypeUnique, models.TokenTypeCheck, models.TokenTypeConstraint) {
			// Check for table-level constraints
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

	// MariaDB: WITH SYSTEM VERSIONING — enables system-versioned temporal history
	if p.isMariaDB() && p.isType(models.TokenTypeWith) {
		// peek ahead to check for SYSTEM VERSIONING (not WITH TIES or WITH CHECK etc.)
		next := p.peekToken()
		if strings.EqualFold(next.Token.Value, "SYSTEM") {
			p.advance() // Consume WITH
			p.advance() // Consume SYSTEM
			if !strings.EqualFold(p.currentToken.Token.Value, "VERSIONING") {
				return nil, p.expectedError("VERSIONING after WITH SYSTEM")
			}
			p.advance() // Consume VERSIONING
			stmt.WithSystemVersioning = true
		}
	}

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
		opt := ast.TableOption{Name: p.currentToken.Token.Value}
		p.advance()
		if p.isType(models.TokenTypeEq) {
			p.advance() // Consume =
		}
		if p.isIdentifier() || p.isType(models.TokenTypeString) {
			opt.Value = p.currentToken.Token.Value
			p.advance()
		}
		// ClickHouse engine values may carry their own argument list:
		//   ENGINE = MergeTree()
		//   ENGINE = ReplicatedMergeTree('/path', '{replica}')
		//   ENGINE = Distributed('cluster', 'db', 'local_t', sharding_key)
		// Consume them as a balanced block appended to the option value.
		if p.isType(models.TokenTypeLParen) {
			args, err := p.parseTypeArgsString()
			if err != nil {
				return nil, err
			}
			opt.Value += args
		}
		stmt.Options = append(stmt.Options, opt)
	}

	// ClickHouse CREATE TABLE trailing clauses: ORDER BY, PARTITION BY,
	// PRIMARY KEY, SAMPLE BY, SETTINGS. These appear after ENGINE = ... and
	// are required for MergeTree-family engines. Parse permissively:
	// each consumes a parenthesised expression list or a single column ref.
	for p.dialect == string(keywords.DialectClickHouse) {
		if p.isType(models.TokenTypeOrder) {
			p.advance() // ORDER
			if p.isType(models.TokenTypeBy) {
				p.advance()
			}
			if err := p.skipClickHouseClauseExpr(); err != nil {
				return nil, err
			}
			continue
		}
		if p.isTokenMatch("PARTITION") {
			p.advance()
			if p.isType(models.TokenTypeBy) {
				p.advance()
			}
			if err := p.skipClickHouseClauseExpr(); err != nil {
				return nil, err
			}
			continue
		}
		if p.isType(models.TokenTypePrimary) {
			p.advance()
			if p.isType(models.TokenTypeKey) {
				p.advance()
			}
			if err := p.skipClickHouseClauseExpr(); err != nil {
				return nil, err
			}
			continue
		}
		if p.isTokenMatch("SAMPLE") {
			p.advance()
			if p.isType(models.TokenTypeBy) {
				p.advance()
			}
			if err := p.skipClickHouseClauseExpr(); err != nil {
				return nil, err
			}
			continue
		}
		if p.isTokenMatch("TTL") {
			p.advance()
			if err := p.skipClickHouseClauseExpr(); err != nil {
				return nil, err
			}
			continue
		}
		if p.isTokenMatch("SETTINGS") {
			p.advance()
			// SETTINGS is a comma-separated list of name=value assignments.
			// Consume each k=v pair until the next clause, EOF, or ';'.
			for {
				t := p.currentToken.Token.Type
				val := strings.ToUpper(p.currentToken.Token.Value)
				if t == models.TokenTypeEOF || t == models.TokenTypeSemicolon {
					break
				}
				if val == "ORDER" || val == "PARTITION" || val == "PRIMARY" ||
					val == "SAMPLE" || val == "TTL" {
					break
				}
				p.advance()
			}
			continue
		}
		break
	}

	// SQLite: optional WITHOUT ROWID clause
	if p.isTokenMatch("WITHOUT") {
		p.advance() // Consume WITHOUT
		if !p.isTokenMatch("ROWID") {
			return nil, p.expectedError("ROWID after WITHOUT")
		}
		p.advance() // Consume ROWID
		stmt.WithoutRowID = true
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
		partitionBy.Columns = append(partitionBy.Columns, p.currentToken.Token.Value)
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
	partDef.Name = p.currentToken.Token.Value
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
		partDef.Tablespace = p.currentToken.Token.Value
		p.advance()
	}

	return partDef, nil
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

// skipClickHouseClauseExpr consumes the expression following a ClickHouse
// CREATE TABLE trailing clause (ORDER BY, PARTITION BY, PRIMARY KEY, SAMPLE BY).
// We do not currently model these clauses on the AST; this just walks the
// tokens until the start of the next clause, EOF, or ';'. Supports both
// parenthesised lists and bare expressions.
func (p *Parser) skipClickHouseClauseExpr() error {
	if p.isType(models.TokenTypeLParen) {
		// Balanced paren block.
		depth := 0
		for {
			switch p.currentToken.Token.Type {
			case models.TokenTypeEOF:
				return p.expectedError(") to close clause expression")
			case models.TokenTypeLParen:
				depth++
				p.advance()
			case models.TokenTypeRParen:
				depth--
				p.advance()
				if depth == 0 {
					return nil
				}
			default:
				p.advance()
			}
		}
	}

	// Bare expression: consume until next clause/EOF/;.
	for {
		t := p.currentToken.Token.Type
		if t == models.TokenTypeEOF || t == models.TokenTypeSemicolon {
			return nil
		}
		// Stop at next CH trailing-clause keyword.
		if t == models.TokenTypeOrder || t == models.TokenTypePrimary {
			return nil
		}
		val := strings.ToUpper(p.currentToken.Token.Value)
		if val == "PARTITION" || val == "SAMPLE" || val == "SETTINGS" || val == "TTL" {
			return nil
		}
		p.advance()
	}
}
