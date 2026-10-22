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

// Package parser - ddl_columns.go
// Column definition and constraint parsing for CREATE TABLE statements.

package parser

import (
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseColumnName parses a column name in DDL context, accepting reserved keywords
// like KEY, TABLE, INDEX as column names when context is unambiguous.
// In SQLite and other dialects, many reserved words may appear as column names.
func (p *Parser) parseColumnName() *ast.Identifier {
	val := p.currentToken.Token.Value
	if val == "" {
		return nil
	}
	// Accept identifiers, double-quoted identifiers, and any keyword token
	// that could be used as a column name (e.g. KEY, TABLE, INDEX, etc.)
	switch p.currentToken.Token.Type {
	case models.TokenTypeEOF, models.TokenTypeComma, models.TokenTypeLParen,
		models.TokenTypeRParen, models.TokenTypeSemicolon, models.TokenTypePeriod,
		models.TokenTypeUnknown:
		return nil
	}
	pos := p.currentLocation()
	ident := &ast.Identifier{Name: val, Pos: pos}
	p.advance()
	return ident
}

// parseColumnDef parses a column definition including column constraints
func (p *Parser) parseColumnDef() (*ast.ColumnDef, error) {
	name := p.parseColumnName()
	if name == nil {
		return nil, goerrors.ExpectedTokenError(
			"column name",
			p.currentToken.Token.Type.String(),
			p.currentLocation(),
			"",
		)
	}

	// Parse the data type: a (possibly multi-word) type name with optional
	// arguments and array suffixes; see parseColumnType. SQLite, ClickHouse and
	// SQL Server columns may omit it.
	dataTypeStr := ""
	if !p.columnTypeOmitted() {
		var err error
		dataTypeStr, err = p.parseColumnType()
		if err != nil {
			return nil, err
		}
	}

	colDef := &ast.ColumnDef{
		Name: name.Name,
		Type: dataTypeStr,
	}

	// ClickHouse column options that may appear between the type and the
	// standard constraint list: CODEC(...), DEFAULT expr, MATERIALIZED expr,
	// ALIAS expr, EPHEMERAL expr, TTL expr. Consume permissively; they are
	// appended to the type string for now so formatters can round-trip, and
	// not yet modeled on the AST.
	if p.dialect == string(keywords.DialectClickHouse) && dataTypeStr != "" {
		for {
			upper := strings.ToUpper(p.currentToken.Token.Value)
			if upper == "CODEC" && p.peekToken().Token.Type == models.TokenTypeLParen {
				p.advance() // CODEC
				args, err := p.parseTypeArgsString()
				if err != nil {
					return nil, err
				}
				colDef.Type += " CODEC" + args
				continue
			}
			break
		}
	}

	// Parse column constraints
	for {
		constraint, ok, err := p.parseColumnConstraint()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		colDef.Constraints = append(colDef.Constraints, *constraint)
	}

	return colDef, nil
}

// parseColumnConstraint parses a single column constraint, optionally named
// with CONSTRAINT <name>. Returns (constraint, found, error).
func (p *Parser) parseColumnConstraint() (*ast.ColumnConstraint, bool, error) {
	if !p.isType(models.TokenTypeConstraint) {
		return p.parseColumnConstraintBody()
	}
	p.advance() // Consume CONSTRAINT
	name := ""
	if p.isIdentifier() || (p.isWordToken() && !p.atColumnConstraintStart()) {
		name = p.currentToken.Token.Value
		p.advance()
	}
	constraint, ok, err := p.parseColumnConstraintBody()
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, p.expectedError("constraint after CONSTRAINT name")
	}
	constraint.Name = name
	return constraint, true, nil
}

// parseColumnConstraintBody parses the constraint itself, without a leading
// CONSTRAINT <name>.
func (p *Parser) parseColumnConstraintBody() (*ast.ColumnConstraint, bool, error) {
	constraint := &ast.ColumnConstraint{}

	// PRIMARY KEY
	if p.isType(models.TokenTypePrimary) {
		p.advance() // Consume PRIMARY
		if !p.isType(models.TokenTypeKey) {
			return nil, false, p.expectedError("KEY after PRIMARY")
		}
		p.advance() // Consume KEY
		constraint.Type = "PRIMARY KEY"
		constraint.Keyword = p.parseClusterKeyword()
		return constraint, true, nil
	}

	// NOT NULL, NOT DEFERRABLE, NOT FOR REPLICATION
	if p.isType(models.TokenTypeNot) {
		p.advance() // Consume NOT
		switch {
		case p.isType(models.TokenTypeNull):
			p.advance() // Consume NULL
			constraint.Type = "NOT NULL"
		case p.isUnquotedWord("DEFERRABLE") && p.dialectAllows(dialect.PostgreSQL, dialect.SQLite, dialect.Oracle, dialect.Redshift):
			p.advance() // Consume DEFERRABLE
			constraint.Type = "NOT DEFERRABLE"
		case p.isType(models.TokenTypeFor) && p.peekValueIs(1, "REPLICATION") && p.dialectAllows(dialect.SQLServer):
			p.advance() // Consume FOR
			p.advance() // Consume REPLICATION
			constraint.Type = "NOT FOR REPLICATION"
		default:
			return nil, false, p.expectedError("NULL after NOT")
		}
		return constraint, true, nil
	}

	// NULL (explicit nullable)
	if p.isType(models.TokenTypeNull) {
		p.advance() // Consume NULL
		constraint.Type = "NULL"
		return constraint, true, nil
	}

	// UNIQUE
	if p.isType(models.TokenTypeUnique) {
		p.advance() // Consume UNIQUE
		constraint.Type = "UNIQUE"
		constraint.Keyword = p.parseClusterKeyword()
		return constraint, true, nil
	}

	// DEFAULT value
	if p.isType(models.TokenTypeDefault) {
		p.advance() // Consume DEFAULT
		constraint.Type = "DEFAULT"

		// Parse default value - can be a literal, function call, or expression in parentheses
		expr, err := p.parseExpression()
		if err != nil {
			return nil, false, err
		}
		constraint.Default = expr
		return constraint, true, nil
	}

	// CHECK (expression)
	if p.isType(models.TokenTypeCheck) {
		p.advance() // Consume CHECK
		constraint.Type = "CHECK"

		if !p.isType(models.TokenTypeLParen) {
			return nil, false, p.expectedError("( after CHECK")
		}
		p.advance() // Consume (

		expr, err := p.parseExpression()
		if err != nil {
			return nil, false, err
		}
		constraint.Check = expr

		if !p.isType(models.TokenTypeRParen) {
			return nil, false, p.expectedError(") after CHECK expression")
		}
		p.advance() // Consume )
		return constraint, true, nil
	}

	// REFERENCES table(column) - inline foreign key
	if p.isType(models.TokenTypeReferences) {
		p.advance() // Consume REFERENCES
		constraint.Type = "REFERENCES"

		// Parse referenced table name (supports double-quoted identifiers)
		if !p.isIdentifier() {
			return nil, false, p.expectedError("table name after REFERENCES")
		}
		refDef := &ast.ReferenceDefinition{
			Table: p.currentToken.Token.Value,
		}
		p.advance()

		// Parse optional column list
		if p.isType(models.TokenTypeLParen) {
			p.advance() // Consume (
			for {
				if !p.isIdentifier() {
					return nil, false, p.expectedError("column name in REFERENCES")
				}
				refDef.Columns = append(refDef.Columns, p.currentToken.Token.Value)
				p.advance()

				if p.isType(models.TokenTypeComma) {
					p.advance()
					continue
				}
				break
			}
			if !p.isType(models.TokenTypeRParen) {
				return nil, false, p.expectedError(") after REFERENCES columns")
			}
			p.advance() // Consume )
		}

		// Parse optional ON DELETE/UPDATE
		refDef.OnDelete, refDef.OnUpdate = p.parseReferentialActions()
		constraint.References = refDef
		return constraint, true, nil
	}

	// AUTO_INCREMENT (MySQL)
	if p.isType(models.TokenTypeAutoIncrement) {
		// Keep the spelling: SQLite and Snowflake write AUTOINCREMENT, which
		// is not valid in MySQL, and MySQL AUTO_INCREMENT is not valid there.
		if equalsUpper(p.currentToken.Token.Value, "AUTOINCREMENT") {
			constraint.Keyword = "AUTOINCREMENT"
		}
		p.advance() // Consume AUTO_INCREMENT / AUTOINCREMENT
		constraint.Type = "AUTO_INCREMENT"
		constraint.AutoIncrement = true
		if p.IsSnowflake() {
			args, err := p.parseIdentityOptions()
			if err != nil {
				return nil, false, err
			}
			constraint.Args = args
		}
		return constraint, true, nil
	}

	// Dialect constraints (GENERATED, COMMENT, COLLATE, ON UPDATE, IDENTITY,
	// DEFERRABLE, ClickHouse column clauses, ...); see ddl_column_ext.go.
	return p.parseColumnConstraintExt(constraint)
}

// parseReferentialActions parses ON DELETE and ON UPDATE actions
func (p *Parser) parseReferentialActions() (onDelete, onUpdate string) {
	for p.isType(models.TokenTypeOn) {
		p.advance() // Consume ON

		if p.isType(models.TokenTypeDelete) {
			p.advance() // Consume DELETE
			onDelete = p.parseReferentialAction()
		} else if p.isType(models.TokenTypeUpdate) {
			p.advance() // Consume UPDATE
			onUpdate = p.parseReferentialAction()
		} else {
			break
		}
	}
	return
}

// parseReferentialAction parses a single referential action (CASCADE, SET NULL, etc.)
func (p *Parser) parseReferentialAction() string {
	if p.isType(models.TokenTypeCascade) {
		p.advance()
		return "CASCADE"
	}
	if p.isType(models.TokenTypeRestrict) {
		p.advance()
		return "RESTRICT"
	}
	if p.isType(models.TokenTypeSet) {
		p.advance() // Consume SET
		if p.isType(models.TokenTypeNull) {
			p.advance()
			return "SET NULL"
		}
		if p.isType(models.TokenTypeDefault) {
			p.advance()
			return "SET DEFAULT"
		}
	}
	if p.isTokenMatch("NO") {
		p.advance() // Consume NO
		if p.isTokenMatch("ACTION") {
			p.advance()
			return "NO ACTION"
		}
	}
	return ""
}

// parseConstraintColumnList parses a parenthesized list of column names
func (p *Parser) parseConstraintColumnList() ([]string, error) {
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("( for column list")
	}
	p.advance() // Consume (

	var columns []string
	for {
		if !p.isIdentifier() {
			return nil, p.expectedError("column name")
		}
		columns = append(columns, p.currentToken.Token.Value)
		p.advance()

		if p.isType(models.TokenTypeComma) {
			p.advance()
			continue
		}
		break
	}

	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") after column list")
	}
	p.advance() // Consume )

	return columns, nil
}

// parseTypeArgsString consumes a balanced parenthesised type-argument list
// and returns it as a string (including the outer parens). Supports nested
// types like Array(Nullable(String)), Map(String, Array(UInt32)),
// Tuple(a UInt8, b String), DateTime64(3, 'UTC'), and engine arguments like
// ReplicatedMergeTree('/path', '{replica}'). The current token must be '('.
func (p *Parser) parseTypeArgsString() (string, error) {
	if !p.isType(models.TokenTypeLParen) {
		return "", p.expectedError("(")
	}

	var buf strings.Builder
	depth := 0
	prevWasIdent := false // for inserting spaces between adjacent tokens (e.g. "a UInt8")

	for {
		tok := p.currentToken.Token
		switch tok.Type {
		case models.TokenTypeEOF:
			return "", p.expectedError(") to close type arguments")
		case models.TokenTypeLParen:
			buf.WriteByte('(')
			depth++
			prevWasIdent = false
			p.advance()
			continue
		case models.TokenTypeRParen:
			buf.WriteByte(')')
			depth--
			p.advance()
			if depth == 0 {
				return buf.String(), nil
			}
			// A word after ")" is separated from it: "sum(b) GROUP BY a".
			prevWasIdent = true
			continue
		case models.TokenTypeComma:
			buf.WriteString(", ")
			prevWasIdent = false
			p.advance()
			continue
		}

		// Render leaf token. Quote string literals; everything else is rendered
		// by its raw value (numbers, identifiers, keywords like Nullable / Array).
		val := tok.Value
		if val == "" {
			return "", p.expectedError("type argument")
		}

		// Insert a space when two adjacent leaf tokens both look like identifiers
		// or numbers — this preserves "name Type" pairs in named tuple elements.
		if prevWasIdent {
			buf.WriteByte(' ')
		}

		switch tok.Type {
		case models.TokenTypeString, models.TokenTypeSingleQuotedString,
			models.TokenTypeDoubleQuotedString:
			buf.WriteByte('\'')
			buf.WriteString(val)
			buf.WriteByte('\'')
			prevWasIdent = false
		default:
			buf.WriteString(val)
			prevWasIdent = true
		}

		p.advance()
	}
}
