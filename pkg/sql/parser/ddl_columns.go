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
	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
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

	// Parse data type (including parameterized types like VARCHAR(100), DECIMAL(10,2)).
	// Use parseColumnName to accept keyword-based type names such as INTEGER, TEXT, REAL.
	dataType := p.parseColumnName()
	if dataType == nil {
		return nil, goerrors.ExpectedTokenError(
			"data type",
			p.currentToken.Token.Type.String(),
			p.currentLocation(),
			"",
		)
	}

	dataTypeStr := dataType.Name

	// Check for type parameters like VARCHAR(100) or DECIMAL(10,2)
	if p.isType(models.TokenTypeLParen) {
		dataTypeStr += "("
		p.advance() // Consume (

		// Parse first parameter (can be number or identifier like MAX)
		if p.isType(models.TokenTypeNumber) || p.isType(models.TokenTypeIdentifier) {
			dataTypeStr += p.currentToken.Token.Value
			p.advance()
		}

		// Check for second parameter (e.g., DECIMAL(10,2))
		if p.isType(models.TokenTypeComma) {
			dataTypeStr += ","
			p.advance()
			if p.isType(models.TokenTypeNumber) || p.isType(models.TokenTypeIdentifier) {
				dataTypeStr += p.currentToken.Token.Value
				p.advance()
			}
		}

		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(") after type parameters")
		}
		dataTypeStr += ")"
		p.advance() // Consume )
	}

	colDef := &ast.ColumnDef{
		Name: name.Name,
		Type: dataTypeStr,
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

// parseColumnConstraint parses a single column constraint
// Returns (constraint, found, error)
func (p *Parser) parseColumnConstraint() (*ast.ColumnConstraint, bool, error) {
	constraint := &ast.ColumnConstraint{}

	// PRIMARY KEY
	if p.isType(models.TokenTypePrimary) {
		p.advance() // Consume PRIMARY
		if !p.isType(models.TokenTypeKey) {
			return nil, false, p.expectedError("KEY after PRIMARY")
		}
		p.advance() // Consume KEY
		constraint.Type = "PRIMARY KEY"
		return constraint, true, nil
	}

	// NOT NULL
	if p.isType(models.TokenTypeNot) {
		p.advance() // Consume NOT
		if !p.isType(models.TokenTypeNull) {
			return nil, false, p.expectedError("NULL after NOT")
		}
		p.advance() // Consume NULL
		constraint.Type = "NOT NULL"
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
		p.advance() // Consume AUTO_INCREMENT
		constraint.Type = "AUTO_INCREMENT"
		constraint.AutoIncrement = true
		return constraint, true, nil
	}

	// No constraint found
	return nil, false, nil
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

// parseTableConstraint parses a table constraint (PRIMARY KEY, FOREIGN KEY, UNIQUE, CHECK)
func (p *Parser) parseTableConstraint() (*ast.TableConstraint, error) {
	constraint := &ast.TableConstraint{}

	// Check for optional CONSTRAINT keyword (may already be consumed by caller)
	if p.isType(models.TokenTypeConstraint) {
		p.advance() // Consume CONSTRAINT
	}

	// Check for optional constraint name (identifier that isn't a constraint type keyword)
	// Constraint name comes before the constraint type (PRIMARY, FOREIGN, UNIQUE, CHECK)
	if p.isType(models.TokenTypeIdentifier) &&
		!p.isAnyType(models.TokenTypePrimary, models.TokenTypeForeign, models.TokenTypeUnique, models.TokenTypeCheck) {
		constraint.Name = p.currentToken.Token.Value
		p.advance()
	}

	// PRIMARY KEY (column_list)
	if p.isType(models.TokenTypePrimary) {
		p.advance() // Consume PRIMARY
		if !p.isType(models.TokenTypeKey) {
			return nil, p.expectedError("KEY after PRIMARY")
		}
		p.advance() // Consume KEY
		constraint.Type = "PRIMARY KEY"

		// Parse column list
		columns, err := p.parseConstraintColumnList()
		if err != nil {
			return nil, err
		}
		constraint.Columns = columns
		return constraint, nil
	}

	// FOREIGN KEY (column_list) REFERENCES table(column_list)
	if p.isType(models.TokenTypeForeign) {
		p.advance() // Consume FOREIGN
		if !p.isType(models.TokenTypeKey) {
			return nil, p.expectedError("KEY after FOREIGN")
		}
		p.advance() // Consume KEY
		constraint.Type = "FOREIGN KEY"

		// Parse column list
		columns, err := p.parseConstraintColumnList()
		if err != nil {
			return nil, err
		}
		constraint.Columns = columns

		// Expect REFERENCES
		if !p.isType(models.TokenTypeReferences) {
			return nil, p.expectedError("REFERENCES after FOREIGN KEY columns")
		}
		p.advance() // Consume REFERENCES

		// Parse referenced table (supports double-quoted identifiers)
		if !p.isIdentifier() {
			return nil, p.expectedError("table name after REFERENCES")
		}
		refDef := &ast.ReferenceDefinition{
			Table: p.currentToken.Token.Value,
		}
		p.advance()

		// Parse optional referenced column list
		if p.isType(models.TokenTypeLParen) {
			refColumns, err := p.parseConstraintColumnList()
			if err != nil {
				return nil, err
			}
			refDef.Columns = refColumns
		}

		// Parse optional ON DELETE/UPDATE
		refDef.OnDelete, refDef.OnUpdate = p.parseReferentialActions()
		constraint.References = refDef
		return constraint, nil
	}

	// UNIQUE (column_list)
	if p.isType(models.TokenTypeUnique) {
		p.advance() // Consume UNIQUE
		constraint.Type = "UNIQUE"

		// Parse column list
		columns, err := p.parseConstraintColumnList()
		if err != nil {
			return nil, err
		}
		constraint.Columns = columns
		return constraint, nil
	}

	// CHECK (expression)
	if p.isType(models.TokenTypeCheck) {
		p.advance() // Consume CHECK
		constraint.Type = "CHECK"

		if !p.isType(models.TokenTypeLParen) {
			return nil, p.expectedError("( after CHECK")
		}
		p.advance() // Consume (

		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		constraint.Check = expr

		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(") after CHECK expression")
		}
		p.advance() // Consume )
		return constraint, nil
	}

	return nil, p.expectedError("constraint name or constraint type (PRIMARY KEY, FOREIGN KEY, UNIQUE, CHECK)")
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
