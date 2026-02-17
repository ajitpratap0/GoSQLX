// Package parser - select.go
// SELECT statement parsing including DDL helpers and set operations.

package parser

import (
	"fmt"
	"strconv"
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseColumnDef parses a column definition including column constraints
func (p *Parser) parseColumnDef() (*ast.ColumnDef, error) {
	name := p.parseIdent()
	if name == nil {
		return nil, goerrors.ExpectedTokenError(
			"column name",
			p.currentToken.Type.String(),
			p.currentLocation(),
			"",
		)
	}

	// Parse data type (including parameterized types like VARCHAR(100), DECIMAL(10,2))
	dataType := p.parseIdent()
	if dataType == nil {
		return nil, goerrors.ExpectedTokenError(
			"data type",
			p.currentToken.Type.String(),
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
			dataTypeStr += p.currentToken.Literal
			p.advance()
		}

		// Check for second parameter (e.g., DECIMAL(10,2))
		if p.isType(models.TokenTypeComma) {
			dataTypeStr += ","
			p.advance()
			if p.isType(models.TokenTypeNumber) || p.isType(models.TokenTypeIdentifier) {
				dataTypeStr += p.currentToken.Literal
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
			Table: p.currentToken.Literal,
		}
		p.advance()

		// Parse optional column list
		if p.isType(models.TokenTypeLParen) {
			p.advance() // Consume (
			for {
				if !p.isIdentifier() {
					return nil, false, p.expectedError("column name in REFERENCES")
				}
				refDef.Columns = append(refDef.Columns, p.currentToken.Literal)
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
		constraint.Name = p.currentToken.Literal
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
			Table: p.currentToken.Literal,
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
		columns = append(columns, p.currentToken.Literal)
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

// parseSelectStatement parses a SELECT statement
func (p *Parser) parseSelectStatement() (ast.Statement, error) {
	// We've already consumed the SELECT token in matchType

	// Check for DISTINCT or ALL keyword
	isDistinct := false
	var distinctOnColumns []ast.Expression
	if p.isType(models.TokenTypeDistinct) {
		isDistinct = true
		p.advance() // Consume DISTINCT

		// Check for DISTINCT ON (PostgreSQL)
		if p.isType(models.TokenTypeOn) {
			p.advance() // Consume ON

			// Expect opening parenthesis
			if !p.isType(models.TokenTypeLParen) {
				return nil, p.expectedError("( after DISTINCT ON")
			}
			p.advance() // Consume (

			// Parse comma-separated list of expressions
			for {
				expr, err := p.parseExpression()
				if err != nil {
					return nil, err
				}
				distinctOnColumns = append(distinctOnColumns, expr)

				// Check for comma (more expressions)
				if !p.isType(models.TokenTypeComma) {
					break
				}
				p.advance() // Consume comma
			}

			// Expect closing parenthesis
			if !p.isType(models.TokenTypeRParen) {
				return nil, p.expectedError(") after DISTINCT ON expression list")
			}
			p.advance() // Consume )
		}
	} else if p.isType(models.TokenTypeAll) {
		// ALL is the default, just consume it
		p.advance()
	}

	// Parse SQL Server TOP clause: SELECT TOP n [PERCENT] ...
	var topClause *ast.TopClause
	if p.dialect == string(keywords.DialectSQLServer) && strings.ToUpper(p.currentToken.Literal) == "TOP" {
		p.advance() // Consume TOP
		if !p.isType(models.TokenTypeNumber) {
			return nil, p.expectedError("number after TOP")
		}
		n, err := strconv.ParseInt(p.currentToken.Literal, 10, 64)
		if err != nil {
			return nil, p.expectedError("integer after TOP")
		}
		p.advance() // Consume number
		topClause = &ast.TopClause{Count: n}
		// Check for optional PERCENT
		if p.isType(models.TokenTypePercent) || (p.currentToken.Type == models.TokenTypeKeyword && strings.ToUpper(p.currentToken.Literal) == "PERCENT") {
			topClause.IsPercent = true
			p.advance() // Consume PERCENT
		}
	}

	// Parse columns — pre-allocate to reduce repeated slice growth
	columns := make([]ast.Expression, 0, 8)

	// Check for SELECT FROM (missing column list)
	if p.isType(models.TokenTypeFrom) {
		return nil, goerrors.ExpectedTokenError(
			"column expression",
			"FROM",
			p.currentLocation(),
			"SELECT requires at least one column expression before FROM",
		)
	}

	for {
		// Handle * as a special case
		if p.isType(models.TokenTypeAsterisk) {
			columns = append(columns, &ast.Identifier{Name: "*"})
			p.advance()
		} else {
			// Use parseExpression to handle all types including function calls
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}

			// Check for optional column alias (AS alias_name or just alias_name)
			if p.isType(models.TokenTypeAs) {
				p.advance() // Consume AS
				if !p.isIdentifier() {
					return nil, p.expectedError("alias name after AS")
				}
				alias := p.currentToken.Literal
				p.advance()
				// Wrap expression with alias
				expr = &ast.AliasedExpression{
					Expr:  expr,
					Alias: alias,
				}
			} else if p.canBeAlias() {
				// Handle implicit alias (identifier without AS keyword)
				// But only for certain expression types, not for simple identifiers
				// to avoid ambiguity with FROM clause
				if _, ok := expr.(*ast.Identifier); !ok {
					alias := p.currentToken.Literal
					p.advance()
					expr = &ast.AliasedExpression{
						Expr:  expr,
						Alias: alias,
					}
				}
			}

			columns = append(columns, expr)
		}

		// Check if there are more columns
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance() // Consume comma
	}

	// Parse FROM clause (optional to support SELECT without FROM like "SELECT 1")
	// Also allow set operation keywords (UNION, EXCEPT, INTERSECT) for queries in CTEs
	if !p.isType(models.TokenTypeFrom) && !p.isType(models.TokenTypeEOF) &&
		!p.isType(models.TokenTypeSemicolon) && !p.isType(models.TokenTypeRParen) &&
		!p.isAnyType(models.TokenTypeUnion, models.TokenTypeExcept, models.TokenTypeIntersect) {
		// If not FROM, EOF, semicolon, right paren, or set operation, it's likely an error
		return nil, p.expectedError("FROM, semicolon, or end of statement")
	}

	var tableName string
	var tables []ast.TableReference
	var joins []ast.JoinClause

	if p.isType(models.TokenTypeFrom) {
		p.advance() // Consume FROM

		// Check for missing table name after FROM
		if p.isType(models.TokenTypeEOF) || p.isType(models.TokenTypeSemicolon) {
			return nil, goerrors.ExpectedTokenError(
				"table name",
				p.currentToken.Type.String(),
				p.currentLocation(),
				"FROM clause requires at least one table reference",
			)
		}

		// Parse first table reference
		tableRef, err := p.parseFromTableReference()
		if err != nil {
			return nil, err
		}
		tableName = tableRef.Name

		// Create tables list for FROM clause
		tables = []ast.TableReference{tableRef}

		// Parse additional comma-separated table references
		for p.isType(models.TokenTypeComma) {
			p.advance() // Consume comma
			additionalRef, err := p.parseFromTableReference()
			if err != nil {
				return nil, err
			}
			tables = append(tables, additionalRef)
		}

		// Parse JOIN clauses if present
		joins = []ast.JoinClause{}
		for p.isJoinKeyword() {
			// Determine JOIN type
			joinType := "INNER" // Default
			isNatural := false

			// Check for NATURAL keyword first (NATURAL can precede LEFT, RIGHT, FULL, INNER JOIN)
			if p.isType(models.TokenTypeNatural) {
				isNatural = true
				p.advance()
			}

			if p.isType(models.TokenTypeLeft) {
				joinType = "LEFT"
				p.advance()
				if p.isType(models.TokenTypeOuter) {
					p.advance() // Optional OUTER keyword
				}
			} else if p.isType(models.TokenTypeRight) {
				joinType = "RIGHT"
				p.advance()
				if p.isType(models.TokenTypeOuter) {
					p.advance() // Optional OUTER keyword
				}
			} else if p.isType(models.TokenTypeFull) {
				joinType = "FULL"
				p.advance()
				if p.isType(models.TokenTypeOuter) {
					p.advance() // Optional OUTER keyword
				}
			} else if p.isType(models.TokenTypeInner) {
				joinType = "INNER"
				p.advance()
			} else if p.isType(models.TokenTypeCross) {
				joinType = "CROSS"
				p.advance()
				// SQL Server CROSS APPLY
				if p.dialect == string(keywords.DialectSQLServer) && p.currentToken.Type == models.TokenTypeIdentifier && strings.ToUpper(p.currentToken.Literal) == "APPLY" {
					joinType = "CROSS APPLY"
					p.advance() // Consume APPLY
				}
			} else if p.isType(models.TokenTypeOuter) && p.dialect == string(keywords.DialectSQLServer) {
				p.advance() // Consume OUTER
				// SQL Server OUTER APPLY
				if p.currentToken.Type == models.TokenTypeIdentifier && strings.ToUpper(p.currentToken.Literal) == "APPLY" {
					joinType = "OUTER APPLY"
					p.advance() // Consume APPLY
				}
			}

			// If NATURAL, prepend to join type
			if isNatural {
				joinType = "NATURAL " + joinType
			}

			// APPLY joins don't use JOIN keyword
			isApply := joinType == "CROSS APPLY" || joinType == "OUTER APPLY"
			if !isApply {
				// Expect JOIN keyword
				if !p.isType(models.TokenTypeJoin) {
					return nil, goerrors.ExpectedTokenError(
						"JOIN after "+joinType,
						p.currentToken.Type.String(),
						p.currentLocation(),
						"",
					)
				}
				p.advance() // Consume JOIN
			}

			var joinedTableRef ast.TableReference

			// Check for LATERAL keyword (PostgreSQL) in JOIN clause
			isLateralJoin := false
			if p.isType(models.TokenTypeLateral) {
				isLateralJoin = true
				p.advance() // Consume LATERAL
			}

			// Check for derived table (subquery in parentheses)
			if p.isType(models.TokenTypeLParen) {
				p.advance() // Consume (

				// Check if this is a subquery (starts with SELECT or WITH)
				if !p.isType(models.TokenTypeSelect) && !p.isType(models.TokenTypeWith) {
					return nil, p.expectedError("SELECT in derived table")
				}

				// Consume SELECT token before calling parseSelectStatement
				p.advance() // Consume SELECT

				// Parse the subquery
				subquery, err := p.parseSelectStatement()
				if err != nil {
					return nil, err
				}
				selectStmt, ok := subquery.(*ast.SelectStatement)
				if !ok {
					return nil, p.expectedError("SELECT statement in derived table")
				}

				// Expect closing parenthesis
				if !p.isType(models.TokenTypeRParen) {
					return nil, p.expectedError(")")
				}
				p.advance() // Consume )

				joinedTableRef = ast.TableReference{
					Subquery: selectStmt,
					Lateral:  isLateralJoin,
				}
			} else {
				// Parse regular joined table name (supports schema.table qualification)
				joinedName, err := p.parseQualifiedName()
				if err != nil {
					return nil, goerrors.ExpectedTokenError(
						"table name after "+joinType+" JOIN",
						p.currentToken.Type.String(),
						p.currentLocation(),
						"",
					)
				}
				joinedTableRef = ast.TableReference{
					Name:    joinedName,
					Lateral: isLateralJoin,
				}
			}

			// Check for table alias
			if p.isIdentifier() || p.isType(models.TokenTypeAs) {
				if p.isType(models.TokenTypeAs) {
					p.advance() // Consume AS
					if !p.isIdentifier() {
						return nil, p.expectedError("alias after AS")
					}
				}
				if p.isIdentifier() {
					joinedTableRef.Alias = p.currentToken.Literal
					p.advance()
				}
			}

			// Parse join condition (ON or USING)
			var joinCondition ast.Expression

			// CROSS JOIN and NATURAL JOIN don't require ON clause
			isCrossJoin := joinType == "CROSS" || isApply
			if !isCrossJoin && !isNatural {
				if p.isType(models.TokenTypeOn) {
					p.advance() // Consume ON

					// Parse join condition
					cond, err := p.parseExpression()
					if err != nil {
						return nil, goerrors.InvalidSyntaxError(
							fmt.Sprintf("error parsing ON condition for %s JOIN: %v", joinType, err),
							p.currentLocation(),
							"",
						)
					}
					joinCondition = cond
				} else if p.isType(models.TokenTypeUsing) {
					p.advance() // Consume USING

					// Parse column list in parentheses
					if !p.isType(models.TokenTypeLParen) {
						return nil, p.expectedError("( after USING")
					}
					p.advance()

					// Parse comma-separated column list for USING clause
					// Supports both single column: USING (id)
					// and multi-column: USING (id, name, category)
					var usingColumns []ast.Expression

					for {
						// Parse column name
						if !p.isIdentifier() {
							return nil, p.expectedError("column name in USING")
						}
						usingColumns = append(usingColumns, &ast.Identifier{Name: p.currentToken.Literal})
						p.advance()

						// Check for comma (more columns)
						if p.isType(models.TokenTypeComma) {
							p.advance() // Consume comma
							continue
						}
						break
					}

					// Check for closing parenthesis
					if !p.isType(models.TokenTypeRParen) {
						return nil, p.expectedError(") after USING column list")
					}
					p.advance()

					// Store as single identifier for single column (backward compatibility)
					// or as ListExpression for multiple columns
					if len(usingColumns) == 1 {
						joinCondition = usingColumns[0]
					} else {
						joinCondition = &ast.ListExpression{Values: usingColumns}
					}
				} else {
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
	} // End of FROM clause parsing

	// Initialize SELECT statement
	selectStmt := &ast.SelectStatement{
		Distinct:          isDistinct,
		DistinctOnColumns: distinctOnColumns,
		Top:               topClause,
		Columns:           columns,
		From:              tables,
		Joins:             joins,
		TableName:         tableName, // Add this for compatibility with tests
	}

	// Parse WHERE clause if present
	if p.isType(models.TokenTypeWhere) {
		p.advance() // Consume WHERE

		// Check for incomplete WHERE clause (missing expression)
		if p.isType(models.TokenTypeEOF) || p.isType(models.TokenTypeSemicolon) ||
			p.isType(models.TokenTypeGroup) || p.isType(models.TokenTypeOrder) ||
			p.isType(models.TokenTypeLimit) || p.isType(models.TokenTypeHaving) ||
			p.isType(models.TokenTypeUnion) || p.isType(models.TokenTypeExcept) ||
			p.isType(models.TokenTypeIntersect) || p.isType(models.TokenTypeRParen) ||
			p.isType(models.TokenTypeFetch) || p.isType(models.TokenTypeFor) {
			return nil, goerrors.ExpectedTokenError(
				"expression after WHERE",
				p.currentToken.Type.String(),
				p.currentLocation(),
				"WHERE clause requires a boolean expression",
			)
		}

		// Parse WHERE condition
		whereClause, err := p.parseExpression()
		if err != nil {
			return nil, err
		}

		// Add WHERE clause to SELECT statement
		selectStmt.Where = whereClause
	}

	// Parse GROUP BY clause if present
	if p.isType(models.TokenTypeGroup) {
		p.advance() // Consume GROUP
		if !p.isType(models.TokenTypeBy) {
			return nil, p.expectedError("BY after GROUP")
		}
		p.advance() // Consume BY

		// Parse GROUP BY expressions (comma-separated list)
		// Supports: regular expressions, ROLLUP, CUBE, GROUPING SETS
		groupByExprs := make([]ast.Expression, 0, 4)
		for {
			var expr ast.Expression
			var err error

			// Check for grouping operations: ROLLUP, CUBE, GROUPING SETS
			// Note: GROUPING SETS may come as a compound keyword or separate tokens
			if p.isType(models.TokenTypeRollup) {
				expr, err = p.parseRollup()
			} else if p.isType(models.TokenTypeCube) {
				expr, err = p.parseCube()
			} else if p.currentToken.Literal == "GROUPING SETS" ||
				(p.isType(models.TokenTypeGrouping) && strings.EqualFold(p.peekToken().Literal, "SETS")) {
				expr, err = p.parseGroupingSets()
			} else {
				expr, err = p.parseExpression()
			}

			if err != nil {
				return nil, err
			}
			groupByExprs = append(groupByExprs, expr)

			// Check for comma (more expressions)
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance() // Consume comma
		}

		// MySQL syntax support: GROUP BY col1, col2 WITH ROLLUP / WITH CUBE
		// This is different from SQL-99 GROUP BY ROLLUP(col1, col2)
		if p.isType(models.TokenTypeWith) {
			nextTok := p.peekToken()
			switch strings.ToUpper(nextTok.Literal) {
			case "ROLLUP":
				p.advance() // Consume WITH
				p.advance() // Consume ROLLUP
				// Wrap all existing expressions in a RollupExpression
				groupByExprs = []ast.Expression{
					&ast.RollupExpression{Expressions: groupByExprs},
				}
			case "CUBE":
				p.advance() // Consume WITH
				p.advance() // Consume CUBE
				// Wrap all existing expressions in a CubeExpression
				groupByExprs = []ast.Expression{
					&ast.CubeExpression{Expressions: groupByExprs},
				}
			}
			// Note: WITH not followed by ROLLUP/CUBE will be handled elsewhere (e.g., CTE)
		}

		selectStmt.GroupBy = groupByExprs
	}

	// Parse HAVING clause if present (must come after GROUP BY)
	if p.isType(models.TokenTypeHaving) {
		p.advance() // Consume HAVING

		// Parse HAVING condition
		havingClause, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		selectStmt.Having = havingClause
	}

	// Parse ORDER BY clause if present
	if p.isType(models.TokenTypeOrder) {
		p.advance() // Consume ORDER

		if !p.isType(models.TokenTypeBy) {
			return nil, p.expectedError("BY")
		}
		p.advance() // Consume BY

		// Parse order expressions (comma-separated list)
		for {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}

			// Create OrderByExpression with defaults
			orderByExpr := ast.OrderByExpression{
				Expression: expr,
				Ascending:  true, // Default to ASC
				NullsFirst: nil,  // Default behavior (database-specific)
			}

			// Check for ASC/DESC after the expression
			if p.isType(models.TokenTypeAsc) {
				orderByExpr.Ascending = true
				p.advance() // Consume ASC
			} else if p.isType(models.TokenTypeDesc) {
				orderByExpr.Ascending = false
				p.advance() // Consume DESC
			}

			// Check for NULLS FIRST/LAST
			nullsFirst, err := p.parseNullsClause()
			if err != nil {
				return nil, err
			}
			orderByExpr.NullsFirst = nullsFirst

			selectStmt.OrderBy = append(selectStmt.OrderBy, orderByExpr)

			// Check for comma (more expressions)
			if p.isType(models.TokenTypeComma) {
				p.advance() // Consume comma
			} else {
				break
			}
		}
	}

	// Parse LIMIT clause if present
	if p.isType(models.TokenTypeLimit) {
		p.advance() // Consume LIMIT

		// Parse LIMIT value
		if !p.isNumericLiteral() {
			return nil, p.expectedError("integer for LIMIT")
		}

		// Convert string to int
		limitVal := 0
		_, _ = fmt.Sscanf(p.currentToken.Literal, "%d", &limitVal)

		// Add LIMIT to SELECT statement
		selectStmt.Limit = &limitVal
		p.advance()
	}

	// Parse OFFSET clause if present (MySQL-style OFFSET or SQL-99 OFFSET ... ROWS)
	if p.isType(models.TokenTypeOffset) {
		p.advance() // Consume OFFSET

		// Parse OFFSET value
		if !p.isNumericLiteral() {
			return nil, p.expectedError("integer for OFFSET")
		}

		// Convert string to int
		offsetVal := 0
		_, _ = fmt.Sscanf(p.currentToken.Literal, "%d", &offsetVal)

		// Add OFFSET to SELECT statement
		selectStmt.Offset = &offsetVal
		p.advance()

		// Check for ROW/ROWS (SQL-99 style: OFFSET n ROWS)
		if p.isAnyType(models.TokenTypeRow, models.TokenTypeRows) {
			p.advance() // Consume ROW/ROWS
		}
	}

	// Parse FETCH clause if present (SQL-99 F861, F862)
	// Syntax: FETCH {FIRST | NEXT} n [{ROW | ROWS}] [{PERCENT}] {ONLY | WITH TIES}
	if p.isType(models.TokenTypeFetch) {
		fetchClause, err := p.parseFetchClause()
		if err != nil {
			return nil, err
		}

		// If FETCH has an offset (from OFFSET ... ROWS before FETCH), it was already set above
		// For standalone FETCH with OFFSET embedded (SQL-99), we need to handle it in parseFetchClause

		selectStmt.Fetch = fetchClause
	}

	// Parse FOR clause if present (row-level locking)
	// Syntax: FOR {UPDATE | SHARE | NO KEY UPDATE | KEY SHARE} [OF table_name [, ...]] [NOWAIT | SKIP LOCKED]
	if p.isType(models.TokenTypeFor) {
		forClause, err := p.parseForClause()
		if err != nil {
			return nil, err
		}
		selectStmt.For = forClause
	}

	return selectStmt, nil
}

// parseFromTableReference parses a single table reference in a FROM clause,
// including derived tables (subqueries), LATERAL, and optional aliases.
func (p *Parser) parseFromTableReference() (ast.TableReference, error) {
	var tableRef ast.TableReference

	// Check for LATERAL keyword (PostgreSQL)
	isLateral := false
	if p.isType(models.TokenTypeLateral) {
		isLateral = true
		p.advance() // Consume LATERAL
	}

	// Check for derived table (subquery in parentheses)
	if p.isType(models.TokenTypeLParen) {
		p.advance() // Consume (

		// Check if this is a subquery (starts with SELECT or WITH)
		if !p.isType(models.TokenTypeSelect) && !p.isType(models.TokenTypeWith) {
			return tableRef, p.expectedError("SELECT in derived table")
		}

		// Consume SELECT token before calling parseSelectStatement
		p.advance() // Consume SELECT

		// Parse the subquery
		subquery, err := p.parseSelectStatement()
		if err != nil {
			return tableRef, err
		}
		selectStmt, ok := subquery.(*ast.SelectStatement)
		if !ok {
			return tableRef, p.expectedError("SELECT statement in derived table")
		}

		// Expect closing parenthesis
		if !p.isType(models.TokenTypeRParen) {
			return tableRef, p.expectedError(")")
		}
		p.advance() // Consume )

		tableRef = ast.TableReference{
			Subquery: selectStmt,
			Lateral:  isLateral,
		}
	} else {
		// Parse regular table name (supports schema.table qualification)
		qualifiedName, err := p.parseQualifiedName()
		if err != nil {
			return tableRef, err
		}

		tableRef = ast.TableReference{
			Name:    qualifiedName,
			Lateral: isLateral,
		}
	}

	// Check for table alias (required for derived tables, optional for regular tables)
	if p.isIdentifier() || p.isType(models.TokenTypeAs) {
		if p.isType(models.TokenTypeAs) {
			p.advance() // Consume AS
			if !p.isIdentifier() {
				return tableRef, p.expectedError("alias after AS")
			}
		}
		if p.isIdentifier() {
			tableRef.Alias = p.currentToken.Literal
			p.advance()
		}
	}

	return tableRef, nil
}

// parseSelectWithSetOperations parses SELECT statements that may have set operations.
// It supports UNION, UNION ALL, EXCEPT, and INTERSECT operations with proper left-associative parsing.
//
// Examples:
//
//	SELECT name FROM users UNION SELECT name FROM customers
//	SELECT id FROM orders UNION ALL SELECT id FROM invoices
//	SELECT product FROM inventory EXCEPT SELECT product FROM discontinued
//	SELECT a FROM t1 UNION SELECT b FROM t2 INTERSECT SELECT c FROM t3
func (p *Parser) parseSelectWithSetOperations() (ast.Statement, error) {
	// Parse the first SELECT statement
	leftStmt, err := p.parseSelectStatement()
	if err != nil {
		return nil, err
	}

	// Check for set operations (UNION, EXCEPT, INTERSECT)
	for p.isAnyType(models.TokenTypeUnion, models.TokenTypeExcept, models.TokenTypeIntersect) {
		// Parse the set operation type
		operationLiteral := p.currentToken.Literal
		p.advance()

		// Check for ALL keyword
		all := false
		if p.isType(models.TokenTypeAll) {
			all = true
			p.advance()
		}

		// Parse the right-hand SELECT statement
		if !p.isType(models.TokenTypeSelect) {
			return nil, p.expectedError("SELECT after set operation")
		}
		p.advance() // Consume SELECT

		rightStmt, err := p.parseSelectStatement()
		if err != nil {
			return nil, goerrors.InvalidSetOperationError(
				operationLiteral,
				fmt.Sprintf("error parsing right SELECT: %v", err),
				p.currentLocation(),
				"",
			)
		}

		// Create the set operation with left as the accumulated result
		setOp := &ast.SetOperation{
			Left:     leftStmt,
			Operator: operationLiteral,
			All:      all,
			Right:    rightStmt,
		}

		leftStmt = setOp // The result becomes the left side for any subsequent operations
	}

	return leftStmt, nil
}

// parseFetchClause parses the SQL-99 FETCH FIRST/NEXT clause (F861, F862).
// Syntax: FETCH {FIRST | NEXT} n [{ROW | ROWS}] [{PERCENT}] {ONLY | WITH TIES}
//
// Examples:
//
//	FETCH FIRST 5 ROWS ONLY
//	FETCH NEXT 10 ROWS ONLY
//	FETCH FIRST 10 PERCENT ROWS WITH TIES
//	FETCH NEXT 20 ROWS WITH TIES
func (p *Parser) parseFetchClause() (*ast.FetchClause, error) {
	fetchClause := &ast.FetchClause{}

	// Consume FETCH keyword (already checked by caller)
	p.advance()

	// Parse FIRST or NEXT
	if p.isType(models.TokenTypeFirst) {
		fetchClause.FetchType = "FIRST"
		p.advance()
	} else if p.isType(models.TokenTypeNext) {
		fetchClause.FetchType = "NEXT"
		p.advance()
	} else {
		return nil, p.expectedError("FIRST or NEXT after FETCH")
	}

	// Parse the count value
	if !p.isNumericLiteral() {
		return nil, p.expectedError("integer for FETCH count")
	}

	// Convert string to int64
	var fetchVal int64
	_, _ = fmt.Sscanf(p.currentToken.Literal, "%d", &fetchVal)
	fetchClause.FetchValue = &fetchVal
	p.advance()

	// Check for PERCENT (optional)
	if p.isType(models.TokenTypePercent) {
		fetchClause.IsPercent = true
		p.advance()
	}

	// Check for ROW/ROWS (optional)
	if p.isAnyType(models.TokenTypeRow, models.TokenTypeRows) {
		p.advance() // Consume ROW/ROWS
	}

	// Parse ONLY or WITH TIES
	if p.isType(models.TokenTypeOnly) {
		fetchClause.WithTies = false
		p.advance()
	} else if p.isType(models.TokenTypeWith) {
		p.advance() // Consume WITH
		if !p.isType(models.TokenTypeTies) {
			return nil, p.expectedError("TIES after WITH")
		}
		fetchClause.WithTies = true
		p.advance() // Consume TIES
	} else {
		// If neither ONLY nor WITH TIES, default to ONLY behavior
		fetchClause.WithTies = false
	}

	return fetchClause, nil
}

// parseForClause parses row-level locking clauses in SELECT statements (SQL:2003, PostgreSQL, MySQL).
// Syntax: FOR {UPDATE | SHARE | NO KEY UPDATE | KEY SHARE} [OF table_name [, ...]] [NOWAIT | SKIP LOCKED]
//
// Examples:
//
//	FOR UPDATE
//	FOR SHARE NOWAIT
//	FOR UPDATE OF orders SKIP LOCKED
//	FOR NO KEY UPDATE
//	FOR KEY SHARE
func (p *Parser) parseForClause() (*ast.ForClause, error) {
	forClause := &ast.ForClause{}

	// Consume FOR keyword (already checked by caller)
	p.advance()

	// Parse lock type: UPDATE, SHARE, or compound types (NO KEY UPDATE, KEY SHARE)
	if p.isTokenMatch("UPDATE") {
		forClause.LockType = "UPDATE"
		p.advance()
	} else if p.isTokenMatch("SHARE") {
		forClause.LockType = "SHARE"
		p.advance()
	} else if p.isTokenMatch("NO") {
		// NO KEY UPDATE
		p.advance() // Consume NO
		if !p.isTokenMatch("KEY") {
			return nil, p.expectedError("KEY after NO in FOR clause")
		}
		p.advance() // Consume KEY
		if !p.isTokenMatch("UPDATE") {
			return nil, p.expectedError("UPDATE after NO KEY in FOR clause")
		}
		forClause.LockType = "NO KEY UPDATE"
		p.advance()
	} else if p.isTokenMatch("KEY") {
		// KEY SHARE
		p.advance() // Consume KEY
		if !p.isTokenMatch("SHARE") {
			return nil, p.expectedError("SHARE after KEY in FOR clause")
		}
		forClause.LockType = "KEY SHARE"
		p.advance()
	} else {
		return nil, p.expectedError("UPDATE, SHARE, NO KEY UPDATE, or KEY SHARE after FOR")
	}

	// Parse OF table_name [, ...] if present
	if p.isTokenMatch("OF") {
		p.advance() // Consume OF

		// Parse comma-separated list of table names
		forClause.Tables = make([]string, 0)
		for {
			// Expect an identifier (table name)
			if !p.isIdentifier() {
				return nil, p.expectedError("table name after OF")
			}
			forClause.Tables = append(forClause.Tables, p.currentToken.Literal)
			p.advance()

			// Check for comma to continue, otherwise break
			if p.isType(models.TokenTypeComma) {
				p.advance() // Consume comma
			} else {
				break
			}
		}
	}

	// Parse NOWAIT or SKIP LOCKED
	if p.isTokenMatch("NOWAIT") {
		forClause.NoWait = true
		p.advance()
	} else if p.isTokenMatch("SKIP") {
		p.advance() // Consume SKIP
		if !p.isTokenMatch("LOCKED") {
			return nil, p.expectedError("LOCKED after SKIP")
		}
		forClause.SkipLocked = true
		p.advance() // Consume LOCKED
	}

	return forClause, nil
}
