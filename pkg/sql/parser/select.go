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

// Package parser - select.go
// SELECT statement parsing including DDL helpers and set operations.

package parser

import (
	"fmt"
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

// parseSelectStatement parses a SELECT statement.
// It delegates each clause to a focused helper method.
func (p *Parser) parseSelectStatement() (ast.Statement, error) {
	// We've already consumed the SELECT token in matchType.

	// DISTINCT / ALL modifier
	isDistinct, distinctOnColumns, err := p.parseDistinctModifier()
	if err != nil {
		return nil, err
	}

	// Reject TOP clause in MySQL and PostgreSQL — these dialects use LIMIT/OFFSET.
	if (p.dialect == string(keywords.DialectMySQL) || p.dialect == string(keywords.DialectPostgreSQL)) &&
		strings.ToUpper(p.currentToken.Literal) == "TOP" {
		return nil, fmt.Errorf(
			"TOP clause is not supported in %s; use LIMIT/OFFSET instead", p.dialect,
		)
	}

	// SQL Server TOP clause
	topClause, err := p.parseTopClause()
	if err != nil {
		return nil, err
	}

	// Column list
	columns, err := p.parseSelectColumnList()
	if err != nil {
		return nil, err
	}

	// FROM … JOIN clauses
	tableName, tables, joins, err := p.parseFromClause()
	if err != nil {
		return nil, err
	}

	// Initialise the statement early so clause parsers can check dialect etc.
	selectStmt := &ast.SelectStatement{
		Distinct:          isDistinct,
		DistinctOnColumns: distinctOnColumns,
		Top:               topClause,
		Columns:           columns,
		From:              tables,
		Joins:             joins,
		TableName:         tableName,
	}

	// WHERE
	if selectStmt.Where, err = p.parseWhereClause(); err != nil {
		return nil, err
	}

	// GROUP BY
	if selectStmt.GroupBy, err = p.parseGroupByClause(); err != nil {
		return nil, err
	}

	// HAVING
	if selectStmt.Having, err = p.parseHavingClause(); err != nil {
		return nil, err
	}

	// ORDER BY
	if selectStmt.OrderBy, err = p.parseOrderByClause(); err != nil {
		return nil, err
	}

	// LIMIT / OFFSET
	if selectStmt.Limit, selectStmt.Offset, err = p.parseLimitOffsetClause(); err != nil {
		return nil, err
	}

	// FETCH FIRST / NEXT
	if p.isType(models.TokenTypeFetch) {
		if selectStmt.Fetch, err = p.parseFetchClause(); err != nil {
			return nil, err
		}
	}

	// FOR UPDATE / SHARE / …
	if p.isType(models.TokenTypeFor) {
		if selectStmt.For, err = p.parseForClause(); err != nil {
			return nil, err
		}
	}

	return selectStmt, nil
}

// parseDistinctModifier parses the optional DISTINCT [ON (...)] or ALL keyword
// immediately after SELECT.
func (p *Parser) parseDistinctModifier() (isDistinct bool, distinctOnColumns []ast.Expression, err error) {
	if p.isType(models.TokenTypeDistinct) {
		isDistinct = true
		p.advance() // Consume DISTINCT

		// PostgreSQL DISTINCT ON (expr, ...)
		if p.isType(models.TokenTypeOn) {
			p.advance() // Consume ON

			if !p.isType(models.TokenTypeLParen) {
				return false, nil, p.expectedError("( after DISTINCT ON")
			}
			p.advance() // Consume (

			for {
				expr, e := p.parseExpression()
				if e != nil {
					return false, nil, e
				}
				distinctOnColumns = append(distinctOnColumns, expr)
				if !p.isType(models.TokenTypeComma) {
					break
				}
				p.advance()
			}

			if !p.isType(models.TokenTypeRParen) {
				return false, nil, p.expectedError(") after DISTINCT ON expression list")
			}
			p.advance() // Consume )
		}
	} else if p.isType(models.TokenTypeAll) {
		p.advance() // ALL is the default; just consume it
	}
	return isDistinct, distinctOnColumns, nil
}

// parseTopClause parses SQL Server's TOP n [PERCENT] [WITH TIES] clause.
// Returns nil when the current dialect is not SQL Server or TOP is absent.
func (p *Parser) parseTopClause() (*ast.TopClause, error) {
	if p.dialect != string(keywords.DialectSQLServer) || strings.ToUpper(p.currentToken.Literal) != "TOP" {
		return nil, nil
	}
	p.advance() // Consume TOP

	hasParen := p.isType(models.TokenTypeLParen)
	if hasParen {
		p.advance() // Consume (
	}

	countExpr, err := p.parsePrimaryExpression()
	if err != nil {
		return nil, fmt.Errorf("expected expression after TOP: %w", err)
	}

	if hasParen {
		if !p.isType(models.TokenTypeRightParen) {
			return nil, p.expectedError(") after TOP expression")
		}
		p.advance() // Consume )
	}

	topClause := &ast.TopClause{Count: countExpr}

	// Optional PERCENT
	if p.isType(models.TokenTypePercent) ||
		(p.currentToken.Type == models.TokenTypeKeyword && strings.ToUpper(p.currentToken.Literal) == "PERCENT") {
		topClause.IsPercent = true
		p.advance()
	}

	// Optional WITH TIES
	if p.isType(models.TokenTypeWith) && p.peekToken().Type == models.TokenTypeTies {
		topClause.WithTies = true
		p.advance() // Consume WITH
		p.advance() // Consume TIES

	}

	return topClause, nil
}

// parseSelectColumnList parses the comma-separated column/expression list in SELECT.
func (p *Parser) parseSelectColumnList() ([]ast.Expression, error) {
	// Guard: SELECT immediately followed by FROM is an error.
	if p.isType(models.TokenTypeFrom) {
		return nil, goerrors.ExpectedTokenError(
			"column expression",
			"FROM",
			p.currentLocation(),
			"SELECT requires at least one column expression before FROM",
		)
	}

	columns := make([]ast.Expression, 0, 8)
	for {
		var expr ast.Expression

		if p.isType(models.TokenTypeAsterisk) {
			expr = &ast.Identifier{Name: "*"}
			p.advance()
		} else {
			var err error
			expr, err = p.parseExpression()
			if err != nil {
				return nil, err
			}

			// Optional alias: AS name  or  implicit name (non-identifier expressions only)
			if p.isType(models.TokenTypeAs) {
				p.advance() // Consume AS
				if !p.isIdentifier() {
					return nil, p.expectedError("alias name after AS")
				}
				alias := p.currentToken.Literal
				p.advance()
				expr = &ast.AliasedExpression{Expr: expr, Alias: alias}
			} else if p.canBeAlias() {
				if _, ok := expr.(*ast.Identifier); !ok {
					alias := p.currentToken.Literal
					p.advance()
					expr = &ast.AliasedExpression{Expr: expr, Alias: alias}
				}
			}
		}

		columns = append(columns, expr)

		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance() // Consume comma
	}
	return columns, nil
}

// parseFromClause parses the FROM clause including comma-separated table references
// and any subsequent JOIN clauses.  Returns the primary table name (for compatibility),
// the full table-reference slice, and the join slice.
func (p *Parser) parseFromClause() (tableName string, tables []ast.TableReference, joins []ast.JoinClause, err error) {
	// FROM is optional (e.g. SELECT 1).  Validate that the next token makes sense.
	if !p.isType(models.TokenTypeFrom) {
		if !p.isType(models.TokenTypeEOF) &&
			!p.isType(models.TokenTypeSemicolon) &&
			!p.isType(models.TokenTypeRParen) &&
			!p.isAnyType(models.TokenTypeUnion, models.TokenTypeExcept, models.TokenTypeIntersect) {
			return "", nil, nil, p.expectedError("FROM, semicolon, or end of statement")
		}
		return "", nil, nil, nil
	}

	p.advance() // Consume FROM

	if p.isType(models.TokenTypeEOF) || p.isType(models.TokenTypeSemicolon) {
		return "", nil, nil, goerrors.ExpectedTokenError(
			"table name",
			p.currentToken.Type.String(),
			p.currentLocation(),
			"FROM clause requires at least one table reference",
		)
	}

	// First table reference
	firstRef, e := p.parseFromTableReference()
	if e != nil {
		return "", nil, nil, e
	}
	tableName = firstRef.Name
	tables = []ast.TableReference{firstRef}

	// Additional comma-separated table references (implicit cross joins)
	for p.isType(models.TokenTypeComma) {
		p.advance()
		ref, e2 := p.parseFromTableReference()
		if e2 != nil {
			return "", nil, nil, e2
		}
		tables = append(tables, ref)
	}

	// JOIN clauses
	joins, err = p.parseJoinClauses(firstRef)
	return tableName, tables, joins, err
}

// parseJoinClauses parses zero or more JOIN clauses that follow the FROM table list.
// firstRef is the primary (left-most) table, used for building JoinClause.Left.
func (p *Parser) parseJoinClauses(firstRef ast.TableReference) ([]ast.JoinClause, error) {
	joins := []ast.JoinClause{}

	for p.isJoinKeyword() {
		joinType, isNatural, err := p.parseJoinType()
		if err != nil {
			return nil, err
		}

		// Expect JOIN keyword (APPLY variants skip it)
		isApply := joinType == "CROSS APPLY" || joinType == "OUTER APPLY"
		if !isApply {
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

		joinedTableRef, err := p.parseJoinedTableRef(joinType)
		if err != nil {
			return nil, err
		}

		joinCondition, err := p.parseJoinCondition(joinType, isNatural, isApply)
		if err != nil {
			return nil, err
		}

		// Build left-side reference (synthetic for chained joins)
		var leftTable ast.TableReference
		if len(joins) == 0 {
			leftTable = firstRef
		} else {
			leftTable = ast.TableReference{
				Name: fmt.Sprintf("(%s_with_%d_joins)", firstRef.Name, len(joins)),
			}
		}

		joins = append(joins, ast.JoinClause{
			Type:      joinType,
			Left:      leftTable,
			Right:     joinedTableRef,
			Condition: joinCondition,
		})
	}
	return joins, nil
}

// parseJoinType parses the optional NATURAL keyword and the join-type keywords
// (LEFT, RIGHT, FULL, INNER, CROSS, OUTER APPLY, …) that precede the JOIN keyword.
// Returns (joinType string, isNatural bool, err).
func (p *Parser) parseJoinType() (string, bool, error) {
	joinType := "INNER"
	isNatural := false

	if p.isType(models.TokenTypeNatural) {
		isNatural = true
		p.advance()
	}

	switch {
	case p.isType(models.TokenTypeLeft):
		joinType = "LEFT"
		p.advance()
		if p.isType(models.TokenTypeOuter) {
			p.advance()
		}
	case p.isType(models.TokenTypeRight):
		joinType = "RIGHT"
		p.advance()
		if p.isType(models.TokenTypeOuter) {
			p.advance()
		}
	case p.isType(models.TokenTypeFull):
		joinType = "FULL"
		p.advance()
		if p.isType(models.TokenTypeOuter) {
			p.advance()
		}
	case p.isType(models.TokenTypeInner):
		joinType = "INNER"
		p.advance()
	case p.isType(models.TokenTypeCross):
		joinType = "CROSS"
		p.advance()
		if p.dialect == string(keywords.DialectSQLServer) &&
			p.currentToken.Type == models.TokenTypeIdentifier &&
			strings.ToUpper(p.currentToken.Literal) == "APPLY" {
			joinType = "CROSS APPLY"
			p.advance()
		}
	case p.isType(models.TokenTypeOuter) && p.dialect == string(keywords.DialectSQLServer):
		p.advance()
		if p.currentToken.Type == models.TokenTypeIdentifier &&
			strings.ToUpper(p.currentToken.Literal) == "APPLY" {
			joinType = "OUTER APPLY"
			p.advance()
		} else {
			return "", false, p.expectedError("APPLY after OUTER (SQL Server OUTER APPLY)")
		}
	}

	if isNatural {
		joinType = "NATURAL " + joinType
	}
	return joinType, isNatural, nil
}

// parseJoinedTableRef parses the table reference on the right-hand side of a JOIN.
func (p *Parser) parseJoinedTableRef(joinType string) (ast.TableReference, error) {
	var ref ast.TableReference

	// Optional LATERAL (PostgreSQL)
	isLateral := false
	if p.isType(models.TokenTypeLateral) {
		isLateral = true
		p.advance()
	}

	if p.isType(models.TokenTypeLParen) {
		// Derived table (subquery)
		p.advance() // Consume (

		if !p.isType(models.TokenTypeSelect) && !p.isType(models.TokenTypeWith) {
			return ref, p.expectedError("SELECT in derived table")
		}
		p.advance() // Consume SELECT

		subquery, err := p.parseSelectStatement()
		if err != nil {
			return ref, err
		}
		selectStmt, ok := subquery.(*ast.SelectStatement)
		if !ok {
			return ref, p.expectedError("SELECT statement in derived table")
		}

		if !p.isType(models.TokenTypeRParen) {
			return ref, p.expectedError(")")
		}
		p.advance() // Consume )

		ref = ast.TableReference{Subquery: selectStmt, Lateral: isLateral}
	} else {
		joinedName, err := p.parseQualifiedName()
		if err != nil {
			return ref, goerrors.ExpectedTokenError(
				"table name after "+joinType+" JOIN",
				p.currentToken.Type.String(),
				p.currentLocation(),
				"",
			)
		}
		ref = ast.TableReference{Name: joinedName, Lateral: isLateral}
	}

	// Optional alias
	if p.isIdentifier() || p.isType(models.TokenTypeAs) {
		if p.isType(models.TokenTypeAs) {
			p.advance()
			if !p.isIdentifier() {
				return ref, p.expectedError("alias after AS")
			}
		}
		if p.isIdentifier() {
			ref.Alias = p.currentToken.Literal
			p.advance()
		}
	}

	// SQL Server table hints
	if p.dialect == string(keywords.DialectSQLServer) && p.isType(models.TokenTypeWith) {
		if p.peekToken().Type == models.TokenTypeLParen {
			hints, err := p.parseTableHints()
			if err != nil {
				return ref, err
			}
			ref.TableHints = hints
		}
	}

	return ref, nil
}

// parseJoinCondition parses the ON / USING clause that follows a joined table reference.
// CROSS JOIN, APPLY, and NATURAL JOIN variants do not require a condition.
func (p *Parser) parseJoinCondition(joinType string, isNatural, isApply bool) (ast.Expression, error) {
	isCrossJoin := joinType == "CROSS" || isApply
	if isCrossJoin || isNatural {
		return nil, nil
	}

	if p.isType(models.TokenTypeOn) {
		p.advance() // Consume ON
		cond, err := p.parseExpression()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("error parsing ON condition for %s JOIN: %v", joinType, err),
				p.currentLocation(),
				"",
			)
		}
		return cond, nil
	}

	if p.isType(models.TokenTypeUsing) {
		p.advance() // Consume USING
		if !p.isType(models.TokenTypeLParen) {
			return nil, p.expectedError("( after USING")
		}
		p.advance()

		var usingColumns []ast.Expression
		for {
			if !p.isIdentifier() {
				return nil, p.expectedError("column name in USING")
			}
			usingColumns = append(usingColumns, &ast.Identifier{Name: p.currentToken.Literal})
			p.advance()
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance()
		}

		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(") after USING column list")
		}
		p.advance()

		if len(usingColumns) == 1 {
			return usingColumns[0], nil
		}
		return &ast.ListExpression{Values: usingColumns}, nil
	}

	return nil, p.expectedError("ON or USING")
}

// parseWhereClause parses "WHERE <expr>" if present.
// Returns nil (no error) when WHERE is absent.
func (p *Parser) parseWhereClause() (ast.Expression, error) {
	if !p.isType(models.TokenTypeWhere) {
		return nil, nil
	}
	p.advance() // Consume WHERE

	// Guard against a WHERE keyword with no following expression.
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

	return p.parseExpression()
}

// parseGroupByClause parses "GROUP BY <expr> [, ...]" including ROLLUP, CUBE,
// GROUPING SETS, and MySQL's trailing WITH ROLLUP / WITH CUBE syntax.
// Returns nil slice (no error) when GROUP BY is absent.
func (p *Parser) parseGroupByClause() ([]ast.Expression, error) {
	if !p.isType(models.TokenTypeGroup) {
		return nil, nil
	}
	p.advance() // Consume GROUP

	if !p.isType(models.TokenTypeBy) {
		return nil, p.expectedError("BY after GROUP")
	}
	p.advance() // Consume BY

	groupByExprs := make([]ast.Expression, 0, 4)
	for {
		var (
			expr ast.Expression
			err  error
		)

		switch {
		case p.isType(models.TokenTypeRollup):
			expr, err = p.parseRollup()
		case p.isType(models.TokenTypeCube):
			expr, err = p.parseCube()
		case p.currentToken.Literal == "GROUPING SETS" ||
			(p.isType(models.TokenTypeGrouping) && strings.EqualFold(p.peekToken().Literal, "SETS")):
			expr, err = p.parseGroupingSets()
		default:
			expr, err = p.parseExpression()
		}

		if err != nil {
			return nil, err
		}
		groupByExprs = append(groupByExprs, expr)

		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance()
	}

	// MySQL: GROUP BY col1 WITH ROLLUP / WITH CUBE
	if p.isType(models.TokenTypeWith) {
		switch strings.ToUpper(p.peekToken().Literal) {
		case "ROLLUP":
			p.advance() // Consume WITH
			p.advance() // Consume ROLLUP
			groupByExprs = []ast.Expression{&ast.RollupExpression{Expressions: groupByExprs}}
		case "CUBE":
			p.advance() // Consume WITH
			p.advance() // Consume CUBE
			groupByExprs = []ast.Expression{&ast.CubeExpression{Expressions: groupByExprs}}
		}
	}

	return groupByExprs, nil
}

// parseHavingClause parses "HAVING <expr>" if present.
// Returns nil (no error) when HAVING is absent.
func (p *Parser) parseHavingClause() (ast.Expression, error) {
	if !p.isType(models.TokenTypeHaving) {
		return nil, nil
	}
	p.advance() // Consume HAVING
	return p.parseExpression()
}

// parseOrderByClause parses "ORDER BY <expr> [ASC|DESC] [NULLS FIRST|LAST] [, ...]".
// Returns nil slice (no error) when ORDER BY is absent.
func (p *Parser) parseOrderByClause() ([]ast.OrderByExpression, error) {
	if !p.isType(models.TokenTypeOrder) {
		return nil, nil
	}
	p.advance() // Consume ORDER

	if !p.isType(models.TokenTypeBy) {
		return nil, p.expectedError("BY")
	}
	p.advance() // Consume BY

	var orderByExprs []ast.OrderByExpression
	for {
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}

		entry := ast.OrderByExpression{
			Expression: expr,
			Ascending:  true,
			NullsFirst: nil,
		}

		if p.isType(models.TokenTypeAsc) {
			entry.Ascending = true
			p.advance()
		} else if p.isType(models.TokenTypeDesc) {
			entry.Ascending = false
			p.advance()
		}

		nullsFirst, err := p.parseNullsClause()
		if err != nil {
			return nil, err
		}
		entry.NullsFirst = nullsFirst

		orderByExprs = append(orderByExprs, entry)

		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance()
	}
	return orderByExprs, nil
}

// parseLimitOffsetClause parses optional LIMIT and/or OFFSET clauses.
// Supports standard "LIMIT n OFFSET m", MySQL "LIMIT offset, count", and
// SQL-99 "OFFSET n ROWS" (ROW/ROWS consumed but value stored).
// Returns (limit, offset, error); either or both pointers may be nil.
func (p *Parser) parseLimitOffsetClause() (limit *int, offset *int, err error) {
	// LIMIT clause
	if p.isType(models.TokenTypeLimit) {
		// Reject LIMIT in SQL Server — use TOP or OFFSET/FETCH NEXT instead.
		if p.dialect == string(keywords.DialectSQLServer) {
			return nil, nil, fmt.Errorf(
				"LIMIT clause is not supported in SQL Server; use TOP or OFFSET/FETCH NEXT instead",
			)
		}
		p.advance() // Consume LIMIT

		if !p.isNumericLiteral() {
			return nil, nil, p.expectedError("integer for LIMIT")
		}
		firstVal := 0
		_, _ = fmt.Sscanf(p.currentToken.Literal, "%d", &firstVal)
		p.advance()

		// MySQL: LIMIT offset, count
		if p.dialect == "mysql" && p.isType(models.TokenTypeComma) {
			p.advance()
			if !p.isNumericLiteral() {
				return nil, nil, p.expectedError("integer for LIMIT count")
			}
			secondVal := 0
			_, _ = fmt.Sscanf(p.currentToken.Literal, "%d", &secondVal)
			p.advance()
			offset = &firstVal
			limit = &secondVal
		} else {
			limit = &firstVal
		}
	}

	// OFFSET clause
	if p.isType(models.TokenTypeOffset) {
		p.advance()

		if !p.isNumericLiteral() {
			return nil, nil, p.expectedError("integer for OFFSET")
		}
		offsetVal := 0
		_, _ = fmt.Sscanf(p.currentToken.Literal, "%d", &offsetVal)
		offset = &offsetVal
		p.advance()

		// SQL-99: OFFSET n ROWS
		if p.isAnyType(models.TokenTypeRow, models.TokenTypeRows) {
			p.advance()
		}
	}

	return limit, offset, nil
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

	// SQL Server table hints: WITH (NOLOCK), WITH (ROWLOCK, UPDLOCK), etc.
	if p.dialect == string(keywords.DialectSQLServer) && p.isType(models.TokenTypeWith) {
		if p.peekToken().Type == models.TokenTypeLParen {
			hints, err := p.parseTableHints()
			if err != nil {
				return tableRef, err
			}
			tableRef.TableHints = hints
		}
	}

	return tableRef, nil
}

// parseTableHints parses SQL Server table hints: WITH (NOLOCK), WITH (ROWLOCK, UPDLOCK), etc.
// Called when current token is WITH and peek is LParen.
func (p *Parser) parseTableHints() ([]string, error) {
	p.advance() // Consume WITH
	p.advance() // Consume (

	var hints []string
	for {
		if p.isType(models.TokenTypeRParen) {
			break
		}
		hint := strings.ToUpper(p.currentToken.Literal)
		if hint == "" {
			return nil, p.expectedError("table hint inside WITH (...)")
		}
		hints = append(hints, hint)
		p.advance()
		// Consume optional comma between hints
		if p.isType(models.TokenTypeComma) {
			p.advance()
		}
	}
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(") after table hints")
	}
	p.advance() // Consume )
	return hints, nil
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
