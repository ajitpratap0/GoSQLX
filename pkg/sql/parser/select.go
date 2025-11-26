// Package parser - select.go
// SELECT statement parsing including DDL helpers and set operations.

package parser

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

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
		if p.isType(models.TokenTypeAsterisk) {
			columns = append(columns, &ast.Identifier{Name: "*"})
			p.advance()
		} else {
			// Use parseExpression to handle all types including function calls
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}

			// Check for optional column alias (AS alias_name)
			if p.isType(models.TokenTypeAs) {
				p.advance() // Consume AS
				if !p.isType(models.TokenTypeIdentifier) {
					return nil, p.expectedError("alias name after AS")
				}
				// Consume the alias name (for now we don't store it in AST)
				p.advance()
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
	if !p.isType(models.TokenTypeFrom) && !p.isType(models.TokenTypeEOF) && !p.isType(models.TokenTypeSemicolon) {
		// If not FROM, EOF, or semicolon, it's likely an error
		return nil, p.expectedError("FROM, semicolon, or end of statement")
	}

	var tableName string
	var tables []ast.TableReference
	var joins []ast.JoinClause

	if p.isType(models.TokenTypeFrom) {
		p.advance() // Consume FROM

		// Parse table name
		if !p.isType(models.TokenTypeIdentifier) {
			return nil, p.expectedError("table name")
		}
		tableName = p.currentToken.Literal
		p.advance()

		// Create table reference
		tableRef := ast.TableReference{
			Name: tableName,
		}

		// Check for table alias
		if p.isType(models.TokenTypeIdentifier) || p.isType(models.TokenTypeAs) {
			if p.isType(models.TokenTypeAs) {
				p.advance() // Consume AS
				if !p.isType(models.TokenTypeIdentifier) {
					return nil, p.expectedError("alias after AS")
				}
			}
			if p.isType(models.TokenTypeIdentifier) {
				tableRef.Alias = p.currentToken.Literal
				p.advance()
			}
		}

		// Create tables list for FROM clause
		tables = []ast.TableReference{tableRef}

		// Parse JOIN clauses if present
		joins = []ast.JoinClause{}
		for p.isJoinKeyword() {
			// Determine JOIN type
			joinType := "INNER" // Default

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
			}

			// Expect JOIN keyword
			if !p.isType(models.TokenTypeJoin) {
				return nil, fmt.Errorf("expected JOIN after %s, got %s", joinType, p.currentToken.Type)
			}
			p.advance() // Consume JOIN

			// Parse joined table name
			if !p.isType(models.TokenTypeIdentifier) {
				return nil, fmt.Errorf("expected table name after %s JOIN, got %s", joinType, p.currentToken.Type)
			}
			joinedTableName := p.currentToken.Literal
			p.advance()

			// Create joined table reference
			joinedTableRef := ast.TableReference{
				Name: joinedTableName,
			}

			// Check for table alias
			if p.isType(models.TokenTypeIdentifier) || p.isType(models.TokenTypeAs) {
				if p.isType(models.TokenTypeAs) {
					p.advance() // Consume AS
					if !p.isType(models.TokenTypeIdentifier) {
						return nil, p.expectedError("alias after AS")
					}
				}
				if p.isType(models.TokenTypeIdentifier) {
					joinedTableRef.Alias = p.currentToken.Literal
					p.advance()
				}
			}

			// Parse join condition (ON or USING)
			var joinCondition ast.Expression

			// CROSS JOIN doesn't require ON clause
			if joinType != "CROSS" {
				if p.isType(models.TokenTypeOn) {
					p.advance() // Consume ON

					// Parse join condition
					cond, err := p.parseExpression()
					if err != nil {
						return nil, fmt.Errorf("error parsing ON condition for %s JOIN: %v", joinType, err)
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
						if !p.isType(models.TokenTypeIdentifier) {
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
	} // End of FROM clause parsing

	// Initialize SELECT statement
	selectStmt := &ast.SelectStatement{
		Columns:   columns,
		From:      tables,
		Joins:     joins,
		TableName: tableName, // Add this for compatibility with tests
	}

	// Parse WHERE clause if present
	if p.isType(models.TokenTypeWhere) {
		p.advance() // Consume WHERE

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
		groupByExprs := make([]ast.Expression, 0)
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
				(p.isType(models.TokenTypeGrouping) && p.peekToken().Type == "SETS") {
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
			if nextTok.Type == "ROLLUP" {
				p.advance() // Consume WITH
				p.advance() // Consume ROLLUP
				// Wrap all existing expressions in a RollupExpression
				groupByExprs = []ast.Expression{
					&ast.RollupExpression{Expressions: groupByExprs},
				}
			} else if nextTok.Type == "CUBE" {
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

	// Parse OFFSET clause if present (MySQL-style OFFSET or SQL-99 OFFSET ... ROWS)
	if p.isType(models.TokenTypeOffset) {
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

	return selectStmt, nil
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
		operationType := p.currentToken.Type
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
			return nil, fmt.Errorf("error parsing right SELECT in set operation: %v", err)
		}

		// Create the set operation with left as the accumulated result
		setOp := &ast.SetOperation{
			Left:     leftStmt,
			Operator: string(operationType),
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
	if p.currentToken.Type != "INT" {
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
