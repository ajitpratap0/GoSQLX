// Package parser - select.go
// SELECT statement parsing including DDL helpers and set operations.

package parser

import (
	"fmt"

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
		if p.currentToken.Type == "*" {
			columns = append(columns, &ast.Identifier{Name: "*"})
			p.advance()
		} else {
			// Use parseExpression to handle all types including function calls
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}

			// Check for optional column alias (AS alias_name)
			if p.currentToken.Type == "AS" {
				p.advance() // Consume AS
				if p.currentToken.Type != "IDENT" {
					return nil, p.expectedError("alias name after AS")
				}
				// Consume the alias name (for now we don't store it in AST)
				p.advance()
			}

			columns = append(columns, expr)
		}

		// Check if there are more columns
		if p.currentToken.Type != "," {
			break
		}
		p.advance() // Consume comma
	}

	// Parse FROM clause (optional to support SELECT without FROM like "SELECT 1")
	if p.currentToken.Type != "FROM" && p.currentToken.Type != "EOF" && p.currentToken.Type != ";" {
		// If not FROM, EOF, or semicolon, it's likely an error
		return nil, p.expectedError("FROM, semicolon, or end of statement")
	}

	var tableName string
	var tables []ast.TableReference
	var joins []ast.JoinClause

	if p.currentToken.Type == "FROM" {
		p.advance() // Consume FROM

		// Parse table name
		if p.currentToken.Type != "IDENT" {
			return nil, p.expectedError("table name")
		}
		tableName = p.currentToken.Literal
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
		tables = []ast.TableReference{tableRef}

		// Parse JOIN clauses if present
		joins = []ast.JoinClause{}
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

					// Parse comma-separated column list for USING clause
					// Supports both single column: USING (id)
					// and multi-column: USING (id, name, category)
					var usingColumns []ast.Expression

					for {
						// Parse column name
						if p.currentToken.Type != "IDENT" {
							return nil, p.expectedError("column name in USING")
						}
						usingColumns = append(usingColumns, &ast.Identifier{Name: p.currentToken.Literal})
						p.advance()

						// Check for comma (more columns)
						if p.currentToken.Type == "," {
							p.advance() // Consume comma
							continue
						}
						break
					}

					// Check for closing parenthesis
					if p.currentToken.Type != ")" {
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

	// Parse GROUP BY clause if present
	if p.currentToken.Type == "GROUP" {
		p.advance() // Consume GROUP
		if p.currentToken.Type != "BY" {
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
			if p.currentToken.Type == "ROLLUP" {
				expr, err = p.parseRollup()
			} else if p.currentToken.Type == "CUBE" {
				expr, err = p.parseCube()
			} else if p.currentToken.Literal == "GROUPING SETS" ||
				(p.currentToken.Type == "GROUPING" && p.peekToken().Type == "SETS") {
				expr, err = p.parseGroupingSets()
			} else {
				expr, err = p.parseExpression()
			}

			if err != nil {
				return nil, err
			}
			groupByExprs = append(groupByExprs, expr)

			// Check for comma (more expressions)
			if p.currentToken.Type != "," {
				break
			}
			p.advance() // Consume comma
		}

		// MySQL syntax support: GROUP BY col1, col2 WITH ROLLUP / WITH CUBE
		// This is different from SQL-99 GROUP BY ROLLUP(col1, col2)
		if p.currentToken.Type == "WITH" {
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
	if p.currentToken.Type == "HAVING" {
		p.advance() // Consume HAVING

		// Parse HAVING condition
		havingClause, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		selectStmt.Having = havingClause
	}

	// Parse ORDER BY clause if present
	if p.currentToken.Type == "ORDER" {
		p.advance() // Consume ORDER

		if p.currentToken.Type != "BY" {
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
			if p.currentToken.Type == "ASC" {
				orderByExpr.Ascending = true
				p.advance() // Consume ASC
			} else if p.currentToken.Type == "DESC" {
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
			if p.currentToken.Type == "," {
				p.advance() // Consume comma
			} else {
				break
			}
		}
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
	for p.currentToken.Type == "UNION" || p.currentToken.Type == "EXCEPT" || p.currentToken.Type == "INTERSECT" {
		// Parse the set operation type
		operationType := p.currentToken.Type
		p.advance()

		// Check for ALL keyword
		all := false
		if p.currentToken.Type == "ALL" {
			all = true
			p.advance()
		}

		// Parse the right-hand SELECT statement
		if p.currentToken.Type != "SELECT" {
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
