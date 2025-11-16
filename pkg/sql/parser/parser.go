// Package parser provides a recursive descent SQL parser that converts tokens into an Abstract Syntax Tree (AST).
// It supports comprehensive SQL features including SELECT, INSERT, UPDATE, DELETE, DDL operations,
// Common Table Expressions (CTEs), set operations (UNION, EXCEPT, INTERSECT), and window functions.
//
// Phase 2 Features (v1.2.0+):
//   - Common Table Expressions (WITH clause) with recursive support
//   - Set operations: UNION, UNION ALL, EXCEPT, INTERSECT
//   - Multiple CTE definitions in single query
//   - CTE column specifications
//   - Left-associative set operation parsing
//   - Integration of CTEs with set operations
//
// Phase 2.5 Features (v1.3.0+):
//   - Window functions with OVER clause support
//   - PARTITION BY and ORDER BY in window specifications
//   - Window frame clauses (ROWS/RANGE with bounds)
//   - Ranking functions: ROW_NUMBER(), RANK(), DENSE_RANK(), NTILE()
//   - Analytic functions: LAG(), LEAD(), FIRST_VALUE(), LAST_VALUE()
//   - Function call parsing with parentheses and arguments
//   - Integration with existing SELECT statement parsing
package parser

import (
	"context"
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// MaxRecursionDepth defines the maximum allowed recursion depth for parsing operations.
// This prevents stack overflow from deeply nested expressions, CTEs, or other recursive structures.
const MaxRecursionDepth = 100

// Parser represents a SQL parser
type Parser struct {
	tokens       []token.Token
	currentPos   int
	currentToken token.Token
	depth        int             // Current recursion depth
	ctx          context.Context // Optional context for cancellation support
}

// Parse parses the tokens into an AST
func (p *Parser) Parse(tokens []token.Token) (*ast.AST, error) {
	p.tokens = tokens
	p.currentPos = 0
	if len(tokens) > 0 {
		p.currentToken = tokens[0]
	}

	// Get a pre-allocated AST from the pool
	result := ast.NewAST()

	// Pre-allocate statements slice based on a reasonable estimate
	estimatedStmts := 1 // Most SQL queries have just one statement
	if len(tokens) > 100 {
		estimatedStmts = 2 // For larger inputs, allocate more
	}
	result.Statements = make([]ast.Statement, 0, estimatedStmts)

	// Parse statements
	for p.currentPos < len(tokens) && p.currentToken.Type != token.EOF {
		// Skip semicolons between statements
		if p.currentToken.Type == token.SEMICOLON {
			p.advance()
			continue
		}

		stmt, err := p.parseStatement()
		if err != nil {
			// Clean up the AST on error
			ast.ReleaseAST(result)
			return nil, err
		}
		result.Statements = append(result.Statements, stmt)

		// Optionally consume semicolon after statement
		if p.currentToken.Type == token.SEMICOLON {
			p.advance()
		}
	}

	// Check if we got any statements
	if len(result.Statements) == 0 {
		ast.ReleaseAST(result)
		return nil, fmt.Errorf("no SQL statements found")
	}

	return result, nil
}

// ParseContext parses the tokens into an AST with context support for cancellation.
// It checks the context at strategic points (every statement and expression) to enable fast cancellation.
// Returns context.Canceled or context.DeadlineExceeded when the context is cancelled.
//
// This method is useful for:
//   - Long-running parsing operations that need to be cancellable
//   - Implementing timeouts for parsing
//   - Graceful shutdown scenarios
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//	astNode, err := parser.ParseContext(ctx, tokens)
//	if err == context.DeadlineExceeded {
//	    // Handle timeout
//	}
func (p *Parser) ParseContext(ctx context.Context, tokens []token.Token) (*ast.AST, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Store context for use during parsing
	p.ctx = ctx
	defer func() { p.ctx = nil }() // Clear context when done

	p.tokens = tokens
	p.currentPos = 0
	if len(tokens) > 0 {
		p.currentToken = tokens[0]
	}

	// Get a pre-allocated AST from the pool
	result := ast.NewAST()

	// Pre-allocate statements slice based on a reasonable estimate
	estimatedStmts := 1 // Most SQL queries have just one statement
	if len(tokens) > 100 {
		estimatedStmts = 2 // For larger inputs, allocate more
	}
	result.Statements = make([]ast.Statement, 0, estimatedStmts)

	// Parse statements
	for p.currentPos < len(tokens) && p.currentToken.Type != token.EOF {
		// Check context before each statement
		if err := ctx.Err(); err != nil {
			// Clean up the AST on error
			ast.ReleaseAST(result)
			return nil, fmt.Errorf("parsing cancelled: %w", err)
		}

		// Skip semicolons between statements
		if p.currentToken.Type == token.SEMICOLON {
			p.advance()
			continue
		}

		stmt, err := p.parseStatement()
		if err != nil {
			// Clean up the AST on error
			ast.ReleaseAST(result)
			return nil, err
		}
		result.Statements = append(result.Statements, stmt)

		// Optionally consume semicolon after statement
		if p.currentToken.Type == token.SEMICOLON {
			p.advance()
		}
	}

	// Check if we got any statements
	if len(result.Statements) == 0 {
		ast.ReleaseAST(result)
		return nil, fmt.Errorf("no SQL statements found")
	}

	return result, nil
}

// Release releases any resources held by the parser
func (p *Parser) Release() {
	// Reset internal state to avoid memory leaks
	p.tokens = nil
	p.currentPos = 0
	p.currentToken = token.Token{}
	p.depth = 0
	p.ctx = nil
}

// parseStatement parses a single SQL statement
func (p *Parser) parseStatement() (ast.Statement, error) {
	// Check context if available
	if p.ctx != nil {
		if err := p.ctx.Err(); err != nil {
			return nil, fmt.Errorf("parsing cancelled: %w", err)
		}
	}

	switch p.currentToken.Type {
	case "WITH":
		return p.parseWithStatement()
	case "SELECT":
		p.advance() // Consume SELECT
		return p.parseSelectWithSetOperations()
	case "INSERT":
		p.advance() // Consume INSERT
		return p.parseInsertStatement()
	case "UPDATE":
		p.advance() // Consume UPDATE
		return p.parseUpdateStatement()
	case "DELETE":
		p.advance() // Consume DELETE
		return p.parseDeleteStatement()
	case "ALTER":
		p.advance() // Consume ALTER
		return p.parseAlterTableStmt()
	default:
		return nil, p.expectedError("statement")
	}
}

// NewParser creates a new parser
func NewParser() *Parser {
	return &Parser{}
}

// matchToken checks if the current token matches the expected type
func (p *Parser) matchToken(expected token.Type) bool {
	// Convert both to strings for comparison
	expectedStr := string(expected)
	currentStr := string(p.currentToken.Type)
	if currentStr == expectedStr {
		p.advance()
		return true
	}
	return false
}

// advance moves to the next token
func (p *Parser) advance() {
	p.currentPos++
	if p.currentPos < len(p.tokens) {
		p.currentToken = p.tokens[p.currentPos]
	}
}

// expectedError returns an error for unexpected token
func (p *Parser) expectedError(expected string) error {
	return fmt.Errorf("expected %s, got %s", expected, p.currentToken.Type)
}

// parseIdent parses an identifier
func (p *Parser) parseIdent() *ast.Identifier {
	if p.currentToken.Type != token.IDENT && p.currentToken.Type != "IDENT" {
		return nil
	}
	ident := &ast.Identifier{Name: p.currentToken.Literal}
	p.advance()
	return ident
}

// parseIdentAsString parses an identifier and returns its name as a string
func (p *Parser) parseIdentAsString() string {
	ident := p.parseIdent()
	if ident == nil {
		return ""
	}
	return ident.Name
}

// parseObjectName parses an object name (possibly qualified)
func (p *Parser) parseObjectName() ast.ObjectName {
	ident := p.parseIdent()
	if ident == nil {
		return ast.ObjectName{}
	}
	return ast.ObjectName{Name: ident.Name}
}

// parseStringLiteral parses a string literal
func (p *Parser) parseStringLiteral() string {
	if p.currentToken.Type != token.STRING && p.currentToken.Type != "STRING" {
		return ""
	}
	value := p.currentToken.Literal
	p.advance()
	return value
}

// parseExpression parses an expression with OR operators (lowest precedence)
func (p *Parser) parseExpression() (ast.Expression, error) {
	// Check context if available
	if p.ctx != nil {
		if err := p.ctx.Err(); err != nil {
			return nil, fmt.Errorf("parsing cancelled: %w", err)
		}
	}

	// Check recursion depth to prevent stack overflow
	p.depth++
	defer func() { p.depth-- }()

	if p.depth > MaxRecursionDepth {
		return nil, fmt.Errorf("maximum recursion depth exceeded (%d) - expression too deeply nested", MaxRecursionDepth)
	}

	// Start by parsing AND expressions (higher precedence)
	left, err := p.parseAndExpression()
	if err != nil {
		return nil, err
	}

	// Handle OR operators (lowest precedence, left-associative)
	for p.currentToken.Type == "OR" {
		operator := p.currentToken.Literal
		p.advance() // Consume OR

		right, err := p.parseAndExpression()
		if err != nil {
			return nil, err
		}

		left = &ast.BinaryExpression{
			Left:     left,
			Operator: operator,
			Right:    right,
		}
	}

	return left, nil
}

// parseAndExpression parses an expression with AND operators (middle precedence)
func (p *Parser) parseAndExpression() (ast.Expression, error) {
	// Parse comparison expressions (higher precedence)
	left, err := p.parseComparisonExpression()
	if err != nil {
		return nil, err
	}

	// Handle AND operators (middle precedence, left-associative)
	for p.currentToken.Type == "AND" {
		operator := p.currentToken.Literal
		p.advance() // Consume AND

		right, err := p.parseComparisonExpression()
		if err != nil {
			return nil, err
		}

		left = &ast.BinaryExpression{
			Left:     left,
			Operator: operator,
			Right:    right,
		}
	}

	return left, nil
}

// parseComparisonExpression parses an expression with comparison operators (highest precedence)
func (p *Parser) parseComparisonExpression() (ast.Expression, error) {
	// Parse the left side (primary expression)
	left, err := p.parsePrimaryExpression()
	if err != nil {
		return nil, err
	}

	// Check if this is a comparison binary expression
	if p.currentToken.Type == "=" || p.currentToken.Type == "<" ||
		p.currentToken.Type == ">" || p.currentToken.Type == "!=" ||
		p.currentToken.Type == "<=" || p.currentToken.Type == ">=" {
		// Save the operator
		operator := p.currentToken.Literal
		p.advance()

		// Parse the right side of the expression
		right, err := p.parsePrimaryExpression()
		if err != nil {
			return nil, err
		}

		// Create a binary expression
		return &ast.BinaryExpression{
			Left:     left,
			Operator: operator,
			Right:    right,
		}, nil
	}

	return left, nil
}

// parsePrimaryExpression parses a primary expression (literals, identifiers, function calls)
func (p *Parser) parsePrimaryExpression() (ast.Expression, error) {
	switch p.currentToken.Type {
	case "IDENT":
		// Handle identifiers and function calls
		identName := p.currentToken.Literal
		p.advance()

		// Check for function call (identifier followed by parentheses)
		if p.currentToken.Type == "(" {
			// This is a function call
			funcCall, err := p.parseFunctionCall(identName)
			if err != nil {
				return nil, err
			}
			return funcCall, nil
		}

		// Handle regular identifier or qualified identifier (table.column)
		ident := &ast.Identifier{Name: identName}

		// Check for qualified identifier (table.column)
		if p.currentToken.Type == "." {
			p.advance() // Consume .
			if p.currentToken.Type != "IDENT" {
				return nil, p.expectedError("identifier after .")
			}
			// Create a qualified identifier
			ident = &ast.Identifier{
				Table: ident.Name,
				Name:  p.currentToken.Literal,
			}
			p.advance()
		}

		return ident, nil

	case "*":
		// Handle asterisk (e.g., in COUNT(*) or SELECT *)
		p.advance()
		return &ast.Identifier{Name: "*"}, nil

	case "STRING":
		// Handle string literals
		value := p.currentToken.Literal
		p.advance()
		return &ast.LiteralValue{Value: value, Type: "string"}, nil

	case "INT":
		// Handle integer literals
		value := p.currentToken.Literal
		p.advance()
		return &ast.LiteralValue{Value: value, Type: "int"}, nil

	case "FLOAT":
		// Handle float literals
		value := p.currentToken.Literal
		p.advance()
		return &ast.LiteralValue{Value: value, Type: "float"}, nil

	case "TRUE", "FALSE":
		// Handle boolean literals
		value := p.currentToken.Literal
		p.advance()
		return &ast.LiteralValue{Value: value, Type: "bool"}, nil

	case "PLACEHOLDER":
		// Handle SQL placeholders (e.g., $1, $2 for PostgreSQL; @param for SQL Server)
		value := p.currentToken.Literal
		p.advance()
		return &ast.LiteralValue{Value: value, Type: "placeholder"}, nil

	default:
		return nil, fmt.Errorf("unexpected token: %s", p.currentToken.Type)
	}
}

// parseFunctionCall parses a function call with optional OVER clause for window functions.
//
// Examples:
//
//	COUNT(*) -> regular aggregate function
//	ROW_NUMBER() OVER (ORDER BY id) -> window function with OVER clause
//	SUM(salary) OVER (PARTITION BY dept ORDER BY date ROWS UNBOUNDED PRECEDING) -> window function with frame
func (p *Parser) parseFunctionCall(funcName string) (*ast.FunctionCall, error) {
	// Expect opening parenthesis
	if p.currentToken.Type != "(" {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	// Parse function arguments
	var arguments []ast.Expression
	var distinct bool

	// Check for DISTINCT keyword
	if p.currentToken.Type == "DISTINCT" {
		distinct = true
		p.advance()
	}

	// Parse arguments if not empty
	if p.currentToken.Type != ")" {
		for {
			arg, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			arguments = append(arguments, arg)

			// Check for comma or end of arguments
			if p.currentToken.Type == "," {
				p.advance() // Consume comma
			} else if p.currentToken.Type == ")" {
				break
			} else {
				return nil, p.expectedError(", or )")
			}
		}
	}

	// Expect closing parenthesis
	if p.currentToken.Type != ")" {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )

	// Create function call
	funcCall := &ast.FunctionCall{
		Name:      funcName,
		Arguments: arguments,
		Distinct:  distinct,
	}

	// Check for OVER clause (window function)
	if p.currentToken.Type == "OVER" {
		p.advance() // Consume OVER

		windowSpec, err := p.parseWindowSpec()
		if err != nil {
			return nil, err
		}
		funcCall.Over = windowSpec
	}

	return funcCall, nil
}

// parseWindowSpec parses a window specification (PARTITION BY, ORDER BY, frame clause)
func (p *Parser) parseWindowSpec() (*ast.WindowSpec, error) {
	// Expect opening parenthesis
	if p.currentToken.Type != "(" {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	windowSpec := &ast.WindowSpec{}

	// Parse PARTITION BY clause
	if p.currentToken.Type == "PARTITION" {
		p.advance() // Consume PARTITION
		if p.currentToken.Type != "BY" {
			return nil, p.expectedError("BY after PARTITION")
		}
		p.advance() // Consume BY

		// Parse partition expressions
		for {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			windowSpec.PartitionBy = append(windowSpec.PartitionBy, expr)

			if p.currentToken.Type == "," {
				p.advance() // Consume comma
			} else {
				break
			}
		}
	}

	// Parse ORDER BY clause
	if p.currentToken.Type == "ORDER" {
		p.advance() // Consume ORDER
		if p.currentToken.Type != "BY" {
			return nil, p.expectedError("BY after ORDER")
		}
		p.advance() // Consume BY

		// Parse order expressions
		for {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}

			// Check for ASC/DESC after the expression
			if p.currentToken.Type == "ASC" || p.currentToken.Type == "DESC" {
				p.advance() // Consume ASC/DESC (we don't store it in this simple implementation)
			}

			windowSpec.OrderBy = append(windowSpec.OrderBy, expr)

			if p.currentToken.Type == "," {
				p.advance() // Consume comma
			} else {
				break
			}
		}
	}

	// Parse frame clause (ROWS/RANGE with bounds)
	if p.currentToken.Type == "ROWS" || p.currentToken.Type == "RANGE" {
		frameType := p.currentToken.Literal
		p.advance() // Consume ROWS/RANGE

		frameClause, err := p.parseWindowFrame(frameType)
		if err != nil {
			return nil, err
		}
		windowSpec.FrameClause = frameClause
	}

	// Expect closing parenthesis
	if p.currentToken.Type != ")" {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )

	return windowSpec, nil
}

// parseWindowFrame parses a window frame clause
func (p *Parser) parseWindowFrame(frameType string) (*ast.WindowFrame, error) {
	frame := &ast.WindowFrame{
		Type: frameType,
	}

	// Parse frame bounds
	if p.currentToken.Type == "BETWEEN" {
		p.advance() // Consume BETWEEN

		// Parse start bound
		startBound, err := p.parseFrameBound()
		if err != nil {
			return nil, err
		}
		frame.Start = *startBound

		// Expect AND
		if p.currentToken.Type != "AND" {
			return nil, p.expectedError("AND")
		}
		p.advance() // Consume AND

		// Parse end bound
		endBound, err := p.parseFrameBound()
		if err != nil {
			return nil, err
		}
		frame.End = endBound
	} else {
		// Single bound (implies CURRENT ROW as end)
		startBound, err := p.parseFrameBound()
		if err != nil {
			return nil, err
		}
		frame.Start = *startBound
		// End is nil for single bound
	}

	return frame, nil
}

// parseFrameBound parses a window frame bound
func (p *Parser) parseFrameBound() (*ast.WindowFrameBound, error) {
	bound := &ast.WindowFrameBound{}

	if p.currentToken.Type == "UNBOUNDED" {
		p.advance() // Consume UNBOUNDED
		if p.currentToken.Type == "PRECEDING" {
			bound.Type = "UNBOUNDED PRECEDING"
			p.advance() // Consume PRECEDING
		} else if p.currentToken.Type == "FOLLOWING" {
			bound.Type = "UNBOUNDED FOLLOWING"
			p.advance() // Consume FOLLOWING
		} else {
			return nil, p.expectedError("PRECEDING or FOLLOWING after UNBOUNDED")
		}
	} else if p.currentToken.Type == "CURRENT" {
		p.advance() // Consume CURRENT
		if p.currentToken.Type != "ROW" {
			return nil, p.expectedError("ROW after CURRENT")
		}
		bound.Type = "CURRENT ROW"
		p.advance() // Consume ROW
	} else {
		// Numeric bound
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		bound.Value = expr

		if p.currentToken.Type == "PRECEDING" {
			bound.Type = "PRECEDING"
			p.advance() // Consume PRECEDING
		} else if p.currentToken.Type == "FOLLOWING" {
			bound.Type = "FOLLOWING"
			p.advance() // Consume FOLLOWING
		} else {
			return nil, p.expectedError("PRECEDING or FOLLOWING after numeric value")
		}
	}

	return bound, nil
}

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

					// TODO: LIMITATION - Currently only supports single column in USING clause
					// Future enhancement needed for multi-column support like USING (col1, col2, col3)
					// This requires parsing comma-separated column list and storing as []Expression
					// Priority: Medium (Phase 2 enhancement)
					if p.currentToken.Type != "IDENT" {
						return nil, p.expectedError("column name in USING")
					}
					joinCondition = &ast.Identifier{Name: p.currentToken.Literal}
					p.advance()

					if p.currentToken.Type != ")" {
						return nil, p.expectedError(") after USING column")
					}
					p.advance()
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
		groupByExprs := make([]ast.Expression, 0)
		for {
			expr, err := p.parseExpression()
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

		// Parse ORDER BY expression
		orderByExpr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}

		// Check for direction (ASC/DESC)
		// Note: Direction is handled separately in the actual implementation
		if p.currentToken.Type == "DESC" {
			p.advance() // Consume DESC
		} else if p.currentToken.Type == "ASC" {
			p.advance() // Consume ASC
		}

		// Add ORDER BY to SELECT statement
		selectStmt.OrderBy = []ast.Expression{orderByExpr}
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

// parseInsertStatement parses an INSERT statement
func (p *Parser) parseInsertStatement() (ast.Statement, error) {
	// We've already consumed the INSERT token in matchToken

	// Parse INTO
	if p.currentToken.Type != "INTO" {
		return nil, p.expectedError("INTO")
	}
	p.advance() // Consume INTO

	// Parse table name
	if p.currentToken.Type != "IDENT" {
		return nil, p.expectedError("table name")
	}
	tableName := p.currentToken.Literal
	p.advance()

	// Parse column list if present
	columns := make([]ast.Expression, 0)
	if p.currentToken.Type == "(" {
		p.advance() // Consume (

		for {
			// Parse column name
			if p.currentToken.Type != "IDENT" {
				return nil, p.expectedError("column name")
			}
			columns = append(columns, &ast.Identifier{Name: p.currentToken.Literal})
			p.advance()

			// Check if there are more columns
			if p.currentToken.Type != "," {
				break
			}
			p.advance() // Consume comma
		}

		if p.currentToken.Type != ")" {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
	}

	// Parse VALUES
	if p.currentToken.Type != "VALUES" {
		return nil, p.expectedError("VALUES")
	}
	p.advance() // Consume VALUES

	// Parse value list
	values := make([]ast.Expression, 0)
	if p.currentToken.Type == "(" {
		p.advance() // Consume (

		for {
			// Parse value
			var expr ast.Expression
			switch p.currentToken.Type {
			case "STRING":
				expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "string"}
				p.advance()
			case "INT":
				expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "int"}
				p.advance()
			case "FLOAT":
				expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "float"}
				p.advance()
			case token.TRUE, token.FALSE:
				expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "bool"}
				p.advance()
			default:
				return nil, fmt.Errorf("unexpected token for value: %s", p.currentToken.Type)
			}
			values = append(values, expr)

			// Check if there are more values
			if p.currentToken.Type != "," {
				break
			}
			p.advance() // Consume comma
		}

		if p.currentToken.Type != ")" {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
	}

	// Create INSERT statement
	return &ast.InsertStatement{
		TableName: tableName,
		Columns:   columns,
		Values:    values,
	}, nil
}

// parseUpdateStatement parses an UPDATE statement
func (p *Parser) parseUpdateStatement() (ast.Statement, error) {
	// We've already consumed the UPDATE token in matchToken

	// Parse table name
	if p.currentToken.Type != "IDENT" {
		return nil, p.expectedError("table name")
	}
	tableName := p.currentToken.Literal
	p.advance()

	// Parse SET
	if p.currentToken.Type != "SET" {
		return nil, p.expectedError("SET")
	}
	p.advance() // Consume SET

	// Parse assignments
	updates := make([]ast.UpdateExpression, 0)
	for {
		// Parse column name
		if p.currentToken.Type != "IDENT" {
			return nil, p.expectedError("column name")
		}
		columnName := p.currentToken.Literal
		p.advance()

		if p.currentToken.Type != "=" {
			return nil, p.expectedError("=")
		}
		p.advance() // Consume =

		// Parse value expression
		var expr ast.Expression
		switch p.currentToken.Type {
		case "STRING":
			expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "string"}
			p.advance()
		case "INT":
			expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "int"}
			p.advance()
		case "FLOAT":
			expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "float"}
			p.advance()
		case "TRUE", "FALSE":
			expr = &ast.LiteralValue{Value: p.currentToken.Literal, Type: "bool"}
			p.advance()
		default:
			var err error
			expr, err = p.parseExpression()
			if err != nil {
				return nil, err
			}
		}

		// Create update expression
		columnExpr := &ast.Identifier{Name: columnName}
		updateExpr := ast.UpdateExpression{
			Column: columnExpr,
			Value:  expr,
		}
		updates = append(updates, updateExpr)

		// Check if there are more assignments
		if p.currentToken.Type != "," {
			break
		}
		p.advance() // Consume comma
	}

	// Parse WHERE clause if present
	var whereClause ast.Expression
	if p.currentToken.Type == "WHERE" {
		p.advance() // Consume WHERE
		var err error
		whereClause, err = p.parseExpression()
		if err != nil {
			return nil, err
		}
	}

	// Create UPDATE statement
	return &ast.UpdateStatement{
		TableName: tableName,
		Updates:   updates,
		Where:     whereClause,
	}, nil
}

// parseDeleteStatement parses a DELETE statement
func (p *Parser) parseDeleteStatement() (ast.Statement, error) {
	// We've already consumed the DELETE token in matchToken

	// Parse FROM
	if p.currentToken.Type != "FROM" {
		return nil, p.expectedError("FROM")
	}
	p.advance() // Consume FROM

	// Parse table name
	if p.currentToken.Type != "IDENT" {
		return nil, p.expectedError("table name")
	}
	tableName := p.currentToken.Literal
	p.advance()

	// Parse WHERE clause if present
	var whereClause ast.Expression
	if p.currentToken.Type == "WHERE" {
		p.advance() // Consume WHERE
		var err error
		whereClause, err = p.parseExpression()
		if err != nil {
			return nil, err
		}
	}

	// Create DELETE statement
	return &ast.DeleteStatement{
		TableName: tableName,
		Where:     whereClause,
	}, nil
}

// parseAlterTableStmt is a simplified version for the parser implementation
// It delegates to the more comprehensive parseAlterStatement in alter.go
func (p *Parser) parseAlterTableStmt() (ast.Statement, error) {
	// We've already consumed the ALTER token in matchToken
	// This is just a placeholder that delegates to the main implementation
	return p.parseAlterStatement()
}

// isJoinKeyword checks if current token is a JOIN-related keyword
func (p *Parser) isJoinKeyword() bool {
	switch p.currentToken.Type {
	case "JOIN", "INNER", "LEFT", "RIGHT", "FULL", "CROSS":
		return true
	default:
		return false
	}
}

// parseWithStatement parses a WITH statement (Common Table Expression).
// It supports both simple and recursive CTEs, multiple CTE definitions, and column specifications.
//
// Examples:
//
//	WITH sales_summary AS (SELECT region, total FROM sales) SELECT * FROM sales_summary
//	WITH RECURSIVE emp_tree AS (SELECT emp_id FROM employees) SELECT * FROM emp_tree
//	WITH first AS (SELECT * FROM t1), second AS (SELECT * FROM first) SELECT * FROM second
//	WITH summary(region, total) AS (SELECT region, SUM(amount) FROM sales GROUP BY region) SELECT * FROM summary
func (p *Parser) parseWithStatement() (ast.Statement, error) {
	// Consume WITH
	p.advance()

	// Check for RECURSIVE keyword
	recursive := false
	if p.currentToken.Type == "RECURSIVE" {
		recursive = true
		p.advance()
	}

	// Parse Common Table Expressions
	ctes := []*ast.CommonTableExpr{}

	for {
		cte, err := p.parseCommonTableExpr()
		if err != nil {
			return nil, fmt.Errorf("error parsing CTE: %v", err)
		}
		ctes = append(ctes, cte)

		// Check for more CTEs (comma-separated)
		if p.currentToken.Type == "," {
			p.advance() // Consume comma
			continue
		}
		break
	}

	// Create WITH clause
	withClause := &ast.WithClause{
		Recursive: recursive,
		CTEs:      ctes,
	}

	// Parse the main statement that follows the WITH clause
	mainStmt, err := p.parseMainStatementAfterWith()
	if err != nil {
		return nil, fmt.Errorf("error parsing statement after WITH: %v", err)
	}

	// Attach WITH clause to the main statement
	switch stmt := mainStmt.(type) {
	case *ast.SelectStatement:
		stmt.With = withClause
		return stmt, nil
	case *ast.SetOperation:
		// For set operations, attach WITH to the left statement if it's a SELECT
		if leftSelect, ok := stmt.Left.(*ast.SelectStatement); ok {
			leftSelect.With = withClause
		}
		return stmt, nil
	case *ast.InsertStatement:
		stmt.With = withClause
		return stmt, nil
	case *ast.UpdateStatement:
		stmt.With = withClause
		return stmt, nil
	case *ast.DeleteStatement:
		stmt.With = withClause
		return stmt, nil
	default:
		return nil, fmt.Errorf("WITH clause not supported with statement type: %T", stmt)
	}
}

// parseCommonTableExpr parses a single Common Table Expression.
// It handles CTE name, optional column list, AS keyword, and the CTE query in parentheses.
//
// Syntax: cte_name [(column_list)] AS (query)
func (p *Parser) parseCommonTableExpr() (*ast.CommonTableExpr, error) {
	// Check recursion depth to prevent stack overflow in recursive CTEs
	// This is critical since CTEs can call parseStatement which leads back to more CTEs
	p.depth++
	defer func() { p.depth-- }()

	if p.depth > MaxRecursionDepth {
		return nil, fmt.Errorf("maximum recursion depth exceeded (%d) - CTE too deeply nested", MaxRecursionDepth)
	}

	// Parse CTE name
	if p.currentToken.Type != "IDENT" {
		return nil, p.expectedError("CTE name")
	}
	name := p.currentToken.Literal
	p.advance()

	// Parse optional column list
	var columns []string
	if p.currentToken.Type == "(" {
		p.advance() // Consume (

		for {
			if p.currentToken.Type != "IDENT" {
				return nil, p.expectedError("column name")
			}
			columns = append(columns, p.currentToken.Literal)
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

	// Parse AS keyword
	if p.currentToken.Type != "AS" {
		return nil, p.expectedError("AS")
	}
	p.advance()

	// Parse the CTE query (must be in parentheses)
	if p.currentToken.Type != "(" {
		return nil, p.expectedError("( before CTE query")
	}
	p.advance() // Consume (

	// Parse the inner statement
	stmt, err := p.parseStatement()
	if err != nil {
		return nil, fmt.Errorf("error parsing CTE statement: %v", err)
	}

	if p.currentToken.Type != ")" {
		return nil, p.expectedError(") after CTE query")
	}
	p.advance() // Consume )

	return &ast.CommonTableExpr{
		Name:      name,
		Columns:   columns,
		Statement: stmt,
	}, nil
}

// parseMainStatementAfterWith parses the main statement after WITH clause.
// It supports SELECT, INSERT, UPDATE, and DELETE statements, routing them to the appropriate
// parsers while preserving set operation support for SELECT statements.
func (p *Parser) parseMainStatementAfterWith() (ast.Statement, error) {
	switch p.currentToken.Type {
	case "SELECT":
		p.advance() // Consume SELECT
		return p.parseSelectWithSetOperations()
	case "INSERT":
		p.advance() // Consume INSERT
		return p.parseInsertStatement()
	case "UPDATE":
		p.advance() // Consume UPDATE
		return p.parseUpdateStatement()
	case "DELETE":
		p.advance() // Consume DELETE
		return p.parseDeleteStatement()
	default:
		return nil, p.expectedError("SELECT, INSERT, UPDATE, or DELETE after WITH")
	}
}
