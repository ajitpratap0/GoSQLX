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
	"strings"

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
	case "MERGE":
		p.advance() // Consume MERGE
		return p.parseMergeStatement()
	case "CREATE":
		p.advance() // Consume CREATE
		return p.parseCreateStatement()
	case "DROP":
		p.advance() // Consume DROP
		return p.parseDropStatement()
	case "REFRESH":
		p.advance() // Consume REFRESH
		return p.parseRefreshStatement()
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

// peekToken returns the next token without advancing the parser position.
// Returns an empty token if at the end of input.
func (p *Parser) peekToken() token.Token {
	nextPos := p.currentPos + 1
	if nextPos < len(p.tokens) {
		return p.tokens[nextPos]
	}
	return token.Token{}
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

// Accepts IDENT or non-reserved keywords that can be used as table names
func (p *Parser) parseTableReference() (*ast.TableReference, error) {
	// Accept IDENT or keywords that can be used as table names
	if p.currentToken.Type != "IDENT" && !p.isNonReservedKeyword() {
		return nil, p.expectedError("table name")
	}
	tableName := p.currentToken.Literal
	p.advance()
	return &ast.TableReference{Name: tableName}, nil
}

// isNonReservedKeyword checks if current token is a non-reserved keyword
// that can be used as a table or column name
func (p *Parser) isNonReservedKeyword() bool {
	// These keywords can be used as table/column names in most SQL dialects
	// Check uppercase version of token type for case-insensitive matching
	upperType := strings.ToUpper(string(p.currentToken.Type))
	switch upperType {
	case "TARGET", "SOURCE", "MATCHED", "VALUE", "NAME", "TYPE", "STATUS":
		return true
	default:
		return false
	}
}

// canBeAlias checks if current token can be used as an alias
// Aliases can be IDENT or certain non-reserved keywords
func (p *Parser) canBeAlias() bool {
	return p.currentToken.Type == "IDENT" || p.isNonReservedKeyword()
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
