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
	"sync"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// parserPool provides object pooling for Parser instances to reduce allocations.
// This significantly improves performance in high-throughput scenarios.
var parserPool = sync.Pool{
	New: func() interface{} {
		return &Parser{}
	},
}

// GetParser returns a Parser instance from the pool.
// The caller must call PutParser when done to return it to the pool.
func GetParser() *Parser {
	return parserPool.Get().(*Parser)
}

// PutParser returns a Parser instance to the pool after resetting it.
// This should be called after parsing is complete to enable reuse.
func PutParser(p *Parser) {
	if p != nil {
		p.Reset()
		parserPool.Put(p)
	}
}

// Reset clears the parser state for reuse from the pool.
func (p *Parser) Reset() {
	p.tokens = nil
	p.currentPos = 0
	p.currentToken = token.Token{}
	p.depth = 0
	p.ctx = nil
	p.positions = nil
}

// currentLocation returns the source location of the current token.
// Returns an empty location if position tracking is not enabled or position is out of bounds.
func (p *Parser) currentLocation() models.Location {
	if p.positions == nil || p.currentPos >= len(p.positions) {
		return models.Location{}
	}
	return p.positions[p.currentPos].Start
}

// MaxRecursionDepth defines the maximum allowed recursion depth for parsing operations.
// This prevents stack overflow from deeply nested expressions, CTEs, or other recursive structures.
const MaxRecursionDepth = 100

// modelTypeUnset is the zero value for ModelType, indicating the type was not set.
// Used for fast path checks: tokens with ModelType set use O(1) switch dispatch.
const modelTypeUnset models.TokenType = 0

// Parser represents a SQL parser
type Parser struct {
	tokens       []token.Token
	currentPos   int
	currentToken token.Token
	depth        int             // Current recursion depth
	ctx          context.Context // Optional context for cancellation support
	positions    []TokenPosition // Position mapping for error reporting
}

// Parse parses the tokens into an AST
// Uses fast ModelType (int) comparisons for hot path optimization
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

	// Parse statements using ModelType (int) comparisons for speed
	for p.currentPos < len(tokens) && !p.isType(models.TokenTypeEOF) {
		// Skip semicolons between statements
		if p.isType(models.TokenTypeSemicolon) {
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
		if p.isType(models.TokenTypeSemicolon) {
			p.advance()
		}
	}

	// Check if we got any statements
	if len(result.Statements) == 0 {
		ast.ReleaseAST(result)
		return nil, goerrors.IncompleteStatementError(models.Location{}, "")
	}

	return result, nil
}

// ParseWithPositions parses tokens with position tracking for enhanced error reporting.
// This method accepts a ConversionResult from the token converter, which includes
// both the converted tokens and their original source positions.
// Errors generated during parsing will include accurate line/column information.
func (p *Parser) ParseWithPositions(result *ConversionResult) (*ast.AST, error) {
	p.tokens = result.Tokens
	p.positions = result.PositionMapping
	p.currentPos = 0
	if len(result.Tokens) > 0 {
		p.currentToken = result.Tokens[0]
	}

	// Get a pre-allocated AST from the pool
	astResult := ast.NewAST()

	// Pre-allocate statements slice based on a reasonable estimate
	estimatedStmts := 1
	if len(result.Tokens) > 100 {
		estimatedStmts = 2
	}
	astResult.Statements = make([]ast.Statement, 0, estimatedStmts)

	// Parse statements
	for p.currentPos < len(result.Tokens) && !p.isType(models.TokenTypeEOF) {
		if p.isType(models.TokenTypeSemicolon) {
			p.advance()
			continue
		}

		stmt, err := p.parseStatement()
		if err != nil {
			ast.ReleaseAST(astResult)
			return nil, err
		}
		astResult.Statements = append(astResult.Statements, stmt)

		if p.isType(models.TokenTypeSemicolon) {
			p.advance()
		}
	}

	if len(astResult.Statements) == 0 {
		ast.ReleaseAST(astResult)
		return nil, goerrors.IncompleteStatementError(p.currentLocation(), "")
	}

	return astResult, nil
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

	// Parse statements using ModelType (int) comparisons for speed
	for p.currentPos < len(tokens) && !p.isType(models.TokenTypeEOF) {
		// Check context before each statement
		if err := ctx.Err(); err != nil {
			// Clean up the AST on error
			ast.ReleaseAST(result)
			// Context cancellation is not a parsing error, return the context error directly
			return nil, fmt.Errorf("parsing cancelled: %w", err)
		}

		// Skip semicolons between statements
		if p.isType(models.TokenTypeSemicolon) {
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
		if p.isType(models.TokenTypeSemicolon) {
			p.advance()
		}
	}

	// Check if we got any statements
	if len(result.Statements) == 0 {
		ast.ReleaseAST(result)
		return nil, goerrors.IncompleteStatementError(p.currentLocation(), "")
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
// Uses O(1) switch dispatch on ModelType (compiles to jump table) for optimal performance
func (p *Parser) parseStatement() (ast.Statement, error) {
	// Check context if available
	if p.ctx != nil {
		if err := p.ctx.Err(); err != nil {
			// Context cancellation is not a parsing error, return the context error directly
			return nil, fmt.Errorf("parsing cancelled: %w", err)
		}
	}

	// Fast path: O(1) switch dispatch on ModelType (compiles to jump table)
	// This replaces the previous O(n) isAnyType + O(n) matchType approach
	if p.currentToken.ModelType != modelTypeUnset {
		switch p.currentToken.ModelType {
		case models.TokenTypeWith:
			return p.parseWithStatement()
		case models.TokenTypeSelect:
			p.advance()
			return p.parseSelectWithSetOperations()
		case models.TokenTypeInsert:
			p.advance()
			return p.parseInsertStatement()
		case models.TokenTypeUpdate:
			p.advance()
			return p.parseUpdateStatement()
		case models.TokenTypeDelete:
			p.advance()
			return p.parseDeleteStatement()
		case models.TokenTypeAlter:
			p.advance()
			return p.parseAlterTableStmt()
		case models.TokenTypeMerge:
			p.advance()
			return p.parseMergeStatement()
		case models.TokenTypeCreate:
			p.advance()
			return p.parseCreateStatement()
		case models.TokenTypeDrop:
			p.advance()
			return p.parseDropStatement()
		case models.TokenTypeRefresh:
			p.advance()
			return p.parseRefreshStatement()
		case models.TokenTypeTruncate:
			p.advance()
			return p.parseTruncateStatement()
		}
		// ModelType set but not a statement keyword - fall through to fallback
	}

	// Fallback: string comparison for tokens without ModelType (e.g., tests)
	// or tokens with ModelType that aren't statement starters (e.g., operators)
	if p.isType(models.TokenTypeWith) {
		return p.parseWithStatement()
	}
	if p.matchType(models.TokenTypeSelect) {
		return p.parseSelectWithSetOperations()
	}
	if p.matchType(models.TokenTypeInsert) {
		return p.parseInsertStatement()
	}
	if p.matchType(models.TokenTypeUpdate) {
		return p.parseUpdateStatement()
	}
	if p.matchType(models.TokenTypeDelete) {
		return p.parseDeleteStatement()
	}
	if p.matchType(models.TokenTypeAlter) {
		return p.parseAlterTableStmt()
	}
	if p.matchType(models.TokenTypeMerge) {
		return p.parseMergeStatement()
	}
	if p.matchType(models.TokenTypeCreate) {
		return p.parseCreateStatement()
	}
	if p.matchType(models.TokenTypeDrop) {
		return p.parseDropStatement()
	}
	if p.matchType(models.TokenTypeRefresh) {
		return p.parseRefreshStatement()
	}
	if p.matchType(models.TokenTypeTruncate) {
		return p.parseTruncateStatement()
	}
	return nil, p.expectedError("statement")
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

// =============================================================================
// ModelType-based Helper Methods (Phase 2 - Fast Int Comparisons)
// =============================================================================
// These methods use int-based ModelType comparisons which are significantly
// faster than string comparisons (~0.24ns vs ~3.4ns). Use these for hot paths.
// They include fallback to string-based Type comparison for backward compatibility
// with tests that create tokens directly without setting ModelType.

// modelTypeToString maps ModelType to expected string Type for fallback comparison.
// This comprehensive map enables isType() to work with tokens that don't have ModelType set
// (e.g., tokens created in tests without using the tokenizer).
// NOTE: Only TokenTypes that exist in models package are included here.
var modelTypeToString = map[models.TokenType]token.Type{
	// Special tokens
	models.TokenTypeEOF:        token.EOF,
	models.TokenTypeSemicolon:  token.SEMICOLON,
	models.TokenTypeIdentifier: "IDENT",

	// Punctuation and operators
	models.TokenTypeComma:    token.COMMA,
	models.TokenTypeLParen:   "(",
	models.TokenTypeRParen:   ")",
	models.TokenTypeEq:       "=",
	models.TokenTypeLt:       "<",
	models.TokenTypeGt:       ">",
	models.TokenTypeNeq:      "!=",
	models.TokenTypeLtEq:     "<=",
	models.TokenTypeGtEq:     ">=",
	models.TokenTypeDot:      ".",
	models.TokenTypeAsterisk: "*",

	// Core SQL keywords
	models.TokenTypeSelect: token.SELECT,
	models.TokenTypeFrom:   token.FROM,
	models.TokenTypeWhere:  token.WHERE,
	models.TokenTypeInsert: token.INSERT,
	models.TokenTypeUpdate: token.UPDATE,
	models.TokenTypeDelete: token.DELETE,
	models.TokenTypeInto:   "INTO",
	models.TokenTypeValues: "VALUES",
	models.TokenTypeSet:    "SET",
	models.TokenTypeAs:     "AS",
	models.TokenTypeOn:     "ON",

	// DDL keywords
	models.TokenTypeCreate:       "CREATE",
	models.TokenTypeAlter:        token.ALTER,
	models.TokenTypeDrop:         token.DROP,
	models.TokenTypeTruncate:     "TRUNCATE",
	models.TokenTypeTable:        "TABLE",
	models.TokenTypeIndex:        "INDEX",
	models.TokenTypeView:         "VIEW",
	models.TokenTypePrimary:      "PRIMARY",
	models.TokenTypeForeign:      "FOREIGN",
	models.TokenTypeUnique:       "UNIQUE",
	models.TokenTypeCheck:        "CHECK",
	models.TokenTypeConstraint:   "CONSTRAINT",
	models.TokenTypeDefault:      "DEFAULT",
	models.TokenTypeReferences:   "REFERENCES",
	models.TokenTypeCascade:      "CASCADE",
	models.TokenTypeRestrict:     "RESTRICT",
	models.TokenTypeMaterialized: "MATERIALIZED",
	models.TokenTypeReplace:      "REPLACE",
	models.TokenTypeCollate:      "COLLATE",

	// Clause keywords
	models.TokenTypeGroup:    "GROUP",
	models.TokenTypeBy:       "BY",
	models.TokenTypeHaving:   "HAVING",
	models.TokenTypeOrder:    "ORDER",
	models.TokenTypeAsc:      "ASC",
	models.TokenTypeDesc:     "DESC",
	models.TokenTypeLimit:    "LIMIT",
	models.TokenTypeOffset:   "OFFSET",
	models.TokenTypeDistinct: "DISTINCT",

	// JOIN keywords
	models.TokenTypeJoin:    "JOIN",
	models.TokenTypeInner:   "INNER",
	models.TokenTypeLeft:    "LEFT",
	models.TokenTypeRight:   "RIGHT",
	models.TokenTypeFull:    "FULL",
	models.TokenTypeOuter:   "OUTER",
	models.TokenTypeCross:   "CROSS",
	models.TokenTypeNatural: "NATURAL",
	models.TokenTypeUsing:   "USING",

	// Set operations
	models.TokenTypeUnion:     "UNION",
	models.TokenTypeExcept:    "EXCEPT",
	models.TokenTypeIntersect: "INTERSECT",
	models.TokenTypeAll:       "ALL",

	// Logical operators
	models.TokenTypeAnd: "AND",
	models.TokenTypeOr:  "OR",
	models.TokenTypeNot: "NOT",

	// Comparison operators
	models.TokenTypeIs:      "IS",
	models.TokenTypeIn:      "IN",
	models.TokenTypeLike:    "LIKE",
	models.TokenTypeBetween: "BETWEEN",
	models.TokenTypeExists:  "EXISTS",
	models.TokenTypeAny:     "ANY",

	// NULL and boolean
	models.TokenTypeNull:  "NULL",
	models.TokenTypeTrue:  "TRUE",
	models.TokenTypeFalse: "FALSE",

	// Window function keywords
	models.TokenTypeOver:      "OVER",
	models.TokenTypePartition: "PARTITION",
	models.TokenTypeRows:      "ROWS",
	models.TokenTypeRange:     "RANGE",
	models.TokenTypeUnbounded: "UNBOUNDED",
	models.TokenTypePreceding: "PRECEDING",
	models.TokenTypeFollowing: "FOLLOWING",
	models.TokenTypeCurrent:   "CURRENT",
	models.TokenTypeRow:       "ROW",
	models.TokenTypeNulls:     "NULLS",
	models.TokenTypeFirst:     "FIRST",
	models.TokenTypeLast:      "LAST",
	models.TokenTypeFilter:    "FILTER",

	// Placeholder token - maps to "PLACEHOLDER" for tests that create tokens manually
	models.TokenTypePlaceholder: "PLACEHOLDER",

	// CTE keywords
	models.TokenTypeWith:      token.WITH,
	models.TokenTypeRecursive: "RECURSIVE",

	// CASE expression
	models.TokenTypeCase: "CASE",
	models.TokenTypeWhen: "WHEN",
	models.TokenTypeThen: "THEN",
	models.TokenTypeElse: "ELSE",
	models.TokenTypeEnd:  "END",

	// MERGE keywords
	models.TokenTypeMerge:   "MERGE",
	models.TokenTypeMatched: "MATCHED",
	models.TokenTypeSource:  "SOURCE",
	models.TokenTypeTarget:  "TARGET",

	// Grouping keywords
	models.TokenTypeRollup:       "ROLLUP",
	models.TokenTypeCube:         "CUBE",
	models.TokenTypeGrouping:     "GROUPING",
	models.TokenTypeGroupingSets: "GROUPING SETS",
	models.TokenTypeSets:         "SETS",

	// Data types
	models.TokenTypeInt:     "INT",
	models.TokenTypeInteger: "INTEGER",
	models.TokenTypeVarchar: "VARCHAR",
	models.TokenTypeText:    "TEXT",
	models.TokenTypeBoolean: "BOOLEAN",

	// FETCH clause keywords (SQL-99 F861, F862)
	models.TokenTypeFetch:   "FETCH",
	models.TokenTypeNext:    "NEXT",
	models.TokenTypeTies:    "TIES",
	models.TokenTypePercent: "PERCENT",
	models.TokenTypeOnly:    "ONLY",

	// Other keywords
	models.TokenTypeIf:      "IF",
	models.TokenTypeRefresh: "REFRESH",
	models.TokenTypeTo:      "TO",
}

// isType checks if the current token's ModelType matches the expected type.
// Falls back to string comparison if ModelType is not set (for backward compatibility).
func (p *Parser) isType(expected models.TokenType) bool {
	// Fast path: use int comparison if ModelType is set
	if p.currentToken.ModelType != modelTypeUnset {
		return p.currentToken.ModelType == expected
	}
	// Fallback: string comparison for tokens without ModelType
	if str, ok := modelTypeToString[expected]; ok {
		return p.currentToken.Type == str
	}
	return false
}

// isAnyType checks if the current token's ModelType matches any of the given types.
// More efficient than multiple isType calls when checking many alternatives.
func (p *Parser) isAnyType(types ...models.TokenType) bool {
	for _, t := range types {
		if p.isType(t) {
			return true
		}
	}
	return false
}

// matchType checks if the current token's ModelType matches and advances if true.
// Returns true if matched (and advanced), false otherwise.
func (p *Parser) matchType(expected models.TokenType) bool {
	if p.isType(expected) {
		p.advance()
		return true
	}
	return false
}

// isComparisonOperator checks if the current token is a comparison operator using O(1) switch.
// This is a hot path optimization for expression parsing.
func (p *Parser) isComparisonOperator() bool {
	// Fast path: use ModelType switch for O(1) lookup
	if p.currentToken.ModelType != modelTypeUnset {
		switch p.currentToken.ModelType {
		case models.TokenTypeEq, models.TokenTypeLt, models.TokenTypeGt,
			models.TokenTypeNeq, models.TokenTypeLtEq, models.TokenTypeGtEq:
			return true
		}
		return false
	}
	// Fallback: string comparison for tokens without ModelType (e.g., tests)
	switch p.currentToken.Type {
	case "=", "<", ">", "!=", "<=", ">=", "<>":
		return true
	}
	return false
}

// isQuantifier checks if the current token is ANY or ALL using O(1) switch.
// This is used for subquery quantifier operators like "= ANY (...)".
func (p *Parser) isQuantifier() bool {
	// Fast path: use ModelType switch for O(1) lookup
	if p.currentToken.ModelType != modelTypeUnset {
		switch p.currentToken.ModelType {
		case models.TokenTypeAny, models.TokenTypeAll:
			return true
		}
		return false
	}
	// Fallback: string comparison for tokens without ModelType
	upper := strings.ToUpper(p.currentToken.Literal)
	return upper == "ANY" || upper == "ALL"
}

// isBooleanLiteral checks if the current token is TRUE or FALSE using O(1) switch.
// This is used for parsing boolean literal values in expressions.
func (p *Parser) isBooleanLiteral() bool {
	// Fast path: use ModelType switch for O(1) lookup
	if p.currentToken.ModelType != modelTypeUnset {
		switch p.currentToken.ModelType {
		case models.TokenTypeTrue, models.TokenTypeFalse:
			return true
		}
		return false
	}
	// Fallback: string comparison for tokens without ModelType
	upper := strings.ToUpper(p.currentToken.Literal)
	return upper == "TRUE" || upper == "FALSE"
}

// =============================================================================

// expectedError returns an error for unexpected token
func (p *Parser) expectedError(expected string) error {
	return goerrors.ExpectedTokenError(expected, string(p.currentToken.Type), p.currentLocation(), "")
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
