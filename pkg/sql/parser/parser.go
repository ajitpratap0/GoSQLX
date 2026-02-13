// Package parser provides a high-performance recursive descent SQL parser that converts
// tokenized SQL into a comprehensive Abstract Syntax Tree (AST).
//
// The parser supports enterprise-grade SQL parsing with 1.38M+ ops/sec throughput,
// comprehensive multi-dialect support (PostgreSQL, MySQL, SQL Server, Oracle, SQLite),
// and production-ready features including DoS protection, context cancellation, and
// object pooling for optimal memory efficiency.
//
// # Quick Start
//
//	// Get parser from pool
//	parser := parser.GetParser()
//	defer parser.PutParser(parser)
//
//	// Parse tokens to AST
//	result := parser.ConvertTokensForParser(tokens)
//	astObj, err := parser.ParseWithPositions(result)
//	defer ast.ReleaseAST(astObj)
//
// # v1.6.0 PostgreSQL Extensions
//
//   - LATERAL JOIN: Correlated subqueries in FROM clause
//   - JSON/JSONB Operators: All 10 operators (->/->>/#>/#>>/@>/<@/?/?|/?&/#-)
//   - DISTINCT ON: PostgreSQL-specific row deduplication
//   - FILTER Clause: Conditional aggregation (SQL:2003 T612)
//   - RETURNING Clause: Return modified rows from DML statements
//   - Aggregate ORDER BY: ORDER BY inside STRING_AGG, ARRAY_AGG
//
// # v1.5.0 Features (SQL-99 Compliance)
//
//   - GROUPING SETS, ROLLUP, CUBE: Advanced grouping (SQL-99 T431)
//   - MERGE Statements: SQL:2003 MERGE with MATCHED/NOT MATCHED
//   - Materialized Views: CREATE/REFRESH/DROP with CONCURRENTLY
//   - FETCH Clause: SQL-99 F861/F862 with PERCENT, ONLY, WITH TIES
//   - TRUNCATE: Enhanced with RESTART/CONTINUE IDENTITY
//
// # v1.3.0 Window Functions (Phase 2.5)
//
//   - Window Functions: OVER clause with PARTITION BY, ORDER BY
//   - Ranking: ROW_NUMBER(), RANK(), DENSE_RANK(), NTILE()
//   - Analytic: LAG(), LEAD(), FIRST_VALUE(), LAST_VALUE()
//   - Frame Clauses: ROWS/RANGE with PRECEDING/FOLLOWING/CURRENT ROW
//
// # v1.2.0 CTEs and Set Operations (Phase 2)
//
//   - Common Table Expressions: WITH clause with recursive support
//   - Set Operations: UNION, UNION ALL, EXCEPT, INTERSECT
//   - Multiple CTEs: Comma-separated CTE definitions in single query
//   - CTE Column Lists: Optional column specifications
//
// For comprehensive documentation, see doc.go in this package.
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
//
// Pool statistics (v1.6.0 production workloads):
//   - Hit Rate: 95%+ in concurrent environments
//   - Memory Savings: 60-80% reduction vs non-pooled allocation
//   - Allocation Rate: <100 bytes/op for pooled parsing
//
// Usage pattern (MANDATORY):
//
//	parser := parser.GetParser()
//	defer parser.PutParser(parser)  // MUST return to pool
//	ast, err := parser.Parse(tokens)
var parserPool = sync.Pool{
	New: func() interface{} {
		return &Parser{}
	},
}

// GetParser returns a Parser instance from the pool.
// The caller MUST call PutParser when done to return it to the pool.
//
// This function is thread-safe and designed for concurrent use. Each goroutine
// should get its own parser instance from the pool.
//
// Performance: O(1) amortized, <50ns typical latency
//
// Usage:
//
//	parser := parser.GetParser()
//	defer parser.PutParser(parser)  // MANDATORY - prevents resource leaks
//	ast, err := parser.Parse(tokens)
//
// Thread Safety: Safe for concurrent calls - each goroutine gets its own instance.
func GetParser() *Parser {
	return parserPool.Get().(*Parser)
}

// PutParser returns a Parser instance to the pool after resetting it.
// This MUST be called after parsing is complete to enable reuse and prevent memory leaks.
//
// The parser is automatically reset before being returned to the pool, clearing all
// internal state (tokens, position, depth, context, position mappings).
//
// Performance: O(1), <30ns typical latency
//
// Usage:
//
//	parser := parser.GetParser()
//	defer parser.PutParser(parser)  // Use defer to ensure cleanup on error paths
//
// Thread Safety: Safe for concurrent calls - operates on independent parser instances.
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
//
// DoS Protection: This limit protects against denial-of-service attacks via malicious SQL
// with deeply nested expressions like: (((((...((value))...)))))
//
// Typical Values:
//   - MaxRecursionDepth = 100: Protects against stack exhaustion
//   - Legitimate queries rarely exceed depth of 10-15
//   - Malicious queries can reach thousands without this limit
//
// Error: Exceeding this depth returns goerrors.RecursionDepthLimitError
const MaxRecursionDepth = 100

// modelTypeUnset is the zero value for ModelType, indicating the type was not set.
// Used for fast path checks: tokens with ModelType set use O(1) switch dispatch.
const modelTypeUnset models.TokenType = 0

// Parser represents a SQL parser that converts a stream of tokens into an Abstract Syntax Tree (AST).
//
// The parser implements a recursive descent algorithm with one-token lookahead, supporting
// comprehensive SQL features across multiple database dialects.
//
// Architecture:
//   - Recursive Descent: Top-down parsing with predictive lookahead
//   - Statement Routing: O(1) ModelType-based dispatch for statement types
//   - Expression Precedence: Handles operator precedence via recursive descent levels
//   - Error Recovery: Provides detailed syntax error messages with position information
//
// Internal State:
//   - tokens: Token stream from the tokenizer (converted to parser tokens)
//   - currentPos: Current position in token stream
//   - currentToken: Current token being examined
//   - depth: Recursion depth counter (DoS protection via MaxRecursionDepth)
//   - ctx: Optional context for cancellation support
//   - positions: Source position mapping for enhanced error reporting
//
// Thread Safety:
//   - NOT thread-safe - each goroutine must use its own parser instance
//   - Use GetParser()/PutParser() to obtain thread-local instances from pool
//   - Parser instances maintain no shared state between calls
//
// Memory Management:
//   - Use GetParser() to obtain from pool
//   - Use defer PutParser() to return to pool (MANDATORY)
//   - Reset() is called automatically by PutParser()
//
// Performance Characteristics:
//   - Throughput: 1.38M+ operations/second sustained
//   - Latency: 347ns average for complex queries
//   - Token Processing: 8M tokens/second
//   - Allocation: <100 bytes/op with object pooling
type Parser struct {
	tokens       []token.Token
	currentPos   int
	currentToken token.Token
	depth        int             // Current recursion depth
	ctx          context.Context // Optional context for cancellation support
	positions    []TokenPosition // Position mapping for error reporting
}

// Parse parses a token stream into an Abstract Syntax Tree (AST).
//
// This is the primary parsing method that converts tokens from the tokenizer into a structured
// AST representing the SQL statements. It uses fast O(1) ModelType-based dispatch for optimal
// performance on hot paths.
//
// Parameters:
//   - tokens: Slice of parser tokens (use ConvertTokensForParser to convert from tokenizer output)
//
// Returns:
//   - *ast.AST: Parsed Abstract Syntax Tree containing one or more statements
//   - error: Syntax error with basic error information (no position tracking)
//
// Performance:
//   - Average: 347ns for complex queries with window functions
//   - Throughput: 1.38M+ operations/second sustained
//   - Memory: <100 bytes/op with object pooling
//
// Error Handling:
//   - Returns syntax errors without position information
//   - Use ParseWithPositions() for enhanced error reporting with line/column
//   - Cleans up AST on error (no memory leaks)
//
// Usage:
//
//	parser := parser.GetParser()
//	defer parser.PutParser(parser)
//
//	// Convert tokenizer output to parser tokens
//	tokens := parser.ConvertTokensForParser(tokenizerOutput)
//
//	// Parse tokens
//	ast, err := parser.Parse(tokens.Tokens)
//	if err != nil {
//	    log.Printf("Parse error: %v", err)
//	    return
//	}
//	defer ast.ReleaseAST(ast)
//
// For position-aware error reporting, use ParseWithPositions() instead.
//
// Thread Safety: NOT thread-safe - use separate parser instances per goroutine.
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

// ParseFromModelTokens parses tokenizer output ([]models.TokenWithSpan) directly into an AST.
//
// This is the preferred entry point for parsing SQL. It accepts the output of the
// tokenizer directly, without requiring the caller to manually convert tokens via
// ConvertTokensForParser. Internally, it still performs conversion for now, but this
// will be optimized in a future version to bypass the legacy token.Type system entirely.
//
// Usage:
//
//	p := parser.GetParser()
//	defer parser.PutParser(p)
//	astObj, err := p.ParseFromModelTokens(tokenizerOutput)
//	if err != nil {
//	    // handle error
//	}
//	defer ast.ReleaseAST(astObj)
//
// See issue #215 for the token type unification roadmap.
func (p *Parser) ParseFromModelTokens(tokens []models.TokenWithSpan) (*ast.AST, error) {
	converted, err := ConvertTokensForParser(tokens)
	if err != nil {
		return nil, fmt.Errorf("token conversion failed: %w", err)
	}
	return p.Parse(converted)
}

// ParseWithPositions parses tokens with position tracking for enhanced error reporting.
//
// This method accepts a ConversionResult from ConvertTokensForParser(), which includes
// both the converted tokens and their original source positions from the tokenizer.
// Syntax errors will include accurate line and column information for debugging.
//
// Parameters:
//   - result: ConversionResult from ConvertTokensForParser containing tokens and position mapping
//
// Returns:
//   - *ast.AST: Parsed Abstract Syntax Tree containing one or more statements
//   - error: Syntax error with line/column position information
//
// Performance:
//   - Slightly slower than Parse() due to position tracking overhead (~5%)
//   - Average: ~365ns for complex queries (vs 347ns for Parse)
//   - Recommended for production use where error reporting is important
//
// Error Reporting Enhancement:
//   - Includes line and column numbers in error messages
//   - Example: "expected 'FROM' but got 'WHERE' at line 1, column 15"
//   - Position information extracted from tokenizer output
//
// Usage:
//
//	parser := parser.GetParser()
//	defer parser.PutParser(parser)
//
//	// Convert tokenizer output with position tracking
//	result := parser.ConvertTokensForParser(tokenizerOutput)
//
//	// Parse with position information
//	ast, err := parser.ParseWithPositions(result)
//	if err != nil {
//	    // Error includes line/column information
//	    log.Printf("Parse error at %v: %v", err.Location, err)
//	    return
//	}
//	defer ast.ReleaseAST(ast)
//
// This is the recommended parsing method for production use where detailed error
// reporting is important for debugging and user feedback.
//
// Thread Safety: NOT thread-safe - use separate parser instances per goroutine.
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

// ParseContext parses tokens into an AST with context support for cancellation and timeouts.
//
// This method enables graceful cancellation of long-running parsing operations by checking
// the context at strategic points (statement boundaries and expression starts). The parser
// checks context.Err() approximately every 10-20 operations, balancing responsiveness with overhead.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - tokens: Slice of parser tokens to parse
//
// Returns:
//   - *ast.AST: Parsed Abstract Syntax Tree if successful
//   - error: Parsing error, context.Canceled, or context.DeadlineExceeded
//
// Context Checking Strategy:
//   - Checked before each statement parsing
//   - Checked at the start of parseExpression (recursive)
//   - Overhead: ~2% vs non-context parsing
//   - Cancellation latency: <100μs typical
//
// Use Cases:
//   - Long-running parsing operations that need to be cancellable
//   - Implementing timeouts for parsing (prevent hanging on malicious input)
//   - Graceful shutdown scenarios in server applications
//   - User-initiated cancellation in interactive tools
//
// Error Handling:
//   - Returns context.Canceled when ctx.Done() is closed
//   - Returns context.DeadlineExceeded when timeout expires
//   - Cleans up partial AST on cancellation (no memory leaks)
//
// Usage with Timeout:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//
//	parser := parser.GetParser()
//	defer parser.PutParser(parser)
//
//	ast, err := parser.ParseContext(ctx, tokens)
//	if err != nil {
//	    if errors.Is(err, context.DeadlineExceeded) {
//	        log.Println("Parsing timeout exceeded")
//	    } else if errors.Is(err, context.Canceled) {
//	        log.Println("Parsing was cancelled")
//	    } else {
//	        log.Printf("Parse error: %v", err)
//	    }
//	    return
//	}
//	defer ast.ReleaseAST(ast)
//
// Usage with Cancellation:
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//
//	// Cancel from another goroutine based on user action
//	go func() {
//	    <-userCancelSignal
//	    cancel()
//	}()
//
//	ast, err := parser.ParseContext(ctx, tokens)
//	// Check for context.Canceled error
//
// Performance Impact:
//   - Adds ~2% overhead vs Parse() due to context checking
//   - Average: ~354ns for complex queries (vs 347ns for Parse)
//   - Negligible impact on modern CPUs with branch prediction
//
// Thread Safety: NOT thread-safe - use separate parser instances per goroutine.
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

// parseStatement parses a single SQL statement using O(1) ModelType-based dispatch.
//
// This is the statement routing function that examines the current token and dispatches
// to the appropriate specialized parser based on the statement type. It uses O(1) switch
// dispatch on ModelType (integer enum) which compiles to a jump table for optimal performance.
//
// Performance Optimization:
//   - Fast Path: O(1) ModelType switch (~0.24ns per comparison)
//   - Fallback: String-based matching for tokens without ModelType (~3.4ns)
//   - Jump Table: Compiler generates jump table for switch on integers
//   - 14x Faster: ModelType vs string comparison on hot paths
//
// Supported Statement Types:
//
// DML (Data Manipulation):
//   - SELECT: Query with joins, subqueries, window functions, CTEs
//   - INSERT: Insert with VALUES, column list, RETURNING
//   - UPDATE: Update with SET, WHERE, RETURNING
//   - DELETE: Delete with WHERE, RETURNING
//   - MERGE: SQL:2003 MERGE with MATCHED/NOT MATCHED
//
// DDL (Data Definition):
//   - CREATE: TABLE, VIEW, MATERIALIZED VIEW, INDEX
//   - ALTER: ALTER TABLE for column and constraint modifications
//   - DROP: Drop objects with CASCADE/RESTRICT
//   - TRUNCATE: TRUNCATE TABLE with identity options
//   - REFRESH: REFRESH MATERIALIZED VIEW
//
// Advanced:
//   - WITH: Common Table Expressions (CTEs) with recursive support
//   - Set Operations: UNION, EXCEPT, INTERSECT (via parseSelectWithSetOperations)
//
// Returns:
//   - ast.Statement: Parsed statement node (specific type depends on SQL)
//   - error: Syntax error if statement is invalid or unsupported
//
// Error Handling:
//   - Returns expectedError("statement") if token is not a statement keyword
//   - Returns specific parse errors from statement-specific parsers
//   - Checks context for cancellation if ctx is set
//
// Context Checking:
//   - Checks p.ctx.Err() before parsing to enable cancellation
//   - Fast path: nil check + atomic read
//   - Overhead: <5ns when context is set
//
// Thread Safety: NOT thread-safe - operates on parser instance state.
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
//
//lint:ignore SA1019 intentional use during #215 migration
func (p *Parser) matchToken(expected token.Type) bool { //nolint:staticcheck // intentional use of deprecated type for Phase 1 bridge
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

// Deprecated: modelTypeToString is part of the legacy dual token type bridge.
// It will be removed once all tokens use models.TokenType exclusively (see #215).
//
// modelTypeToString maps ModelType to expected string Type for fallback comparison.
// This comprehensive map enables isType() to work with tokens that don't have ModelType set
// (e.g., tokens created in tests without using the tokenizer).
// NOTE: Only TokenTypes that exist in models package are included here.
//
//lint:ignore SA1019 intentional use during #215 migration
var modelTypeToString = map[models.TokenType]token.Type{ //nolint:staticcheck // intentional use of deprecated type for Phase 1 bridge
	// Special tokens
	models.TokenTypeEOF:        token.EOF,
	models.TokenTypeSemicolon:  token.SEMICOLON,
	models.TokenTypeIdentifier: "IDENT",

	// Punctuation and operators
	models.TokenTypeComma:        token.COMMA,
	models.TokenTypeLParen:       "(",
	models.TokenTypeRParen:       ")",
	models.TokenTypeEq:           "=",
	models.TokenTypeLt:           "<",
	models.TokenTypeGt:           ">",
	models.TokenTypeNeq:          "!=",
	models.TokenTypeLtEq:         "<=",
	models.TokenTypeGtEq:         ">=",
	models.TokenTypeDot:          ".",
	models.TokenTypeAsterisk:     "*",
	models.TokenTypePlus:         "PLUS",
	models.TokenTypeMinus:        "MINUS",
	models.TokenTypeMul:          "MUL",
	models.TokenTypeDiv:          "DIV",
	models.TokenTypeMod:          "MOD",
	models.TokenTypeStringConcat: "STRING_CONCAT",

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
	models.TokenTypeLateral: "LATERAL",

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

	// CAST expression
	models.TokenTypeCast: "CAST",

	// INTERVAL expression
	models.TokenTypeInterval: "INTERVAL",

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

// isIdentifier checks if the current token is an identifier.
// Includes both regular identifiers and double-quoted identifiers.
// In SQL, double-quoted strings are treated as identifiers (e.g., "column_name").
func (p *Parser) isIdentifier() bool {
	return p.isType(models.TokenTypeIdentifier) || p.isType(models.TokenTypeDoubleQuotedString)
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
			models.TokenTypeNeq, models.TokenTypeLtEq, models.TokenTypeGtEq,
			models.TokenTypeTilde, models.TokenTypeTildeAsterisk,
			models.TokenTypeExclamationMarkTilde, models.TokenTypeExclamationMarkTildeAsterisk:
			return true
		}
		return false
	}
	// Fallback: string comparison for tokens without ModelType (e.g., tests)
	switch p.currentToken.Type {
	case "=", "<", ">", "!=", "<=", ">=", "<>", "~", "~*", "!~", "!~*":
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
	// Accept both regular identifiers and double-quoted identifiers
	if p.currentToken.Type != token.IDENT && p.currentToken.Type != "IDENT" &&
		!p.isType(models.TokenTypeDoubleQuotedString) {
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

// parseQualifiedName parses a potentially schema-qualified name (e.g., schema.table or db.schema.table).
// Returns the full dotted name as a string. Supports up to 3-part names.
func (p *Parser) parseQualifiedName() (string, error) {
	if !p.isIdentifier() && !p.isNonReservedKeyword() {
		return "", p.expectedError("identifier")
	}
	name := p.currentToken.Literal
	p.advance()

	// Check for schema.table or db.schema.table
	for p.isType(models.TokenTypePeriod) {
		p.advance() // Consume .
		if !p.isIdentifier() && !p.isNonReservedKeyword() {
			return "", p.expectedError("identifier after .")
		}
		name = name + "." + p.currentToken.Literal
		p.advance()
	}

	return name, nil
}

// Accepts IDENT or non-reserved keywords that can be used as table names
func (p *Parser) parseTableReference() (*ast.TableReference, error) {
	name, err := p.parseQualifiedName()
	if err != nil {
		return nil, err
	}
	return &ast.TableReference{Name: name}, nil
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
// Aliases can be IDENT, double-quoted identifiers, or certain non-reserved keywords
func (p *Parser) canBeAlias() bool {
	return p.isIdentifier() || p.isNonReservedKeyword()
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
	case "JOIN", "INNER", "LEFT", "RIGHT", "FULL", "CROSS", "NATURAL":
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
