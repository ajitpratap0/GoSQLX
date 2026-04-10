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

package parser

import (
	"context"
	"fmt"
	"strings"
	"sync"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/metrics"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// ConversionResult holds a preprocessed token stream and optional source-position
// mappings. Callers typically obtain this via ParseFromModelTokensWithPositions and
// pass it to ParseWithPositions.
//
// After the token-type unification (#322) the Tokens field holds
// []models.TokenWithSpan directly; span information is no longer stripped.
type ConversionResult struct {
	Tokens []models.TokenWithSpan
	// Deprecated: PositionMapping is always nil. Position information is now embedded
	// directly in models.TokenWithSpan.Start and .End fields.
	PositionMapping []TokenPosition
}

// TokenPosition maps a parser token back to its original source position.
type TokenPosition struct {
	OriginalIndex int
	Start         models.Location
	End           models.Location
	SourceToken   *models.TokenWithSpan
}

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
	metrics.RecordNamedPoolGet("parser")
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
		metrics.RecordNamedPoolPut("parser")
	}
}

// Reset clears the parser state for reuse from the pool.
func (p *Parser) Reset() {
	p.tokens = p.tokens[:0]
	p.currentPos = 0
	p.currentToken = models.TokenWithSpan{}
	p.depth = 0
	p.ctx = nil
	p.strict = false
	p.dialect = ""
}

// currentLocation returns the source location of the current token.
// Span information is embedded directly in models.TokenWithSpan so no
// separate position-mapping slice is required.
func (p *Parser) currentLocation() models.Location {
	if p.currentPos < len(p.tokens) {
		return p.tokens[p.currentPos].Start
	}
	return models.Location{}
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

// Used for fast path checks: tokens with Type set use O(1) switch dispatch.

// Parser represents a SQL parser that converts a stream of tokens into an Abstract Syntax Tree (AST).
//
// The parser implements a recursive descent algorithm with one-token lookahead, supporting
// comprehensive SQL features across multiple database dialects.
//
// Architecture:
//   - Recursive Descent: Top-down parsing with predictive lookahead
//   - Statement Routing: O(1) Type-based dispatch for statement types
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
//
// ParserOption configures optional parser behavior.
type ParserOption func(*Parser)

// WithStrictMode enables strict parsing mode. In strict mode, the parser rejects
// empty statements (e.g., lone semicolons like ";;; SELECT 1 ;;;" will error
// instead of silently discarding empty statements between semicolons).
//
// By default, the parser operates in lenient mode where empty statements are
// silently ignored for backward compatibility.
func WithStrictMode() ParserOption {
	return func(p *Parser) {
		p.strict = true
	}
}

// WithDialect sets the SQL dialect for dialect-aware parsing.
// Supported values: "postgresql", "mysql", "sqlserver", "oracle", "sqlite", etc.
// If not set, defaults to "postgresql" for backward compatibility.
func WithDialect(dialect string) ParserOption {
	return func(p *Parser) {
		p.dialect = dialect
	}
}

// Dialect returns the SQL dialect configured for this parser.
// Returns "postgresql" if no dialect was explicitly set.
func (p *Parser) Dialect() string {
	if p.dialect == "" {
		return "postgresql"
	}
	return p.dialect
}

// Parser is a recursive-descent SQL parser that converts a token stream into an
// Abstract Syntax Tree (AST).
//
// Parser instances are not thread-safe. Each goroutine must use its own instance,
// obtained from the pool via GetParser and returned with PutParser:
//
//	p := parser.GetParser()
//	defer parser.PutParser(p)
//	tree, err := p.ParseFromModelTokens(tokens)
//
// For dialect-aware parsing or strict mode, use NewParser with options, or call
// ApplyOptions on a pooled instance before parsing.
type Parser struct {
	tokens       []models.TokenWithSpan
	currentPos   int
	currentToken models.TokenWithSpan
	depth        int             // Current recursion depth
	ctx          context.Context // Optional context for cancellation support
	strict       bool            // Strict mode rejects empty statements
	dialect      string          // SQL dialect for dialect-aware parsing (default: "postgresql")
}

// Deprecated: Parse is provided for backward compatibility only. Use ParseFromModelTokens
// with a []models.TokenWithSpan slice from the tokenizer instead. This shim wraps each
// token.Token into a zero-span models.TokenWithSpan and has no position information.
//
// Parse parses a slice of token.Token into an AST.
//
// This API is preserved for backward compatibility. Prefer ParseFromModelTokens
// which accepts []models.TokenWithSpan directly and preserves span information.
//
// Internally the tokens are wrapped into models.TokenWithSpan (with empty spans)
// and the preprocessing step is applied before parsing.
//
// Thread Safety: NOT thread-safe - use separate parser instances per goroutine.
func (p *Parser) Parse(tokens []token.Token) (*ast.AST, error) {
	// Wrap legacy token.Token into models.TokenWithSpan (spans are zero).
	wrapped := make([]models.TokenWithSpan, len(tokens))
	for i, t := range tokens {
		wrapped[i] = models.WrapToken(models.Token{Type: t.Type, Value: t.Literal})
	}
	// Preprocessing still normalises compound tokens and keyword types.
	preprocessed := preprocessTokens(wrapped)
	return p.parseTokens(preprocessed)
}

// parseTokens is the core parsing routine. It takes a preprocessed
// []models.TokenWithSpan (already normalised by preprocessTokens) and returns
// the parsed AST.
func (p *Parser) parseTokens(tokens []models.TokenWithSpan) (*ast.AST, error) {
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

	// Parse statements using Type (int) comparisons for speed
	for p.currentPos < len(tokens) && !p.isType(models.TokenTypeEOF) {
		// Skip semicolons between statements
		if p.isType(models.TokenTypeSemicolon) {
			if err := p.checkStrictEmptySemicolon(); err != nil {
				ast.ReleaseAST(result)
				return nil, err
			}
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
		if err := p.checkStrictEmpty(); err != nil {
			return nil, err
		}
		return nil, goerrors.IncompleteStatementError(models.Location{}, "")
	}

	return result, nil
}

// ParseFromModelTokens parses tokenizer output ([]models.TokenWithSpan) directly into an AST.
//
// This is the preferred entry point for parsing SQL. It accepts the output of the
// tokenizer directly without any conversion step. Span information is preserved
// throughout parsing and is available for error reporting.
//
// Issue #322: token_conversion.go has been removed; preprocessing is now a
// lightweight normalisation step that works entirely with models.TokenWithSpan.
func (p *Parser) ParseFromModelTokens(tokens []models.TokenWithSpan) (*ast.AST, error) {
	preprocessed := preprocessTokens(tokens)
	return p.parseTokens(preprocessed)
}

// ParseFromModelTokensWithPositions is identical to ParseFromModelTokens.
// Position information is embedded in every models.TokenWithSpan.
//
// Deprecated: Use ParseFromModelTokens directly.
func (p *Parser) ParseFromModelTokensWithPositions(tokens []models.TokenWithSpan) (*ast.AST, error) {
	return p.ParseFromModelTokens(tokens)
}

// ParseContextFromModelTokens parses tokenizer output with context support for cancellation.
func (p *Parser) ParseContextFromModelTokens(ctx context.Context, tokens []models.TokenWithSpan) (*ast.AST, error) {
	preprocessed := preprocessTokens(tokens)
	return p.parseContextTokens(ctx, preprocessed)
}

// ParseWithPositions parses tokens with position tracking for enhanced error reporting.
//
// ParseWithPositions parses a ConversionResult into an AST.
// Since models.TokenWithSpan already embeds span/position information,
// this is now a thin wrapper around parseTokens - no separate conversion step needed.
//
// Thread Safety: NOT thread-safe - use separate parser instances per goroutine.
func (p *Parser) ParseWithPositions(result *ConversionResult) (*ast.AST, error) {
	return p.parseTokens(result.Tokens)
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
// ParseContext parses a slice of token.Token with context support (backward compat shim).
// For new code prefer ParseContextFromModelTokens.
func (p *Parser) ParseContext(ctx context.Context, tokens []token.Token) (*ast.AST, error) {
	// Wrap legacy token.Token into models.TokenWithSpan.
	wrapped := make([]models.TokenWithSpan, len(tokens))
	for i, t := range tokens {
		wrapped[i] = models.WrapToken(models.Token{Type: t.Type, Value: t.Literal})
	}
	preprocessed := preprocessTokens(wrapped)
	return p.parseContextTokens(ctx, preprocessed)
}

// parseContextTokens is the core context-aware parsing routine. It takes
// a preprocessed []models.TokenWithSpan and respects ctx for cancellation.
func (p *Parser) parseContextTokens(ctx context.Context, tokens []models.TokenWithSpan) (*ast.AST, error) {
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

	// Parse statements using Type (int) comparisons for speed
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
	p.currentToken = models.TokenWithSpan{}
	p.depth = 0
	p.ctx = nil
}

// parseStatement parses a single SQL statement using O(1) Type-based dispatch.
//
// This is the statement routing function that examines the current token and dispatches
// to the appropriate specialized parser based on the statement type. It uses O(1) switch
// dispatch on Type (integer enum) which compiles to a jump table for optimal performance.
//
// Performance Optimization:
//   - Fast Path: O(1) Type switch (~0.24ns per comparison)
//   - Fallback: String-based matching for tokens without Type (~3.4ns)
//   - Jump Table: Compiler generates jump table for switch on integers
//   - 14x Faster: Type vs string comparison on hot paths
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

	// O(1) switch dispatch on Token.Type (compiles to jump table).
	// All tokens are normalized at parse entry so Type is always set.
	switch p.currentToken.Token.Type {
	case models.TokenTypeWith:
		return p.parseWithStatement()
	case models.TokenTypeSelect:
		stmtPos := p.currentLocation()
		p.advance()
		stmt, err := p.parseSelectWithSetOperations()
		if err != nil {
			return nil, err
		}
		if ss, ok := stmt.(*ast.SelectStatement); ok {
			if ss.Pos.IsZero() {
				ss.Pos = stmtPos
			}
		}
		// ClickHouse trailing SETTINGS k=v [, k=v]... on SELECT. Parse-only;
		// the settings are consumed but not modeled on the AST.
		if p.dialect == string(keywords.DialectClickHouse) && p.isTokenMatch("SETTINGS") {
			p.advance() // SETTINGS
			for {
				t := p.currentToken.Token.Type
				if t == models.TokenTypeEOF || t == models.TokenTypeSemicolon ||
					t == models.TokenTypeRParen {
					break
				}
				p.advance()
			}
		}
		return stmt, nil
	case models.TokenTypeInsert:
		stmtPos := p.currentLocation()
		p.advance()
		stmt, err := p.parseInsertStatement()
		if err != nil {
			return nil, err
		}
		if is, ok := stmt.(*ast.InsertStatement); ok {
			if is.Pos.IsZero() {
				is.Pos = stmtPos
			}
		}
		return stmt, nil
	case models.TokenTypeUpdate:
		stmtPos := p.currentLocation()
		p.advance()
		stmt, err := p.parseUpdateStatement()
		if err != nil {
			return nil, err
		}
		if us, ok := stmt.(*ast.UpdateStatement); ok {
			if us.Pos.IsZero() {
				us.Pos = stmtPos
			}
		}
		return stmt, nil
	case models.TokenTypeDelete:
		stmtPos := p.currentLocation()
		p.advance()
		stmt, err := p.parseDeleteStatement()
		if err != nil {
			return nil, err
		}
		if ds, ok := stmt.(*ast.DeleteStatement); ok {
			if ds.Pos.IsZero() {
				ds.Pos = stmtPos
			}
		}
		return stmt, nil
	case models.TokenTypeAlter:
		stmtPos := p.currentLocation()
		p.advance()
		// MariaDB: ALTER SEQUENCE [IF EXISTS] name [options...]
		if p.isMariaDB() && p.isTokenMatch("SEQUENCE") {
			p.advance() // Consume SEQUENCE
			stmt, err := p.parseAlterSequenceStatement()
			if err != nil {
				return nil, err
			}
			if stmt.Pos.IsZero() {
				stmt.Pos = stmtPos
			}
			return stmt, nil
		}
		return p.parseAlterTableStmt()
	case models.TokenTypeMerge:
		p.advance()
		return p.parseMergeStatement()
	case models.TokenTypeCreate:
		p.advance()
		return p.parseCreateStatement()
	case models.TokenTypeDrop:
		stmtPos := p.currentLocation()
		p.advance()
		// MariaDB: DROP SEQUENCE [IF EXISTS | IF NOT EXISTS] name
		if p.isMariaDB() && p.isTokenMatch("SEQUENCE") {
			p.advance() // Consume SEQUENCE
			stmt, err := p.parseDropSequenceStatement()
			if err != nil {
				return nil, err
			}
			if stmt.Pos.IsZero() {
				stmt.Pos = stmtPos
			}
			return stmt, nil
		}
		return p.parseDropStatement()
	case models.TokenTypeRefresh:
		p.advance()
		return p.parseRefreshStatement()
	case models.TokenTypeTruncate:
		p.advance()
		return p.parseTruncateStatement()
	case models.TokenTypeShow:
		p.advance()
		return p.parseShowStatement()
	case models.TokenTypeDescribe, models.TokenTypeExplain, models.TokenTypeDesc:
		// DESC is the ORDER-BY sort-direction token but also a synonym for
		// DESCRIBE at statement position (Oracle, Snowflake, MySQL).
		p.advance()
		return p.parseDescribeStatement()
	case models.TokenTypeReplace:
		p.advance()
		return p.parseReplaceStatement()
	case models.TokenTypeKeyword:
		// Handle keyword-type tokens that have dedicated parsers.
		// PRAGMA is a SQLite statement keyword tokenized as TokenTypeKeyword
		// when the SQLite dialect keyword set is active.
		if strings.EqualFold(p.currentToken.Token.Value, "PRAGMA") {
			p.advance()
			return p.parsePragmaStatement()
		}
		// Snowflake stage operations may arrive as keyword tokens depending on
		// the active keyword table (LIST, COPY, etc. can be registered).
		if p.dialect == string(keywords.DialectSnowflake) {
			upper := strings.ToUpper(p.currentToken.Token.Value)
			switch upper {
			case "COPY", "PUT", "GET", "LIST", "REMOVE", "LS":
				return p.parseSnowflakeStageStatement(upper)
			}
		}
	case models.TokenTypeIdentifier:
		// PRAGMA may be tokenized as IDENTIFIER when no dialect-specific keyword
		// set is active (e.g. when using the default PostgreSQL tokenizer dialect).
		// Support it as a statement keyword regardless of tokenizer dialect.
		if strings.EqualFold(p.currentToken.Token.Value, "PRAGMA") {
			p.advance()
			return p.parsePragmaStatement()
		}
		// Snowflake session-context switches: USE [WAREHOUSE|DATABASE|SCHEMA|ROLE] <name>.
		// USE is not tokenized as a keyword; dispatch by value in the Snowflake dialect.
		if p.dialect == string(keywords.DialectSnowflake) &&
			strings.EqualFold(p.currentToken.Token.Value, "USE") {
			return p.parseSnowflakeUseStatement()
		}
		// Snowflake stage operations: COPY INTO, PUT, GET, LIST, REMOVE.
		// All tokenize as identifiers; parse-only stubs that consume the
		// rest of the statement body.
		if p.dialect == string(keywords.DialectSnowflake) {
			upper := strings.ToUpper(p.currentToken.Token.Value)
			switch upper {
			case "COPY", "PUT", "GET", "LIST", "REMOVE", "LS":
				return p.parseSnowflakeStageStatement(upper)
			}
		}
	}
	return nil, p.expectedError("statement")
}

// parseSnowflakeUseStatement parses:
//
//	USE [WAREHOUSE | DATABASE | SCHEMA | ROLE] <name>
//
// The object-kind keyword is optional (plain "USE <name>" switches the current
// database). We parse-only; the statement is represented as a DescribeStatement
// placeholder until a dedicated UseStatement node is introduced.
func (p *Parser) parseSnowflakeUseStatement() (ast.Statement, error) {
	p.advance() // Consume USE
	// Optional object kind.
	switch strings.ToUpper(p.currentToken.Token.Value) {
	case "WAREHOUSE", "DATABASE", "SCHEMA", "ROLE":
		p.advance()
	}
	name, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.expectedError("name after USE")
	}
	stmt := ast.GetDescribeStatement()
	stmt.TableName = "USE " + name
	return stmt, nil
}

// parseSnowflakeStageStatement parses Snowflake stage operations as stubs:
//
//	COPY INTO <target> FROM <source> [options]
//	PUT file://<path> @<stage>
//	GET @<stage> file://<path>
//	LIST @<stage>   (or LS)
//	REMOVE @<stage>/<path>
//
// The statement is consumed token-by-token (tracking balanced parens) until
// ';' or EOF and returned as a DescribeStatement placeholder tagged with the
// operation kind. No AST modeling yet; follow-up work.
func (p *Parser) parseSnowflakeStageStatement(kind string) (ast.Statement, error) {
	p.advance() // Consume leading kind token

	// COPY INTO: consume the INTO keyword if present.
	if kind == "COPY" && p.isType(models.TokenTypeInto) {
		p.advance()
	}

	// Consume the rest of the statement body.
	depth := 0
	for {
		t := p.currentToken.Token.Type
		if t == models.TokenTypeEOF {
			break
		}
		if t == models.TokenTypeSemicolon && depth == 0 {
			break
		}
		if t == models.TokenTypeLParen {
			depth++
		} else if t == models.TokenTypeRParen {
			depth--
		}
		p.advance()
	}
	stub := ast.GetDescribeStatement()
	stub.TableName = kind
	return stub, nil
}

// NewParser creates a new parser with optional configuration.
func NewParser(opts ...ParserOption) *Parser {
	p := &Parser{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// ApplyOptions applies parser options to configure behavior.
func (p *Parser) ApplyOptions(opts ...ParserOption) {
	for _, opt := range opts {
		opt(p)
	}
}

// checkStrictEmpty returns an error if strict mode is enabled and no statements were parsed.
// This consolidates the repeated strict empty-statement check pattern.
func (p *Parser) checkStrictEmpty() error {
	if p.strict {
		return goerrors.InvalidSyntaxError(
			"empty statement not allowed in strict mode",
			p.currentLocation(),
			"provide at least one SQL statement",
		)
	}
	return nil
}

// checkStrictEmptySemicolon returns an error if strict mode is enabled and a bare semicolon is encountered.
func (p *Parser) checkStrictEmptySemicolon() error {
	if p.strict {
		return goerrors.InvalidSyntaxError(
			"empty statement not allowed in strict mode",
			p.currentLocation(),
			"remove extra semicolons or disable strict mode",
		)
	}
	return nil
}

// advance moves to the next token
func (p *Parser) advance() {
	p.currentPos++
	if p.currentPos < len(p.tokens) {
		p.currentToken = p.tokens[p.currentPos]
	} else {
		p.currentToken = models.TokenWithSpan{} // EOF sentinel
	}
}

// peekToken returns the next token without advancing the parser position.
// Returns an empty TokenWithSpan if at the end of input.
func (p *Parser) peekToken() models.TokenWithSpan {
	nextPos := p.currentPos + 1
	if nextPos < len(p.tokens) {
		return p.tokens[nextPos]
	}
	return models.TokenWithSpan{}
}

// =============================================================================
// Type-based Helper Methods (Fast Int Comparisons)
// =============================================================================
// These methods use int-based Type comparisons which are significantly
// faster than string comparisons (~0.24ns vs ~3.4ns). Use these for hot paths.
// They include fallback to string-based Type comparison for backward compatibility
// with tests that create tokens directly without setting Type.

// isType checks if the current token's Type matches the expected type.
// Pure integer comparison - no string fallback.
func (p *Parser) isType(expected models.TokenType) bool {
	return p.currentToken.Token.Type == expected
}

// matchType checks if the current token's Type matches the expected type and advances if so.
func (p *Parser) matchType(expected models.TokenType) bool {
	if p.currentToken.Token.Type == expected {
		p.advance()
		return true
	}
	return false
}

// isAnyType checks if the current token's Type matches any of the given types.
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

// isStringLiteral checks if the current token is a string literal.
// Handles all string token subtypes (single-quoted, dollar-quoted, etc.)
func (p *Parser) isStringLiteral() bool {
	switch p.currentToken.Token.Type {
	case models.TokenTypeString, models.TokenTypeSingleQuotedString, models.TokenTypeDollarQuotedString:
		return true
	}
	return false
}

// isComparisonOperator checks if the current token is a comparison operator using O(1) switch.
func (p *Parser) isComparisonOperator() bool {
	switch p.currentToken.Token.Type {
	case models.TokenTypeEq, models.TokenTypeLt, models.TokenTypeGt,
		models.TokenTypeNeq, models.TokenTypeLtEq, models.TokenTypeGtEq,
		models.TokenTypeTilde, models.TokenTypeTildeAsterisk,
		models.TokenTypeExclamationMarkTilde, models.TokenTypeExclamationMarkTildeAsterisk:
		return true
	}
	return false
}

// isQuantifier checks if the current token is ANY or ALL using O(1) switch.
func (p *Parser) isQuantifier() bool {
	switch p.currentToken.Token.Type {
	case models.TokenTypeAny, models.TokenTypeAll:
		return true
	}
	return false
}

// isBooleanLiteral checks if the current token is TRUE or FALSE using O(1) switch.
func (p *Parser) isBooleanLiteral() bool {
	switch p.currentToken.Token.Type {
	case models.TokenTypeTrue, models.TokenTypeFalse:
		return true
	}
	return false
}

// =============================================================================

// expectedError returns an error for unexpected token
func (p *Parser) expectedError(expected string) error {
	return goerrors.ExpectedTokenError(expected, p.currentToken.Token.Type.String(), p.currentLocation(), "")
}

// parseIdent parses an identifier
func (p *Parser) parseIdent() *ast.Identifier {
	// Accept both regular identifiers and double-quoted identifiers
	if !p.isType(models.TokenTypeIdentifier) && !p.isType(models.TokenTypeDoubleQuotedString) {
		return nil
	}
	pos := p.currentLocation()
	ident := &ast.Identifier{Name: p.currentToken.Token.Value, Pos: pos}
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

// parseBareWordAsString parses any word-like token (identifier or keyword) and
// returns its value as a string.  This is used in contexts where arbitrary
// user-defined names may collide with SQL keywords (e.g. DCPROPERTIES keys).
// It advances the parser position and returns "" if no word-like token is found.
func (p *Parser) parseBareWordAsString() string {
	typ := p.currentToken.Token.Type
	// Reject punctuation / operator / structural tokens.
	switch typ {
	case models.TokenTypeEOF, models.TokenTypeEq, models.TokenTypeComma,
		models.TokenTypeLParen, models.TokenTypeRParen,
		models.TokenTypeLBracket, models.TokenTypeRBracket,
		models.TokenTypeLBrace, models.TokenTypeRBrace,
		models.TokenTypeSemicolon, models.TokenTypePeriod,
		models.TokenTypeUnknown:
		return ""
	}
	if p.currentToken.Token.Value == "" {
		return ""
	}
	val := p.currentToken.Token.Value
	p.advance()
	return val
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
	if !p.isStringLiteral() {
		return ""
	}
	value := p.currentToken.Token.Value
	p.advance()
	return value
}

// parseQualifiedName parses a potentially schema-qualified name (e.g., schema.table or db.schema.table).
// Returns the full dotted name as a string. Supports up to 3-part names.
func (p *Parser) parseQualifiedName() (string, error) {
	if !p.isIdentifier() && !p.isNonReservedKeyword() {
		return "", p.expectedError("identifier")
	}
	name := p.currentToken.Token.Value
	p.advance()

	// Check for schema.table or db.schema.table
	for p.isType(models.TokenTypePeriod) {
		p.advance() // Consume .
		if !p.isIdentifier() && !p.isNonReservedKeyword() {
			return "", p.expectedError("identifier after .")
		}
		name = name + "." + p.currentToken.Token.Value
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
	// These keywords can be used as table/column names in most SQL dialects.
	// Use Type where possible, with value fallback for tokens that have
	// the generic TokenTypeKeyword.
	switch p.currentToken.Token.Type {
	case models.TokenTypeTarget, models.TokenTypeSource, models.TokenTypeMatched:
		return true
	case models.TokenTypeTable, models.TokenTypeIndex, models.TokenTypeView,
		models.TokenTypeKey, models.TokenTypeColumn, models.TokenTypeDatabase,
		models.TokenTypePartition, models.TokenTypeRows, models.TokenTypeDefault:
		// DDL keywords that are commonly used as quoted identifiers in MySQL (backtick)
		// and SQL Server (bracket) dialects, and as plain column names in ClickHouse
		// system tables (system.parts.partition, system.replicas.table,
		// system.tables.rows, etc).
		return true
	case models.TokenTypeKeyword:
		// Token may have generic Type; check value for specific keywords
		switch strings.ToUpper(p.currentToken.Token.Value) {
		case "TARGET", "SOURCE", "MATCHED", "VALUE", "NAME", "TYPE", "STATUS",
			"TABLES", "DATABASES":
			return true
		}
	}
	return false
}

// canBeAlias checks if current token can be used as an alias
// Aliases can be IDENT, double-quoted identifiers, or certain non-reserved keywords
func (p *Parser) canBeAlias() bool {
	return p.isIdentifier() || p.isNonReservedKeyword()
}

// parseAlterTableStmt is a simplified version for the parser implementation
// It delegates to the more comprehensive parseAlterStatement in alter.go
func (p *Parser) parseAlterTableStmt() (ast.Statement, error) {
	// We've already consumed the ALTER token in matchType
	// This is just a placeholder that delegates to the main implementation
	return p.parseAlterStatement()
}

// isJoinKeyword checks if current token is a JOIN-related keyword
func (p *Parser) isJoinKeyword() bool {
	if p.isAnyType(
		models.TokenTypeJoin, models.TokenTypeInner, models.TokenTypeLeft,
		models.TokenTypeRight, models.TokenTypeFull, models.TokenTypeCross,
		models.TokenTypeNatural,
	) {
		return true
	}
	// SQL Server: OUTER APPLY starts with OUTER
	if p.dialect == string(keywords.DialectSQLServer) && p.isType(models.TokenTypeOuter) {
		return true
	}
	// ClickHouse: GLOBAL JOIN — GLOBAL is TokenTypeKeyword, not a dedicated join token
	if p.dialect == string(keywords.DialectClickHouse) && p.isTokenMatch("GLOBAL") {
		return true
	}
	// ClickHouse: ANY / ALL as join strictness prefix (ANY LEFT JOIN, ALL INNER JOIN)
	if p.dialect == string(keywords.DialectClickHouse) &&
		(p.isType(models.TokenTypeAny) || p.isType(models.TokenTypeAll)) {
		return true
	}
	return false
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
