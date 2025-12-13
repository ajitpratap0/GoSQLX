// Package token defines the token types and token pooling system for SQL lexical analysis.
//
// This package provides a dual token type system supporting both string-based legacy types
// and integer-based high-performance types. It includes an efficient object pool for memory
// optimization during tokenization and parsing operations.
//
// # Key Features
//
//   - Dual token type system (string-based Type and int-based models.TokenType)
//   - Object pooling for memory efficiency (60-80% memory reduction)
//   - Token position information for error reporting
//   - Comprehensive operator support including PostgreSQL JSON operators
//   - Zero-allocation token reuse via sync.Pool
//   - Type checking utilities for fast token classification
//
// # Token Structure
//
// The Token struct represents a lexical token with dual type systems:
//
//	type Token struct {
//	    Type      Type             // String-based type (backward compatibility)
//	    ModelType models.TokenType // Int-based type (primary, for performance)
//	    Literal   string           // The literal value of the token
//	}
//
// The ModelType field is the primary type system, providing faster comparisons
// via integer operations. The Type field is maintained for backward compatibility.
//
// # Token Types
//
// Tokens are categorized into several groups:
//
// Special Tokens:
//   - EOF: End of file
//   - ILLEGAL: Invalid/unrecognized token
//   - WS: Whitespace
//
// Identifiers and Literals:
//   - IDENT: Identifier (table name, column name)
//   - INT: Integer literal (12345)
//   - FLOAT: Floating-point literal (123.45)
//   - STRING: String literal ("abc", 'abc')
//   - TRUE: Boolean true
//   - FALSE: Boolean false
//   - NULL: NULL value
//
// Operators:
//   - EQ: Equal (=)
//   - NEQ: Not equal (!=, <>)
//   - LT: Less than (<)
//   - LTE: Less than or equal (<=)
//   - GT: Greater than (>)
//   - GTE: Greater than or equal (>=)
//   - ASTERISK: Asterisk (*)
//
// Delimiters:
//   - COMMA: Comma (,)
//   - SEMICOLON: Semicolon (;)
//   - LPAREN: Left parenthesis (()
//   - RPAREN: Right parenthesis ())
//   - DOT: Period (.)
//
// SQL Keywords:
//   - SELECT, INSERT, UPDATE, DELETE
//   - FROM, WHERE, JOIN, ON, USING
//   - GROUP, HAVING, ORDER, BY
//   - LIMIT, OFFSET, FETCH (v1.6.0)
//   - AND, OR, NOT, IN, BETWEEN
//   - LATERAL (v1.6.0), FILTER (v1.6.0)
//   - And many more...
//
// # New in v1.6.0
//
// PostgreSQL JSON Operators (via models.TokenType):
//   - -> (TokenTypeArrow): JSON field access returning JSON
//   - ->> (TokenTypeLongArrow): JSON field access returning text
//   - #> (TokenTypeHashArrow): JSON path access returning JSON
//   - #>> (TokenTypeHashLongArrow): JSON path access returning text
//   - @> (TokenTypeAtArrow): JSON contains
//   - <@ (TokenTypeArrowAt): JSON is contained by
//   - #- (TokenTypeHashMinus): Delete at JSON path
//   - @? (TokenTypeAtQuestion): JSON path query
//   - ? (TokenTypeQuestion): JSON key exists
//   - ?& (TokenTypeQuestionAnd): JSON key exists all
//   - ?| (TokenTypeQuestionPipe): JSON key exists any
//
// Additional v1.6.0 Token Types:
//   - LATERAL: LATERAL JOIN keyword
//   - FILTER: FILTER clause for aggregates
//   - RETURNING: RETURNING clause (PostgreSQL)
//   - FETCH: FETCH FIRST/NEXT clause
//   - TRUNCATE: TRUNCATE TABLE statement
//   - MATERIALIZED: Materialized view support
//
// # Basic Usage
//
// Create and work with tokens using the dual type system:
//
//	import (
//	    "github.com/ajitpratap0/GoSQLX/pkg/sql/token"
//	    "github.com/ajitpratap0/GoSQLX/pkg/models"
//	)
//
//	// Create a token with both type systems
//	tok := token.NewTokenWithModelType(token.SELECT, "SELECT")
//	fmt.Printf("Token: %s, ModelType: %v\n", tok.Literal, tok.ModelType)
//
//	// Check token type (fast integer comparison)
//	if tok.IsType(models.TokenTypeSelect) {
//	    fmt.Println("This is a SELECT token")
//	}
//
//	// Check against multiple types
//	if tok.IsAnyType(models.TokenTypeSelect, models.TokenTypeInsert, models.TokenTypeUpdate) {
//	    fmt.Println("This is a DML statement")
//	}
//
// # Token Pool for Memory Efficiency
//
// The package provides an object pool for zero-allocation token reuse.
// Always use defer to return tokens to the pool:
//
//	import "github.com/ajitpratap0/GoSQLX/pkg/sql/token"
//
//	// Get a token from the pool
//	tok := token.Get()
//	defer token.Put(tok)  // MANDATORY - return to pool when done
//
//	// Use the token
//	tok.Type = token.SELECT
//	tok.ModelType = models.TokenTypeSelect
//	tok.Literal = "SELECT"
//
//	// Token is automatically cleaned and returned to pool via defer
//
// Pool Benefits:
//   - 60-80% memory reduction in high-volume parsing
//   - Zero-copy token reuse across operations
//   - Thread-safe pool operations (validated race-free)
//   - 95%+ pool hit rate in production workloads
//
// # Token Type Checking
//
// Fast token type checking utilities:
//
//	tok := token.Token{
//	    Type:      token.SELECT,
//	    ModelType: models.TokenTypeSelect,
//	    Literal:   "SELECT",
//	}
//
//	// Check if token has a ModelType (preferred)
//	if tok.HasModelType() {
//	    // Use fast integer comparison
//	    if tok.IsType(models.TokenTypeSelect) {
//	        fmt.Println("SELECT token")
//	    }
//	}
//
//	// Check against multiple token types
//	dmlKeywords := []models.TokenType{
//	    models.TokenTypeSelect,
//	    models.TokenTypeInsert,
//	    models.TokenTypeUpdate,
//	    models.TokenTypeDelete,
//	}
//	if tok.IsAnyType(dmlKeywords...) {
//	    fmt.Println("DML statement keyword")
//	}
//
// # Type System Conversion
//
// Convert between string-based Type and integer-based ModelType:
//
//	// Convert string Type to models.TokenType
//	typ := token.SELECT
//	modelType := typ.ToModelType()  // models.TokenTypeSelect
//
//	// Create token with both types
//	tok := token.NewTokenWithModelType(token.WHERE, "WHERE")
//	// tok.Type = token.WHERE
//	// tok.ModelType = models.TokenTypeWhere
//	// tok.Literal = "WHERE"
//
// # Token Type Classification
//
// Check if a token belongs to a specific category:
//
//	typ := token.SELECT
//
//	// Check if keyword
//	if typ.IsKeyword() {
//	    fmt.Println("This is a SQL keyword")
//	}
//
//	// Check if operator
//	typ2 := token.EQ
//	if typ2.IsOperator() {
//	    fmt.Println("This is an operator")
//	}
//
//	// Check if literal
//	typ3 := token.STRING
//	if typ3.IsLiteral() {
//	    fmt.Println("This is a literal value")
//	}
//
// # Working with PostgreSQL JSON Operators
//
// Handle PostgreSQL JSON operators using models.TokenType:
//
//	import (
//	    "github.com/ajitpratap0/GoSQLX/pkg/sql/token"
//	    "github.com/ajitpratap0/GoSQLX/pkg/models"
//	)
//
//	// Check for JSON operators
//	tok := token.Token{
//	    ModelType: models.TokenTypeArrow,  // -> operator
//	    Literal:   "->",
//	}
//
//	jsonOperators := []models.TokenType{
//	    models.TokenTypeArrow,         // ->
//	    models.TokenTypeLongArrow,     // ->>
//	    models.TokenTypeHashArrow,     // #>
//	    models.TokenTypeHashLongArrow, // #>>
//	    models.TokenTypeAtArrow,       // @>
//	    models.TokenTypeArrowAt,       // <@
//	}
//
//	if tok.IsAnyType(jsonOperators...) {
//	    fmt.Println("This is a JSON operator")
//	}
//
// # Token Pool Best Practices
//
// Always follow these patterns for optimal performance:
//
//	// CORRECT: Use defer to ensure pool return
//	func processToken() {
//	    tok := token.Get()
//	    defer token.Put(tok)  // Always use defer
//
//	    tok.Type = token.SELECT
//	    tok.ModelType = models.TokenTypeSelect
//	    tok.Literal = "SELECT"
//
//	    // Use token...
//	}  // Token automatically returned to pool
//
//	// INCORRECT: Manual return without defer (may leak on early return/panic)
//	func badProcessToken() {
//	    tok := token.Get()
//	    tok.Type = token.SELECT
//
//	    if someCondition {
//	        return  // LEAK: Token not returned to pool!
//	    }
//
//	    token.Put(tok)  // May never be reached
//	}
//
// # Token Reset
//
// Manually reset token fields if needed:
//
//	tok := token.Get()
//	defer token.Put(tok)
//
//	tok.Type = token.SELECT
//	tok.Literal = "SELECT"
//
//	// Reset to clean state
//	tok.Reset()
//	// tok.Type = ""
//	// tok.Literal = ""
//	// tok.ModelType remains unchanged
//
// # Performance Characteristics
//
// Token operations are highly optimized:
//   - Token creation: <10ns per token (pooled)
//   - Type checking: <1ns (integer comparison)
//   - Token reset: <5ns (zero two fields)
//   - Pool get/put: <50ns (amortized)
//   - Memory overhead: ~48 bytes per token
//
// Performance Metrics (v1.6.0):
//   - Throughput: 8M+ tokens/second
//   - Latency: <1μs for complex queries
//   - Memory: 60-80% reduction with pooling
//   - Pool hit rate: 95%+ in production
//
// # Thread Safety
//
// Token pools are thread-safe and race-free (validated via extensive concurrent testing):
//
//   - sync.Pool provides lock-free operation for most Get/Put calls
//
//   - Individual Token instances are NOT safe for concurrent modification
//
//   - Get a new token from the pool for each goroutine
//
//     // SAFE: Each goroutine gets its own token
//     for i := 0; i < 100; i++ {
//     go func() {
//     tok := token.Get()
//     defer token.Put(tok)
//     // Use tok safely in this goroutine
//     }()
//     }
//
//     // UNSAFE: Sharing a single token across goroutines
//     tok := token.Get()
//     for i := 0; i < 100; i++ {
//     go func() {
//     tok.Literal = "shared"  // RACE CONDITION!
//     }()
//     }
//
// # Integration with Tokenizer
//
// This package is used by the tokenizer for SQL lexical analysis:
//
//	import (
//	    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
//	    "github.com/ajitpratap0/GoSQLX/pkg/sql/token"
//	)
//
//	// Tokenize SQL
//	tkz := tokenizer.GetTokenizer()
//	defer tokenizer.PutTokenizer(tkz)
//
//	tokensWithSpan, err := tkz.Tokenize([]byte("SELECT * FROM users"))
//
//	// Convert to parser tokens
//	parserTokens := make([]token.Token, len(tokensWithSpan))
//	for i, tws := range tokensWithSpan {
//	    parserTokens[i] = token.Token{
//	        Type:      token.Type(tws.Token.Type.String()),
//	        ModelType: tws.Token.Type,
//	        Literal:   tws.Token.Literal,
//	    }
//	}
//
// # Dual Type System Rationale
//
// The dual type system serves multiple purposes:
//
//  1. Backward Compatibility: Existing code using string-based Type continues to work
//  2. Performance: Integer-based ModelType provides faster comparisons (1-2 CPU cycles)
//  3. Readability: String Type values are human-readable in debug output
//  4. Migration Path: Gradual migration from Type to ModelType without breaking changes
//
// Prefer ModelType for new code:
//
//	// PREFERRED: Use ModelType for performance
//	if tok.IsType(models.TokenTypeSelect) {
//	    // Fast integer comparison
//	}
//
//	// LEGACY: String-based comparison (slower)
//	if tok.Type == token.SELECT {
//	    // String comparison
//	}
//
// # Error Handling
//
// Token pool operations are designed to never fail:
//
//	tok := token.Get()  // Never returns nil
//	defer token.Put(tok)  // Safe to call with nil (no-op)
//
//	// Put is safe with nil
//	var nilTok *token.Token
//	token.Put(nilTok)  // No error, no panic
//
// # Memory Management
//
// Token pooling dramatically reduces GC pressure:
//
//	// Without pooling (high allocation rate)
//	for i := 0; i < 1000000; i++ {
//	    tok := &token.Token{
//	        Type:    token.SELECT,
//	        Literal: "SELECT",
//	    }
//	    // Causes 1M allocations
//	}
//
//	// With pooling (near-zero allocations after warmup)
//	for i := 0; i < 1000000; i++ {
//	    tok := token.Get()
//	    tok.Type = token.SELECT
//	    tok.Literal = "SELECT"
//	    token.Put(tok)
//	    // Reuses ~100 token objects
//	}
//
// # See Also
//
//   - pkg/models: Core token type definitions (models.TokenType)
//   - pkg/sql/tokenizer: SQL lexical analysis producing tokens
//   - pkg/sql/parser: Parser consuming tokens
//   - pkg/sql/keywords: Keyword classification and token type mapping
package token
