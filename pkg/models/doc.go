// Package models provides core data structures for SQL tokenization and parsing in GoSQLX v1.6.0.
//
// This package contains the fundamental types used throughout the GoSQLX library for representing
// SQL tokens, their locations in source code, and tokenization errors. All types are designed with
// zero-copy operations and object pooling in mind for optimal performance.
//
// # Core Components
//
// The package is organized into several key areas:
//
//   - Token Types: Token, TokenType, Word, Keyword for representing lexical units
//   - Location Tracking: Location, Span for precise error reporting with line/column information
//   - Token Wrappers: TokenWithSpan for tokens with position information
//   - Error Types: TokenizerError for tokenization failures
//   - Helper Functions: Factory functions for creating tokens efficiently
//
// # Performance Characteristics
//
// GoSQLX v1.6.0 achieves exceptional performance metrics:
//
//   - Tokenization: 1.38M+ operations/second sustained, 1.5M peak throughput
//   - Memory Efficiency: 60-80% reduction via object pooling
//   - Zero-Copy: Direct byte slice operations without string allocation
//   - Thread-Safe: All operations are race-free and goroutine-safe
//   - Test Coverage: 100% code coverage with comprehensive test suite
//
// # Token Type System
//
// The TokenType system supports v1.6.0 features including:
//
//   - PostgreSQL Extensions: JSON/JSONB operators (->/->>/#>/#>>/@>/<@/?/?|/?&/#-), LATERAL, RETURNING
//   - SQL-99 Standards: Window functions, CTEs, GROUPING SETS, ROLLUP, CUBE
//   - SQL:2003 Features: MERGE statements, FILTER clause, FETCH FIRST/NEXT
//   - Multi-Dialect: PostgreSQL, MySQL, SQL Server, Oracle, SQLite keywords
//
// Token types are organized into ranges for efficient categorization:
//
//   - Basic tokens (10-29): WORD, NUMBER, IDENTIFIER, PLACEHOLDER
//   - String literals (30-49): Single/double quoted, dollar quoted, hex strings
//   - Operators (50-149): Arithmetic, comparison, JSON/JSONB operators
//   - Keywords (200-499): SQL keywords organized by category
//
// # Location Tracking
//
// Location and Span provide precise position information for error reporting:
//
//   - 1-based indexing for line and column numbers (SQL standard)
//   - Line numbers start at 1, column numbers start at 1
//   - Spans represent ranges from start to end locations
//   - Used extensively in error messages and IDE integration
//
// # Usage Examples
//
// Creating tokens with location information:
//
//	loc := models.Location{Line: 1, Column: 5}
//	token := models.NewTokenWithSpan(
//	    models.TokenTypeSelect,
//	    "SELECT",
//	    loc,
//	    models.Location{Line: 1, Column: 11},
//	)
//
// Working with token types:
//
//	if tokenType.IsKeyword() {
//	    // Handle SQL keyword
//	}
//	if tokenType.IsOperator() {
//	    // Handle operator
//	}
//	if tokenType.IsDMLKeyword() {
//	    // Handle SELECT, INSERT, UPDATE, DELETE
//	}
//
// Checking for specific token categories:
//
//	// Check for window function keywords
//	if tokenType.IsWindowKeyword() {
//	    // Handle OVER, PARTITION BY, ROWS, RANGE, etc.
//	}
//
//	// Check for PostgreSQL JSON operators
//	switch tokenType {
//	case models.TokenTypeArrow:         // ->
//	case models.TokenTypeLongArrow:     // ->>
//	case models.TokenTypeHashArrow:     // #>
//	case models.TokenTypeHashLongArrow: // #>>
//	    // Handle JSON field access
//	}
//
// Creating error locations:
//
//	err := models.TokenizerError{
//	    Message:  "unexpected character '@'",
//	    Location: models.Location{Line: 2, Column: 15},
//	}
//
// # PostgreSQL v1.6.0 Features
//
// New token types for PostgreSQL extensions:
//
//   - TokenTypeLateral: LATERAL JOIN support for correlated subqueries
//   - TokenTypeReturning: RETURNING clause for INSERT/UPDATE/DELETE
//   - TokenTypeArrow, TokenTypeLongArrow: -> and ->> JSON operators
//   - TokenTypeHashArrow, TokenTypeHashLongArrow: #> and #>> path operators
//   - TokenTypeAtArrow, TokenTypeArrowAt: @> contains and <@ is-contained-by
//   - TokenTypeHashMinus: #- delete at path operator
//   - TokenTypeAtQuestion: @? JSON path query
//   - TokenTypeQuestionAnd, TokenTypeQuestionPipe: ?& and ?| key existence
//
// # SQL Standards Support
//
// SQL-99 (Core + Extensions):
//
//   - Window Functions: OVER, PARTITION BY, ROWS, RANGE, frame clauses
//   - CTEs: WITH, RECURSIVE for common table expressions
//   - Set Operations: UNION, INTERSECT, EXCEPT with ALL modifier
//   - GROUPING SETS: ROLLUP, CUBE for multi-dimensional aggregation
//   - Analytic Functions: ROW_NUMBER, RANK, DENSE_RANK, LAG, LEAD
//
// SQL:2003 Features:
//
//   - MERGE Statements: MERGE INTO with MATCHED/NOT MATCHED
//   - FILTER Clause: Conditional aggregation in window functions
//   - FETCH FIRST/NEXT: Standard limit syntax with TIES support
//   - Materialized Views: CREATE MATERIALIZED VIEW, REFRESH
//
// # Thread Safety
//
// All types in this package are immutable value types and safe for concurrent use:
//
//   - Token, TokenType, Location, Span are all value types
//   - No shared mutable state
//   - Safe to pass between goroutines
//   - Used extensively with object pooling (sync.Pool)
//
// # Integration with Parser
//
// The models package integrates seamlessly with the parser:
//
//	// Tokenize SQL
//	tkz := tokenizer.GetTokenizer()
//	defer tokenizer.PutTokenizer(tkz)
//	tokens, err := tkz.Tokenize([]byte(sql))
//	if err != nil {
//	    if tokErr, ok := err.(models.TokenizerError); ok {
//	        // Access error location: tokErr.Location.Line, tokErr.Location.Column
//	    }
//	}
//
//	// Parse tokens
//	ast, parseErr := parser.Parse(tokens)
//	if parseErr != nil {
//	    // Parser errors include location information
//	}
//
// # Design Philosophy
//
// The models package follows GoSQLX design principles:
//
//   - Zero Dependencies: Only depends on Go standard library
//   - Value Types: Immutable structs for safety and performance
//   - Explicit Ranges: Token type ranges for O(1) categorization
//   - 1-Based Indexing: Matches SQL and editor conventions
//   - Clear Semantics: Descriptive names and comprehensive documentation
//
// # Testing and Quality
//
// The package maintains exceptional quality standards:
//
//   - 100% Test Coverage: All code paths tested
//   - Race Detection: No race conditions (go test -race)
//   - Benchmarks: Performance validation for all operations
//   - Property Testing: Extensive edge case validation
//   - Real-World SQL: Validated against 115+ production queries
//
// For complete examples and advanced usage, see:
//   - docs/GETTING_STARTED.md - Quick start guide
//   - docs/USAGE_GUIDE.md - Comprehensive usage documentation
//   - examples/ directory - Production-ready examples
package models
