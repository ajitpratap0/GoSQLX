// Package errors provides a structured error system for GoSQLX v1.6.0 with rich context,
// intelligent suggestions, and comprehensive error codes.
//
// This package delivers production-grade error handling for SQL parsing with:
//
//   - Structured Error Codes: E1xxx-E4xxx for programmatic error handling
//   - Precise Location Tracking: Line and column information for every error
//   - SQL Context Extraction: Visual error highlighting in source code
//   - Intelligent Hints: Auto-generated suggestions using Levenshtein distance
//   - Typo Detection: "Did you mean?" suggestions for common mistakes
//   - Error Recovery: Graceful degradation with actionable feedback
//
// # Error Code Taxonomy
//
// Errors are categorized into four main groups:
//
// E1xxx - Tokenizer Errors:
//
//   - E1001: ErrCodeUnexpectedChar - Invalid character in SQL input
//   - E1002: ErrCodeUnterminatedString - Missing closing quote
//   - E1003: ErrCodeInvalidNumber - Malformed numeric literal
//   - E1004: ErrCodeInvalidOperator - Invalid operator sequence
//   - E1005: ErrCodeInvalidIdentifier - Malformed identifier
//   - E1006: ErrCodeInputTooLarge - Input exceeds size limits (DoS protection)
//   - E1007: ErrCodeTokenLimitReached - Token count exceeds limit (DoS protection)
//   - E1008: ErrCodeTokenizerPanic - Recovered panic (bug detection)
//
// E2xxx - Parser Syntax Errors:
//
//   - E2001: ErrCodeUnexpectedToken - Unexpected token in grammar
//   - E2002: ErrCodeExpectedToken - Missing required token
//   - E2003: ErrCodeMissingClause - Required SQL clause missing
//   - E2004: ErrCodeInvalidSyntax - General syntax violation
//   - E2005: ErrCodeIncompleteStatement - Incomplete SQL statement
//   - E2006: ErrCodeInvalidExpression - Invalid expression syntax
//   - E2007: ErrCodeRecursionDepthLimit - Recursion too deep (DoS protection)
//   - E2008: ErrCodeUnsupportedDataType - Data type not supported
//   - E2009: ErrCodeUnsupportedConstraint - Constraint type not supported
//   - E2010: ErrCodeUnsupportedJoin - JOIN type not supported
//   - E2011: ErrCodeInvalidCTE - Invalid CTE (WITH clause) syntax
//   - E2012: ErrCodeInvalidSetOperation - Invalid UNION/EXCEPT/INTERSECT
//
// E3xxx - Semantic Errors:
//
//   - E3001: ErrCodeUndefinedTable - Table reference not found
//   - E3002: ErrCodeUndefinedColumn - Column reference not found
//   - E3003: ErrCodeTypeMismatch - Type incompatibility in expression
//   - E3004: ErrCodeAmbiguousColumn - Column appears in multiple tables
//
// E4xxx - Unsupported Features:
//
//   - E4001: ErrCodeUnsupportedFeature - Feature not yet implemented
//   - E4002: ErrCodeUnsupportedDialect - SQL dialect not supported
//
// # Core Components
//
// Error Structure:
//
//   - Error: Main error type with code, message, location, context, hint
//   - ErrorCode: Strongly-typed error code (string type)
//   - ErrorContext: SQL source context with highlighting
//
// Builder Functions:
//
//   - UnexpectedTokenError, ExpectedTokenError, MissingClauseError
//   - InvalidSyntaxError, UnsupportedFeatureError, IncompleteStatementError
//   - All E1xxx-E4xxx errors have dedicated builder functions
//
// Suggestion System:
//
//   - GenerateHint: Auto-generates context-aware suggestions
//   - SuggestKeyword: Levenshtein-based typo correction
//   - SuggestFromPattern: Regex-based pattern matching
//   - CommonHints: Pre-built hints for frequent errors
//
// Formatting Functions:
//
//   - FormatErrorWithContext: Full error with SQL context
//   - FormatErrorSummary: Brief error for logging
//   - FormatErrorList: Multiple errors in readable format
//   - FormatContextWindow: Larger context (N lines before/after)
//
// # Performance and Caching
//
// The error system is optimized for production use:
//
//   - Keyword suggestion cache (1000 entries) for fast typo detection
//   - Cache hit rate: 85%+ in LSP scenarios with repeated typos
//   - Lock-free atomic metrics for cache statistics
//   - Partial eviction strategy (keeps 50% on overflow)
//   - Thread-safe cache operations for concurrent use
//
// Cache Management:
//
//	// Check cache statistics
//	stats := errors.GetSuggestionCacheStats()
//	fmt.Printf("Hit rate: %.2f%%\n", stats.HitRate*100)
//
//	// Clear cache if needed
//	errors.ClearSuggestionCache()
//
//	// Reset metrics
//	errors.ResetSuggestionCacheStats()
//
// # Usage Examples
//
// Basic error creation with context:
//
//	err := errors.NewError(
//	    errors.ErrCodeUnexpectedToken,
//	    "unexpected token: COMMA",
//	    models.Location{Line: 5, Column: 20},
//	)
//	err = err.WithContext(sqlSource, 1)
//	err = err.WithHint("Expected FROM keyword after SELECT clause")
//
// Using builder functions:
//
//	err := errors.ExpectedTokenError(
//	    "FROM", "FORM",
//	    models.Location{Line: 1, Column: 15},
//	    sqlSource,
//	)
//	// Automatically includes context and "Did you mean 'FROM'?" hint
//
// Handling errors in application code:
//
//	if err != nil {
//	    if errors.IsCode(err, errors.ErrCodeUnterminatedString) {
//	        // Handle unterminated string specifically
//	    }
//
//	    code := errors.GetCode(err)
//	    switch code {
//	    case errors.ErrCodeExpectedToken:
//	        // Handle syntax errors
//	    case errors.ErrCodeUndefinedTable:
//	        // Handle semantic errors
//	    }
//
//	    // Extract location for IDE integration
//	    if loc, ok := errors.ExtractLocation(err); ok {
//	        fmt.Printf("Error at line %d, column %d\n", loc.Line, loc.Column)
//	    }
//	}
//
// Formatting errors for display:
//
//	// Full error with context
//	formatted := errors.FormatErrorWithContext(err, sqlSource)
//	fmt.Println(formatted)
//	// Output:
//	// Error E2002 at line 1, column 15: expected FROM, got FORM
//	//
//	//   1 | SELECT * FORM users WHERE id = 1
//	//                ^^^^
//	//   2 |
//	//
//	// Hint: Did you mean 'FROM' instead of 'FORM'?
//	// Help: https://docs.gosqlx.dev/errors/E2002
//
//	// Brief summary for logging
//	summary := errors.FormatErrorSummary(err)
//	// Output: [E2002] expected FROM, got FORM at line 1, column 15
//
// # Intelligent Suggestions
//
// The package provides sophisticated error suggestions:
//
// Typo Detection:
//
//	// Detects common SQL keyword typos
//	suggestion := errors.SuggestKeyword("SELCT")
//	// Returns: "SELECT"
//
//	suggestion = errors.SuggestKeyword("WAHER")
//	// Returns: "WHERE"
//
// Pattern-Based Suggestions:
//
//	// Matches error messages against known patterns
//	hint := errors.SuggestFromPattern("expected FROM but got FORM")
//	// Returns: "Check spelling of SQL keywords (e.g., FORM → FROM)"
//
// Context-Aware Suggestions:
//
//	// Window function errors
//	hint := errors.SuggestForWindowFunction("SELECT ROW_NUMBER()", "ROW_NUMBER")
//	// Returns: "Window function ROW_NUMBER requires OVER clause..."
//
//	// CTE errors
//	hint := errors.SuggestForCTE("WITH cte AS (SELECT * FROM users)")
//	// Returns: "WITH clause must be followed by SELECT, INSERT, UPDATE..."
//
//	// JOIN errors
//	hint := errors.SuggestForJoinError("INNER", "FROM users INNER JOIN orders")
//	// Returns: "INNER JOIN requires ON condition or USING clause..."
//
// # Common Mistake Detection
//
// The package includes 20+ common SQL mistake patterns:
//
//	// Get mistake explanation
//	if mistake, ok := errors.GetMistakeExplanation("window_function_without_over"); ok {
//	    fmt.Println(errors.FormatMistakeExample(mistake))
//	    // Output:
//	    // Common Mistake: window_function_without_over
//	    //   ❌ Wrong: SELECT name, ROW_NUMBER() FROM employees
//	    //   ✓ Right: SELECT name, ROW_NUMBER() OVER (ORDER BY salary DESC) FROM employees
//	    //   Explanation: Window functions require OVER clause with optional PARTITION BY and ORDER BY
//	}
//
// Common mistakes include:
//   - window_function_without_over, partition_by_without_over
//   - cte_without_select, recursive_cte_without_union
//   - window_frame_without_order, window_function_in_where
//   - missing_comma_in_list, missing_join_condition
//   - wrong_aggregate_syntax, missing_group_by, having_without_group_by
//
// # v1.6.0 Feature Support
//
// Error handling for PostgreSQL extensions:
//
//	// LATERAL JOIN errors
//	err := errors.InvalidSyntaxError(
//	    "LATERAL requires subquery or table function",
//	    location, sqlSource,
//	)
//
//	// JSON operator errors
//	err := errors.UnexpectedTokenError("->", "ARROW", location, sqlSource)
//
//	// RETURNING clause errors
//	err := errors.MissingClauseError("RETURNING", location, sqlSource)
//
// Error handling for advanced SQL features:
//
//	// Window function errors
//	err := errors.InvalidSyntaxError(
//	    "window frame requires ORDER BY clause",
//	    location, sqlSource,
//	)
//
//	// GROUPING SETS errors
//	err := errors.InvalidSyntaxError(
//	    "GROUPING SETS requires parenthesized expression list",
//	    location, sqlSource,
//	)
//
//	// MERGE statement errors
//	err := errors.InvalidSyntaxError(
//	    "MERGE requires MATCHED or NOT MATCHED clause",
//	    location, sqlSource,
//	)
//
// # Thread Safety and Concurrency
//
// All error operations are thread-safe:
//
//   - Error creation is safe for concurrent use
//   - Suggestion cache uses sync.RWMutex for concurrent reads
//   - Atomic operations for cache metrics
//   - No shared mutable state in error instances
//   - Safe for use in LSP server with multiple clients
//
// # IDE and LSP Integration
//
// The error system integrates seamlessly with IDE tooling:
//
//	// Extract location for diagnostic
//	loc, ok := errors.ExtractLocation(err)
//	diagnostic := lsp.Diagnostic{
//	    Range: lsp.Range{
//	        Start: lsp.Position{Line: loc.Line - 1, Character: loc.Column - 1},
//	    },
//	    Severity: lsp.DiagnosticSeverityError,
//	    Code:     string(errors.GetCode(err)),
//	    Message:  err.Error(),
//	}
//
// # Error Recovery and Debugging
//
// DoS Protection Errors:
//
//	// Input size limits
//	err := errors.InputTooLargeError(10*1024*1024, 5*1024*1024, location)
//	// Message: "input size 10485760 bytes exceeds limit of 5242880 bytes"
//	// Hint: "Reduce input size to under 5242880 bytes or adjust MaxInputSize configuration"
//
//	// Token count limits
//	err := errors.TokenLimitReachedError(15000, 10000, location, sqlSource)
//	// Message: "token count 15000 exceeds limit of 10000 tokens"
//	// Hint: "Simplify query or adjust MaxTokens limit (currently 10000)"
//
// Panic Recovery:
//
//	err := errors.TokenizerPanicError(panicValue, location)
//	// Message: "tokenizer panic recovered: <panic value>"
//	// Hint: "This indicates a serious tokenizer bug. Please report this issue..."
//
// # Design Principles
//
// The error package follows GoSQLX design philosophy:
//
//   - Actionable Messages: Every error includes what went wrong and how to fix it
//   - Precise Location: Exact line/column for every error
//   - Visual Context: SQL source highlighting for quick debugging
//   - Smart Suggestions: Levenshtein distance for typo detection
//   - Caching: Fast repeated suggestions for LSP scenarios
//   - Extensible: Easy to add new error codes and patterns
//
// # Testing and Quality
//
// The package maintains high quality standards:
//
//   - Comprehensive test coverage for all error codes
//   - Suggestion accuracy validation with real typos
//   - Cache performance benchmarks
//   - Thread safety validation (go test -race)
//   - Real-world error message validation
//
// For complete documentation and examples, see:
//   - docs/GETTING_STARTED.md - Quick start guide
//   - docs/USAGE_GUIDE.md - Comprehensive usage documentation
//   - docs/LSP_GUIDE.md - IDE integration with error diagnostics
package errors
