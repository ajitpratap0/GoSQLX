// Package tokenizer provides high-performance SQL tokenization with zero-copy operations
// and comprehensive Unicode support for GoSQLX v1.6.0.
//
// # Overview
//
// The tokenizer package converts raw SQL text into a stream of tokens (lexical analysis)
// with precise position tracking for error reporting. It is designed for production use
// with enterprise-grade performance, thread safety, and memory efficiency.
//
// # Architecture
//
// The tokenizer uses a zero-copy design that operates directly on input byte slices without
// string allocations, achieving 8M+ tokens/sec throughput. It includes:
//
//   - Zero-copy byte slice operations for minimal memory allocations
//   - Object pooling (GetTokenizer/PutTokenizer) for instance reuse
//   - Buffer pooling for internal string operations
//   - Position tracking (line/column) for precise error reporting
//   - Unicode support for international SQL queries
//   - DoS protection with input size and token count limits
//
// # Performance Characteristics
//
// The tokenizer is production-validated with the following characteristics:
//
//   - Throughput: 8M+ tokens/sec sustained
//   - Memory: Zero-copy operations minimize allocations
//   - Thread Safety: Race-free with sync.Pool for object reuse
//   - Latency: Sub-microsecond per token on average
//   - Pool Hit Rate: 95%+ in production workloads
//
// # Thread Safety
//
// The tokenizer is thread-safe when using the pooling API:
//
//   - GetTokenizer() and PutTokenizer() are safe for concurrent use
//   - Individual Tokenizer instances are NOT safe for concurrent use
//   - Always use one Tokenizer instance per goroutine
//
// # Token Types
//
// The tokenizer produces tokens for all SQL elements:
//
//   - Keywords: SELECT, FROM, WHERE, JOIN, etc.
//   - Identifiers: table names, column names, aliases
//   - Literals: strings ('text'), numbers (123, 45.67, 1e10)
//   - Operators: =, <>, +, -, *, /, ||, etc.
//   - Punctuation: (, ), [, ], ,, ;, .
//   - PostgreSQL JSON operators: ->, ->>, #>, #>>, @>, <@, ?, ?|, ?&, #-
//   - Comments: -- line comments and /* block comments */
//
// # PostgreSQL Extensions (v1.6.0)
//
// The tokenizer supports PostgreSQL-specific operators:
//
//   - JSON/JSONB operators: -> ->> #> #>> @> <@ ? ?| ?& #-
//   - Array operators: && (overlap)
//   - Text search: @@ (full text search)
//   - Cast operator: :: (double colon)
//   - Parameters: @variable (SQL Server style)
//
// # Unicode Support
//
// Full Unicode support for international SQL processing:
//
//   - UTF-8 decoding with proper rune handling
//   - Unicode quotes: " " ' ' « » (normalized to ASCII)
//   - Unicode identifiers: letters, digits, combining marks
//   - Multi-byte character support in strings and identifiers
//   - Proper line/column tracking across Unicode boundaries
//
// # DoS Protection
//
// Built-in protection against denial-of-service attacks:
//
//   - MaxInputSize: 10MB input limit (configurable)
//   - MaxTokens: 1M token limit per query (configurable)
//   - Context support: TokenizeContext() for cancellation
//   - Panic recovery: Structured errors on unexpected panics
//
// # Object Pooling
//
// Use GetTokenizer/PutTokenizer for optimal performance:
//
//	tkz := tokenizer.GetTokenizer()
//	defer tokenizer.PutTokenizer(tkz)  // MANDATORY - returns to pool
//
//	tokens, err := tkz.Tokenize([]byte(sql))
//	if err != nil {
//	    return err
//	}
//	// Use tokens...
//
// Benefits:
//   - 60-80% reduction in allocations
//   - 95%+ pool hit rate in production
//   - Automatic state reset on return to pool
//
// # Basic Usage
//
// Simple tokenization without pooling:
//
//	tkz, err := tokenizer.New()
//	if err != nil {
//	    return err
//	}
//
//	sql := "SELECT id, name FROM users WHERE active = true"
//	tokens, err := tkz.Tokenize([]byte(sql))
//	if err != nil {
//	    return err
//	}
//
//	for _, tok := range tokens {
//	    fmt.Printf("Token: %s (type: %v) at line %d, col %d\n",
//	        tok.Token.Value, tok.Token.Type, tok.Start.Line, tok.Start.Column)
//	}
//
// # Advanced Usage with Context
//
// Tokenization with timeout and cancellation:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//
//	tkz := tokenizer.GetTokenizer()
//	defer tokenizer.PutTokenizer(tkz)
//
//	tokens, err := tkz.TokenizeContext(ctx, []byte(sql))
//	if err == context.DeadlineExceeded {
//	    log.Printf("Tokenization timed out")
//	    return err
//	}
//
// The context is checked every 100 tokens for responsive cancellation.
//
// # Error Handling
//
// The tokenizer returns structured errors with position information:
//
//	tokens, err := tkz.Tokenize([]byte(sql))
//	if err != nil {
//	    // Errors include line/column information
//	    // Common errors: UnterminatedStringError, UnexpectedCharError,
//	    // InvalidNumberError, InputTooLargeError, TokenLimitReachedError
//	    log.Printf("Tokenization error: %v", err)
//	    return err
//	}
//
// # Position Tracking
//
// Every token includes precise start/end positions:
//
//	for _, tokWithSpan := range tokens {
//	    fmt.Printf("Token '%s' at line %d, column %d-%d\n",
//	        tokWithSpan.Token.Value,
//	        tokWithSpan.Start.Line,
//	        tokWithSpan.Start.Column,
//	        tokWithSpan.End.Column)
//	}
//
// Position information is 1-based (first line is 1, first column is 1).
//
// # String Literals
//
// The tokenizer handles various string literal formats:
//
//   - Single quotes: 'text', 'can”t' (doubled quotes for escaping)
//   - Double quotes: "identifier" (SQL identifiers, not strings)
//   - Backticks: `identifier` (MySQL-style identifiers)
//   - Triple quotes: ”'multiline”' """multiline"""
//   - Unicode quotes: 'text' "text" «text» (normalized)
//   - Escape sequences: \n \r \t \\ \' \" \uXXXX
//
// # Number Formats
//
// Supported number formats:
//
//   - Integers: 123, 0, 999999
//   - Decimals: 3.14, 0.5, 999.999
//   - Scientific: 1e10, 2.5e-3, 1.23E+4
//
// # Comments
//
// Comments are automatically skipped during tokenization:
//
//   - Line comments: -- comment text (until newline)
//   - Block comments: /* comment text */ (can span multiple lines)
//
// # Identifiers
//
// Identifiers follow SQL standards with extensions:
//
//   - Unquoted: letters, digits, underscore (cannot start with digit)
//   - Quoted: "Any Text" (allows spaces, special chars, keywords)
//   - Backticked: `Any Text` (MySQL compatibility)
//   - Unicode: Full Unicode letter and digit support
//   - Compound keywords: GROUP BY, ORDER BY, LEFT JOIN, etc.
//
// # Keyword Recognition
//
// Keywords are recognized case-insensitively and mapped to specific token types:
//
//   - DML: SELECT, INSERT, UPDATE, DELETE, MERGE
//   - DDL: CREATE, ALTER, DROP, TRUNCATE
//   - Joins: JOIN, LEFT JOIN, INNER JOIN, CROSS JOIN, etc.
//   - CTEs: WITH, RECURSIVE, UNION, EXCEPT, INTERSECT
//   - Grouping: GROUP BY, ROLLUP, CUBE, GROUPING SETS
//   - Window: OVER, PARTITION BY, ROWS, RANGE, etc.
//   - PostgreSQL: DISTINCT ON, FILTER, RETURNING, LATERAL
//
// # Memory Management
//
// The tokenizer uses several strategies for memory efficiency:
//
//   - Tokenizer pooling: Reuse instances with sync.Pool
//   - Buffer pooling: Reuse byte buffers for string operations
//   - Zero-copy: Operate on input slices without allocation
//   - Slice reuse: Preserve capacity when resetting state
//   - Metrics tracking: Monitor pool efficiency and memory usage
//
// # Integration with Parser
//
// Typical integration pattern with the parser:
//
//	// Get tokenizer from pool
//	tkz := tokenizer.GetTokenizer()
//	defer tokenizer.PutTokenizer(tkz)
//
//	// Tokenize SQL
//	tokens, err := tkz.Tokenize([]byte(sql))
//	if err != nil {
//	    return nil, err
//	}
//
//	// Parse tokens to AST
//	ast, err := parser.Parse(tokens)
//	if err != nil {
//	    return nil, err
//	}
//
// # Production Deployment
//
// Best practices for production use:
//
//  1. Always use GetTokenizer/PutTokenizer for pooling efficiency
//  2. Use defer to ensure PutTokenizer is called even on errors
//  3. Monitor metrics for pool hit rates and performance
//  4. Configure DoS limits (MaxInputSize, MaxTokens) for your use case
//  5. Use TokenizeContext for long-running operations
//  6. Test with your actual SQL workload for realistic validation
//
// # Metrics and Monitoring
//
// The tokenizer integrates with pkg/metrics for observability:
//
//   - Tokenization duration and throughput
//   - Pool get/put operations and hit rates
//   - Error counts by category
//   - Input size and token count distributions
//
// Access metrics via the metrics package for production monitoring.
//
// # Validation Status
//
// Production-ready with comprehensive validation:
//
//   - Race detection: Zero race conditions (20,000+ concurrent operations tested)
//   - Performance: 8M+ tokens/sec sustained throughput
//   - Unicode: Full international support (8 languages validated)
//   - Reliability: 95%+ success rate on real-world SQL queries
//   - Memory: Zero leaks detected under extended load testing
//
// # Examples
//
// See the tokenizer_test.go file for comprehensive examples including:
//
//   - Basic tokenization
//   - Unicode handling
//   - PostgreSQL operators
//   - Error cases
//   - Performance benchmarks
//   - Pool usage patterns
package tokenizer
