// Package parser provides a high-performance, production-ready recursive descent SQL parser
// that converts tokenized SQL into a comprehensive Abstract Syntax Tree (AST).
//
// # Overview
//
// The parser implements a predictive recursive descent parser with one-token lookahead,
// supporting comprehensive SQL features across multiple database dialects including PostgreSQL,
// MySQL, SQL Server, Oracle, and SQLite. It achieves enterprise-grade performance with
// 1.38M+ operations/second sustained throughput and 347ns average latency for complex queries.
//
// # Architecture
//
// The parser follows a modular architecture with specialized parsing functions for each SQL construct:
//
//   - parser.go: Main parser entry point, statement routing, and core token management
//   - select.go: SELECT statement parsing including DISTINCT ON, FETCH, and table operations
//   - dml.go: Data Manipulation Language (INSERT, UPDATE, DELETE, MERGE statements)
//   - ddl.go: Data Definition Language (CREATE, ALTER, DROP, TRUNCATE statements)
//   - expressions.go: Expression parsing with operator precedence and JSON operators
//   - window.go: Window function parsing (OVER clause, PARTITION BY, ORDER BY, frame specs)
//   - cte.go: Common Table Expression parsing with recursive CTE support
//   - grouping.go: GROUPING SETS, ROLLUP, CUBE parsing (SQL-99 T431)
//   - alter.go: ALTER TABLE statement parsing
//
// # Parsing Flow
//
// The typical parsing flow involves three stages:
//
//  1. Token Conversion: Convert tokenizer output to parser tokens
//     tokens := tokenizer.Tokenize(sqlBytes)
//     result := parser.ParseFromModelTokens(tokens)
//
//  2. AST Generation: Parse tokens into Abstract Syntax Tree
//     parser := parser.GetParser()
//     defer parser.PutParser(parser)
//     ast, err := parser.ParseWithPositions(result)
//
//  3. AST Processing: Traverse and analyze the generated AST
//     visitor.Walk(ast, myVisitor)
//
// # Token Management
//
// The parser uses Type-based token matching for optimal performance. Type is an
// integer enumeration that enables O(1) switch-based dispatch instead of O(n) string comparisons.
// This optimization provides ~14x performance improvement on hot paths (0.24ns vs 3.4ns per comparison).
//
// Fast path example:
//
//	if p.currentToken.Type == models.TokenTypeSelect {
//	    // O(1) integer comparison
//	    return p.parseSelectWithSetOperations()
//	}
//
// The parser maintains backward compatibility with legacy token matching for tests
// and legacy code that creates tokens without Type.
//
// # Performance Optimizations
//
// The parser implements several performance optimizations:
//
//   - Object Pooling: All major data structures use sync.Pool for zero-allocation reuse
//   - Fast Token Dispatch: O(1) Type switch instead of O(n) string comparisons
//   - Pre-allocation: Statement slices pre-allocated based on input size estimation
//   - Zero-copy Operations: Direct token access without string allocation
//   - Recursion Depth Limiting: MaxRecursionDepth prevents stack overflow (DoS protection)
//
// # DoS Protection
//
// The parser includes protection against denial-of-service attacks via deeply nested expressions:
//
//	const MaxRecursionDepth = 100  // Prevents stack overflow
//
// Expressions deeper than this limit return a RecursionDepthLimitError, preventing both
// stack exhaustion and excessive parsing time on malicious input.
//
// # Error Handling
//
// The parser provides structured error handling with precise position information:
//
//   - Syntax errors include line/column location from the tokenizer
//   - Error messages preserve SQL context for debugging
//   - Errors use the pkg/errors package with error codes for categorization
//   - ParseWithPositions() enables enhanced error reporting with source positions
//
// Example error:
//
//	error: expected 'FROM' but got 'WHERE' at line 1, column 15
//
// # SQL Feature Support (v1.6.0)
//
// # Core DML Operations
//
//   - SELECT: Full SELECT support with DISTINCT, DISTINCT ON, aliases, subqueries
//   - INSERT: INSERT INTO with VALUES, column lists, RETURNING clause
//   - UPDATE: UPDATE with SET clauses, WHERE conditions, RETURNING clause
//   - DELETE: DELETE FROM with WHERE conditions, RETURNING clause
//   - MERGE: SQL:2003 MERGE statements with MATCHED/NOT MATCHED clauses
//
// # DDL Operations
//
//   - CREATE TABLE: Tables with constraints, partitioning, column definitions
//   - CREATE VIEW: Views with OR REPLACE, TEMPORARY, IF NOT EXISTS
//   - CREATE MATERIALIZED VIEW: Materialized views with WITH [NO] DATA
//   - CREATE INDEX: Indexes with UNIQUE, USING, partial indexes (WHERE clause)
//   - ALTER TABLE: ADD/DROP COLUMN, ADD/DROP CONSTRAINT, RENAME operations
//   - DROP: Drop tables, views, materialized views, indexes with CASCADE/RESTRICT
//   - TRUNCATE: TRUNCATE TABLE with RESTART/CONTINUE IDENTITY, CASCADE/RESTRICT
//   - REFRESH MATERIALIZED VIEW: With CONCURRENTLY and WITH [NO] DATA options
//
// # Advanced SELECT Features
//
//   - JOINs: INNER, LEFT, RIGHT, FULL, CROSS, NATURAL joins with ON/USING
//   - LATERAL JOIN: PostgreSQL correlated subqueries in FROM clause
//   - Subqueries: Scalar, EXISTS, IN, ANY, ALL subqueries
//   - CTEs: WITH clause, recursive CTEs, multiple CTE definitions
//   - Set Operations: UNION, UNION ALL, EXCEPT, INTERSECT with proper associativity
//   - DISTINCT ON: PostgreSQL-specific row selection by expression
//   - Window Functions: OVER clause with PARTITION BY, ORDER BY, frame specs
//   - GROUPING SETS: GROUPING SETS, ROLLUP, CUBE (SQL-99 T431)
//   - ORDER BY: With NULLS FIRST/LAST (SQL-99 F851)
//   - LIMIT/OFFSET: Standard pagination with ROW/ROWS variants
//   - FETCH FIRST/NEXT: SQL-99 FETCH clause with PERCENT, ONLY, WITH TIES
//
// # PostgreSQL Extensions (v1.6.0)
//
//   - LATERAL JOIN: Correlated lateral subqueries in FROM/JOIN clauses
//   - JSON/JSONB Operators: All 10 operators (->/->>/#>/#>>/@>/<@/?/?|/?&/#-)
//   - DISTINCT ON: Row deduplication by expression with ORDER BY
//   - FILTER Clause: Conditional aggregation (SQL:2003 T612)
//   - RETURNING Clause: Return modified rows from INSERT/UPDATE/DELETE
//   - Aggregate ORDER BY: ORDER BY inside STRING_AGG, ARRAY_AGG functions
//   - Materialized CTE Hints: AS [NOT] MATERIALIZED in CTE definitions
//
// # Expression Support
//
// The parser handles comprehensive expression types with correct operator precedence:
//
//   - Logical: AND, OR, NOT with proper precedence (OR < AND < comparison)
//   - Comparison: =, <, >, !=, <=, >=, <> with type-safe evaluation
//   - Arithmetic: +, -, *, /, % with standard precedence (* > +)
//   - String: || (concatenation) with proper precedence
//   - JSON: ->, ->>, #>, #>>, @>, <@, ?, ?|, ?&, #- (PostgreSQL)
//   - Pattern Matching: LIKE, ILIKE, NOT LIKE with escape sequences
//   - Range: BETWEEN, NOT BETWEEN with inclusive bounds
//   - Set Membership: IN, NOT IN with value lists or subqueries
//   - NULL Testing: IS NULL, IS NOT NULL with three-valued logic
//   - Quantifiers: ANY, ALL with comparison operators
//   - Existence: EXISTS, NOT EXISTS with subquery evaluation
//   - CASE: Both simple and searched CASE expressions
//   - CAST: Type conversion with CAST(expr AS type)
//   - Function Calls: Regular functions and aggregate functions
//
// # Window Functions (SQL-99)
//
// Complete support for SQL-99 window functions with OVER clause:
//
//   - Ranking: ROW_NUMBER(), RANK(), DENSE_RANK(), NTILE(n)
//   - Offset: LAG(expr, offset, default), LEAD(expr, offset, default)
//   - Value: FIRST_VALUE(expr), LAST_VALUE(expr), NTH_VALUE(expr, n)
//   - PARTITION BY: Partition data into groups for window computation
//   - ORDER BY: Order rows within each partition
//   - Frame Clause: ROWS/RANGE with PRECEDING/FOLLOWING/CURRENT ROW
//   - Frame Bounds: UNBOUNDED PRECEDING, n PRECEDING, CURRENT ROW, n FOLLOWING, UNBOUNDED FOLLOWING
//
// Example window function query:
//
//	SELECT
//	    dept,
//	    name,
//	    salary,
//	    ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) as rank,
//	    LAG(salary, 1) OVER (ORDER BY hire_date) as prev_salary,
//	    SUM(salary) OVER (ORDER BY hire_date ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) as rolling_sum
//	FROM employees;
//
// # Context and Cancellation
//
// The parser supports context-based cancellation for long-running operations:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//	ast, err := parser.ParseContext(ctx, tokens)
//	if err == context.DeadlineExceeded {
//	    // Handle timeout
//	}
//
// The parser checks context.Err() at strategic points (statement boundaries, expression starts)
// to enable fast cancellation without excessive overhead.
//
// # Thread Safety
//
// The parser is designed for concurrent use with proper object pooling:
//
//   - GetParser()/PutParser(): Thread-safe parser pooling via sync.Pool
//   - Zero race conditions: Validated via comprehensive race detection tests
//   - Per-goroutine instances: Each goroutine gets its own parser from pool
//   - No shared state: Parser instances maintain no shared mutable state
//
// # Memory Management
//
// Critical: Always use defer with pool return functions to prevent resource leaks:
//
//	parser := parser.GetParser()
//	defer parser.PutParser(parser)  // MANDATORY - prevents memory leaks
//
// The parser integrates with the AST object pool:
//
//	astObj := ast.NewAST()
//	defer ast.ReleaseAST(astObj)  // MANDATORY - returns to pool
//
// Object pooling provides 60-80% memory reduction in production workloads with 95%+ pool hit rates.
//
// # Usage Examples
//
// Basic parsing with position tracking:
//
//	import (
//	    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
//	    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
//	)
//
//	// Tokenize SQL
//	tkz := tokenizer.GetTokenizer()
//	defer tokenizer.PutTokenizer(tkz)
//	tokens, err := tkz.Tokenize([]byte("SELECT * FROM users WHERE active = true"))
//	if err != nil {
//	    // Handle tokenization error
//	}
//
//	// Convert tokens
//	result := parser.ParseFromModelTokens(tokens)
//
//	// Parse to AST
//	p := parser.GetParser()
//	defer parser.PutParser(p)
//	astObj, err := p.ParseWithPositions(result)
//	defer ast.ReleaseAST(astObj)
//	if err != nil {
//	    // Handle parsing error with line/column information
//	}
//
//	// Access parsed statements
//	for _, stmt := range astObj.Statements {
//	    // Process each statement
//	}
//
// Parsing with timeout:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//
//	p := parser.GetParser()
//	defer parser.PutParser(p)
//
//	astObj, err := p.ParseContext(ctx, tokens)
//	defer ast.ReleaseAST(astObj)
//	if err != nil {
//	    if errors.Is(err, context.DeadlineExceeded) {
//	        log.Println("Parsing timeout exceeded")
//	    }
//	    // Handle other errors
//	}
//
// # Performance Characteristics
//
// Measured performance on production workloads (v1.6.0):
//
//   - Throughput: 1.38M+ operations/second sustained, 1.5M peak
//   - Latency: 347ns average for complex queries with window functions
//   - Token Processing: 8M tokens/second
//   - Memory Efficiency: 60-80% reduction via object pooling
//   - Allocation Rate: <100 bytes/op for pooled parsing
//   - Cache Efficiency: 95%+ pool hit rate in production
//
// # SQL Compliance
//
// The parser provides approximately 80-85% SQL-99 compliance:
//
//   - Core SQL-99: Full support for basic SELECT, INSERT, UPDATE, DELETE
//   - SQL-99 Features: Window functions (F611), CTEs (T121), set operations
//   - SQL:2003 Features: MERGE statements (F312), XML/JSON operators
//   - SQL:2008 Features: TRUNCATE TABLE, enhanced grouping operations
//   - Vendor Extensions: PostgreSQL, MySQL, SQL Server, Oracle specific syntax
//
// # Empty Statement Handling
//
// By default, the parser silently ignores empty statements between semicolons.
// For example, ";;; SELECT 1 ;;;" is treated as a single "SELECT 1" statement.
// This lenient behavior matches common SQL client behavior where extra semicolons
// are harmless.
//
// To reject empty statements, enable strict mode:
//
//	p := parser.NewParser(parser.WithStrictMode())
//	// or
//	p := parser.GetParser()
//	p.ApplyOptions(parser.WithStrictMode())
//
// In strict mode, empty statements (consecutive semicolons or leading/trailing
// semicolons with no SQL) return an error.
//
// # Limitations
//
// Current limitations (will be addressed in future releases):
//
//   - Stored procedures: CREATE PROCEDURE/FUNCTION not yet supported
//   - Triggers: CREATE TRIGGER parsing not implemented
//   - Some vendor-specific extensions may require additional work
//
// # Related Packages
//
//   - github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer: Token generation from SQL text
//   - github.com/ajitpratap0/GoSQLX/pkg/sql/ast: AST node definitions and visitor pattern
//   - github.com/ajitpratap0/GoSQLX/pkg/models: Token types, spans, locations
//   - github.com/ajitpratap0/GoSQLX/pkg/errors: Structured error types with codes
//   - github.com/ajitpratap0/GoSQLX/pkg/sql/keywords: Multi-dialect keyword classification
//
// # Further Reading
//
//   - docs/USAGE_GUIDE.md: Comprehensive usage guide with examples
//   - docs/SQL_COMPATIBILITY.md: SQL dialect compatibility matrix
//   - CHANGELOG.md: Version history and feature additions
package parser
