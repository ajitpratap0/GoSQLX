// Package sql provides the core SQL parsing infrastructure for GoSQLX, including
// tokenization, parsing, AST generation, and SQL dialect support.
//
// This package serves as the parent for all SQL-related functionality in GoSQLX,
// organizing the parsing pipeline into cohesive subpackages.
//
// # Package Architecture
//
// The sql package is organized into several specialized subpackages:
//
//   - tokenizer: Zero-copy SQL lexical analysis and token generation
//   - parser: Recursive descent parser that builds AST from tokens
//   - ast: Abstract Syntax Tree node definitions and visitor patterns
//   - token: Token type definitions and pool management
//   - keywords: SQL keyword categorization and dialect-specific recognition
//   - security: SQL injection detection and security pattern scanning
//
// # SQL Processing Pipeline
//
// The standard SQL processing pipeline flows through these stages:
//
// 1. Tokenization (pkg/sql/tokenizer):
//
//	tkz := tokenizer.GetTokenizer()
//	defer tokenizer.PutTokenizer(tkz)
//	tokens, err := tkz.Tokenize([]byte("SELECT * FROM users"))
//
// 2. Parsing (pkg/sql/parser):
//
//	p := parser.GetParser()
//	defer parser.PutParser(p)
//	astObj, err := p.ParseFromModelTokens(tokens)
//	defer ast.ReleaseAST(astObj)
//
// 4. AST Traversal (pkg/sql/ast):
//
//	visitor := &MyVisitor{}
//	ast.Walk(visitor, astObj.Statements[0])
//
// # Supported SQL Dialects
//
// GoSQLX supports multiple SQL dialects through the keywords package:
//
//   - PostgreSQL: Full support including LATERAL, RETURNING, ILIKE, MATERIALIZED
//   - MySQL: ZEROFILL, UNSIGNED, FORCE, IGNORE
//   - SQL Server: Dialect-specific keywords
//   - Oracle: Dialect-specific keywords
//   - SQLite: AUTOINCREMENT, VACUUM, ATTACH, DETACH
//   - Generic: Standard SQL-99 keywords common to all dialects
//
// Example dialect usage:
//
//	import "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
//
//	kw := keywords.New(keywords.DialectPostgreSQL, true)
//	if kw.IsKeyword("LATERAL") {
//	    // Handle PostgreSQL-specific LATERAL keyword
//	}
//
// # Advanced SQL Features (v1.6.0)
//
// The sql package supports comprehensive SQL-99 features:
//
// Window Functions (SQL-99 F611):
//
//	SELECT name, salary,
//	       ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) as rank,
//	       LAG(salary, 1) OVER (ORDER BY hire_date) as prev_salary
//	FROM employees
//
// Common Table Expressions (SQL-99 F121):
//
//	WITH sales_summary AS (
//	    SELECT region, SUM(amount) as total FROM sales GROUP BY region
//	)
//	SELECT * FROM sales_summary WHERE total > 1000
//
// Recursive CTEs (SQL-99 F131):
//
//	WITH RECURSIVE employee_tree AS (
//	    SELECT id, name, manager_id FROM employees WHERE manager_id IS NULL
//	    UNION ALL
//	    SELECT e.id, e.name, e.manager_id
//	    FROM employees e JOIN employee_tree et ON e.manager_id = et.id
//	)
//	SELECT * FROM employee_tree
//
// Set Operations (SQL-99 F302):
//
//	SELECT name FROM customers
//	UNION
//	SELECT name FROM suppliers
//	EXCEPT
//	SELECT name FROM blacklist
//
// PostgreSQL Extensions (v1.6.0):
//
//	-- LATERAL JOIN
//	SELECT u.name, r.order_date FROM users u,
//	LATERAL (SELECT * FROM orders WHERE user_id = u.id LIMIT 3) r
//
//	-- DISTINCT ON
//	SELECT DISTINCT ON (dept_id) dept_id, name, salary
//	FROM employees ORDER BY dept_id, salary DESC
//
//	-- JSON operators
//	SELECT data->>'name', data->'address'->>'city' FROM users
//
//	-- FILTER clause
//	SELECT COUNT(*) FILTER (WHERE status = 'active') FROM users
//
//	-- RETURNING clause
//	INSERT INTO users (name) VALUES ('John') RETURNING id, created_at
//
// GROUPING SETS, ROLLUP, CUBE (SQL-99 T431):
//
//	SELECT region, product, SUM(sales)
//	FROM orders
//	GROUP BY GROUPING SETS ((region), (product), ())
//
//	SELECT year, quarter, SUM(revenue)
//	FROM sales
//	GROUP BY ROLLUP (year, quarter)
//
//	SELECT region, product, SUM(amount)
//	FROM sales
//	GROUP BY CUBE (region, product)
//
// MERGE Statements (SQL:2003 F312):
//
//	MERGE INTO target t USING source s ON t.id = s.id
//	WHEN MATCHED THEN UPDATE SET t.value = s.value
//	WHEN NOT MATCHED THEN INSERT (id, value) VALUES (s.id, s.value)
//
// Materialized Views:
//
//	CREATE MATERIALIZED VIEW sales_summary AS
//	SELECT region, SUM(amount) FROM sales GROUP BY region
//
//	REFRESH MATERIALIZED VIEW CONCURRENTLY sales_summary
//
// # Performance Characteristics
//
// The sql package is optimized for high-performance parsing:
//
//   - Zero-copy tokenization: Direct byte slice operations
//   - Object pooling: 60-80% memory reduction via sync.Pool
//   - Concurrent parsing: Thread-safe, scales linearly to 128+ cores
//   - 1.38M+ ops/sec sustained throughput
//   - 1.5M+ ops/sec peak throughput
//   - 8M+ tokens/sec processing speed
//   - <1μs latency for complex queries
//
// Memory management:
//
//	// CORRECT: Always use defer with pool returns
//	tkz := tokenizer.GetTokenizer()
//	defer tokenizer.PutTokenizer(tkz)
//
//	astObj := ast.NewAST()
//	defer ast.ReleaseAST(astObj)
//
// # Thread Safety
//
// All sql subpackages are designed for concurrent use:
//
//   - Tokenizers from pool are safe for single-goroutine use
//   - Parsers are stateless and safe for concurrent creation
//   - AST nodes are immutable after creation
//   - Object pools use sync.Pool for thread-safe access
//   - Keywords package is read-only after initialization
//
// Race detection validation:
//
//	go test -race ./pkg/sql/...
//
// # Error Handling
//
// The sql package provides detailed error information:
//
//	tokens, err := tkz.Tokenize(sqlBytes)
//	if err != nil {
//	    // Error includes line, column, and context
//	    fmt.Printf("Tokenization error: %v\n", err)
//	}
//
//	astObj, err := parser.Parse(tokens)
//	if err != nil {
//	    // Parser errors include token position and expected vs actual
//	    fmt.Printf("Parse error: %v\n", err)
//	}
//
// # Security Scanning
//
// The sql/security subpackage provides SQL injection detection:
//
//	import "github.com/ajitpratapsingh/GoSQLX/pkg/sql/security"
//
//	scanner := security.NewScanner()
//	findings := scanner.Scan(sqlBytes)
//	for _, finding := range findings {
//	    fmt.Printf("Security issue: %s (severity: %s)\n",
//	        finding.Description, finding.Severity)
//	}
//
// # SQL Compatibility
//
// SQL-99 compliance: ~80-85% of SQL-99 standard
//
// Fully supported:
//   - Basic SELECT, INSERT, UPDATE, DELETE
//   - All JOIN types (INNER, LEFT, RIGHT, FULL, CROSS, NATURAL)
//   - Subqueries in SELECT, FROM, WHERE clauses
//   - Window functions with PARTITION BY, ORDER BY, frame clauses
//   - Common Table Expressions (CTEs) with WITH clause
//   - Recursive CTEs with WITH RECURSIVE
//   - Set operations (UNION, EXCEPT, INTERSECT) with ALL variants
//   - Aggregate functions with GROUP BY, HAVING
//   - ORDER BY with ASC/DESC, NULLS FIRST/LAST
//   - CASE expressions (simple and searched)
//   - BETWEEN, IN, LIKE, IS NULL operators
//   - GROUPING SETS, ROLLUP, CUBE
//   - MERGE statements
//   - Materialized views
//
// Partially supported:
//   - DDL statements (CREATE, ALTER, DROP)
//   - Complex constraints
//   - Stored procedures (syntax recognition only)
//
// Not yet supported:
//   - Full SQL:2011 temporal features
//   - Some advanced windowing features
//   - Full OLAP extensions
//
// # Subpackage Details
//
// tokenizer:
//   - Zero-copy lexical analysis
//   - UTF-8/Unicode support
//   - Position tracking (line, column)
//   - Object pooling for tokenizer instances
//   - Performance: 8M+ tokens/second
//
// parser:
//   - Recursive descent parser
//   - One-token lookahead
//   - Comprehensive SQL-99 support
//   - Error recovery and detailed messages
//   - Object pooling for statements
//
// ast:
//   - Complete node hierarchy
//   - Visitor pattern support
//   - Object pooling for all node types
//   - Immutable after creation
//   - 73.4% test coverage
//
// token:
//   - Token type definitions
//   - Token pool management
//   - Comprehensive token categories
//
// keywords:
//   - Multi-dialect keyword recognition
//   - Compound keyword support (GROUP BY, ORDER BY, etc.)
//   - Case-sensitive/insensitive modes
//   - Categorized keywords (DML, DDL, functions, etc.)
//
// security:
//   - SQL injection pattern detection
//   - Severity classification (high, medium, low)
//   - Zero false positives on valid parameterized queries
//
// # Example: Complete Parsing Pipeline
//
//	package main
//
//	import (
//	    "fmt"
//	    "log"
//
//	    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
//	    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
//	    "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
//	)
//
//	func main() {
//	    sql := `WITH sales AS (
//	        SELECT region, SUM(amount) as total FROM orders GROUP BY region
//	    )
//	    SELECT * FROM sales WHERE total > 1000`
//
//	    // Tokenize
//	    tkz := tokenizer.GetTokenizer()
//	    defer tokenizer.PutTokenizer(tkz)
//
//	    tokens, err := tkz.Tokenize([]byte(sql))
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    // Parse
//	    p := &parser.Parser{}
//	    astObj, err := p.Parse(tokens)
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    defer ast.ReleaseAST(astObj)
//
//	    // Process AST
//	    fmt.Printf("Parsed %d statements\n", len(astObj.Statements))
//	}
//
// # Version History
//
// v1.6.0: PostgreSQL extensions (LATERAL, JSON operators, DISTINCT ON, FILTER, RETURNING)
// v1.5.0: GROUPING SETS, ROLLUP, CUBE, MERGE statements, materialized views
// v1.4.0: Window functions with PARTITION BY, ORDER BY, frame clauses
// v1.3.0: Common Table Expressions (CTEs) and recursive CTEs
// v1.2.0: Set operations (UNION, EXCEPT, INTERSECT)
// v1.1.0: Complete JOIN support
// v1.0.0: Basic SQL parsing with SELECT, INSERT, UPDATE, DELETE
//
// # See Also
//
//   - pkg/sql/tokenizer - Tokenization and lexical analysis
//   - pkg/sql/parser - SQL parsing and AST generation
//   - pkg/sql/ast - AST node definitions
//   - pkg/sql/keywords - Keyword and dialect management
//   - pkg/sql/security - Security scanning
//   - docs/SQL_COMPATIBILITY.md - Detailed SQL compatibility matrix
//   - docs/ARCHITECTURE.md - System architecture documentation
package sql
