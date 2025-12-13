// Package gosqlx provides a production-ready, high-performance SQL parsing SDK for Go with
// zero-copy tokenization and comprehensive object pooling. It offers enterprise-grade SQL lexing,
// parsing, and AST generation with support for multiple SQL dialects and advanced SQL features.
//
// GoSQLX v1.6.0 includes both a powerful Go SDK and a high-performance CLI tool for SQL processing,
// validated for production deployment with race-free concurrent operation and extensive real-world testing.
//
// Production Status: VALIDATED FOR PRODUCTION DEPLOYMENT (v1.6.0+)
//   - Thread Safety: Race-free through comprehensive concurrent testing
//   - Performance: 1.38M+ ops/sec sustained, 1.5M+ peak with memory-efficient pooling
//   - International: Full Unicode/UTF-8 support for global SQL processing
//   - Reliability: 95%+ success rate on real-world SQL queries
//   - Standards: Multi-dialect SQL compatibility (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)
//   - SQL Compliance: ~80-85% SQL-99 compliance (window functions, CTEs, set operations)
//   - Test Coverage: AST package 73.4%, Models package 100%
//
// Core Features:
//
// - Zero-copy tokenization for optimal performance
// - Object pooling for 60-80% memory reduction
// - Multi-dialect SQL support (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)
// - Thread-safe implementation with linear scaling to 128+ cores
// - Full Unicode/UTF-8 support for international SQL
// - Performance monitoring and metrics collection
// - Visitor pattern support for AST traversal
// - Production-ready CLI tool with 1.38M+ ops/sec performance
//
// Advanced SQL Features:
//
// SQL-99 Core Features (v1.3.0+):
//   - Window functions with OVER clause (ROW_NUMBER, RANK, DENSE_RANK, NTILE, LAG, LEAD, FIRST_VALUE, LAST_VALUE)
//   - PARTITION BY and ORDER BY window specifications
//   - Window frame clauses (ROWS/RANGE with UNBOUNDED/CURRENT ROW/value PRECEDING/FOLLOWING)
//   - Common Table Expressions (CTEs) with WITH clause
//   - Recursive CTEs with WITH RECURSIVE support
//   - Multiple CTEs in single query with proper scoping
//   - Set operations: UNION, UNION ALL, EXCEPT, INTERSECT with correct precedence
//   - Complete JOIN support (INNER/LEFT/RIGHT/FULL/CROSS/NATURAL with ON/USING)
//
// PostgreSQL Extensions (v1.6.0+):
//   - LATERAL JOIN for correlated subqueries in FROM clause
//   - JSON/JSONB operators (->/->>/#>/#>>/@>/<@/?/?|/?&/#-)
//   - DISTINCT ON for row selection by column values
//   - FILTER clause for conditional aggregation (SQL:2003)
//   - RETURNING clause for INSERT/UPDATE/DELETE operations
//   - ILIKE for case-insensitive pattern matching
//   - MATERIALIZED views with REFRESH CONCURRENTLY
//
// Advanced Grouping (v1.5.0+):
//   - GROUPING SETS for explicit grouping combinations
//   - ROLLUP for hierarchical subtotals
//   - CUBE for all possible combinations
//   - MERGE statements (SQL:2003 F312)
//
// Expression Operators:
//   - BETWEEN with expressions
//   - IN with subqueries and value lists
//   - LIKE/ILIKE with pattern matching
//   - IS NULL/IS NOT NULL
//   - NULLS FIRST/LAST ordering (SQL-99 F851)
//
// ~80-85% SQL-99 standards compliance
//
// CLI Tool (v1.6.0):
//
// Install the CLI:
//
//	go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
//
// CLI Commands:
//
//	gosqlx validate "SELECT * FROM users"              // Ultra-fast validation (1.38M+ ops/sec)
//	gosqlx format -i query.sql                        // Intelligent formatting (2,600+ files/sec)
//	gosqlx analyze complex_query.sql                  // Advanced analysis (1M+ queries/sec)
//	gosqlx parse -f json query.sql                    // AST generation (JSON/YAML output)
//	gosqlx lsp                                        // Start LSP server for IDE integration
//	gosqlx lint --config .gosqlx.yml src/**/*.sql     // SQL linting with 10 rules (L001-L010)
//
// Configuration (.gosqlx.yml):
//
//	format:
//	  indent: 2
//	  uppercase_keywords: true
//	validation:
//	  dialect: postgresql
//	lsp:
//	  trace_server: messages
//	server:
//	  log_level: info
//
// See docs/CONFIGURATION.md for complete configuration reference.
//
// Basic Usage:
//
//	import (
//	    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
//	    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
//	    "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
//	)
//
//	// Get a tokenizer from the pool
//	tkz := tokenizer.GetTokenizer()
//	defer tokenizer.PutTokenizer(tkz)
//
//	// Tokenize SQL
//	tokens, err := tkz.Tokenize([]byte("SELECT * FROM users WHERE id = 1"))
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Parse tokens into AST
//	p := &parser.Parser{}
//	astObj, err := p.Parse(tokens)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer ast.ReleaseAST(astObj)
//
// Advanced Usage (Window Functions, CTEs, PostgreSQL Extensions):
//
//	// Window Functions (SQL-99 F611)
//	windowSQL := `SELECT name, salary,
//	    ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) as rank,
//	    LAG(salary, 1) OVER (ORDER BY hire_date) as prev_salary,
//	    SUM(salary) OVER (ORDER BY hire_date ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) as rolling_sum
//	FROM employees`
//
//	// Common Table Expression (CTE) (SQL-99 F121)
//	cteSQL := `WITH sales_summary AS (
//	    SELECT region, SUM(amount) as total
//	    FROM sales
//	    GROUP BY region
//	) SELECT region FROM sales_summary WHERE total > 1000`
//
//	// Recursive CTE (SQL-99 F131)
//	recursiveSQL := `WITH RECURSIVE employee_tree AS (
//	    SELECT employee_id, manager_id, name FROM employees WHERE manager_id IS NULL
//	    UNION ALL
//	    SELECT e.employee_id, e.manager_id, e.name
//	    FROM employees e JOIN employee_tree et ON e.manager_id = et.employee_id
//	) SELECT * FROM employee_tree`
//
//	// Set Operations (SQL-99 F302)
//	unionSQL := `SELECT name FROM customers UNION SELECT name FROM suppliers`
//	exceptSQL := `SELECT product FROM inventory EXCEPT SELECT product FROM discontinued`
//	intersectSQL := `SELECT customer_id FROM orders INTERSECT SELECT customer_id FROM payments`
//
//	// PostgreSQL Extensions (v1.6.0)
//	lateralSQL := `SELECT u.name, r.order_date FROM users u,
//	    LATERAL (SELECT * FROM orders WHERE user_id = u.id ORDER BY order_date DESC LIMIT 3) r`
//
//	jsonSQL := `SELECT data->>'name' AS name, data->'address'->>'city' AS city FROM users
//	    WHERE data @> '{"active": true}'`
//
//	distinctOnSQL := `SELECT DISTINCT ON (dept_id) dept_id, name, salary
//	    FROM employees ORDER BY dept_id, salary DESC`
//
//	filterSQL := `SELECT COUNT(*) FILTER (WHERE status = 'active') AS active_count,
//	    SUM(amount) FILTER (WHERE type = 'credit') AS total_credits
//	FROM transactions`
//
//	returningSQL := `INSERT INTO users (name, email) VALUES ('John', 'john@example.com')
//	    RETURNING id, created_at`
//
//	// Advanced Grouping (SQL-99 T431)
//	groupingSetsSQL := `SELECT region, product, SUM(sales)
//	    FROM orders GROUP BY GROUPING SETS ((region), (product), ())`
//
//	rollupSQL := `SELECT year, quarter, SUM(revenue)
//	    FROM sales GROUP BY ROLLUP (year, quarter)`
//
//	cubeSQL := `SELECT region, product, SUM(amount)
//	    FROM sales GROUP BY CUBE (region, product)`
//
//	// MERGE Statement (SQL:2003 F312)
//	mergeSQL := `MERGE INTO target t USING source s ON t.id = s.id
//	    WHEN MATCHED THEN UPDATE SET t.value = s.value
//	    WHEN NOT MATCHED THEN INSERT (id, value) VALUES (s.id, s.value)`
//
// Performance:
//
// GoSQLX Library achieves:
// - 1.38M+ sustained operations/second (validated benchmarks)
// - 1.5M+ operations/second peak throughput (concurrent)
// - 8M+ tokens/second processing speed
// - <1μs latency for complex queries with window functions
// - Linear scaling to 128+ cores
// - 60-80% memory reduction with object pooling
// - Zero memory leaks under extended load
// - Race-free concurrent operation validated
//
// CLI Performance:
// - 1.38M+ operations/second SQL validation
// - 2,600+ files/second formatting throughput
// - 1M+ queries/second analysis performance
// - Memory leak prevention with proper AST cleanup
//
// # Package Organization
//
// Core Packages:
//   - pkg/sql/tokenizer: Zero-copy SQL tokenization (8M+ tokens/sec)
//   - pkg/sql/parser: Recursive descent parser with comprehensive SQL support
//   - pkg/sql/ast: Abstract Syntax Tree nodes with visitor pattern (73.4% coverage)
//   - pkg/sql/keywords: Multi-dialect keyword recognition (PostgreSQL, MySQL, SQLite, etc.)
//   - pkg/sql/token: Token type definitions and pool management
//   - pkg/models: Core data structures (100% test coverage)
//   - pkg/errors: Structured error handling with position tracking
//
// Analysis and Tooling:
//   - pkg/linter: SQL linting with 10 built-in rules (L001-L010)
//   - pkg/sql/security: SQL injection detection with severity classification
//   - pkg/metrics: Performance monitoring and observability
//   - pkg/lsp: Language Server Protocol server for IDE integration
//
// Configuration and Compatibility:
//   - pkg/config: Unified configuration management (YAML/JSON/env/LSP)
//   - pkg/compatibility: Backward compatibility testing suite
//
// CLI and Integration:
//   - cmd/gosqlx: Production-ready command-line tool
//   - examples: Tutorial examples and real-world usage patterns
//
// # IDE Integration
//
// GoSQLX provides a full-featured LSP server for IDE integration:
//
//	gosqlx lsp --log /tmp/lsp.log
//
// Features:
//   - Real-time syntax validation
//   - Hover documentation
//   - Code completion
//   - Intelligent formatting
//   - Diagnostic messages
//   - Workspace configuration
//
// See docs/LSP_GUIDE.md for complete IDE setup instructions.
//
// # SQL Linting
//
// Built-in linting rules (L001-L010):
//   - L001: Enforce uppercase keywords
//   - L002: Consistent indentation
//   - L003: Avoid SELECT *
//   - L004: Consistent alias style
//   - L005: Trailing whitespace
//   - L006-L010: Additional style rules
//
// See docs/LINTING_RULES.md for complete linting reference.
//
// # Documentation
//
// Complete documentation available at:
//   - docs/GETTING_STARTED.md - Quick start guide
//   - docs/USAGE_GUIDE.md - Comprehensive usage guide
//   - docs/API_REFERENCE.md - Complete API documentation
//   - docs/CONFIGURATION.md - Configuration file guide
//   - docs/LSP_GUIDE.md - LSP server and IDE integration
//   - docs/LINTING_RULES.md - All linting rules reference
//   - docs/SQL_COMPATIBILITY.md - SQL dialect compatibility matrix
//   - docs/ARCHITECTURE.md - System architecture details
//   - docs/PERFORMANCE_TUNING.md - Performance optimization guide
//   - docs/TROUBLESHOOTING.md - Common issues and solutions
//
// # Version History
//
// v1.6.0: PostgreSQL extensions (LATERAL, JSON operators, DISTINCT ON, FILTER, RETURNING)
// v1.5.0: GROUPING SETS, ROLLUP, CUBE, MERGE statements, materialized views
// v1.4.0: Window functions with PARTITION BY, ORDER BY, frame clauses
// v1.3.0: Common Table Expressions (CTEs) and recursive CTEs
// v1.2.0: Set operations (UNION, EXCEPT, INTERSECT)
// v1.1.0: Complete JOIN support
// v1.0.0: Initial release with basic SQL parsing
//
// For more examples and detailed documentation, see:
// https://github.com/ajitpratap0/GoSQLX
package gosqlx
