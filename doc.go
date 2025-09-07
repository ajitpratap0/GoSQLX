// Package gosqlx provides a high-performance SQL parsing SDK for Go with zero-copy tokenization
// and object pooling. It offers production-ready SQL lexing, parsing, and AST generation with
// support for multiple SQL dialects and advanced SQL features.
//
// GoSQLX v1.4.0 includes both a powerful Go SDK and a high-performance CLI tool for SQL processing.
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
// Advanced SQL Features (Phase 2.5 - v1.3.0+):
//
// - Window functions with OVER clause (ROW_NUMBER, RANK, LAG, LEAD, etc.)
// - PARTITION BY and ORDER BY window specifications
// - Window frame clauses (ROWS/RANGE with bounds)
// - Common Table Expressions (CTEs) with WITH clause
// - Recursive CTEs with WITH RECURSIVE support
// - Multiple CTEs in single query
// - Set operations: UNION, UNION ALL, EXCEPT, INTERSECT
// - Complete JOIN support (INNER/LEFT/RIGHT/FULL/CROSS/NATURAL)
// - ~80-85% SQL-99 standards compliance
//
// CLI Tool (v1.4.0):
//
// Install the CLI:
//
//	go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
//
// CLI Commands:
//
//	gosqlx validate "SELECT * FROM users"     // Ultra-fast validation
//	gosqlx format -i query.sql               // Intelligent formatting
//	gosqlx analyze complex_query.sql         // Advanced analysis
//	gosqlx parse -f json query.sql           // AST generation
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
// Advanced Usage (Phase 2 Features):
//
//	// Common Table Expression (CTE)
//	cteSQL := `WITH sales_summary AS (
//	    SELECT region, SUM(amount) as total
//	    FROM sales
//	    GROUP BY region
//	) SELECT region FROM sales_summary WHERE total > 1000`
//
//	// Recursive CTE
//	recursiveSQL := `WITH RECURSIVE employee_tree AS (
//	    SELECT employee_id, manager_id, name FROM employees WHERE manager_id IS NULL
//	    UNION ALL
//	    SELECT e.employee_id, e.manager_id, e.name
//	    FROM employees e JOIN employee_tree et ON e.manager_id = et.employee_id
//	) SELECT * FROM employee_tree`
//
//	// Set Operations
//	unionSQL := `SELECT name FROM customers UNION SELECT name FROM suppliers`
//	exceptSQL := `SELECT product FROM inventory EXCEPT SELECT product FROM discontinued`
//	intersectSQL := `SELECT customer_id FROM orders INTERSECT SELECT customer_id FROM payments`
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
// For more examples and detailed documentation, see:
// https://github.com/ajitpratap0/GoSQLX
package gosqlx
