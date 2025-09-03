// Package gosqlx provides a high-performance SQL parsing SDK for Go with zero-copy tokenization
// and object pooling. It offers production-ready SQL lexing, parsing, and AST generation with
// support for multiple SQL dialects and advanced SQL features.
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
//
// Advanced SQL Features (Phase 2 - v1.2.0+):
//
// - Common Table Expressions (CTEs) with WITH clause
// - Recursive CTEs with WITH RECURSIVE support
// - Multiple CTEs in single query
// - Set operations: UNION, UNION ALL, EXCEPT, INTERSECT
// - Complex query compositions and left-associative parsing
// - ~70% SQL-92 standards compliance
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
// GoSQLX achieves:
// - 946K+ sustained operations/second (30s load testing)
// - 1.25M+ operations/second peak throughput (concurrent)
// - 8M+ tokens/second processing speed
// - <280ns latency for simple queries
// - <1μs latency for complex queries with CTEs/set operations
// - Linear scaling to 128+ cores
// - 60-80% memory reduction with object pooling
// - Zero memory leaks under extended load
// - Race-free concurrent operation validated
//
// For more examples and detailed documentation, see:
// https://github.com/ajitpratap0/GoSQLX
package gosqlx
