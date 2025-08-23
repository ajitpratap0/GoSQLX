// Package gosqlx provides a high-performance SQL parsing SDK for Go with zero-copy tokenization
// and object pooling. It offers production-ready SQL lexing, parsing, and AST generation with
// support for multiple SQL dialects.
//
// Features:
//
// - Zero-copy tokenization for optimal performance
// - Object pooling for 60-80% memory reduction  
// - Multi-dialect SQL support (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)
// - Thread-safe implementation with linear scaling to 128+ cores
// - Full Unicode/UTF-8 support for international SQL
// - Performance monitoring and metrics collection
// - Visitor pattern support for AST traversal
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
// Performance:
//
// GoSQLX achieves:
// - 2.2M operations/second throughput
// - 8M tokens/second processing speed
// - <200ns latency for simple queries
// - Linear scaling to 128 cores
// - 60-80% memory reduction with pooling
//
// For more examples and detailed documentation, see:
// https://github.com/ajitpratap0/GoSQLX
package gosqlx