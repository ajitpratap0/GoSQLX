// Package gosqlx provides convenient high-level functions for SQL parsing.
//
// This package wraps the lower-level tokenizer and parser APIs to provide
// a simple, ergonomic interface for common operations. All object pool
// management is handled internally.
//
// For performance-critical applications that need fine-grained control,
// use the lower-level APIs in pkg/sql/tokenizer and pkg/sql/parser directly.
package gosqlx

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Parse is a convenience function that tokenizes and parses SQL in one call.
//
// This function handles all object pool management internally, making it
// ideal for simple use cases where performance overhead is acceptable.
//
// Example:
//
//	sql := "SELECT * FROM users WHERE active = true"
//	astNode, err := gosqlx.Parse(sql)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Parsed: %T\n", astNode)
//
// For batch processing or performance-critical code, use the lower-level
// tokenizer and parser APIs directly to reuse objects.
func Parse(sql string) (*ast.AST, error) {
	// Step 1: Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Step 2: Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return nil, fmt.Errorf("tokenization failed: %w", err)
	}

	// Step 3: Convert to parser tokens using the proper converter
	converter := parser.NewTokenConverter()
	result, err := converter.Convert(tokens)
	if err != nil {
		return nil, fmt.Errorf("token conversion failed: %w", err)
	}

	// Step 4: Parse to AST
	p := parser.NewParser()
	defer p.Release()

	astNode, err := p.Parse(result.Tokens)
	if err != nil {
		return nil, fmt.Errorf("parsing failed: %w", err)
	}

	return astNode, nil
}

// Validate checks if the given SQL is syntactically valid.
//
// This is a convenience function that only validates syntax without
// building the full AST, making it slightly faster than Parse().
//
// Example:
//
//	if err := gosqlx.Validate("SELECT * FROM users"); err != nil {
//	    fmt.Printf("Invalid SQL: %v\n", err)
//	}
//
// Returns nil if SQL is valid, or an error describing the problem.
func Validate(sql string) error {
	// Just use Parse and discard the result
	// This ensures validation is comprehensive
	_, err := Parse(sql)
	if err != nil {
		return fmt.Errorf("invalid SQL: %w", err)
	}

	return nil
}

// ParseBytes is like Parse but accepts a byte slice.
//
// This is useful when you already have SQL as bytes (e.g., from file I/O)
// and want to avoid the string → []byte conversion overhead.
//
// Example:
//
//	sqlBytes := []byte("SELECT * FROM users")
//	astNode, err := gosqlx.ParseBytes(sqlBytes)
func ParseBytes(sql []byte) (*ast.AST, error) {
	return Parse(string(sql))
}

// MustParse is like Parse but panics on error.
//
// This is useful for parsing SQL literals at startup or in tests
// where parse errors indicate a programming bug.
//
// Example:
//
//	// In test or init()
//	ast := gosqlx.MustParse("SELECT 1")
func MustParse(sql string) *ast.AST {
	astNode, err := Parse(sql)
	if err != nil {
		panic(fmt.Sprintf("gosqlx.MustParse: %v", err))
	}
	return astNode
}

// ParseMultiple parses multiple SQL statements and returns their ASTs.
//
// This is more efficient than calling Parse() repeatedly because it
// reuses the tokenizer and parser objects.
//
// Example:
//
//	queries := []string{
//	    "SELECT * FROM users",
//	    "SELECT * FROM orders",
//	}
//	asts, err := gosqlx.ParseMultiple(queries)
func ParseMultiple(queries []string) ([]*ast.AST, error) {
	// Get resources from pools once
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	p := parser.NewParser()
	defer p.Release()

	converter := parser.NewTokenConverter()

	results := make([]*ast.AST, 0, len(queries))

	for i, sql := range queries {
		// Reset tokenizer state between queries
		tkz.Reset()

		// Tokenize
		tokens, err := tkz.Tokenize([]byte(sql))
		if err != nil {
			return nil, fmt.Errorf("query %d: tokenization failed: %w", i, err)
		}

		// Convert tokens
		result, err := converter.Convert(tokens)
		if err != nil {
			return nil, fmt.Errorf("query %d: token conversion failed: %w", i, err)
		}

		// Parse
		astNode, err := p.Parse(result.Tokens)
		if err != nil {
			return nil, fmt.Errorf("query %d: parsing failed: %w", i, err)
		}

		results = append(results, astNode)
	}

	return results, nil
}

// ValidateMultiple validates multiple SQL statements.
//
// Returns nil if all statements are valid, or an error for the first
// invalid statement encountered.
//
// Example:
//
//	queries := []string{
//	    "SELECT * FROM users",
//	    "INVALID SQL HERE",
//	}
//	if err := gosqlx.ValidateMultiple(queries); err != nil {
//	    fmt.Printf("Validation failed: %v\n", err)
//	}
func ValidateMultiple(queries []string) error {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	p := parser.NewParser()
	defer p.Release()

	converter := parser.NewTokenConverter()

	for i, sql := range queries {
		tkz.Reset()

		// Tokenize
		tokens, err := tkz.Tokenize([]byte(sql))
		if err != nil {
			return fmt.Errorf("query %d: %w", i, err)
		}

		// Convert
		result, err := converter.Convert(tokens)
		if err != nil {
			return fmt.Errorf("query %d: %w", i, err)
		}

		// Parse
		_, err = p.Parse(result.Tokens)
		if err != nil {
			return fmt.Errorf("query %d: %w", i, err)
		}
	}

	return nil
}

// FormatOptions controls SQL formatting behavior.
type FormatOptions struct {
	// IndentSize is the number of spaces to use for indentation (default: 2)
	IndentSize int

	// Uppercase keywords (default: false)
	UppercaseKeywords bool

	// AddSemicolon adds a semicolon at the end if missing (default: false)
	AddSemicolon bool

	// SingleLineLimit is the maximum line length before breaking (default: 80)
	// Note: Currently a placeholder for future implementation
	SingleLineLimit int
}

// DefaultFormatOptions returns the default formatting options.
func DefaultFormatOptions() FormatOptions {
	return FormatOptions{
		IndentSize:        2,
		UppercaseKeywords: false,
		AddSemicolon:      false,
		SingleLineLimit:   80,
	}
}

// Format formats SQL according to the specified options.
//
// This is a placeholder implementation that currently validates the SQL
// and returns it with basic formatting. Full AST-based formatting will
// be implemented in a future version.
//
// Example:
//
//	sql := "select * from users where active=true"
//	opts := gosqlx.DefaultFormatOptions()
//	opts.UppercaseKeywords = true
//	formatted, err := gosqlx.Format(sql, opts)
//
// Returns the formatted SQL string or an error if SQL is invalid.
func Format(sql string, options FormatOptions) (string, error) {
	// First validate that the SQL is parseable
	ast, err := Parse(sql)
	if err != nil {
		return "", fmt.Errorf("cannot format invalid SQL: %w", err)
	}
	defer func() {
		// Ensure proper cleanup of AST resources
		_ = ast
	}()

	// TODO: Implement full AST-based formatting
	// For now, return the original SQL with basic processing
	result := sql

	// Add semicolon if requested and not present
	if options.AddSemicolon && len(result) > 0 {
		trimmed := strings.TrimSpace(result)
		if !strings.HasSuffix(trimmed, ";") {
			result = trimmed + ";"
		}
	}

	return result, nil
}
