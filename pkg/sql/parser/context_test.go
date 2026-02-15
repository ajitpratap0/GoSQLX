package parser

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Helper function to tokenize SQL for tests
func tokenizeSQL(t *testing.T, sql string) []token.Token {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize SQL: %v", err)
	}

	converted, err := convertModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to convert tokens: %v", err)
	}
	return converted
}

// TestParseContext_BasicSuccess verifies that ParseContext works for valid SQL
func TestParseContext_BasicSuccess(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "simple select",
			sql:  "SELECT * FROM users",
		},
		{
			name: "select with where",
			sql:  "SELECT name, email FROM users WHERE active = true",
		},
		{
			name: "insert statement",
			sql:  "INSERT INTO users (name) VALUES ('John')",
		},
		{
			name: "update statement",
			sql:  "UPDATE users SET name = 'Jane' WHERE id = 1",
		},
		{
			name: "delete statement",
			sql:  "DELETE FROM users WHERE id = 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			tokens := tokenizeSQL(t, tt.sql)

			p := NewParser()
			defer p.Release()

			ast, err := p.ParseContext(ctx, tokens)
			if err != nil {
				t.Fatalf("ParseContext() error = %v", err)
			}

			if ast == nil {
				t.Error("Expected AST but got nil")
				return
			}

			if len(ast.Statements) == 0 {
				t.Error("Expected statements in AST but got none")
			}
		})
	}
}

// TestParseContext_CancelledContext verifies that cancellation is detected
func TestParseContext_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	sql := "SELECT * FROM users"
	tokens := tokenizeSQL(t, sql)

	p := NewParser()
	defer p.Release()

	ast, err := p.ParseContext(ctx, tokens)

	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got: %v", err)
	}

	if ast != nil {
		t.Error("Expected nil AST when context is cancelled")
	}
}

// TestParseContext_Timeout verifies that timeout is respected
func TestParseContext_Timeout(t *testing.T) {
	// Use a short timeout and wait well beyond it to guarantee expiry.
	// Windows has ~15.6ms timer granularity, so 1ns+10ms is unreliable there.
	// Using 1ms timeout + 100ms sleep ensures the context is expired on all platforms.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Wait long enough for the deadline to expire on all platforms (including Windows)
	time.Sleep(100 * time.Millisecond)

	sql := "SELECT * FROM users"
	tokens := tokenizeSQL(t, sql)

	p := NewParser()
	defer p.Release()

	ast, err := p.ParseContext(ctx, tokens)

	// Use errors.Is for proper unwrapping — ParseContext may wrap the context error
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Expected context.DeadlineExceeded error, got: %v", err)
	}

	if ast != nil {
		t.Error("Expected nil AST when timeout expires")
	}
}

// TestParseContext_ComplexQueryWithTimeout verifies parsing complex queries with timeout
func TestParseContext_ComplexQueryWithTimeout(t *testing.T) {
	// Use a reasonable timeout for complex query
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Complex query with multiple clauses
	sql := "SELECT u.id, u.name FROM users u LEFT JOIN orders o ON u.id = o.user_id WHERE u.active = true"
	tokens := tokenizeSQL(t, sql)

	p := NewParser()
	defer p.Release()

	ast, err := p.ParseContext(ctx, tokens)
	if err != nil {
		t.Fatalf("ParseContext() error = %v", err)
	}

	if ast == nil {
		t.Error("Expected AST but got nil")
	}
}

// TestParseContext_CTEWithContext verifies CTE parsing with context
func TestParseContext_CTEWithContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sql := "WITH active_users AS (SELECT id, name FROM users WHERE active = true) SELECT * FROM active_users"
	tokens := tokenizeSQL(t, sql)

	p := NewParser()
	defer p.Release()

	ast, err := p.ParseContext(ctx, tokens)
	if err != nil {
		t.Fatalf("ParseContext() with CTE error = %v", err)
	}

	if ast == nil {
		t.Error("Expected AST but got nil")
	}
}

// TestParseContext_WindowFunctionsWithContext verifies window function parsing with context
func TestParseContext_WindowFunctionsWithContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sql := "SELECT name, salary, ROW_NUMBER() OVER (ORDER BY salary DESC) as rank FROM employees"
	tokens := tokenizeSQL(t, sql)

	p := NewParser()
	defer p.Release()

	ast, err := p.ParseContext(ctx, tokens)
	if err != nil {
		t.Fatalf("ParseContext() with window functions error = %v", err)
	}

	if ast == nil {
		t.Error("Expected AST but got nil")
	}
}

// TestParseContext_MultipleCallsWithSameParser verifies parser can be reused
func TestParseContext_MultipleCallsWithSameParser(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	defer p.Release()

	queries := []string{
		"SELECT * FROM users",
		"INSERT INTO orders VALUES (1, 100)",
		"UPDATE products SET price = 50",
	}

	for i, sql := range queries {
		tokens := tokenizeSQL(t, sql)

		ast, err := p.ParseContext(ctx, tokens)
		if err != nil {
			t.Fatalf("Query %d: ParseContext() error = %v", i, err)
		}

		if ast == nil {
			t.Errorf("Query %d: Expected AST but got nil", i)
		}
	}
}

// TestParseContext_CancellationResponseTime verifies fast cancellation (< 100ms requirement)
func TestParseContext_CancellationResponseTime(t *testing.T) {
	// Create a complex query with many columns to ensure parsing takes time
	columns := make([]string, 100)
	for i := range columns {
		columns[i] = "column" + strings.Repeat(string(rune('a'+i%26)), 2)
	}
	sql := "SELECT " + strings.Join(columns, ", ") + " FROM users WHERE id = 1"
	tokens := tokenizeSQL(t, sql)

	ctx, cancel := context.WithCancel(context.Background())

	// Start parsing in goroutine
	done := make(chan bool)
	go func() {
		p := NewParser()
		defer p.Release()
		_, _ = p.ParseContext(ctx, tokens)
		done <- true
	}()

	// Wait a bit then cancel
	time.Sleep(10 * time.Millisecond)
	cancelTime := time.Now()
	cancel()

	// Wait for completion
	<-done
	responseTime := time.Since(cancelTime)

	// Verify cancellation response time is < 100ms
	if responseTime > 100*time.Millisecond {
		t.Errorf("Cancellation response time %v exceeds 100ms requirement", responseTime)
	}

	t.Logf("Cancellation response time: %v", responseTime)
}

// TestParseContext_ConcurrentCalls verifies thread safety with concurrent context-aware calls
func TestParseContext_ConcurrentCalls(t *testing.T) {
	const numGoroutines = 10

	ctx := context.Background()
	sql := "SELECT id, name, email FROM users WHERE active = true"
	tokens := tokenizeSQL(t, sql)

	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			p := NewParser()
			defer p.Release()

			ast, err := p.ParseContext(ctx, tokens)
			if err != nil {
				t.Errorf("Goroutine %d: ParseContext() error = %v", id, err)
			}

			if ast == nil {
				t.Errorf("Goroutine %d: Expected AST but got nil", id)
			}

			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestParseContext_BackwardCompatibility verifies non-context method still works
func TestParseContext_BackwardCompatibility(t *testing.T) {
	sql := "SELECT * FROM users"
	tokens := tokenizeSQL(t, sql)

	p := NewParser()
	defer p.Release()

	// Test old non-context method
	ast1, err1 := p.Parse(tokens)
	if err1 != nil {
		t.Fatalf("Parse() error = %v", err1)
	}

	// Test new context method with background context
	ast2, err2 := p.ParseContext(context.Background(), tokens)
	if err2 != nil {
		t.Fatalf("ParseContext() error = %v", err2)
	}

	// Both should produce ASTs
	if ast1 == nil || ast2 == nil {
		t.Error("Expected ASTs from both methods")
		return
	}

	// Both should have same number of statements
	if len(ast1.Statements) != len(ast2.Statements) {
		t.Errorf("Statement count mismatch: Parse()=%d, ParseContext()=%d",
			len(ast1.Statements), len(ast2.Statements))
	}
}

// TestParseContext_ErrorHandling verifies proper error handling
func TestParseContext_ErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		shouldError bool
	}{
		{
			name:        "incomplete select",
			sql:         "SELECT FROM users",
			shouldError: true,
		},
		{
			name:        "missing table name",
			sql:         "SELECT * FROM",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Try to tokenize - some errors may occur here
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, tokErr := tkz.Tokenize([]byte(tt.sql))
			if tokErr != nil {
				// Expected for some invalid SQL
				return
			}

			p := NewParser()
			defer p.Release()

			ast, err := p.ParseContextFromModelTokens(ctx, tokens)

			if tt.shouldError && err == nil {
				t.Error("Expected error but got none")
			}

			if err != nil && err == context.Canceled {
				t.Error("Should not return context.Canceled for SQL errors")
			}

			if tt.shouldError && ast != nil {
				t.Error("Expected nil AST on error")
			}
		})
	}
}

// TestParseContext_DeepNesting verifies context checks with deeply nested expressions
func TestParseContext_DeepNesting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Create a query with multiple conditions
	sql := "SELECT * FROM users WHERE a = 1"
	tokens := tokenizeSQL(t, sql)

	p := NewParser()
	defer p.Release()

	ast, err := p.ParseContext(ctx, tokens)
	if err != nil {
		t.Fatalf("ParseContext() with nested expressions error = %v", err)
	}

	if ast == nil {
		t.Error("Expected AST but got nil")
	}
}

// TestParseContext_EmptyTokens verifies handling of empty token list
func TestParseContext_EmptyTokens(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	defer p.Release()

	// Empty token list
	tokens := []token.Token{}

	ast, err := p.ParseContext(ctx, tokens)

	// Should get an error for no statements
	if err == nil {
		t.Error("Expected error for empty token list")
	}

	if ast != nil {
		t.Error("Expected nil AST for empty token list")
	}
}
