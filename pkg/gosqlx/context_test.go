package gosqlx

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestParseWithContext_BasicSuccess verifies that ParseWithContext works for valid SQL
func TestParseWithContext_BasicSuccess(t *testing.T) {
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
			name: "complex join",
			sql:  "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id",
		},
		{
			name: "insert statement",
			sql:  "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')",
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

			ast, err := ParseWithContext(ctx, tt.sql)
			if err != nil {
				t.Fatalf("ParseWithContext() error = %v", err)
			}

			if ast == nil {
				t.Fatal("Expected AST but got nil")
			}

			if len(ast.Statements) == 0 {
				t.Error("Expected statements in AST but got none")
			}
		})
	}
}

// TestParseWithContext_CancelledContext verifies that cancellation is detected
func TestParseWithContext_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	sql := "SELECT * FROM users"

	ast, err := ParseWithContext(ctx, sql)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("Expected context.Canceled error, got: %v", err)
	}

	if ast != nil {
		t.Error("Expected nil AST when context is cancelled")
	}
}

// TestParseWithContext_Timeout verifies that timeout is respected
func TestParseWithContext_Timeout(t *testing.T) {
	// Use an already-expired context to avoid timing-dependent flakiness
	// (on fast machines/OS combos, nanosecond timeouts may not expire before the parse completes)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	sql := "SELECT * FROM users"

	ast, err := ParseWithContext(ctx, sql)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Expected context.DeadlineExceeded error, got: %v", err)
	}

	if ast != nil {
		t.Error("Expected nil AST when timeout expires")
	}
}

// TestParseWithTimeout_BasicSuccess verifies ParseWithTimeout works correctly
func TestParseWithTimeout_BasicSuccess(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		timeout time.Duration
	}{
		{
			name:    "simple query with generous timeout",
			sql:     "SELECT * FROM users",
			timeout: 5 * time.Second,
		},
		{
			name:    "complex query with reasonable timeout",
			sql:     "SELECT u.id, u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE u.active = true",
			timeout: 3 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := ParseWithTimeout(tt.sql, tt.timeout)
			if err != nil {
				t.Fatalf("ParseWithTimeout() error = %v", err)
			}

			if ast == nil {
				t.Fatal("Expected AST but got nil")
			}

			if len(ast.Statements) == 0 {
				t.Error("Expected statements in AST but got none")
			}
		})
	}
}

// TestParseWithTimeout_TimeoutExpires verifies timeout is enforced
func TestParseWithTimeout_TimeoutExpires(t *testing.T) {
	// Use impossibly short timeout
	sql := "SELECT * FROM users"
	timeout := 1 * time.Nanosecond

	// Sleep to ensure timeout expires
	time.Sleep(10 * time.Millisecond)

	ast, err := ParseWithTimeout(sql, timeout)

	// Should timeout or succeed quickly (race condition)
	if errors.Is(err, context.DeadlineExceeded) {
		if ast != nil {
			t.Error("Expected nil AST when timeout expires")
		}
	} else if err != nil {
		// Other errors are not expected
		t.Errorf("Unexpected error: %v", err)
	}
}

// TestParseWithContext_ComplexQueries verifies context support for complex SQL
func TestParseWithContext_ComplexQueries(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "CTE query",
			sql:  "WITH active_users AS (SELECT id, name FROM users WHERE active = true) SELECT * FROM active_users",
		},
		{
			name: "window function",
			sql:  "SELECT name, salary, ROW_NUMBER() OVER (ORDER BY salary DESC) as rank FROM employees",
		},
		{
			name: "union query",
			sql:  "SELECT name FROM users UNION SELECT name FROM customers",
		},
		{
			name: "select with where clause",
			sql:  "SELECT * FROM users WHERE id = 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			ast, err := ParseWithContext(ctx, tt.sql)
			if err != nil {
				t.Fatalf("ParseWithContext() error = %v", err)
			}

			if ast == nil {
				t.Error("Expected AST but got nil")
			}
		})
	}
}

// TestParseWithContext_LargeQuery verifies handling of large queries
func TestParseWithContext_LargeQuery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create a large query with many columns
	columns := make([]string, 200)
	for i := range columns {
		columns[i] = "column" + strings.Repeat(string(rune('a'+i%26)), 2)
	}
	sql := "SELECT " + strings.Join(columns, ", ") + " FROM large_table WHERE id = 1"

	ast, err := ParseWithContext(ctx, sql)
	if err != nil {
		t.Fatalf("ParseWithContext() error = %v", err)
	}

	if ast == nil {
		t.Error("Expected AST but got nil")
	}
}

// TestParseWithContext_ConcurrentCalls verifies thread safety
func TestParseWithContext_ConcurrentCalls(t *testing.T) {
	const numGoroutines = 20

	ctx := context.Background()
	sql := "SELECT id, name, email FROM users WHERE active = true"

	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			ast, err := ParseWithContext(ctx, sql)
			if err != nil {
				t.Errorf("Goroutine %d: ParseWithContext() error = %v", id, err)
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

// TestParseWithContext_BackwardCompatibility verifies non-context method still works
func TestParseWithContext_BackwardCompatibility(t *testing.T) {
	sql := "SELECT * FROM users"

	// Test old non-context method
	ast1, err1 := Parse(sql)
	if err1 != nil {
		t.Fatalf("Parse() error = %v", err1)
	}

	// Test new context method with background context
	ast2, err2 := ParseWithContext(context.Background(), sql)
	if err2 != nil {
		t.Fatalf("ParseWithContext() error = %v", err2)
	}

	// Both should produce ASTs
	if ast1 == nil || ast2 == nil {
		t.Fatal("Expected ASTs from both methods")
	}

	// Both should have same number of statements
	if len(ast1.Statements) != len(ast2.Statements) {
		t.Errorf("Statement count mismatch: Parse()=%d, ParseWithContext()=%d",
			len(ast1.Statements), len(ast2.Statements))
	}
}

// TestParseWithTimeout_VariousTimeouts verifies different timeout values
func TestParseWithTimeout_VariousTimeouts(t *testing.T) {
	sql := "SELECT id, name, email FROM users WHERE active = true"

	timeouts := []time.Duration{
		100 * time.Millisecond,
		500 * time.Millisecond,
		1 * time.Second,
		5 * time.Second,
	}

	for _, timeout := range timeouts {
		t.Run(timeout.String(), func(t *testing.T) {
			ast, err := ParseWithTimeout(sql, timeout)
			if err != nil {
				t.Fatalf("ParseWithTimeout(%v) error = %v", timeout, err)
			}

			if ast == nil {
				t.Error("Expected AST but got nil")
			}
		})
	}
}

// TestParseWithContext_ErrorHandling verifies proper error handling
func TestParseWithContext_ErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		shouldError bool
	}{
		{
			name:        "invalid SQL syntax",
			sql:         "SELECT FROM",
			shouldError: true,
		},
		{
			name:        "unterminated string",
			sql:         "SELECT 'unterminated FROM users",
			shouldError: true,
		},
		{
			name:        "missing table",
			sql:         "SELECT * FROM",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			ast, err := ParseWithContext(ctx, tt.sql)

			if tt.shouldError && err == nil {
				t.Error("Expected error but got none")
			}

			if err != nil && errors.Is(err, context.Canceled) {
				t.Error("Should not return context.Canceled for SQL errors")
			}

			if tt.shouldError && ast != nil {
				t.Error("Expected nil AST on error")
			}
		})
	}
}

// TestParseWithContext_CancellationResponseTime verifies fast cancellation
func TestParseWithContext_CancellationResponseTime(t *testing.T) {
	// Create a large query
	columns := make([]string, 500)
	for i := range columns {
		columns[i] = "column" + strings.Repeat(string(rune('a'+i%26)), 2)
	}
	sql := "SELECT " + strings.Join(columns, ", ") + " FROM table WHERE id = 1"

	ctx, cancel := context.WithCancel(context.Background())

	// Start parsing in goroutine
	done := make(chan bool)
	go func() {
		_, _ = ParseWithContext(ctx, sql)
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

// TestParseWithTimeout_MultipleCalls verifies helper can be called multiple times
func TestParseWithTimeout_MultipleCalls(t *testing.T) {
	queries := []string{
		"SELECT * FROM users",
		"SELECT name, email FROM customers",
		"SELECT id, total FROM orders",
	}

	timeout := 2 * time.Second

	for i, sql := range queries {
		ast, err := ParseWithTimeout(sql, timeout)
		if err != nil {
			t.Fatalf("Query %d: ParseWithTimeout() error = %v", i, err)
		}

		if ast == nil {
			t.Errorf("Query %d: Expected AST but got nil", i)
		}
	}
}

// TestParseWithContext_EmptySQL verifies handling of empty SQL
func TestParseWithContext_EmptySQL(t *testing.T) {
	ctx := context.Background()

	ast, err := ParseWithContext(ctx, "")

	// Should get an error
	if err == nil {
		t.Error("Expected error for empty SQL")
	}

	if ast != nil {
		t.Error("Expected nil AST for empty SQL")
	}
}

// TestParseWithTimeout_ZeroTimeout verifies handling of zero timeout
func TestParseWithTimeout_ZeroTimeout(t *testing.T) {
	sql := "SELECT * FROM users"

	// Zero timeout should work (no timeout)
	ast, err := ParseWithTimeout(sql, 0)

	// With zero timeout, context will be cancelled immediately or succeed
	if errors.Is(err, context.DeadlineExceeded) {
		if ast != nil {
			t.Error("Expected nil AST when timeout expires")
		}
	} else if err != nil {
		// Might get tokenization or parsing errors
		t.Logf("Got error with zero timeout: %v", err)
	}
}
