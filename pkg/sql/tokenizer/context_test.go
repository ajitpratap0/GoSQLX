package tokenizer

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestTokenizeContext_BasicSuccess verifies that TokenizeContext works for valid SQL
func TestTokenizeContext_BasicSuccess(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "simple select",
			input: "SELECT * FROM users",
		},
		{
			name:  "complex query with joins",
			input: "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE u.active = true",
		},
		{
			name:  "insert statement",
			input: "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)

			tokens, err := tkz.TokenizeContext(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("TokenizeContext() error = %v", err)
			}

			if len(tokens) == 0 {
				t.Error("Expected tokens but got none")
			}

			// Verify last token is EOF (TokenTypeEOF = 0)
			if tokens[len(tokens)-1].Token.Type != 0 {
				t.Errorf("Expected last token to be EOF (0), got %d", tokens[len(tokens)-1].Token.Type)
			}
		})
	}
}

// TestTokenizeContext_CancelledContext verifies that cancellation is detected
func TestTokenizeContext_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	sql := "SELECT * FROM users"
	tokens, err := tkz.TokenizeContext(ctx, []byte(sql))

	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got: %v", err)
	}

	if tokens != nil {
		t.Error("Expected nil tokens when context is cancelled")
	}
}

// TestTokenizeContext_Timeout verifies that timeout is respected
func TestTokenizeContext_Timeout(t *testing.T) {
	// Use a very short timeout that should expire before processing large input
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Give the timeout time to expire
	time.Sleep(10 * time.Millisecond)

	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	// Create a large SQL query to ensure processing takes time
	sql := "SELECT " + strings.Repeat("column1, column2, column3, ", 1000) + "column_final FROM table"

	tokens, err := tkz.TokenizeContext(ctx, []byte(sql))

	if err != context.DeadlineExceeded {
		t.Errorf("Expected context.DeadlineExceeded error, got: %v", err)
	}

	if tokens != nil {
		t.Error("Expected nil tokens when timeout expires")
	}
}

// TestTokenizeContext_TimeoutDuringTokenization verifies cancellation during active tokenization
func TestTokenizeContext_TimeoutDuringTokenization(t *testing.T) {
	// Use a timeout that expires during tokenization
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	// Create a very large SQL query that takes time to tokenize
	// This should have more than 100 tokens to trigger context checks
	parts := make([]string, 200)
	for i := range parts {
		parts[i] = "col" + strings.Repeat(string(rune('a'+i%26)), 1)
	}
	sql := "SELECT " + strings.Join(parts, ", ") + " FROM table"

	tokens, err := tkz.TokenizeContext(ctx, []byte(sql))

	// Should get either DeadlineExceeded or successfully complete
	// We can't guarantee timeout will fire, but if it does, verify behavior
	if err == context.DeadlineExceeded {
		if tokens != nil {
			t.Error("Expected nil tokens when timeout expires during tokenization")
		}
	} else if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

// TestTokenizeContext_LongTimeoutSuccess verifies that tokenization completes with reasonable timeout
func TestTokenizeContext_LongTimeoutSuccess(t *testing.T) {
	// Use a generous timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	sql := "SELECT name, email, created_at FROM users WHERE active = true ORDER BY created_at DESC LIMIT 100"

	tokens, err := tkz.TokenizeContext(ctx, []byte(sql))
	if err != nil {
		t.Fatalf("TokenizeContext() with long timeout failed: %v", err)
	}

	if len(tokens) == 0 {
		t.Error("Expected tokens but got none")
	}
}

// TestTokenizeContext_MultipleCallsWithSameTokenizer verifies tokenizer can be reused
func TestTokenizeContext_MultipleCallsWithSameTokenizer(t *testing.T) {
	ctx := context.Background()
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	queries := []string{
		"SELECT * FROM users",
		"INSERT INTO orders VALUES (1, 100)",
		"UPDATE products SET price = 50",
	}

	for i, sql := range queries {
		tokens, err := tkz.TokenizeContext(ctx, []byte(sql))
		if err != nil {
			t.Fatalf("Query %d: TokenizeContext() error = %v", i, err)
		}

		if len(tokens) == 0 {
			t.Errorf("Query %d: Expected tokens but got none", i)
		}
	}
}

// TestTokenizeContext_ErrorHandling verifies proper error handling
func TestTokenizeContext_ErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldError bool
	}{
		{
			name:        "unterminated string",
			input:       "SELECT 'unterminated",
			shouldError: true,
		},
		{
			name:        "invalid character",
			input:       "SELECT \x00 FROM users",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)

			tokens, err := tkz.TokenizeContext(ctx, []byte(tt.input))

			if tt.shouldError && err == nil {
				t.Error("Expected error but got none")
			}

			if err != nil && err == context.Canceled {
				t.Error("Should not return context.Canceled for SQL errors")
			}

			if tt.shouldError && tokens != nil {
				t.Error("Expected nil tokens on error")
			}
		})
	}
}

// TestTokenizeContext_CancellationResponseTime verifies fast cancellation (< 100ms requirement)
func TestTokenizeContext_CancellationResponseTime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	// Create a large SQL query
	parts := make([]string, 500)
	for i := range parts {
		parts[i] = "column" + strings.Repeat(string(rune('a'+i%26)), 2)
	}
	sql := "SELECT " + strings.Join(parts, ", ") + " FROM table"

	// Start tokenization in goroutine
	done := make(chan bool)
	go func() {
		_, _ = tkz.TokenizeContext(ctx, []byte(sql))
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

// TestTokenizeContext_ConcurrentCalls verifies thread safety with concurrent context-aware calls
func TestTokenizeContext_ConcurrentCalls(t *testing.T) {
	const numGoroutines = 10

	ctx := context.Background()
	sql := "SELECT id, name, email FROM users WHERE active = true"

	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)

			tokens, err := tkz.TokenizeContext(ctx, []byte(sql))
			if err != nil {
				t.Errorf("Goroutine %d: TokenizeContext() error = %v", id, err)
			}

			if len(tokens) == 0 {
				t.Errorf("Goroutine %d: Expected tokens but got none", id)
			}

			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestTokenizeContext_BackwardCompatibility verifies non-context method still works
func TestTokenizeContext_BackwardCompatibility(t *testing.T) {
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	sql := "SELECT * FROM users"

	// Test old non-context method
	tokens1, err1 := tkz.Tokenize([]byte(sql))
	if err1 != nil {
		t.Fatalf("Tokenize() error = %v", err1)
	}

	// Test new context method with background context
	tokens2, err2 := tkz.TokenizeContext(context.Background(), []byte(sql))
	if err2 != nil {
		t.Fatalf("TokenizeContext() error = %v", err2)
	}

	// Both should produce same number of tokens
	if len(tokens1) != len(tokens2) {
		t.Errorf("Token count mismatch: Tokenize()=%d, TokenizeContext()=%d", len(tokens1), len(tokens2))
	}
}
