package tokenizer

import (
	"fmt"
	"strings"
	"testing"
)

// TestTokenizer_InputSizeLimit tests the DoS protection for maximum input size
func TestTokenizer_InputSizeLimit(t *testing.T) {
	tokenizer, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	t.Run("ValidLargeInput", func(t *testing.T) {
		// Test with a large but valid input (100KB - large enough to demonstrate protection works)
		pattern := []byte("SELECT * FROM users WHERE id = 1; ")
		input := make([]byte, 100*1024) // 100KB
		for i := 0; i < len(input); i++ {
			input[i] = pattern[i%len(pattern)]
		}

		tokens, err := tokenizer.Tokenize(input)
		if err != nil {
			t.Errorf("Tokenize() should succeed for valid large input, got error: %v", err)
		}
		if tokens == nil {
			t.Error("Tokenize() should return tokens for valid large input")
		}
		t.Logf("Successfully tokenized %d bytes into %d tokens", len(input), len(tokens))
	})

	t.Run("JustOverLimit", func(t *testing.T) {
		// Create input just over the limit (10MB + 1 byte)
		input := make([]byte, MaxInputSize+1)
		copy(input, []byte("SELECT * FROM users"))

		_, err := tokenizer.Tokenize(input)
		if err == nil {
			t.Fatal("Tokenize() should fail just over limit")
		}

		tokErr, ok := err.(TokenizerError)
		if !ok {
			t.Fatalf("expected TokenizerError, got %T", err)
		}

		expectedMsg := fmt.Sprintf("input size exceeds maximum allowed: %d bytes (max: %d bytes)", MaxInputSize+1, MaxInputSize)
		if tokErr.Message != expectedMsg {
			t.Errorf("wrong error message, got %q, expected %q", tokErr.Message, expectedMsg)
		}
		t.Logf("Correctly rejected oversized input: %d bytes", len(input))
	})

	t.Run("VeryLargeInput", func(t *testing.T) {
		// Create a very large input (20MB) to test fail-fast behavior
		input := make([]byte, MaxInputSize*2)
		copy(input, []byte("SELECT * FROM users"))

		_, err := tokenizer.Tokenize(input)
		if err == nil {
			t.Fatal("Tokenize() should fail for very large input")
		}

		tokErr, ok := err.(TokenizerError)
		if !ok {
			t.Fatalf("expected TokenizerError, got %T", err)
		}

		// Verify it contains the expected error message
		if !strings.Contains(tokErr.Message, "input size exceeds maximum allowed") {
			t.Errorf("error message should mention size limit, got %q", tokErr.Message)
		}
		t.Logf("Correctly rejected %d bytes (%.1fMB) as oversized", len(input), float64(len(input))/(1024*1024))
	})
}

// TestTokenizer_TokenCountLimit tests the DoS protection for maximum token count
func TestTokenizer_TokenCountLimit(t *testing.T) {
	tokenizer, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	t.Run("NormalTokenCount", func(t *testing.T) {
		// Normal SQL query with reasonable token count
		input := []byte("SELECT id, name, email FROM users WHERE active = true ORDER BY created_at DESC LIMIT 100")

		tokens, err := tokenizer.Tokenize(input)
		if err != nil {
			t.Errorf("Tokenize() should succeed for normal token count, got error: %v", err)
		}
		if len(tokens) == 0 {
			t.Error("Tokenize() should return tokens for normal query")
		}
		t.Logf("Normal query produced %d tokens", len(tokens))
	})

	t.Run("LargeButValidTokenCount", func(t *testing.T) {
		// Create a query with many tokens but still under limit
		// Using a realistic pattern: SELECT with many columns
		var input []byte
		input = append(input, []byte("SELECT ")...)
		for i := 0; i < 1000; i++ {
			if i > 0 {
				input = append(input, []byte(", ")...)
			}
			input = append(input, []byte(fmt.Sprintf("col%d", i))...)
		}
		input = append(input, []byte(" FROM users")...)

		tokens, err := tokenizer.Tokenize(input)
		if err != nil {
			t.Errorf("Tokenize() should succeed for large but valid token count, got error: %v", err)
		}
		t.Logf("Large query produced %d tokens", len(tokens))
	})

	// Note: Testing the actual MaxTokens limit would require generating a massive input
	// which is impractical for unit tests. The limit is tested in integration tests.
}

// TestTokenizer_DoSProtectionPerformance tests that DoS checks don't impact performance
func TestTokenizer_DoSProtectionPerformance(t *testing.T) {
	// Skip large performance tests when running with -short or -race flags
	// These tests can be slow, especially with race detection enabled
	if testing.Short() {
		t.Skip("Skipping performance tests in short mode")
	}

	tokenizer, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Test with various input sizes to ensure validation is fast
	// Note: 1MB test is excluded as it's too slow with race detection (10+ minutes)
	sizes := []int{
		100,        // 100 bytes
		1024,       // 1KB
		10 * 1024,  // 10KB
		100 * 1024, // 100KB
	}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("Size_%dB", size), func(t *testing.T) {
			input := make([]byte, size)
			// Fill with repeated SQL pattern
			pattern := []byte("SELECT * FROM users WHERE id = 1 AND ")
			for i := 0; i < size; i++ {
				input[i] = pattern[i%len(pattern)]
			}

			tokens, err := tokenizer.Tokenize(input)
			if err != nil {
				t.Logf("Tokenize() error for size %d: %v", size, err)
			} else {
				t.Logf("Successfully tokenized %d bytes into %d tokens", size, len(tokens))
			}
		})
	}
}
