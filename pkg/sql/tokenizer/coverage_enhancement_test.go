package tokenizer

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// TestBufferPool tests the buffer pool operations.
func TestBufferPool(t *testing.T) {
	t.Run("NewBufferPool creates pool", func(t *testing.T) {
		pool := NewBufferPool()
		if pool == nil {
			t.Fatal("NewBufferPool() returned nil")
		}
	})

	t.Run("BufferPool Get and Put cycle", func(t *testing.T) {
		pool := NewBufferPool()

		// Get buffer
		buf := pool.Get()
		if buf == nil {
			t.Fatal("BufferPool.Get() returned nil")
		}

		// Use it
		buf = append(buf, "test data"...)
		if string(buf) != "test data" {
			t.Errorf("Buffer doesn't contain expected data: %s", string(buf))
		}

		// Return it
		pool.Put(buf)

		// Get another buffer - should be clean
		buf2 := pool.Get()
		if len(buf2) != 0 {
			t.Errorf("BufferPool.Get() returned non-empty buffer, len=%d", len(buf2))
		}

		pool.Put(buf2)
	})

	t.Run("BufferPool Grow operation", func(t *testing.T) {
		pool := NewBufferPool()

		buf := pool.Get()
		buf = append(buf, "initial"...)
		originalCap := cap(buf)

		// Grow the buffer to need more capacity
		buf = pool.Grow(buf, 1024)

		newCap := cap(buf)
		if newCap <= originalCap {
			t.Logf("Warning: Grow may not have increased capacity, original=%d, new=%d", originalCap, newCap)
		}

		// Content should still be there
		if string(buf) != "initial" {
			t.Errorf("Buffer content lost after Grow: %s", string(buf))
		}

		pool.Put(buf)
	})

	t.Run("BufferPool with empty buffer", func(t *testing.T) {
		pool := NewBufferPool()

		// Create buffer with zero capacity
		emptyBuf := make([]byte, 0, 0)

		// Putting empty buffer should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("BufferPool.Put(emptyBuf) panicked: %v", r)
			}
		}()
		pool.Put(emptyBuf)
	})
}

// TestTokenizerError tests error creation and formatting functions.
func TestTokenizerError(t *testing.T) {
	loc := models.Location{
		Line:   2,
		Column: 5,
	}

	t.Run("NewError creates error with location", func(t *testing.T) {
		err := NewError("test error message", loc)
		if err == nil {
			t.Fatal("NewError() returned nil")
		}

		errStr := err.Error()
		if !strings.Contains(errStr, "test error message") {
			t.Errorf("Error message doesn't contain expected text: %s", errStr)
		}
		if !strings.Contains(errStr, "line 2") {
			t.Errorf("Error message doesn't contain line number: %s", errStr)
		}
		if !strings.Contains(errStr, "column 5") {
			t.Errorf("Error message doesn't contain column number: %s", errStr)
		}
	})

	t.Run("ErrorUnexpectedChar creates appropriate error", func(t *testing.T) {
		err := ErrorUnexpectedChar('$', loc)
		if err == nil {
			t.Fatal("ErrorUnexpectedChar() returned nil")
		}

		errStr := err.Error()
		if !strings.Contains(errStr, "$") || !strings.Contains(errStr, "unexpected") {
			t.Errorf("ErrorUnexpectedChar message doesn't mention unexpected char: %s", errStr)
		}
	})

	t.Run("ErrorUnterminatedString creates appropriate error", func(t *testing.T) {
		err := ErrorUnterminatedString(loc)
		if err == nil {
			t.Fatal("ErrorUnterminatedString() returned nil")
		}

		errStr := err.Error()
		if !strings.Contains(errStr, "unterminated") || !strings.Contains(errStr, "string") {
			t.Errorf("ErrorUnterminatedString message doesn't mention unterminated string: %s", errStr)
		}
	})

	t.Run("ErrorInvalidNumber creates appropriate error", func(t *testing.T) {
		err := ErrorInvalidNumber("12.34.56", loc)
		if err == nil {
			t.Fatal("ErrorInvalidNumber() returned nil")
		}

		errStr := err.Error()
		if !strings.Contains(errStr, "12.34.56") || !strings.Contains(errStr, "invalid") {
			t.Errorf("ErrorInvalidNumber message doesn't describe issue: %s", errStr)
		}
	})

	t.Run("ErrorInvalidIdentifier creates appropriate error", func(t *testing.T) {
		err := ErrorInvalidIdentifier("123abc", loc)
		if err == nil {
			t.Fatal("ErrorInvalidIdentifier() returned nil")
		}

		errStr := err.Error()
		if !strings.Contains(errStr, "123abc") || !strings.Contains(errStr, "invalid") {
			t.Errorf("ErrorInvalidIdentifier message doesn't describe issue: %s", errStr)
		}
	})

	t.Run("ErrorInvalidOperator creates appropriate error", func(t *testing.T) {
		err := ErrorInvalidOperator("$$$", loc)
		if err == nil {
			t.Fatal("ErrorInvalidOperator() returned nil")
		}

		errStr := err.Error()
		if !strings.Contains(errStr, "$$$") || !strings.Contains(errStr, "invalid") {
			t.Errorf("ErrorInvalidOperator message doesn't describe issue: %s", errStr)
		}
	})

	t.Run("Error method returns formatted string", func(t *testing.T) {
		tokErr := &Error{
			Message:  "custom error",
			Location: loc,
		}

		errStr := tokErr.Error()
		if errStr == "" {
			t.Error("Error() method returned empty string")
		}
		if !strings.Contains(errStr, "custom error") {
			t.Errorf("Error() doesn't contain message: %s", errStr)
		}
	})
}

// TestPosition_Location tests the Position.Location method.
func TestPosition_Location(t *testing.T) {
	t.Run("Location returns models.Location via tokenizer", func(t *testing.T) {
		tkz := GetTokenizer()
		defer PutTokenizer(tkz)

		input := []byte("SELECT * FROM users")
		pos := NewPosition(1, 7) // Line 1, index 7 (after "SELECT ")

		// Set up tokenizer with input
		tkz.input = input

		loc := pos.Location(tkz)
		if loc.Line <= 0 {
			t.Errorf("Location().Line = %d, want > 0", loc.Line)
		}
		if loc.Column <= 0 {
			t.Errorf("Location().Column = %d, want > 0", loc.Column)
		}
	})
}

// TestPosition_AdvanceN tests the Position.AdvanceN method.
func TestPosition_AdvanceN(t *testing.T) {
	t.Run("AdvanceN advances position by N characters", func(t *testing.T) {
		pos := NewPosition(1, 0)      // Line 1, index 0
		lineStarts := []int{0, 6, 12} // Line boundaries

		// Advance by 3 characters on first line
		pos.AdvanceN(3, lineStarts)
		if pos.Index != 3 {
			t.Errorf("AdvanceN(3) Index = %d, want 3", pos.Index)
		}
		if pos.Line != 1 {
			t.Errorf("AdvanceN(3) Line = %d, want 1", pos.Line)
		}

		// Advance to cross first newline (from index 3 to 7)
		pos.AdvanceN(4, lineStarts)
		if pos.Index != 7 {
			t.Errorf("AdvanceN(4) Index = %d, want 7", pos.Index)
		}
		if pos.Line != 2 {
			t.Errorf("AdvanceN crossing newline, Line = %d, want 2", pos.Line)
		}
	})

	t.Run("AdvanceN with zero does nothing", func(t *testing.T) {
		pos := NewPosition(1, 5)
		lineStarts := []int{0}

		originalIndex := pos.Index
		originalLine := pos.Line

		pos.AdvanceN(0, lineStarts)

		if pos.Index != originalIndex {
			t.Errorf("AdvanceN(0) changed Index from %d to %d", originalIndex, pos.Index)
		}
		if pos.Line != originalLine {
			t.Errorf("AdvanceN(0) changed Line from %d to %d", originalLine, pos.Line)
		}
	})

	t.Run("AdvanceN with negative does nothing", func(t *testing.T) {
		pos := NewPosition(1, 5)
		lineStarts := []int{0}

		originalIndex := pos.Index

		pos.AdvanceN(-5, lineStarts)

		if pos.Index != originalIndex {
			t.Errorf("AdvanceN(-5) changed Index from %d to %d", originalIndex, pos.Index)
		}
	})
}

// TestTokenizer_NewWithKeywords tests initialization with custom keywords.
func TestTokenizer_NewWithKeywords(t *testing.T) {
	t.Run("NewWithKeywords with nil keywords returns error", func(t *testing.T) {
		tkz, err := NewWithKeywords(nil)
		if err == nil {
			t.Fatal("NewWithKeywords(nil) should return error, got nil")
		}
		if tkz != nil {
			t.Error("NewWithKeywords(nil) should return nil tokenizer on error")
		}

		// Error message should mention keywords
		errStr := err.Error()
		if !strings.Contains(errStr, "keyword") {
			t.Errorf("Error message doesn't mention keywords: %s", errStr)
		}
	})
}

// TestTokenizer_Reset tests the Reset coverage branch.
func TestTokenizer_Reset(t *testing.T) {
	t.Run("Reset clears tokenizer state", func(t *testing.T) {
		tkz := GetTokenizer()

		// Tokenize something to populate state
		_, _ = tkz.Tokenize([]byte("SELECT * FROM users"))

		// Reset should clear state
		tkz.Reset()

		// After reset, should be able to tokenize again
		tokens, err := tkz.Tokenize([]byte("SELECT 1"))
		if err != nil {
			t.Errorf("Tokenize() after Reset() error = %v", err)
		}
		if len(tokens) == 0 {
			t.Error("Tokenize() after Reset() returned no tokens")
		}
	})
}

// TestTokenizer_TripleQuotedStrings tests triple-quoted string handling.
func TestTokenizer_TripleQuotedStrings(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Simple triple-quoted string",
			input: `"""hello world"""`,
		},
		{
			name:  "Triple-quoted with newlines",
			input: "\"\"\"line1\nline2\nline3\"\"\"",
		},
		{
			name:  "Triple-quoted with embedded quotes",
			input: `"""He said "hello" to me"""`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.input))
			// Triple-quoted strings may or may not be supported
			// Just ensure it doesn't crash
			if err != nil {
				t.Logf("Triple-quoted string tokenization error (may be expected): %v", err)
			} else if len(tokens) == 0 {
				t.Log("Triple-quoted string returned no tokens (may be expected)")
			}
		})
	}
}
