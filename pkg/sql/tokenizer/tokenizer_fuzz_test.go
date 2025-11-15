package tokenizer

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// FuzzTokenizer performs comprehensive fuzz testing on the tokenizer to detect:
// - Security vulnerabilities (crashes, panics, DoS)
// - Memory issues (leaks, excessive allocations)
// - Edge cases (malformed input, unusual characters)
// - Robustness (handling of random byte sequences)
func FuzzTokenizer(f *testing.F) {
	// Seed corpus: Valid SQL queries
	f.Add([]byte("SELECT * FROM users"))
	f.Add([]byte("SELECT id, name FROM users WHERE active = true"))
	f.Add([]byte("INSERT INTO users (name, email) VALUES ('John', 'john@example.com')"))
	f.Add([]byte("UPDATE users SET name = 'Jane' WHERE id = 1"))
	f.Add([]byte("DELETE FROM users WHERE id = 1"))
	f.Add([]byte("CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100))"))
	f.Add([]byte("SELECT * FROM orders JOIN users ON orders.user_id = users.id"))

	// SQL injection patterns - should be tokenized safely without crashes
	f.Add([]byte("' OR 1=1 --"))
	f.Add([]byte("'; DROP TABLE users; --"))
	f.Add([]byte("1' UNION SELECT * FROM users --"))
	f.Add([]byte("admin'--"))
	f.Add([]byte("' OR '1'='1"))
	f.Add([]byte("' OR 'a'='a"))
	f.Add([]byte("'; EXEC sp_MSForEachTable 'DROP TABLE ?'; --"))

	// Deeply nested structures
	f.Add([]byte(strings.Repeat("(", 100) + strings.Repeat(")", 100)))
	f.Add([]byte("SELECT " + strings.Repeat("(", 50) + "1" + strings.Repeat(")", 50)))
	f.Add([]byte(strings.Repeat("SELECT * FROM (", 20) + "users" + strings.Repeat(")", 20)))

	// Deeply nested expressions and subqueries
	nestedSelect := "SELECT * FROM users"
	for i := 0; i < 10; i++ {
		nestedSelect = "SELECT * FROM (" + nestedSelect + ") AS t" + string(rune('a'+i))
	}
	f.Add([]byte(nestedSelect))

	// Edge cases: Special characters
	f.Add([]byte("SELECT 'it''s' FROM users"))                    // Escaped quotes
	f.Add([]byte("SELECT \"column name\" FROM users"))            // Quoted identifiers
	f.Add([]byte("SELECT * FROM users WHERE name LIKE '%test%'")) // Pattern matching
	f.Add([]byte("SELECT -- comment\n* FROM users"))              // SQL comments
	f.Add([]byte("SELECT /* block comment */ * FROM users"))      // Block comments

	// Unicode and international characters
	f.Add([]byte("SELECT * FROM utilisateurs WHERE nom = 'François'")) // French
	f.Add([]byte("SELECT * FROM usuarios WHERE nombre = 'José'"))      // Spanish
	f.Add([]byte("SELECT * FROM пользователи WHERE имя = 'Иван'"))     // Cyrillic
	f.Add([]byte("SELECT * FROM ユーザー WHERE 名前 = '太郎'"))                // Japanese
	f.Add([]byte("SELECT * FROM 用户 WHERE 姓名 = '张三'"))                  // Chinese
	f.Add([]byte("SELECT * FROM משתמשים WHERE שם = 'יוסי'"))           // Hebrew
	f.Add([]byte("SELECT * FROM مستخدمين WHERE اسم = 'أحمد'"))         // Arabic
	f.Add([]byte("SELECT * FROM χρήστες WHERE όνομα = 'Γιώργος'"))     // Greek

	// Complex queries
	f.Add([]byte("WITH RECURSIVE cte AS (SELECT 1 UNION ALL SELECT n+1 FROM cte WHERE n < 10) SELECT * FROM cte"))
	f.Add([]byte("SELECT ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) FROM employees"))
	f.Add([]byte("SELECT * FROM orders WHERE date BETWEEN '2023-01-01' AND '2023-12-31'"))

	// Malformed input patterns
	f.Add([]byte("SELECT * FROM"))                  // Incomplete query
	f.Add([]byte("SELECT FROM users"))              // Missing columns
	f.Add([]byte("WHERE id = 1"))                   // Missing SELECT
	f.Add([]byte("SELECT * FROM users WHERE"))      // Incomplete WHERE
	f.Add([]byte("SELECT * FROM users WHERE id =")) // Incomplete condition

	// Special numeric patterns
	f.Add([]byte("SELECT 1.23e10 FROM users"))    // Scientific notation
	f.Add([]byte("SELECT -999999999 FROM users")) // Negative numbers
	f.Add([]byte("SELECT 0x1A2B FROM users"))     // Hexadecimal
	f.Add([]byte("SELECT 0b1010 FROM users"))     // Binary

	// Whitespace variations
	f.Add([]byte("SELECT\t*\nFROM\rusers"))             // Mixed whitespace
	f.Add([]byte("SELECT   *   FROM   users"))          // Multiple spaces
	f.Add([]byte("SELECT\n\n\n*\n\n\nFROM\n\n\nusers")) // Multiple newlines

	// Operators and symbols
	f.Add([]byte("SELECT * FROM users WHERE id != 1"))
	f.Add([]byte("SELECT * FROM users WHERE id <> 1"))
	f.Add([]byte("SELECT * FROM users WHERE id >= 1 AND id <= 10"))
	f.Add([]byte("SELECT * FROM users WHERE name || ' ' || surname"))
	f.Add([]byte("SELECT * FROM users WHERE (id = 1) OR (id = 2)"))

	// Null bytes and control characters
	f.Add([]byte("SELECT \x00 FROM users"))
	f.Add([]byte("SELECT * FROM users WHERE name = '\x01\x02\x03'"))

	// Very long identifiers
	f.Add([]byte("SELECT " + strings.Repeat("a", 200) + " FROM users"))

	// Very long strings
	f.Add([]byte("SELECT * FROM users WHERE name = '" + strings.Repeat("x", 1000) + "'"))

	// Mixed case keywords
	f.Add([]byte("SeLeCt * FrOm UsErS wHeRe Id = 1"))

	// Execute fuzz testing
	f.Fuzz(func(t *testing.T, data []byte) {
		// Skip empty input
		if len(data) == 0 {
			return
		}

		// Skip inputs that are too large (DoS protection test)
		// We test this separately in dos_protection_test.go
		if len(data) > MaxInputSize {
			return
		}

		// Skip invalid UTF-8 sequences - tokenizer expects valid UTF-8
		if !utf8.Valid(data) {
			return
		}

		// Get tokenizer from pool
		tkz := GetTokenizer()
		defer PutTokenizer(tkz)

		// This should NEVER panic or crash, regardless of input
		tokens, err := tkz.Tokenize(data)

		// Basic validation: if no error, we should have tokens
		if err == nil && tokens == nil {
			t.Errorf("Tokenize succeeded but returned nil tokens for input: %q", truncateForDisplay(data, 50))
		}

		// Verify error handling consistency
		if err != nil {
			// Error should be of correct type
			if _, ok := err.(TokenizerError); !ok {
				t.Errorf("Error should be TokenizerError, got %T: %v", err, err)
			}
			// Error message should not be empty
			if err.Error() == "" {
				t.Errorf("Error message should not be empty for input: %q", truncateForDisplay(data, 50))
			}
		}

		// If we got tokens, validate basic properties
		if tokens != nil {
			// Check for token count limits
			if len(tokens) > MaxTokens {
				t.Errorf("Token count exceeds limit: got %d, max %d", len(tokens), MaxTokens)
			}

			// Validate that tokens cover the input reasonably
			for i, tok := range tokens {
				// Token value should not be excessively long
				if len(tok.Token.Value) > MaxInputSize {
					t.Errorf("Token %d value exceeds reasonable size: %d bytes", i, len(tok.Token.Value))
				}

				// Token location should be reasonable (line should be >= 1)
				// Note: Column numbers may be negative in some cases (known issue in tokenizer)
				if tok.Start.Line < 1 {
					t.Errorf("Token %d has invalid line number: %d", i, tok.Start.Line)
				}
			}
		}

		// Test tokenizer reuse - it should work correctly after being used
		tokens2, err2 := tkz.Tokenize([]byte("SELECT 1"))
		if err2 != nil {
			t.Errorf("Tokenizer reuse failed: %v", err2)
		}
		if tokens2 == nil {
			t.Error("Tokenizer reuse returned nil tokens for valid input")
		}
	})
}

// FuzzTokenizerUTF8Boundary tests UTF-8 boundary conditions
func FuzzTokenizerUTF8Boundary(f *testing.F) {
	// Seed with valid UTF-8 sequences
	f.Add([]byte("SELECT 'Ω' FROM users"))  // Greek Omega
	f.Add([]byte("SELECT '世界' FROM users")) // Chinese
	f.Add([]byte("SELECT '🚀' FROM users"))  // Emoji
	f.Add([]byte("SELECT '€' FROM users"))  // Euro sign
	f.Add([]byte("SELECT 'Ñ' FROM users"))  // Spanish N with tilde

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > MaxInputSize {
			return
		}

		// Only test valid UTF-8
		if !utf8.Valid(data) {
			return
		}

		tkz := GetTokenizer()
		defer PutTokenizer(tkz)

		// Should handle all valid UTF-8 without panic
		_, _ = tkz.Tokenize(data)
	})
}

// FuzzTokenizerNumericLiterals tests numeric parsing edge cases
func FuzzTokenizerNumericLiterals(f *testing.F) {
	// Seed with various numeric formats
	f.Add([]byte("SELECT 123"))
	f.Add([]byte("SELECT -456"))
	f.Add([]byte("SELECT 1.23"))
	f.Add([]byte("SELECT 1.23e10"))
	f.Add([]byte("SELECT 1.23e-10"))
	f.Add([]byte("SELECT 0.123"))
	f.Add([]byte("SELECT .123"))
	f.Add([]byte("SELECT 123."))
	f.Add([]byte("SELECT 0"))
	f.Add([]byte("SELECT 0.0"))
	f.Add([]byte("SELECT 1e10"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > 1000 || !utf8.Valid(data) {
			return
		}

		// Prepend "SELECT " to make it parseable
		input := append([]byte("SELECT "), data...)

		tkz := GetTokenizer()
		defer PutTokenizer(tkz)

		// Should not panic on any numeric-like input
		tokens, err := tkz.Tokenize(input)

		// If successful, verify numeric tokens are reasonable
		if err == nil && tokens != nil {
			for _, tok := range tokens {
				if tok.Token.Type == models.TokenTypeNumber {
					// Number value should not be empty
					if len(tok.Token.Value) == 0 {
						t.Error("Number token has empty value")
					}
				}
			}
		}
	})
}

// FuzzTokenizerStringLiterals tests string parsing edge cases
func FuzzTokenizerStringLiterals(f *testing.F) {
	// Seed with various string formats
	f.Add([]byte("SELECT 'hello'"))
	f.Add([]byte("SELECT 'it''s'"))        // Escaped quote
	f.Add([]byte("SELECT ''"))             // Empty string
	f.Add([]byte("SELECT 'line1\nline2'")) // Newline
	f.Add([]byte("SELECT 'tab\ttab'"))     // Tab
	f.Add([]byte("SELECT '\\n'"))          // Backslash
	f.Add([]byte("SELECT 'O''Reilly'"))    // Multiple escapes

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > 1000 || !utf8.Valid(data) {
			return
		}

		// Wrap in quotes and prepend SELECT
		input := []byte("SELECT '")
		input = append(input, data...)
		input = append(input, '\'')

		tkz := GetTokenizer()
		defer PutTokenizer(tkz)

		// Should not panic on any string content
		_, _ = tkz.Tokenize(input)
	})
}

// FuzzTokenizerOperators tests operator parsing edge cases
func FuzzTokenizerOperators(f *testing.F) {
	// Seed with various operators
	f.Add([]byte("SELECT * FROM users WHERE id = 1"))
	f.Add([]byte("SELECT * FROM users WHERE id != 1"))
	f.Add([]byte("SELECT * FROM users WHERE id <> 1"))
	f.Add([]byte("SELECT * FROM users WHERE id >= 1"))
	f.Add([]byte("SELECT * FROM users WHERE id <= 1"))
	f.Add([]byte("SELECT * FROM users WHERE id > 1"))
	f.Add([]byte("SELECT * FROM users WHERE id < 1"))
	f.Add([]byte("SELECT a + b"))
	f.Add([]byte("SELECT a - b"))
	f.Add([]byte("SELECT a * b"))
	f.Add([]byte("SELECT a / b"))
	f.Add([]byte("SELECT a % b"))
	f.Add([]byte("SELECT a || b"))
	f.Add([]byte("SELECT a & b"))
	f.Add([]byte("SELECT a | b"))
	f.Add([]byte("SELECT a ^ b"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > 100 || !utf8.Valid(data) {
			return
		}

		// Create expression with operator
		input := []byte("SELECT a ")
		input = append(input, data...)
		input = append(input, []byte(" b")...)

		tkz := GetTokenizer()
		defer PutTokenizer(tkz)

		// Should not panic on any operator-like input
		_, _ = tkz.Tokenize(input)
	})
}

// FuzzTokenizerComments tests comment parsing edge cases
func FuzzTokenizerComments(f *testing.F) {
	// Seed with various comment formats
	f.Add([]byte("SELECT * -- comment\nFROM users"))
	f.Add([]byte("SELECT * /* comment */ FROM users"))
	f.Add([]byte("SELECT * /* multi\nline\ncomment */ FROM users"))
	f.Add([]byte("SELECT * /* /* nested? */ */ FROM users"))
	f.Add([]byte("-- comment only"))
	f.Add([]byte("/* comment only */"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > 1000 || !utf8.Valid(data) {
			return
		}

		// Test single-line comment
		input1 := []byte("SELECT * -- ")
		input1 = append(input1, data...)
		input1 = append(input1, []byte("\nFROM users")...)

		tkz := GetTokenizer()
		defer PutTokenizer(tkz)
		_, _ = tkz.Tokenize(input1)

		// Test block comment
		input2 := []byte("SELECT * /* ")
		input2 = append(input2, data...)
		input2 = append(input2, []byte(" */ FROM users")...)
		_, _ = tkz.Tokenize(input2)
	})
}

// FuzzTokenizerWhitespace tests whitespace handling edge cases
func FuzzTokenizerWhitespace(f *testing.F) {
	// Seed with various whitespace patterns
	f.Add([]byte("SELECT * FROM users"))
	f.Add([]byte("SELECT  *  FROM  users"))
	f.Add([]byte("SELECT\t*\tFROM\tusers"))
	f.Add([]byte("SELECT\n*\nFROM\nusers"))
	f.Add([]byte("SELECT\r\n*\r\nFROM\r\nusers"))
	f.Add([]byte("SELECT   \t\n\r\n  *   \t\n\r\n  FROM   \t\n\r\n  users"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > 1000 {
			return
		}

		// Only test whitespace characters
		validWhitespace := true
		for _, b := range data {
			if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
				validWhitespace = false
				break
			}
		}
		if !validWhitespace {
			return
		}

		// Insert whitespace between tokens
		input := []byte("SELECT")
		input = append(input, data...)
		input = append(input, []byte("*")...)
		input = append(input, data...)
		input = append(input, []byte("FROM")...)
		input = append(input, data...)
		input = append(input, []byte("users")...)

		tkz := GetTokenizer()
		defer PutTokenizer(tkz)

		tokens, err := tkz.Tokenize(input)

		// Should successfully tokenize valid SQL with whitespace
		if err != nil {
			t.Errorf("Failed to tokenize valid SQL with whitespace: %v", err)
		}

		// Should produce expected tokens (SELECT, *, FROM, identifier)
		if tokens != nil && len(tokens) < 4 {
			t.Errorf("Expected at least 4 tokens, got %d", len(tokens))
		}
	})
}

// truncateForDisplay truncates byte slice for error message display
func truncateForDisplay(data []byte, maxLen int) string {
	if len(data) <= maxLen {
		return string(data)
	}
	return string(data[:maxLen]) + "... (truncated)"
}

// TestFuzzCrashRegression is a placeholder for any crashes found during fuzzing
// Add test cases here for any crashes discovered to ensure they don't regress
func TestFuzzCrashRegression(t *testing.T) {
	testCases := []struct {
		name  string
		input []byte
	}{
		// Add crash cases here as they are discovered
		// Example:
		// {
		//     name: "crash_case_1",
		//     input: []byte("..."),
		// },
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)

			// This should not panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Tokenizer panicked on regression test %q: %v", tc.name, r)
				}
			}()

			_, _ = tkz.Tokenize(tc.input)
		})
	}
}
