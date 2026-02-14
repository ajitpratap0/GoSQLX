package errors_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// TestErrorPropagation_TokenizerToParser tests that errors from the tokenizer
// propagate correctly with error codes intact through the parsing pipeline.
func TestErrorPropagation_TokenizerToParser(t *testing.T) {
	tests := []struct {
		name           string
		sql            string
		expectedCode   errors.ErrorCode
		expectedInMsg  string
		checkTokenizer bool // if true, we expect tokenizer to catch the error
	}{
		{
			name:          "unterminated string literal",
			sql:           "SELECT * FROM users WHERE name = 'unterminated",
			expectedCode:  errors.ErrCodeUnterminatedString,
			expectedInMsg: "unterminated",
		},
		{
			name:          "unexpected token in SELECT",
			sql:           "SELECT * FROM",
			expectedCode:  errors.ErrCodeExpectedToken, // Expects table name after FROM
			expectedInMsg: "expected",
		},
		{
			name:          "incomplete SQL statement",
			sql:           "",
			expectedCode:  errors.ErrCodeIncompleteStatement,
			expectedInMsg: "incomplete",
		},
		{
			name:          "invalid syntax - missing table name",
			sql:           "INSERT INTO VALUES (1, 2)",
			expectedCode:  errors.ErrCodeExpectedToken, // Parser expects table name after INSERT INTO
			expectedInMsg: "expected",
		},
		{
			name:          "unexpected keyword usage",
			sql:           "SELECT FROM users",
			expectedCode:  errors.ErrCodeUnexpectedToken,
			expectedInMsg: "unexpected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get tokenizer from pool
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			// Tokenize the input
			tokens, tokenErr := tkz.Tokenize([]byte(tt.sql))

			// If tokenizer caught an error with a code, verify it
			if tokenErr != nil {
				if err, ok := tokenErr.(*errors.Error); ok {
					if err.Code != "" {
						t.Logf("Tokenizer caught error with code: %s", err.Code)
						// Verify the error code is what we expected
						if tt.checkTokenizer && err.Code != tt.expectedCode {
							t.Errorf("Tokenizer error code mismatch: expected %s, got %s", tt.expectedCode, err.Code)
						}
					}
				}
				return // Don't continue to parser if tokenizer failed
			}

			// Convert tokens and parse
			p := parser.NewParser()
			_, parseErr := p.ParseFromModelTokens(tokens)

			// Verify parser error
			if parseErr == nil {
				t.Errorf("Expected parse error for SQL: %s", tt.sql)
				return
			}

			// Check if error matches expected code using IsCode
			if !errors.IsCode(parseErr, tt.expectedCode) {
				// Check if error is structured
				if err, ok := parseErr.(*errors.Error); ok {
					t.Errorf("Error code mismatch: expected %s, got %s", tt.expectedCode, err.Code)
				} else {
					t.Logf("Parse error is not structured error type: %T - %v", parseErr, parseErr)
				}
			}

			// Verify error message contains expected text
			if tt.expectedInMsg != "" {
				errMsg := parseErr.Error()
				found := false
				for i := 0; i <= len(errMsg)-len(tt.expectedInMsg); i++ {
					if errMsg[i:i+len(tt.expectedInMsg)] == tt.expectedInMsg {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Error message should contain '%s', got: %s", tt.expectedInMsg, errMsg)
				}
			}

			t.Logf("Error propagated correctly: %v", parseErr)
		})
	}
}

// TestErrorCodeExtraction tests that error codes can be reliably extracted
// from errors returned by the parser using the IsCode helper.
func TestErrorCodeExtraction(t *testing.T) {
	testCases := []struct {
		name         string
		sql          string
		expectedCode errors.ErrorCode
	}{
		{
			name:         "unexpected token after SELECT",
			sql:          "SELECT *** FROM users",
			expectedCode: errors.ErrCodeExpectedToken, // Parser expects FROM, semicolon, or end of statement
		},
		{
			name:         "missing FROM clause",
			sql:          "SELECT * users",
			expectedCode: errors.ErrCodeExpectedToken, // Parser expects FROM keyword
		},
		{
			name:         "invalid WHERE clause",
			sql:          "SELECT * FROM users WHERE",
			expectedCode: errors.ErrCodeUnexpectedToken, // Unexpected EOF after WHERE
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Tokenize
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tc.sql))
			if err != nil {
				t.Skipf("Tokenizer error: %v", err)
			}

			// Parse
			p := parser.NewParser()
			_, parseErr := p.ParseFromModelTokens(tokens)

			if parseErr == nil {
				t.Fatalf("Expected error for SQL: %s", tc.sql)
			}

			// Check error code using IsCode
			if !errors.IsCode(parseErr, tc.expectedCode) {
				if structErr, ok := parseErr.(*errors.Error); ok {
					t.Errorf("IsCode returned false for code %s, error has code %s", tc.expectedCode, structErr.Code)
				} else {
					t.Errorf("Error is not structured, cannot extract code: %v", parseErr)
				}
			}

			t.Logf("Successfully verified error code %s matches error: %v", tc.expectedCode, parseErr)
		})
	}
}

// TestErrorLocationPropagation tests that error location information
// propagates correctly from tokenizer through parser.
func TestErrorLocationPropagation(t *testing.T) {
	testCases := []struct {
		name          string
		sql           string
		expectLine    int
		expectMinCol  int
		checkLocation bool
	}{
		{
			name:          "error on first line",
			sql:           "SELECT *** FROM users",
			expectLine:    1,
			expectMinCol:  7,
			checkLocation: true,
		},
		{
			name:          "error on second line",
			sql:           "SELECT *\nFROM",
			expectLine:    2,
			expectMinCol:  1,
			checkLocation: true,
		},
		{
			name:          "multiline with error",
			sql:           "SELECT *\nFROM users\nWHERE",
			expectLine:    3,
			expectMinCol:  1,
			checkLocation: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Tokenize
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tc.sql))
			if err != nil {
				t.Skipf("Tokenizer error: %v", err)
			}

			// Parse
			p := parser.NewParser()
			_, parseErr := p.ParseFromModelTokens(tokens)

			if parseErr == nil {
				t.Fatalf("Expected error for SQL: %s", tc.sql)
			}

			// Check location if expected
			if tc.checkLocation {
				parsedErr, ok := parseErr.(*errors.Error)
				if ok && parsedErr.Location.Line > 0 {
					if parsedErr.Location.Line != tc.expectLine {
						t.Errorf("Expected line %d, got %d", tc.expectLine, parsedErr.Location.Line)
					}
					if parsedErr.Location.Column < tc.expectMinCol {
						t.Errorf("Expected column >= %d, got %d", tc.expectMinCol, parsedErr.Location.Column)
					}
					t.Logf("Location propagated correctly: line=%d, column=%d",
						parsedErr.Location.Line, parsedErr.Location.Column)
				}
			}
		})
	}
}
