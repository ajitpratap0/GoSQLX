package tokenizer

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

func TestTokenizer_ScientificNotation(t *testing.T) {
	tests := []struct {
		input    string
		expected []struct {
			tokenType models.TokenType
			value     string
		}
	}{
		{
			input: "1.23e4",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeNumber, "1.23e4"},
			},
		},
		{
			input: "1.23E+4",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeNumber, "1.23E+4"},
			},
		},
		{
			input: "1.23e-4",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeNumber, "1.23e-4"},
			},
		},
	}

	for _, test := range tests {
		tokenizer, err := New()
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		tokens, err := tokenizer.Tokenize([]byte(test.input))
		if err != nil {
			t.Fatalf("Tokenize() error = %v", err)
		}

		// Debug: Print raw tokens before adjustment
		t.Logf("Raw tokens for input: %q", test.input)
		for i, token := range tokens {
			if i < len(tokens)-1 { // Skip EOF
				t.Logf("  Token %d: Type=%d, Value=%q, Quote=%c", i, token.Token.Type, token.Token.Value, token.Token.Quote)
			}
		}

		if len(tokens)-1 != len(test.expected) { // -1 for EOF
			t.Fatalf("wrong number of tokens for %q, got %d, expected %d", test.input, len(tokens)-1, len(test.expected))
		}
		for i, exp := range test.expected {
			if tokens[i].Token.Type != exp.tokenType {
				t.Errorf("wrong type for token %d in %q, got %v, expected %v", i, test.input, tokens[i].Token.Type, exp.tokenType)
			}
			if tokens[i].Token.Value != exp.value {
				t.Errorf("wrong value for token %d in %q, got %v, expected %v", i, test.input, tokens[i].Token.Value, exp.value)
			}
		}
	}
}

func TestTokenizer_UnicodeIdentifiers(t *testing.T) {
	tests := []struct {
		input    string
		expected []struct {
			tokenType models.TokenType
			value     string
		}
	}{
		{
			input: "über",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeIdentifier, "über"},
			},
		},
		{
			input: "café",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeIdentifier, "café"},
			},
		},
		{
			input: "SELECT * FROM \"café\" WHERE name = \u2018test\u2019",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeSelect, "SELECT"},
				{models.TokenTypeMul, "*"},
				{models.TokenTypeFrom, "FROM"},
				{models.TokenTypeDoubleQuotedString, "café"},
				{models.TokenTypeWhere, "WHERE"},
				{models.TokenTypeIdentifier, "name"},
				{models.TokenTypeEq, "="},
				{models.TokenTypeSingleQuotedString, "test"},
			},
		},
	}

	for _, test := range tests {
		tokenizer, err := New()
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		tokens, err := tokenizer.Tokenize([]byte(test.input))
		if err != nil {
			t.Fatalf("Tokenize() error = %v", err)
		}

		// Debug: Print raw tokens before adjustment
		t.Logf("Raw tokens for input: %q", test.input)
		for i, token := range tokens {
			if i < len(tokens)-1 { // Skip EOF
				t.Logf("  Token %d: Type=%d, Value=%q, Quote=%c", i, token.Token.Type, token.Token.Value, token.Token.Quote)
			}
		}

		if len(tokens)-1 != len(test.expected) { // -1 for EOF
			t.Fatalf("wrong number of tokens for %q, got %d, expected %d", test.input, len(tokens)-1, len(test.expected))
		}
		for i, exp := range test.expected {
			if tokens[i].Token.Type != exp.tokenType {
				t.Errorf("wrong type for token %d in %q, got %v, expected %v", i, test.input, tokens[i].Token.Type, exp.tokenType)
			}
			if tokens[i].Token.Value != exp.value {
				t.Errorf("wrong value for token %d in %q, got %v, expected %v", i, test.input, tokens[i].Token.Value, exp.value)
			}
		}
	}
}

func TestTokenizer_BasicSelect(t *testing.T) {
	input := "SELECT id FROM users;"
	tokenizer, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	tokens, err := tokenizer.Tokenize([]byte(input))
	if err != nil {
		t.Fatalf("Tokenize() error = %v", err)
	}

	// Adjust token types for test compatibility

	expected := []struct {
		tokenType models.TokenType
		value     string
	}{
		{models.TokenTypeSelect, "SELECT"},
		{models.TokenTypeIdentifier, "id"},
		{models.TokenTypeFrom, "FROM"},
		{models.TokenTypeIdentifier, "users"},
		{models.TokenTypeSemicolon, ";"},
	}

	if len(tokens)-1 != len(expected) { // -1 for EOF
		t.Fatalf("wrong number of tokens, got %d, expected %d", len(tokens)-1, len(expected))
	}

	for i, exp := range expected {
		if tokens[i].Token.Type != exp.tokenType {
			t.Errorf("wrong type for token %d, got %v, expected %v", i, tokens[i].Token.Type, exp.tokenType)
		}
		if tokens[i].Token.Value != exp.value {
			t.Errorf("wrong value for token %d, got %v, expected %v", i, tokens[i].Token.Value, exp.value)
		}
	}
}

func TestTokenizer_UnicodeQuotes(t *testing.T) {
	// Print token type constants for debugging
	t.Logf("TokenTypeWord = %d", models.TokenTypeWord)
	t.Logf("TokenTypeSingleQuotedString = %d", models.TokenTypeSingleQuotedString)
	t.Logf("TokenTypeDoubleQuotedString = %d", models.TokenTypeDoubleQuotedString)
	t.Logf("TokenTypeString = %d", models.TokenTypeString)
	t.Logf("Unicode quotes: \u201C = %q, \u201D = %q, \u00AB = %q, \u00BB = %q", '\u201C', '\u201D', '\u00AB', '\u00BB')

	tests := []struct {
		input    string
		expected []struct {
			tokenType models.TokenType
			value     string
		}
	}{
		{
			// Using Unicode left/right double quotation marks (U+201C, U+201D)
			input: "SELECT * FROM \u201Cusers\u201D",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeSelect, "SELECT"},
				{models.TokenTypeMul, "*"},
				{models.TokenTypeFrom, "FROM"},
				{models.TokenTypeDoubleQuotedString, "users"},
			},
		},
		{
			input: "SELECT \u2018name\u2019 FROM users",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeSelect, "SELECT"},
				{models.TokenTypeSingleQuotedString, "name"},
				{models.TokenTypeFrom, "FROM"},
				{models.TokenTypeIdentifier, "users"},
			},
		},
		{
			input: "SELECT * FROM users WHERE name = \u00ABJohn\u00BB",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeSelect, "SELECT"},
				{models.TokenTypeMul, "*"},
				{models.TokenTypeFrom, "FROM"},
				{models.TokenTypeIdentifier, "users"},
				{models.TokenTypeWhere, "WHERE"},
				{models.TokenTypeIdentifier, "name"},
				{models.TokenTypeEq, "="},
				{models.TokenTypeSingleQuotedString, "John"},
			},
		},
	}

	for _, test := range tests {
		tokenizer, err := New()
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		tokens, err := tokenizer.Tokenize([]byte(test.input))
		if err != nil {
			t.Fatalf("Tokenize() error = %v", err)
		}

		// Debug: Print raw tokens before adjustment
		t.Logf("Raw tokens for input: %q", test.input)
		for i, token := range tokens {
			if i < len(tokens)-1 { // Skip EOF
				t.Logf("  Token %d: Type=%d, Value=%q, Quote=%c", i, token.Token.Type, token.Token.Value, token.Token.Quote)
			}
		}

		if len(tokens)-1 != len(test.expected) { // -1 for EOF
			t.Fatalf("wrong number of tokens for %q, got %d, expected %d", test.input, len(tokens)-1, len(test.expected))
		}
		for i, exp := range test.expected {
			if tokens[i].Token.Type != exp.tokenType {
				t.Errorf("wrong type for token %d in %q, got %v, expected %v", i, test.input, tokens[i].Token.Type, exp.tokenType)
			}
			if tokens[i].Token.Value != exp.value {
				t.Errorf("wrong value for token %d in %q, got %v, expected %v", i, test.input, tokens[i].Token.Value, exp.value)
			}
		}
	}
}

func TestTokenizer_MultiLine(t *testing.T) {
	input := `
SELECT 
    id,
    name,
    age
FROM 
    users
WHERE
    age > 18
    AND name LIKE 'J%'
ORDER BY
    name ASC;
`
	tokenizer, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	tokens, err := tokenizer.Tokenize([]byte(input))
	if err != nil {
		t.Fatalf("Tokenize() error = %v", err)
	}

	// Debug: Print raw tokens
	t.Logf("Raw tokens for input: MultiLine SQL query")
	for i, token := range tokens {
		if i < len(tokens)-1 { // Skip EOF
			t.Logf("  Token %d: Type=%d, Value=%q, Quote=%c", i, token.Token.Type, token.Token.Value, token.Token.Quote)
		}
	}

	expected := []struct {
		tokenType models.TokenType
		value     string
	}{
		{models.TokenTypeSelect, "SELECT"},
		{models.TokenTypeIdentifier, "id"},
		{models.TokenTypeComma, ","},
		{models.TokenTypeIdentifier, "name"},
		{models.TokenTypeComma, ","},
		{models.TokenTypeIdentifier, "age"},
		{models.TokenTypeFrom, "FROM"},
		{models.TokenTypeIdentifier, "users"},
		{models.TokenTypeWhere, "WHERE"},
		{models.TokenTypeIdentifier, "age"},
		{models.TokenTypeGt, ">"},
		{models.TokenTypeNumber, "18"},
		{models.TokenTypeAnd, "AND"},
		{models.TokenTypeIdentifier, "name"},
		{models.TokenTypeLike, "LIKE"},
		{models.TokenTypeSingleQuotedString, "J%"},
		{models.TokenTypeOrderBy, "ORDER BY"}, // Combined token for ORDER BY
		{models.TokenTypeIdentifier, "name"},
		{models.TokenTypeAsc, "ASC"},
		{models.TokenTypeSemicolon, ";"},
	}

	if len(tokens)-1 != len(expected) { // -1 for EOF
		t.Fatalf("wrong number of tokens, got %d, expected %d", len(tokens)-1, len(expected))
	}

	// Debug: Print tokens
	t.Logf("Tokens for comparison:")
	for i, token := range tokens {
		if i < len(tokens)-1 && i < len(expected) { // Skip EOF
			t.Logf("  Token %d: Type=%d, Value=%q, Expected Type=%d",
				i, token.Token.Type, token.Token.Value, expected[i].tokenType)
		}
	}

	for i, exp := range expected {
		if tokens[i].Token.Value != exp.value {
			t.Errorf("wrong value for token %d, got %q, expected %q",
				i, tokens[i].Token.Value, exp.value)
		}
		if tokens[i].Token.Type != exp.tokenType {
			t.Errorf("wrong type for token %d, got %v, expected %v",
				i, tokens[i].Token.Type, exp.tokenType)
		}
	}
}

func TestTokenizer_ErrorLocation(t *testing.T) {
	input := `
SELECT 
    id,
    name,
    age
FROM 
    users
WHERE
    age > 18
    AND name LIKE 'J%
ORDER BY
    name ASC;
`
	tokenizer, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = tokenizer.Tokenize([]byte(input))
	if err == nil {
		t.Fatal("expected error for unterminated string literal")
	}

	tokErr, ok := err.(TokenizerError)
	if !ok {
		t.Fatalf("expected TokenizerError, got %T", err)
	}

	if tokErr.Location.Line != 10 {
		t.Errorf("wrong error line, got %d, expected %d", tokErr.Location.Line, 10)
	}

	// Column should point to the start of the string literal
	if tokErr.Location.Column != 16 {
		t.Errorf("wrong error column, got %d, expected %d", tokErr.Location.Column, 16)
	}
}

func TestTokenizer_StringLiteral(t *testing.T) {
	tests := []struct {
		input    string
		expected []struct {
			tokenType models.TokenType
			value     string
		}
	}{
		{
			input: "'Hello, world!'",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeSingleQuotedString, "Hello, world!"},
			},
		},
		{
			input: "'It''s a nice day'",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeSingleQuotedString, "It's a nice day"},
			},
		},
		{
			input: "'Hello\nworld'",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeSingleQuotedString, "Hello\nworld"},
			},
		},
	}

	for _, test := range tests {
		tokenizer, err := New()
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		tokens, err := tokenizer.Tokenize([]byte(test.input))
		if err != nil {
			t.Fatalf("Tokenize() error = %v", err)
		}

		// Debug: Print raw tokens before adjustment
		t.Logf("Raw tokens for input: %q", test.input)
		for i, token := range tokens {
			if i < len(tokens)-1 { // Skip EOF
				t.Logf("  Token %d: Type=%d, Value=%q, Quote=%c", i, token.Token.Type, token.Token.Value, token.Token.Quote)
			}
		}

		if len(tokens)-1 != len(test.expected) { // -1 for EOF
			t.Fatalf("wrong number of tokens for %q, got %d, expected %d", test.input, len(tokens)-1, len(test.expected))
		}
		for i, exp := range test.expected {
			if tokens[i].Token.Type != exp.tokenType {
				t.Errorf("wrong type for token %d in %q, got %v, expected %v", i, test.input, tokens[i].Token.Type, exp.tokenType)
			}
			if tokens[i].Token.Value != exp.value {
				t.Errorf("wrong value for token %d in %q, got %v, expected %v", i, test.input, tokens[i].Token.Value, exp.value)
			}
		}
	}
}
