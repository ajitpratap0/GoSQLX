package tokenizer

import (
	"testing"

	"github.com/ajitpratapsingh/GoSQLX/pkg/models"
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
				{models.TokenTypeOperator, "*"},
				{models.TokenTypeFrom, "FROM"},
				{models.TokenTypeString, "café"},
				{models.TokenTypeWhere, "WHERE"},
				{models.TokenTypeIdentifier, "name"},
				{models.TokenTypeOperator, "="},
				{models.TokenTypeString, "test"},
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
	tests := []struct {
		input    string
		expected []struct {
			tokenType models.TokenType
			value     string
		}
	}{
		{
			input: "SELECT * FROM \u201Cusers\u201D",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeSelect, "SELECT"},
				{models.TokenTypeOperator, "*"},
				{models.TokenTypeFrom, "FROM"},
				{models.TokenTypeString, "users"},
			},
		},
		{
			input: "SELECT \u2018name\u2019 FROM users",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeSelect, "SELECT"},
				{models.TokenTypeString, "name"},
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
				{models.TokenTypeOperator, "*"},
				{models.TokenTypeFrom, "FROM"},
				{models.TokenTypeIdentifier, "users"},
				{models.TokenTypeWhere, "WHERE"},
				{models.TokenTypeIdentifier, "name"},
				{models.TokenTypeOperator, "="},
				{models.TokenTypeString, "John"},
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
		{models.TokenTypeOperator, ">"},
		{models.TokenTypeNumber, "18"},
		{models.TokenTypeAnd, "AND"},
		{models.TokenTypeIdentifier, "name"},
		{models.TokenTypeLike, "LIKE"},
		{models.TokenTypeString, "J%"},
		{models.TokenTypeOrderBy, "ORDER BY"},
		{models.TokenTypeIdentifier, "name"},
		{models.TokenTypeAsc, "ASC"},
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
				{models.TokenTypeString, "Hello, world!"},
			},
		},
		{
			input: "'It''s a nice day'",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeString, "It's a nice day"},
			},
		},
		{
			input: "'Hello\nworld'",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeString, "Hello\nworld"},
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
