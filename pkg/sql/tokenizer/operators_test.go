package tokenizer

import (
	"testing"

	"github.com/ajitpratapsingh/GoSQLX/pkg/models"
)

func TestTokenizer_Operators(t *testing.T) {
	tests := []struct {
		input    string
		expected []struct {
			tokenType models.TokenType
			value     string
		}
	}{
		{
			input: "a + b * c / d % e",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeIdentifier, "a"},
				{models.TokenTypeOperator, "+"},
				{models.TokenTypeIdentifier, "b"},
				{models.TokenTypeOperator, "*"},
				{models.TokenTypeIdentifier, "c"},
				{models.TokenTypeOperator, "/"},
				{models.TokenTypeIdentifier, "d"},
				{models.TokenTypeOperator, "%"},
				{models.TokenTypeIdentifier, "e"},
			},
		},
		{
			input: "x || y",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeIdentifier, "x"},
				{models.TokenTypeConcat, "||"},
				{models.TokenTypeIdentifier, "y"},
			},
		},
		{
			input: "data->>'field'",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeIdentifier, "data"},
				{models.TokenTypeArrow, "->"},
				{models.TokenTypeOperator, ">"},
				{models.TokenTypeString, "field"},
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

func TestTokenizer_SpecialOperators(t *testing.T) {
	tests := []struct {
		input    string
		expected []struct {
			tokenType models.TokenType
			value     string
		}
	}{
		{
			input: "x::text",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeIdentifier, "x"},
				{models.TokenTypeCast, "::"},
				{models.TokenTypeIdentifier, "text"},
			},
		},
		{
			input: "data=>>'field'",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeIdentifier, "data"},
				{models.TokenTypeDoubleArrow, "=>"},
				{models.TokenTypeOperator, ">"},
				{models.TokenTypeString, "field"},
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
