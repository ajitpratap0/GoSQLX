package tokenizer

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
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
				{models.TokenTypeWord, "a"},
				{models.TokenTypePlus, "+"},
				{models.TokenTypeWord, "b"},
				{models.TokenTypeOperator, "*"},
				{models.TokenTypeWord, "c"},
				{models.TokenTypeDiv, "/"},
				{models.TokenTypeWord, "d"},
				{models.TokenTypeMod, "%"},
				{models.TokenTypeWord, "e"},
			},
		},
		{
			input: "x || y",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeWord, "x"},
				{models.TokenTypeStringConcat, "||"},
				{models.TokenTypeWord, "y"},
			},
		},
		{
			input: "data->>'field'",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeWord, "data"},
				{models.TokenTypeArrow, "->"},
				{models.TokenTypeOperator, ">"},
				{models.TokenTypeSingleQuotedString, "field"},
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
			t.Logf("Tokens for %q:", test.input)
			for i, token := range tokens {
				if i < len(tokens)-1 { // Skip EOF
					t.Logf("Token %d: Type=%v, Value=%q", i, token.Token.Type, token.Token.Value)
				}
			}
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
				{models.TokenTypeWord, "x"},
				{models.TokenTypeDoubleColon, "::"},
				{models.TokenTypeWord, "text"},
			},
		},
		{
			input: "data=>>'field'",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeWord, "data"},
				{models.TokenTypeRArrow, "=>"},
				{models.TokenTypeOperator, ">"},
				{models.TokenTypeSingleQuotedString, "field"},
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
			t.Logf("Tokens for %q:", test.input)
			for i, token := range tokens {
				if i < len(tokens)-1 { // Skip EOF
					t.Logf("Token %d: Type=%v, Value=%q", i, token.Token.Type, token.Token.Value)
				}
			}
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
