// Package tokenizer - positional_params_test.go
// Tests for PostgreSQL positional parameter ($1, $2, etc.) tokenization

package tokenizer

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

func TestTokenizer_PositionalParameters(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []struct {
			tokenType models.TokenType
			value     string
		}
	}{
		{
			name:  "Single positional parameter",
			input: "SELECT * FROM users WHERE id = $1",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeSelect, "SELECT"},
				{models.TokenTypeMul, "*"},
				{models.TokenTypeFrom, "FROM"},
				{models.TokenTypeIdentifier, "users"},
				{models.TokenTypeWhere, "WHERE"},
				{models.TokenTypeIdentifier, "id"},
				{models.TokenTypeEq, "="},
				{models.TokenTypePlaceholder, "$1"},
			},
		},
		{
			name:  "Multiple positional parameters",
			input: "INSERT INTO users (name, email) VALUES ($1, $2)",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeInsert, "INSERT"},
				{models.TokenTypeInto, "INTO"},
				{models.TokenTypeIdentifier, "users"},
				{models.TokenTypeLParen, "("},
				{models.TokenTypeIdentifier, "name"},
				{models.TokenTypeComma, ","},
				{models.TokenTypeIdentifier, "email"},
				{models.TokenTypeRParen, ")"},
				{models.TokenTypeValues, "VALUES"},
				{models.TokenTypeLParen, "("},
				{models.TokenTypePlaceholder, "$1"},
				{models.TokenTypeComma, ","},
				{models.TokenTypePlaceholder, "$2"},
				{models.TokenTypeRParen, ")"},
			},
		},
		{
			name:  "Double digit positional parameter",
			input: "SELECT $10, $11, $12",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeSelect, "SELECT"},
				{models.TokenTypePlaceholder, "$10"},
				{models.TokenTypeComma, ","},
				{models.TokenTypePlaceholder, "$11"},
				{models.TokenTypeComma, ","},
				{models.TokenTypePlaceholder, "$12"},
			},
		},
		{
			name:  "Positional parameter in comparison",
			input: "SELECT * FROM orders WHERE amount > $1 AND status = $2",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeSelect, "SELECT"},
				{models.TokenTypeMul, "*"},
				{models.TokenTypeFrom, "FROM"},
				{models.TokenTypeIdentifier, "orders"},
				{models.TokenTypeWhere, "WHERE"},
				{models.TokenTypeIdentifier, "amount"},
				{models.TokenTypeGt, ">"},
				{models.TokenTypePlaceholder, "$1"},
				{models.TokenTypeAnd, "AND"},
				{models.TokenTypeIdentifier, "status"},
				{models.TokenTypeEq, "="},
				{models.TokenTypePlaceholder, "$2"},
			},
		},
		{
			name:  "Positional parameter without space",
			input: "SELECT name FROM users WHERE id=$1",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeSelect, "SELECT"},
				{models.TokenTypeIdentifier, "name"},
				{models.TokenTypeFrom, "FROM"},
				{models.TokenTypeIdentifier, "users"},
				{models.TokenTypeWhere, "WHERE"},
				{models.TokenTypeIdentifier, "id"},
				{models.TokenTypeEq, "="},
				{models.TokenTypePlaceholder, "$1"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.input))
			if err != nil {
				t.Fatalf("Tokenize() error = %v", err)
			}

			// Remove EOF token
			tokens = tokens[:len(tokens)-1]

			if len(tokens) != len(tt.expected) {
				t.Fatalf("Expected %d tokens, got %d", len(tt.expected), len(tokens))
			}

			for i, exp := range tt.expected {
				if tokens[i].Token.Type != exp.tokenType {
					t.Errorf("Token %d: expected type %s, got %s (value: %s)",
						i, exp.tokenType.String(), tokens[i].Token.Type.String(), tokens[i].Token.Value)
				}
				if tokens[i].Token.Value != exp.value {
					t.Errorf("Token %d: expected value %q, got %q",
						i, exp.value, tokens[i].Token.Value)
				}
			}
		})
	}
}

func TestTokenizer_PositionalParametersEdgeCases(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		wantPlaceholders int
	}{
		{
			name:             "Parameter at start",
			input:            "$1",
			wantPlaceholders: 1,
		},
		{
			name:             "Parameter with leading zero",
			input:            "SELECT $01",
			wantPlaceholders: 1,
		},
		{
			name:             "Large parameter number",
			input:            "SELECT $999",
			wantPlaceholders: 1,
		},
		{
			name:             "Parameters in array",
			input:            "SELECT * FROM t WHERE id IN ($1, $2, $3)",
			wantPlaceholders: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.input))
			if err != nil {
				t.Fatalf("Tokenize() error = %v", err)
			}

			placeholderCount := 0
			for _, tok := range tokens {
				if tok.Token.Type == models.TokenTypePlaceholder {
					placeholderCount++
				}
			}

			if placeholderCount != tt.wantPlaceholders {
				t.Errorf("Expected %d placeholders, got %d", tt.wantPlaceholders, placeholderCount)
			}
		})
	}
}
