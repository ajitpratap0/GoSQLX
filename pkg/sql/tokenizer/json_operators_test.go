// Package tokenizer - json_operators_test.go
// Tests for JSON/JSONB operator tokenization (PostgreSQL)

package tokenizer

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

func TestTokenizer_JSONArrowOperators(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []models.TokenType
	}{
		{
			name:  "Arrow operator ->",
			input: "data -> 'key'",
			expected: []models.TokenType{
				models.TokenTypeIdentifier,         // data
				models.TokenTypeArrow,              // ->
				models.TokenTypeSingleQuotedString, // 'key'
			},
		},
		{
			name:  "Long arrow operator ->>",
			input: "data ->> 'key'",
			expected: []models.TokenType{
				models.TokenTypeIdentifier,         // data
				models.TokenTypeLongArrow,          // ->>
				models.TokenTypeSingleQuotedString, // 'key'
			},
		},
		{
			name:  "Mixed arrow operators",
			input: "data -> 'a' ->> 'b'",
			expected: []models.TokenType{
				models.TokenTypeIdentifier,         // data
				models.TokenTypeArrow,              // ->
				models.TokenTypeSingleQuotedString, // 'a'
				models.TokenTypeLongArrow,          // ->>
				models.TokenTypeSingleQuotedString, // 'b'
			},
		},
		{
			name:  "Arrow with integer",
			input: "data -> 0",
			expected: []models.TokenType{
				models.TokenTypeIdentifier, // data
				models.TokenTypeArrow,      // ->
				models.TokenTypeNumber,     // 0
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

			// Remove EOF token for comparison
			tokens = tokens[:len(tokens)-1]

			if len(tokens) != len(tt.expected) {
				t.Fatalf("Expected %d tokens, got %d", len(tt.expected), len(tokens))
			}

			for i, expected := range tt.expected {
				if tokens[i].Token.Type != expected {
					t.Errorf("Token %d: expected type %s, got %s (value: %s)",
						i, expected.String(), tokens[i].Token.Type.String(), tokens[i].Token.Value)
				}
			}
		})
	}
}

func TestTokenizer_JSONPathOperators(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []models.TokenType
	}{
		{
			name:  "Hash arrow operator #>",
			input: "data #> '{a,b}'",
			expected: []models.TokenType{
				models.TokenTypeIdentifier,         // data
				models.TokenTypeHashArrow,          // #>
				models.TokenTypeSingleQuotedString, // '{a,b}'
			},
		},
		{
			name:  "Hash long arrow operator #>>",
			input: "data #>> '{a,b}'",
			expected: []models.TokenType{
				models.TokenTypeIdentifier,         // data
				models.TokenTypeHashLongArrow,      // #>>
				models.TokenTypeSingleQuotedString, // '{a,b}'
			},
		},
		{
			name:  "Hash minus operator #-",
			input: "data #- '{a,b}'",
			expected: []models.TokenType{
				models.TokenTypeIdentifier,         // data
				models.TokenTypeHashMinus,          // #-
				models.TokenTypeSingleQuotedString, // '{a,b}'
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

			// Remove EOF token for comparison
			tokens = tokens[:len(tokens)-1]

			if len(tokens) != len(tt.expected) {
				t.Fatalf("Expected %d tokens, got %d", len(tt.expected), len(tokens))
			}

			for i, expected := range tt.expected {
				if tokens[i].Token.Type != expected {
					t.Errorf("Token %d: expected type %s, got %s (value: %s)",
						i, expected.String(), tokens[i].Token.Type.String(), tokens[i].Token.Value)
				}
			}
		})
	}
}

func TestTokenizer_JSONContainmentOperators(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []models.TokenType
	}{
		{
			name:  "Contains operator @>",
			input: "data @> '{\"key\": \"value\"}'",
			expected: []models.TokenType{
				models.TokenTypeIdentifier,         // data
				models.TokenTypeAtArrow,            // @>
				models.TokenTypeSingleQuotedString, // '{"key": "value"}'
			},
		},
		{
			name:  "Is contained by operator <@",
			input: "data <@ '{\"key\": \"value\"}'",
			expected: []models.TokenType{
				models.TokenTypeIdentifier,         // data
				models.TokenTypeArrowAt,            // <@
				models.TokenTypeSingleQuotedString, // '{"key": "value"}'
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

			// Remove EOF token for comparison
			tokens = tokens[:len(tokens)-1]

			if len(tokens) != len(tt.expected) {
				t.Fatalf("Expected %d tokens, got %d", len(tt.expected), len(tokens))
			}

			for i, expected := range tt.expected {
				if tokens[i].Token.Type != expected {
					t.Errorf("Token %d: expected type %s, got %s (value: %s)",
						i, expected.String(), tokens[i].Token.Type.String(), tokens[i].Token.Value)
				}
			}
		})
	}
}

func TestTokenizer_JSONExistenceOperators(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []models.TokenType
	}{
		{
			name:  "Key exists operator ?",
			input: "data ? 'key'",
			expected: []models.TokenType{
				models.TokenTypeIdentifier,         // data
				models.TokenTypeQuestion,           // ?
				models.TokenTypeSingleQuotedString, // 'key'
			},
		},
		{
			name:  "Any keys exist operator ?|",
			input: "data ?| ARRAY['a','b']",
			expected: []models.TokenType{
				models.TokenTypeIdentifier,         // data
				models.TokenTypeQuestionPipe,       // ?|
				models.TokenTypeArray,              // ARRAY (now a keyword)
				models.TokenTypeLBracket,           // [
				models.TokenTypeSingleQuotedString, // 'a'
				models.TokenTypeComma,              // ,
				models.TokenTypeSingleQuotedString, // 'b'
				models.TokenTypeRBracket,           // ]
			},
		},
		{
			name:  "All keys exist operator ?&",
			input: "data ?& ARRAY['a','b']",
			expected: []models.TokenType{
				models.TokenTypeIdentifier,         // data
				models.TokenTypeQuestionAnd,        // ?&
				models.TokenTypeArray,              // ARRAY (now a keyword)
				models.TokenTypeLBracket,           // [
				models.TokenTypeSingleQuotedString, // 'a'
				models.TokenTypeComma,              // ,
				models.TokenTypeSingleQuotedString, // 'b'
				models.TokenTypeRBracket,           // ]
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

			// Remove EOF token for comparison
			tokens = tokens[:len(tokens)-1]

			if len(tokens) != len(tt.expected) {
				t.Fatalf("Expected %d tokens, got %d", len(tt.expected), len(tokens))
			}

			for i, expected := range tt.expected {
				if tokens[i].Token.Type != expected {
					t.Errorf("Token %d: expected type %s, got %s (value: %s)",
						i, expected.String(), tokens[i].Token.Type.String(), tokens[i].Token.Value)
				}
			}
		})
	}
}

func TestTokenizer_JSONOperatorsWithSpacing(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []models.TokenType
	}{
		{
			name:  "Arrow without spaces",
			input: "data->'key'",
			expected: []models.TokenType{
				models.TokenTypeIdentifier,         // data
				models.TokenTypeArrow,              // ->
				models.TokenTypeSingleQuotedString, // 'key'
			},
		},
		{
			name:  "Long arrow without spaces",
			input: "data->>'key'",
			expected: []models.TokenType{
				models.TokenTypeIdentifier,         // data
				models.TokenTypeLongArrow,          // ->>
				models.TokenTypeSingleQuotedString, // 'key'
			},
		},
		{
			name:  "Hash arrow without spaces",
			input: "data#>'{a}'",
			expected: []models.TokenType{
				models.TokenTypeIdentifier,         // data
				models.TokenTypeHashArrow,          // #>
				models.TokenTypeSingleQuotedString, // '{a}'
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

			// Remove EOF token for comparison
			tokens = tokens[:len(tokens)-1]

			if len(tokens) != len(tt.expected) {
				t.Fatalf("Expected %d tokens, got %d", len(tt.expected), len(tokens))
			}

			for i, expected := range tt.expected {
				if tokens[i].Token.Type != expected {
					t.Errorf("Token %d: expected type %s, got %s (value: %s)",
						i, expected.String(), tokens[i].Token.Type.String(), tokens[i].Token.Value)
				}
			}
		})
	}
}

func TestTokenizer_JSONOperatorsVsOtherOperators(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []models.TokenType
	}{
		{
			name:  "Distinguish -> from -",
			input: "a - b -> c",
			expected: []models.TokenType{
				models.TokenTypeIdentifier, // a
				models.TokenTypeMinus,      // -
				models.TokenTypeIdentifier, // b
				models.TokenTypeArrow,      // ->
				models.TokenTypeIdentifier, // c
			},
		},
		{
			name:  "Distinguish #> from #",
			input: "a # b #> c",
			expected: []models.TokenType{
				models.TokenTypeIdentifier, // a
				models.TokenTypeSharp,      // #
				models.TokenTypeIdentifier, // b
				models.TokenTypeHashArrow,  // #>
				models.TokenTypeIdentifier, // c
			},
		},
		{
			name:  "Distinguish <@ from <",
			input: "a < b <@ c",
			expected: []models.TokenType{
				models.TokenTypeIdentifier, // a
				models.TokenTypeLt,         // <
				models.TokenTypeIdentifier, // b
				models.TokenTypeArrowAt,    // <@
				models.TokenTypeIdentifier, // c
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

			// Remove EOF token for comparison
			tokens = tokens[:len(tokens)-1]

			if len(tokens) != len(tt.expected) {
				t.Fatalf("Expected %d tokens, got %d", len(tt.expected), len(tokens))
			}

			for i, expected := range tt.expected {
				if tokens[i].Token.Type != expected {
					t.Errorf("Token %d: expected type %s, got %s (value: %s)",
						i, expected.String(), tokens[i].Token.Type.String(), tokens[i].Token.Value)
				}
			}
		})
	}
}

func TestTokenizer_JSONOperatorsInComplexQueries(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "JSON in SELECT",
			input:   "SELECT data -> 'name', data ->> 'age' FROM users",
			wantErr: false,
		},
		{
			name:    "JSON in WHERE with comparison",
			input:   "SELECT * FROM users WHERE data -> 'age' > 18",
			wantErr: false,
		},
		{
			name:    "JSON containment in WHERE",
			input:   "SELECT * FROM users WHERE data @> '{\"active\": true}'",
			wantErr: false,
		},
		{
			name:    "JSON path operations",
			input:   "SELECT data #> '{address,city}', data #>> '{address,zipcode}' FROM users",
			wantErr: false,
		},
		{
			name:    "JSON existence checks",
			input:   "SELECT * FROM users WHERE data ? 'email' AND data ?| array['phone', 'mobile']",
			wantErr: false,
		},
		{
			name:    "Chained JSON operators",
			input:   "SELECT data -> 'user' -> 'profile' ->> 'name' FROM users",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("Tokenize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Just verify we got tokens
				if len(tokens) == 0 {
					t.Error("Expected tokens but got none")
				}
			}
		})
	}
}
