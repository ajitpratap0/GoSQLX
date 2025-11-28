package tokenizer

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

func TestTokenizer_PostgreSQLParameters(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedTokens []models.Token
	}{
		{
			name:  "Simple parameter",
			input: "SELECT @user_id",
			expectedTokens: []models.Token{
				{Type: models.TokenTypeSelect, Value: "SELECT"},
				{Type: models.TokenTypePlaceholder, Value: "@user_id"},
			},
		},
		{
			name:  "Multiple parameters",
			input: "UPDATE users SET name = @name WHERE id = @id",
			expectedTokens: []models.Token{
				{Type: models.TokenTypeUpdate, Value: "UPDATE"},
				{Type: models.TokenTypeIdentifier, Value: "users"},
				{Type: models.TokenTypeSet, Value: "SET"},
				{Type: models.TokenTypeIdentifier, Value: "name"},
				{Type: models.TokenTypeEq, Value: "="},
				{Type: models.TokenTypePlaceholder, Value: "@name"},
				{Type: models.TokenTypeWhere, Value: "WHERE"},
				{Type: models.TokenTypeIdentifier, Value: "id"},
				{Type: models.TokenTypeEq, Value: "="},
				{Type: models.TokenTypePlaceholder, Value: "@id"},
			},
		},
		{
			name:  "Standalone @ symbol",
			input: "SELECT @ FROM test",
			expectedTokens: []models.Token{
				{Type: models.TokenTypeSelect, Value: "SELECT"},
				{Type: models.TokenTypeAtSign, Value: "@"},
				{Type: models.TokenTypeFrom, Value: "FROM"},
				{Type: models.TokenTypeIdentifier, Value: "test"},
			},
		},
		{
			name:  "Parameter in function call",
			input: "CALL proc(@param1, @param2)",
			expectedTokens: []models.Token{
				{Type: models.TokenTypeIdentifier, Value: "CALL"},
				{Type: models.TokenTypeIdentifier, Value: "proc"},
				{Type: models.TokenTypeLeftParen, Value: "("},
				{Type: models.TokenTypePlaceholder, Value: "@param1"},
				{Type: models.TokenTypeComma, Value: ","},
				{Type: models.TokenTypePlaceholder, Value: "@param2"},
				{Type: models.TokenTypeRightParen, Value: ")"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenizer := GetTokenizer()
			defer PutTokenizer(tokenizer)

			tokens, err := tokenizer.Tokenize([]byte(tt.input))
			if err != nil {
				t.Fatalf("Tokenize failed: %v", err)
			}

			// Filter out EOF and whitespace tokens for comparison
			var actualTokens []models.Token
			for _, token := range tokens {
				if token.Token.Type != models.TokenTypeEOF && token.Token.Type != models.TokenTypeWhitespace {
					actualTokens = append(actualTokens, token.Token)
				}
			}

			if len(actualTokens) != len(tt.expectedTokens) {
				t.Errorf("Expected %d tokens, got %d", len(tt.expectedTokens), len(actualTokens))
				for i, token := range actualTokens {
					t.Logf("  Token %d: Type=%d, Value=%q", i, token.Type, token.Value)
				}
				return
			}

			for i, expected := range tt.expectedTokens {
				actual := actualTokens[i]
				if actual.Type != expected.Type {
					t.Errorf("Token %d: expected type %d, got %d", i, expected.Type, actual.Type)
				}
				if actual.Value != expected.Value {
					t.Errorf("Token %d: expected value %q, got %q", i, expected.Value, actual.Value)
				}
			}
		})
	}
}

func TestTokenizer_PostgreSQLParameterEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name:        "Valid parameter with underscore",
			input:       "SELECT @user_id_123",
			expectError: false,
		},
		{
			name:        "Valid parameter with numbers",
			input:       "SELECT @param1",
			expectError: false,
		},
		{
			name:        "Multiple @ symbols",
			input:       "SELECT @param1, @param2, @param3",
			expectError: false,
		},
		{
			name:        "Parameter at end of input",
			input:       "SELECT @param",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenizer := GetTokenizer()
			defer PutTokenizer(tokenizer)

			_, err := tokenizer.Tokenize([]byte(tt.input))
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestTokenizer_PostgreSQLArrayOperators(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedTokens []models.Token
	}{
		{
			name:  "Array contains operator (@>)",
			input: "col @> val",
			expectedTokens: []models.Token{
				{Type: models.TokenTypeIdentifier, Value: "col"},
				{Type: models.TokenTypeAtArrow, Value: "@>"},
				{Type: models.TokenTypeIdentifier, Value: "val"},
			},
		},
		{
			name:  "Full text search operator (@@)",
			input: "content @@ query",
			expectedTokens: []models.Token{
				{Type: models.TokenTypeIdentifier, Value: "content"},
				{Type: models.TokenTypeAtAt, Value: "@@"},
				{Type: models.TokenTypeIdentifier, Value: "query"},
			},
		},
		{
			name:  "Array overlap operator (&&)",
			input: "arr1 && arr2",
			expectedTokens: []models.Token{
				{Type: models.TokenTypeIdentifier, Value: "arr1"},
				{Type: models.TokenTypeOverlap, Value: "&&"},
				{Type: models.TokenTypeIdentifier, Value: "arr2"},
			},
		},
		{
			name:  "All PostgreSQL operators combined",
			input: "col @> val AND content @@ search AND arr1 && arr2",
			expectedTokens: []models.Token{
				{Type: models.TokenTypeIdentifier, Value: "col"},
				{Type: models.TokenTypeAtArrow, Value: "@>"},
				{Type: models.TokenTypeIdentifier, Value: "val"},
				{Type: models.TokenTypeAnd, Value: "AND"},
				{Type: models.TokenTypeIdentifier, Value: "content"},
				{Type: models.TokenTypeAtAt, Value: "@@"},
				{Type: models.TokenTypeIdentifier, Value: "search"},
				{Type: models.TokenTypeAnd, Value: "AND"},
				{Type: models.TokenTypeIdentifier, Value: "arr1"},
				{Type: models.TokenTypeOverlap, Value: "&&"},
				{Type: models.TokenTypeIdentifier, Value: "arr2"},
			},
		},
		{
			name:  "Mixed with parameters",
			input: "tags @> @tag_array && @other_tags",
			expectedTokens: []models.Token{
				{Type: models.TokenTypeIdentifier, Value: "tags"},
				{Type: models.TokenTypeAtArrow, Value: "@>"},
				{Type: models.TokenTypePlaceholder, Value: "@tag_array"},
				{Type: models.TokenTypeOverlap, Value: "&&"},
				{Type: models.TokenTypePlaceholder, Value: "@other_tags"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenizer := GetTokenizer()
			defer PutTokenizer(tokenizer)

			tokens, err := tokenizer.Tokenize([]byte(tt.input))
			if err != nil {
				t.Fatalf("Tokenize failed: %v", err)
			}

			// Filter out EOF and whitespace tokens for comparison
			var actualTokens []models.Token
			for _, token := range tokens {
				if token.Token.Type != models.TokenTypeEOF && token.Token.Type != models.TokenTypeWhitespace {
					actualTokens = append(actualTokens, token.Token)
				}
			}

			if len(actualTokens) != len(tt.expectedTokens) {
				t.Errorf("Expected %d tokens, got %d", len(tt.expectedTokens), len(actualTokens))
				for i, token := range actualTokens {
					t.Logf("  Token %d: Type=%d, Value=%q", i, token.Type, token.Value)
				}
				return
			}

			for i, expected := range tt.expectedTokens {
				actual := actualTokens[i]
				if actual.Type != expected.Type {
					t.Errorf("Token %d: expected type %d, got %d", i, expected.Type, actual.Type)
				}
				if actual.Value != expected.Value {
					t.Errorf("Token %d: expected value %q, got %q", i, expected.Value, actual.Value)
				}
			}
		})
	}
}
