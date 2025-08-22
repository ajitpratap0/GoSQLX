package main

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// exampleFunc is a function type that matches the Example function signature
type exampleFunc func() ([]models.TokenWithSpan, error)

func TestExample(t *testing.T) {
	tokens, err := Example()
	if err != nil {
		t.Fatalf("Example() error = %v", err)
	}

	// Expected token types and values based on corrected tokenizer output
	// Note: Using corrected token type values after fixing iota collisions
	expectedTokens := []struct {
		tokenType models.TokenType
		value     string
	}{
		{43, "SELECT"},         // TokenTypeSelect
		{4, "名前"},            // TokenTypeSingleQuotedString (Japanese "name")
		{80, "as"},             // TokenTypeAs
		{1, "name"},            // TokenTypeWord for unquoted identifiers
		{15, ","},              // TokenTypeComma
		{4, "年齢"},            // TokenTypeSingleQuotedString (Japanese "age") 
		{80, "as"},             // TokenTypeAs
		{1, "age"},             // TokenTypeWord for unquoted identifiers
		{15, ","},              // TokenTypeComma
		{64, "COUNT"},          // TokenTypeCount
		{127, "("},             // TokenTypeLeftParen
		{126, "*"},             // TokenTypeOperator for asterisk
		{128, ")"},             // TokenTypeRightParen
		{80, "as"},             // TokenTypeAs
		{1, "order_count"},     // TokenTypeWord for unquoted identifiers
		{59, "FROM"},           // TokenTypeFrom
		{4, "ユーザー"},        // TokenTypeSingleQuotedString (Japanese "user")
		{1, "u"},               // TokenTypeWord for unquoted identifiers
		{44, "JOIN"},           // TokenTypeJoin
		{4, "注文"},            // TokenTypeSingleQuotedString (Japanese "order")
		{1, "o"},               // TokenTypeWord for unquoted identifiers
		{55, "ON"},             // TokenTypeOn
		{1, "u"},               // TokenTypeWord for unquoted identifiers
		{129, "."},             // TokenTypeDot
		{1, "id"},              // TokenTypeWord for unquoted identifiers
		{126, "="},             // TokenTypeOperator for equals
		{1, "o"},               // TokenTypeWord for unquoted identifiers
		{129, "."},             // TokenTypeDot
		{1, "user_id"},         // TokenTypeWord for unquoted identifiers
		{51, "WHERE"},          // TokenTypeWhere
		{1, "u"},               // TokenTypeWord for unquoted identifiers
		{129, "."},             // TokenTypeDot
		{4, "国"},              // TokenTypeSingleQuotedString (Japanese "country")
		{126, "="},             // TokenTypeOperator for equals
		{4, "日本"},            // TokenTypeSingleQuotedString (Japanese "Japan")
		{56, "AND"},            // TokenTypeAnd
		{1, "u"},               // TokenTypeWord for unquoted identifiers
		{129, "."},             // TokenTypeDot
		{4, "都市"},            // TokenTypeSingleQuotedString (Japanese "city")
		{126, "="},             // TokenTypeOperator for equals
		{4, "東京"},            // TokenTypeSingleQuotedString (Japanese "Tokyo")
		{56, "AND"},            // TokenTypeAnd
		{1, "o"},               // TokenTypeWord for unquoted identifiers
		{129, "."},             // TokenTypeDot
		{4, "価格"},            // TokenTypeSingleQuotedString (Japanese "price")
		{126, ">"},             // TokenTypeOperator for greater than
		{2, "1000"},            // TokenTypeNumber
		{81, "GROUP BY"},       // TokenTypeGroupBy
		{4, "名前"},            // TokenTypeSingleQuotedString (Japanese "name")
		{15, ","},              // TokenTypeComma
		{4, "年齢"},            // TokenTypeSingleQuotedString (Japanese "age")
		{50, "HAVING"},         // TokenTypeHaving
		{64, "COUNT"},          // TokenTypeCount
		{127, "("},             // TokenTypeLeftParen
		{126, "*"},             // TokenTypeOperator for asterisk
		{128, ")"},             // TokenTypeRightParen
		{126, ">"},             // TokenTypeOperator for greater than
		{2, "5"},               // TokenTypeNumber
		{82, "ORDER BY"},       // TokenTypeOrderBy
		{1, "order_count"},     // TokenTypeWord for unquoted identifiers
		{74, "DESC"},           // TokenTypeDesc
		{37, ";"},              // TokenTypeSemicolon
	}

	// Check that we have enough tokens
	if len(tokens)-1 < len(expectedTokens) { // -1 for EOF token
		t.Fatalf("got %d tokens, want at least %d", len(tokens)-1, len(expectedTokens))
	}

	// Check each expected token
	for i, want := range expectedTokens {
		if tokens[i].Token.Type != want.tokenType {
			t.Errorf("token[%d].Type = %v, want %v", i, tokens[i].Token.Type, want.tokenType)
		}
		if tokens[i].Token.Value != want.value {
			t.Errorf("token[%d].Value = %q, want %q", i, tokens[i].Token.Value, want.value)
		}
	}

	// Check that we have location information for each token
	for i, token := range tokens {
		if token.Start.Line == 0 || token.Start.Column == 0 {
			t.Errorf("token[%d] missing start location information", i)
		}
		if token.End.Line == 0 || token.End.Column == 0 {
			t.Errorf("token[%d] missing end location information", i)
		}
	}
}

func TestExampleErrorCases(t *testing.T) {
	// Create test cases
	testCases := []struct {
		name  string
		query string
	}{
		{
			name:  "unterminated quoted identifier",
			query: `SELECT "unterminated FROM users;`,
		},
		{
			name:  "unterminated string literal",
			query: `SELECT * FROM users WHERE name = 'unterminated;`,
		},
		{
			name:  "invalid Unicode escape sequence",
			query: `SELECT * FROM users WHERE name = '\u123';`, // Invalid Unicode escape
		},
	}

	// Run each test case
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new tokenizer for each test
			tok, err := tokenizer.New()
			if err != nil {
				t.Fatalf("Failed to create tokenizer: %v", err)
			}

			// Try to tokenize the query
			_, err = tok.Tokenize([]byte(tc.query))
			if err == nil {
				t.Errorf("Expected error for %s, got nil", tc.name)
			}
		})
	}
}