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

	// Expected token types and values for key parts of the query
	expectedTokens := []struct {
		tokenType models.TokenType
		value     string
	}{
		{models.TokenTypeSelect, "SELECT"},
		{models.TokenTypeString, "名前"}, // "名前"
		{models.TokenTypeKeyword, "as"},
		{models.TokenTypeIdentifier, "name"},
		{models.TokenTypeComma, ","},
		{models.TokenTypeString, "年齢"}, // "年齢"
		{models.TokenTypeKeyword, "as"},
		{models.TokenTypeIdentifier, "age"},
		{models.TokenTypeComma, ","},
		{models.TokenTypeCount, "COUNT"},
		{models.TokenTypeLeftParen, "("},
		{models.TokenTypeOperator, "*"},
		{models.TokenTypeRightParen, ")"},
		{models.TokenTypeKeyword, "as"},
		{models.TokenTypeIdentifier, "order_count"},
		{models.TokenTypeFrom, "FROM"},
		{models.TokenTypeString, "ユーザー"}, // "ユーザー"
		{models.TokenTypeIdentifier, "u"},
		{models.TokenTypeJoin, "JOIN"},
		{models.TokenTypeString, "注文"}, // "注文"
		{models.TokenTypeIdentifier, "o"},
		{models.TokenTypeOn, "ON"},
		{models.TokenTypeIdentifier, "u"},
		{models.TokenTypeDot, "."},
		{models.TokenTypeIdentifier, "id"},
		{models.TokenTypeOperator, "="},
		{models.TokenTypeIdentifier, "o"},
		{models.TokenTypeDot, "."},
		{models.TokenTypeIdentifier, "user_id"},
		{models.TokenTypeWhere, "WHERE"},
		{models.TokenTypeIdentifier, "u"},
		{models.TokenTypeDot, "."},
		{models.TokenTypeString, "国"}, // "国"
		{models.TokenTypeOperator, "="},
		{models.TokenTypeString, "日本"}, // "日本"
		{models.TokenTypeAnd, "AND"},
		{models.TokenTypeIdentifier, "u"},
		{models.TokenTypeDot, "."},
		{models.TokenTypeString, "都市"}, // "都市"
		{models.TokenTypeOperator, "="},
		{models.TokenTypeString, "東京"}, // "東京"
		{models.TokenTypeAnd, "AND"},
		{models.TokenTypeIdentifier, "o"},
		{models.TokenTypeDot, "."},
		{models.TokenTypeString, "価格"}, // "価格"
		{models.TokenTypeOperator, ">"},
		{models.TokenTypeNumber, "1000"},
		{models.TokenTypeGroupBy, "GROUP BY"},
		{models.TokenTypeString, "名前"}, // "名前"
		{models.TokenTypeComma, ","},
		{models.TokenTypeString, "年齢"}, // "年齢"
		{models.TokenTypeHaving, "HAVING"},
		{models.TokenTypeCount, "COUNT"},
		{models.TokenTypeLeftParen, "("},
		{models.TokenTypeOperator, "*"},
		{models.TokenTypeRightParen, ")"},
		{models.TokenTypeOperator, ">"},
		{models.TokenTypeNumber, "5"},
		{models.TokenTypeOrderBy, "ORDER BY"},
		{models.TokenTypeIdentifier, "order_count"},
		{models.TokenTypeDesc, "DESC"},
		{models.TokenTypeSemicolon, ";"},
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
