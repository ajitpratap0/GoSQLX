package main

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestExample(t *testing.T) {
	tokens, err := Example()
	if err != nil {
		t.Fatalf("Example() error = %v", err)
	}

	// Expected token types and values based on actual tokenizer output
	// Using the correct token type values after fixing the implementation
	expectedTokens := []struct {
		tokenType models.TokenType
		value     string
	}{
		{models.TokenTypeSelect, "SELECT"},           // 201
		{models.TokenTypeDoubleQuotedString, "名前"},   // 32 - Japanese "name"
		{models.TokenTypeAs, "as"},                   // 210
		{models.TokenTypeIdentifier, "name"},         // 14
		{models.TokenTypeComma, ","},                 // 51
		{models.TokenTypeDoubleQuotedString, "年齢"},   // 32 - Japanese "age"
		{models.TokenTypeAs, "as"},                   // 210
		{models.TokenTypeIdentifier, "age"},          // 14
		{models.TokenTypeComma, ","},                 // 51
		{models.TokenTypeCount, "COUNT"},             // 250
		{models.TokenTypeLParen, "("},                // 67
		{models.TokenTypeMul, "*"},                   // 62
		{models.TokenTypeRParen, ")"},                // 68
		{models.TokenTypeAs, "as"},                   // 210
		{models.TokenTypeIdentifier, "order_count"},  // 14
		{models.TokenTypeFrom, "FROM"},               // 202
		{models.TokenTypeDoubleQuotedString, "ユーザー"}, // 32 - Japanese "users"
		{models.TokenTypeIdentifier, "u"},            // 14
		{models.TokenTypeJoin, "JOIN"},               // 204
		{models.TokenTypeDoubleQuotedString, "注文"},   // 32 - Japanese "orders"
		{models.TokenTypeIdentifier, "o"},            // 14
		{models.TokenTypeOn, "ON"},                   // 209
		{models.TokenTypeIdentifier, "u"},            // 14
		{models.TokenTypePeriod, "."},                // 69
		{models.TokenTypeIdentifier, "id"},           // 14
		{models.TokenTypeEq, "="},                    // 52
		{models.TokenTypeIdentifier, "o"},            // 14
		{models.TokenTypePeriod, "."},                // 69
		{models.TokenTypeIdentifier, "user_id"},      // 14
		{models.TokenTypeWhere, "WHERE"},             // 203
		{models.TokenTypeIdentifier, "u"},            // 14
		{models.TokenTypePeriod, "."},                // 69
		{models.TokenTypeDoubleQuotedString, "国"},    // 32 - Japanese "country"
		{models.TokenTypeEq, "="},                    // 52
		{models.TokenTypeSingleQuotedString, "日本"},   // 31 - Japanese "Japan"
		{models.TokenTypeAnd, "AND"},                 // 211
		{models.TokenTypeIdentifier, "u"},            // 14
		{models.TokenTypePeriod, "."},                // 69
		{models.TokenTypeDoubleQuotedString, "都市"},   // 32 - Japanese "city"
		{models.TokenTypeEq, "="},                    // 52
		{models.TokenTypeSingleQuotedString, "東京"},   // 31 - Japanese "Tokyo"
		{models.TokenTypeAnd, "AND"},                 // 211
		{models.TokenTypeIdentifier, "o"},            // 14
		{models.TokenTypePeriod, "."},                // 69
		{models.TokenTypeDoubleQuotedString, "価格"},   // 32 - Japanese "price"
		{models.TokenTypeGt, ">"},                    // 56
		{models.TokenTypeNumber, "1000"},             // 11
		{models.TokenTypeGroupBy, "GROUP BY"},        // 270
		{models.TokenTypeDoubleQuotedString, "名前"},   // 32
		{models.TokenTypeComma, ","},                 // 51
		{models.TokenTypeDoubleQuotedString, "年齢"},   // 32
		{models.TokenTypeHaving, "HAVING"},           // 228
		{models.TokenTypeCount, "COUNT"},             // 250
		{models.TokenTypeLParen, "("},                // 67
		{models.TokenTypeMul, "*"},                   // 62
		{models.TokenTypeRParen, ")"},                // 68
		{models.TokenTypeGt, ">"},                    // 56
		{models.TokenTypeNumber, "5"},                // 11
		{models.TokenTypeOrderBy, "ORDER BY"},        // 271
		{models.TokenTypeIdentifier, "order_count"},  // 14
		{models.TokenTypeDesc, "DESC"},               // 231
		{models.TokenTypeSemicolon, ";"},             // 73
	}

	// Check that we have enough tokens
	if len(tokens)-1 < len(expectedTokens) { // -1 for EOF token
		t.Fatalf("got %d tokens, want at least %d", len(tokens)-1, len(expectedTokens))
	}

	// Check each expected token
	for i, want := range expectedTokens {
		got := tokens[i]
		if got.Token.Type != want.tokenType {
			t.Errorf("token[%d].Type = %v(%d), want %v(%d) for value %q",
				i, got.Token.Type, got.Token.Type, want.tokenType, want.tokenType, want.value)
		}
		if got.Token.Value != want.value {
			t.Errorf("token[%d].Value = %q, want %q", i, got.Token.Value, want.value)
		}
	}

	// Check that we have location information for each token
	for i, token := range tokens {
		if i == len(tokens)-1 && token.Token.Type == models.TokenTypeEOF {
			continue // Skip EOF token
		}
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
			// Get tokenizer from pool
			tok := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tok)

			// Try to tokenize the query
			_, err := tok.Tokenize([]byte(tc.query))
			if err == nil {
				t.Errorf("Expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestResourceManagement(t *testing.T) {
	// Test that tokenizers can be obtained and returned to pool
	queries := []string{
		`SELECT * FROM users;`,
		`INSERT INTO logs (message) VALUES ('test');`,
		`UPDATE settings SET value = 42 WHERE key = 'count';`,
		`DELETE FROM sessions WHERE expired = true;`,
	}

	for i, query := range queries {
		// Get tokenizer from pool
		tok := tokenizer.GetTokenizer()

		// Tokenize query
		tokens, err := tok.Tokenize([]byte(query))
		if err != nil {
			t.Errorf("Query %d failed: %v", i, err)
			tokenizer.PutTokenizer(tok)
			continue
		}

		// Verify we got tokens
		if len(tokens) == 0 {
			t.Errorf("Query %d produced no tokens", i)
		}

		// Return to pool
		tokenizer.PutTokenizer(tok)
	}
}

func TestUnicodeSupport(t *testing.T) {
	// Test various Unicode characters in SQL
	testCases := []struct {
		name      string
		query     string
		minTokens int
	}{
		{
			name:      "Japanese identifiers",
			query:     `SELECT "名前" FROM "テーブル";`,
			minTokens: 4, // SELECT, identifier, FROM, identifier, semicolon
		},
		{
			name:      "Emoji in strings",
			query:     `SELECT * FROM users WHERE status = '🚀';`,
			minTokens: 8, // Multiple tokens for the WHERE clause
		},
		{
			name:      "Mixed scripts",
			query:     `SELECT "Имя", "名前", "Name" FROM интернационал;`,
			minTokens: 6, // SELECT and multiple identifiers
		},
		{
			name:      "Unicode quotes",
			query:     `SELECT 'test' FROM users;`, // Using Unicode quotes
			minTokens: 4,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tok := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tok)

			tokens, err := tok.Tokenize([]byte(tc.query))
			if err != nil {
				t.Fatalf("Failed to tokenize %s: %v", tc.name, err)
			}

			// -1 for EOF token
			if len(tokens)-1 < tc.minTokens {
				t.Errorf("Expected at least %d tokens, got %d", tc.minTokens, len(tokens)-1)
			}
		})
	}
}
