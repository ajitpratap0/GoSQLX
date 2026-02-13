package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// TestIsAnyType tests the isAnyType helper method
func TestIsAnyType(t *testing.T) {
	tests := []struct {
		name     string
		token    token.Token
		types    []models.TokenType
		expected bool
	}{
		{
			name:     "match first type with ModelType",
			token:    token.Token{Type: "SELECT", ModelType: models.TokenTypeSelect, Literal: "SELECT"},
			types:    []models.TokenType{models.TokenTypeSelect, models.TokenTypeInsert},
			expected: true,
		},
		{
			name:     "match second type with ModelType",
			token:    token.Token{Type: "INSERT", ModelType: models.TokenTypeInsert, Literal: "INSERT"},
			types:    []models.TokenType{models.TokenTypeSelect, models.TokenTypeInsert},
			expected: true,
		},
		{
			name:     "no match with ModelType",
			token:    token.Token{Type: "UPDATE", ModelType: models.TokenTypeUpdate, Literal: "UPDATE"},
			types:    []models.TokenType{models.TokenTypeSelect, models.TokenTypeInsert},
			expected: false,
		},
		{
			name:     "match after normalization",
			token:    token.Token{Type: "SELECT", Literal: "SELECT"},
			types:    []models.TokenType{models.TokenTypeSelect, models.TokenTypeInsert},
			expected: true,
		},
		{
			name:     "single type match",
			token:    token.Token{Type: "DELETE", ModelType: models.TokenTypeDelete, Literal: "DELETE"},
			types:    []models.TokenType{models.TokenTypeDelete},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := []token.Token{tt.token}
			tokens = normalizeTokens(tokens)
			p := &Parser{
				tokens:       tokens,
				currentPos:   0,
				currentToken: tokens[0],
			}
			result := p.isAnyType(tt.types...)
			if result != tt.expected {
				t.Errorf("isAnyType() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestMatchType tests the matchType helper method
func TestMatchType(t *testing.T) {
	tests := []struct {
		name         string
		tokens       []token.Token
		matchAgainst models.TokenType
		wantMatch    bool
		wantPosAfter int
	}{
		{
			name: "match and advance with ModelType",
			tokens: []token.Token{
				{Type: "SELECT", ModelType: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: "FROM", ModelType: models.TokenTypeFrom, Literal: "FROM"},
			},
			matchAgainst: models.TokenTypeSelect,
			wantMatch:    true,
			wantPosAfter: 1,
		},
		{
			name: "no match, no advance",
			tokens: []token.Token{
				{Type: "INSERT", ModelType: models.TokenTypeInsert, Literal: "INSERT"},
				{Type: "INTO", ModelType: models.TokenTypeInto, Literal: "INTO"},
			},
			matchAgainst: models.TokenTypeSelect,
			wantMatch:    false,
			wantPosAfter: 0,
		},
		{
			name: "match after normalization",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "FROM", Literal: "FROM"},
			},
			matchAgainst: models.TokenTypeSelect,
			wantMatch:    true,
			wantPosAfter: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.tokens = normalizeTokens(tt.tokens)
			p := &Parser{
				tokens:       tt.tokens,
				currentPos:   0,
				currentToken: tt.tokens[0],
			}
			result := p.matchType(tt.matchAgainst)
			if result != tt.wantMatch {
				t.Errorf("matchType() = %v, expected %v", result, tt.wantMatch)
			}
			if p.currentPos != tt.wantPosAfter {
				t.Errorf("currentPos = %d, expected %d", p.currentPos, tt.wantPosAfter)
			}
		})
	}
}

// TestNormalizeTokens verifies that normalizeTokens correctly fills in ModelType
// from string Type for tokens that don't have ModelType set.
func TestNormalizeTokens(t *testing.T) {
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "INSERT", Literal: "INSERT"},
		{Type: "UPDATE", Literal: "UPDATE"},
		{Type: "DELETE", Literal: "DELETE"},
		{Type: "IDENT", Literal: "foo"},
	}

	tokens = normalizeTokens(tokens)

	expected := []models.TokenType{
		models.TokenTypeSelect,
		models.TokenTypeInsert,
		models.TokenTypeUpdate,
		models.TokenTypeDelete,
		models.TokenTypeIdentifier,
	}

	for i, tok := range tokens {
		if tok.ModelType != expected[i] {
			t.Errorf("token[%d] (%s): ModelType = %d, expected %d", i, tok.Literal, tok.ModelType, expected[i])
		}
	}
}

// TestNormalizeTokensPreservesExisting verifies that normalizeTokens does not
// overwrite ModelType that is already set.
func TestNormalizeTokensPreservesExisting(t *testing.T) {
	tokens := []token.Token{
		{Type: "SELECT", ModelType: models.TokenTypeSelect, Literal: "SELECT"},
	}

	tokens = normalizeTokens(tokens)

	if tokens[0].ModelType != models.TokenTypeSelect {
		t.Errorf("normalizeTokens overwrote existing ModelType: got %d", tokens[0].ModelType)
	}
}
