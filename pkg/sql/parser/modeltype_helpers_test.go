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
			name:     "match with string fallback",
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
			p := &Parser{
				tokens:       []token.Token{tt.token},
				currentPos:   0,
				currentToken: tt.token,
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
			name: "match with string fallback",
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

// TestModelTypeHelpersFallback ensures string fallback works when ModelType is not set
// Note: Only types in modelTypeToString map will work with fallback
func TestModelTypeHelpersFallback(t *testing.T) {
	// Create tokens without ModelType (simulating old test code)
	// Use only types that are in modelTypeToString map: SELECT, INSERT, UPDATE, DELETE, etc.
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "INSERT", Literal: "INSERT"},
		{Type: "UPDATE", Literal: "UPDATE"},
		{Type: "DELETE", Literal: "DELETE"},
	}

	p := &Parser{
		tokens:       tokens,
		currentPos:   0,
		currentToken: tokens[0],
	}

	// Test isType fallback
	if !p.isType(models.TokenTypeSelect) {
		t.Error("isType fallback failed for SELECT")
	}

	// Test isAnyType fallback
	if !p.isAnyType(models.TokenTypeInsert, models.TokenTypeSelect) {
		t.Error("isAnyType fallback failed")
	}

	// Test matchType fallback - should advance
	if !p.matchType(models.TokenTypeSelect) {
		t.Error("matchType fallback failed for SELECT")
	}
	if p.currentPos != 1 {
		t.Errorf("matchType did not advance, currentPos = %d", p.currentPos)
	}
}
