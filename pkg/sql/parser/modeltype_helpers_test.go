package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// TestIsAnyType tests the isAnyType helper method
func TestIsAnyType(t *testing.T) {
	tests := []struct {
		name     string
		token    parserToken
		types    []models.TokenType
		expected bool
	}{
		{
			name:     "match first type",
			token:    parserToken{Type: models.TokenTypeSelect, Literal: "SELECT"},
			types:    []models.TokenType{models.TokenTypeSelect, models.TokenTypeInsert},
			expected: true,
		},
		{
			name:     "match second type",
			token:    parserToken{Type: models.TokenTypeInsert, Literal: "INSERT"},
			types:    []models.TokenType{models.TokenTypeSelect, models.TokenTypeInsert},
			expected: true,
		},
		{
			name:     "no match",
			token:    parserToken{Type: models.TokenTypeUpdate, Literal: "UPDATE"},
			types:    []models.TokenType{models.TokenTypeSelect, models.TokenTypeInsert},
			expected: false,
		},
		{
			name:     "single type match",
			token:    parserToken{Type: models.TokenTypeDelete, Literal: "DELETE"},
			types:    []models.TokenType{models.TokenTypeDelete},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{
				tokens:       []parserToken{tt.token},
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
		tokens       []parserToken
		matchAgainst models.TokenType
		wantMatch    bool
		wantPosAfter int
	}{
		{
			name: "match and advance",
			tokens: []parserToken{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
			},
			matchAgainst: models.TokenTypeSelect,
			wantMatch:    true,
			wantPosAfter: 1,
		},
		{
			name: "no match, no advance",
			tokens: []parserToken{
				{Type: models.TokenTypeInsert, Literal: "INSERT"},
				{Type: models.TokenTypeInto, Literal: "INTO"},
			},
			matchAgainst: models.TokenTypeSelect,
			wantMatch:    false,
			wantPosAfter: 0,
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

// TestModelTypeHelpers tests that type checks work with the int-based type system
func TestModelTypeHelpers(t *testing.T) {
	tokens := []parserToken{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeInsert, Literal: "INSERT"},
		{Type: models.TokenTypeUpdate, Literal: "UPDATE"},
		{Type: models.TokenTypeDelete, Literal: "DELETE"},
	}

	p := &Parser{
		tokens:       tokens,
		currentPos:   0,
		currentToken: tokens[0],
	}

	// Test isType
	if !p.isType(models.TokenTypeSelect) {
		t.Error("isType failed for SELECT")
	}

	// Test isAnyType
	if !p.isAnyType(models.TokenTypeInsert, models.TokenTypeSelect) {
		t.Error("isAnyType failed")
	}

	// Test matchType - should advance
	if !p.matchType(models.TokenTypeSelect) {
		t.Error("matchType failed for SELECT")
	}
	if p.currentPos != 1 {
		t.Errorf("matchType did not advance, currentPos = %d", p.currentPos)
	}
}
