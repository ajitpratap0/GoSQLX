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
			name:     "match first type",
			token:    token.Token{Type: models.TokenTypeSelect, Literal: "SELECT"},
			types:    []models.TokenType{models.TokenTypeSelect, models.TokenTypeInsert},
			expected: true,
		},
		{
			name:     "match second type",
			token:    token.Token{Type: models.TokenTypeInsert, Literal: "INSERT"},
			types:    []models.TokenType{models.TokenTypeSelect, models.TokenTypeInsert},
			expected: true,
		},
		{
			name:     "no match",
			token:    token.Token{Type: models.TokenTypeUpdate, Literal: "UPDATE"},
			types:    []models.TokenType{models.TokenTypeSelect, models.TokenTypeInsert},
			expected: false,
		},
		{
			name:     "single type match",
			token:    token.Token{Type: models.TokenTypeDelete, Literal: "DELETE"},
			types:    []models.TokenType{models.TokenTypeDelete},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := []token.Token{tt.token}
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
			name: "match and advance",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
			},
			matchAgainst: models.TokenTypeSelect,
			wantMatch:    true,
			wantPosAfter: 1,
		},
		{
			name: "no match, no advance",
			tokens: []token.Token{
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
