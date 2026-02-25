// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// mkSpanToken is a convenience helper that wraps a models.Token into a
// models.TokenWithSpan with empty span information.  It keeps test table
// entries terse.
func mkSpanToken(typ models.TokenType, value string) models.TokenWithSpan {
	return models.WrapToken(models.Token{Type: typ, Value: value})
}

// TestIsAnyType tests the isAnyType helper method
func TestIsAnyType(t *testing.T) {
	tests := []struct {
		name     string
		token    models.TokenWithSpan
		types    []models.TokenType
		expected bool
	}{
		{
			name:     "match first type",
			token:    mkSpanToken(models.TokenTypeSelect, "SELECT"),
			types:    []models.TokenType{models.TokenTypeSelect, models.TokenTypeInsert},
			expected: true,
		},
		{
			name:     "match second type",
			token:    mkSpanToken(models.TokenTypeInsert, "INSERT"),
			types:    []models.TokenType{models.TokenTypeSelect, models.TokenTypeInsert},
			expected: true,
		},
		{
			name:     "no match",
			token:    mkSpanToken(models.TokenTypeUpdate, "UPDATE"),
			types:    []models.TokenType{models.TokenTypeSelect, models.TokenTypeInsert},
			expected: false,
		},
		{
			name:     "single type match",
			token:    mkSpanToken(models.TokenTypeDelete, "DELETE"),
			types:    []models.TokenType{models.TokenTypeDelete},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := []models.TokenWithSpan{tt.token}
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
		tokens       []models.TokenWithSpan
		matchAgainst models.TokenType
		wantMatch    bool
		wantPosAfter int
	}{
		{
			name: "match and advance",
			tokens: []models.TokenWithSpan{
				mkSpanToken(models.TokenTypeSelect, "SELECT"),
				mkSpanToken(models.TokenTypeFrom, "FROM"),
			},
			matchAgainst: models.TokenTypeSelect,
			wantMatch:    true,
			wantPosAfter: 1,
		},
		{
			name: "no match, no advance",
			tokens: []models.TokenWithSpan{
				mkSpanToken(models.TokenTypeInsert, "INSERT"),
				mkSpanToken(models.TokenTypeInto, "INTO"),
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
