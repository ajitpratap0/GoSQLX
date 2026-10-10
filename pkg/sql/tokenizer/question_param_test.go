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

// Package tokenizer - question_param_test.go
// Tests for MySQL/MariaDB/SQLite `?` positional parameter placeholder
// tokenization, and the regression guard that PostgreSQL keeps `?` as its
// JSON key-existence operator.

package tokenizer

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestTokenizer_QuestionMarkPlaceholder(t *testing.T) {
	dialects := []keywords.SQLDialect{
		keywords.DialectMySQL,
		keywords.DialectMariaDB,
		keywords.DialectSQLite,
	}

	tests := []struct {
		name     string
		input    string
		expected []struct {
			tokenType models.TokenType
			value     string
		}
	}{
		{
			name:  "Single ? placeholder",
			input: "SELECT * FROM users WHERE id = ?",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeSelect, "SELECT"},
				{models.TokenTypeMul, "*"},
				{models.TokenTypeFrom, "FROM"},
				{models.TokenTypeIdentifier, "users"},
				{models.TokenTypeWhere, "WHERE"},
				{models.TokenTypeIdentifier, "id"},
				{models.TokenTypeEq, "="},
				{models.TokenTypePlaceholder, "?"},
			},
		},
		{
			name:  "Multiple ? placeholders in VALUES",
			input: "INSERT INTO users (name, email) VALUES (?, ?, ?)",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeInsert, "INSERT"},
				{models.TokenTypeInto, "INTO"},
				{models.TokenTypeIdentifier, "users"},
				{models.TokenTypeLParen, "("},
				{models.TokenTypeIdentifier, "name"},
				{models.TokenTypeComma, ","},
				{models.TokenTypeIdentifier, "email"},
				{models.TokenTypeRParen, ")"},
				{models.TokenTypeValues, "VALUES"},
				{models.TokenTypeLParen, "("},
				{models.TokenTypePlaceholder, "?"},
				{models.TokenTypeComma, ","},
				{models.TokenTypePlaceholder, "?"},
				{models.TokenTypeComma, ","},
				{models.TokenTypePlaceholder, "?"},
				{models.TokenTypeRParen, ")"},
			},
		},
		{
			name:  "? placeholder without surrounding space",
			input: "SELECT name FROM users WHERE id=?",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeSelect, "SELECT"},
				{models.TokenTypeIdentifier, "name"},
				{models.TokenTypeFrom, "FROM"},
				{models.TokenTypeIdentifier, "users"},
				{models.TokenTypeWhere, "WHERE"},
				{models.TokenTypeIdentifier, "id"},
				{models.TokenTypeEq, "="},
				{models.TokenTypePlaceholder, "?"},
			},
		},
	}

	for _, dialect := range dialects {
		for _, tt := range tests {
			t.Run(string(dialect)+"/"+tt.name, func(t *testing.T) {
				tkz, err := NewWithDialect(dialect)
				if err != nil {
					t.Fatalf("NewWithDialect(%q) error = %v", dialect, err)
				}

				tokens, err := tkz.Tokenize([]byte(tt.input))
				if err != nil {
					t.Fatalf("Tokenize() error = %v", err)
				}

				// Remove EOF token
				tokens = tokens[:len(tokens)-1]

				if len(tokens) != len(tt.expected) {
					t.Fatalf("Expected %d tokens, got %d", len(tt.expected), len(tokens))
				}

				for i, exp := range tt.expected {
					if tokens[i].Token.Type != exp.tokenType {
						t.Errorf("Token %d: expected type %s, got %s (value: %s)",
							i, exp.tokenType.String(), tokens[i].Token.Type.String(), tokens[i].Token.Value)
					}
					if tokens[i].Token.Value != exp.value {
						t.Errorf("Token %d: expected value %q, got %q",
							i, exp.value, tokens[i].Token.Value)
					}
				}
			})
		}
	}
}

// TestTokenizer_QuestionMarkPostgreSQLJSONOperator guards against a regression
// where `?`, `?|`, and `?&` under PostgreSQL would be mistaken for placeholders
// instead of JSON operators.
func TestTokenizer_QuestionMarkPostgreSQLJSONOperator(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		tokenType models.TokenType
		value     string
	}{
		{"single ? existence operator", "data ? 'key'", models.TokenTypeQuestion, "?"},
		{"?| any key exists", "data ?| array['a','b']", models.TokenTypeQuestionPipe, "?|"},
		{"?& all keys exist", "data ?& array['a','b']", models.TokenTypeQuestionAnd, "?&"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz, err := NewWithDialect(keywords.DialectPostgreSQL)
			if err != nil {
				t.Fatalf("NewWithDialect() error = %v", err)
			}

			tokens, err := tkz.Tokenize([]byte(tt.input))
			if err != nil {
				t.Fatalf("Tokenize() error = %v", err)
			}

			var found bool
			for _, tok := range tokens {
				if tok.Token.Type == tt.tokenType && tok.Token.Value == tt.value {
					found = true
					break
				}
				if tok.Token.Type == models.TokenTypePlaceholder {
					t.Fatalf("PostgreSQL emitted a placeholder for %q; expected JSON operator", tt.input)
				}
			}
			if !found {
				t.Errorf("expected token %s %q in %q", tt.tokenType.String(), tt.value, tt.input)
			}
		})
	}
}
