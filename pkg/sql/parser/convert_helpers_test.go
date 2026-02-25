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

// Package parser — test-only conversion helpers retained for backward-compat
// tests that verify the old Parse([]token.Token) path produces the same result
// as the modern ParseFromModelTokens([]models.TokenWithSpan) path.

package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// convertModelTokens converts a []models.TokenWithSpan to []token.Token.
//
// This is a test helper used to verify that the backward-compatible Parse API
// produces the same AST as ParseFromModelTokens. Production code should use
// ParseFromModelTokens directly and never convert backwards.
//
// Deprecated: used only by backward-compat tests; prefer ParseFromModelTokens.
func convertModelTokens(tokens []models.TokenWithSpan) ([]token.Token, error) {
	result := make([]token.Token, len(tokens))
	for i, t := range tokens {
		result[i] = token.Token{
			Type:    t.Token.Type,
			Literal: t.Token.Value,
		}
	}
	return result, nil
}
