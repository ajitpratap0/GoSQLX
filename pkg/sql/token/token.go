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

package token

import "github.com/ajitpratap0/GoSQLX/pkg/models"

// Token represents a lexical token in SQL source code.
//
// The Token struct uses the unified integer-based type system (models.TokenType)
// for all type identification. String-based token types have been removed as part
// of the token type unification (#215).
//
// Example:
//
//	tok := Token{
//	    Type:    models.TokenTypeSelect,
//	    Literal: "SELECT",
//	}
//
//	if tok.IsType(models.TokenTypeSelect) {
//	    // Process SELECT token
//	}
type Token struct {
	Type    models.TokenType // Int-based token type (primary, for performance)
	Literal string           // The literal value of the token
}

// HasType returns true if the Type field is populated with a valid type.
// Returns false for TokenTypeUnknown or zero value.
//
// Example:
//
//	tok := Token{Type: models.TokenTypeSelect, Literal: "SELECT"}
//	if tok.HasType() {
//	    // Use fast Type-based operations
//	}
func (t Token) HasType() bool {
	return t.Type != models.TokenTypeUnknown && t.Type != 0
}

// IsType checks if the token matches the given models.TokenType.
// This uses fast integer comparison and is the preferred way to check token types.
//
// Example:
//
//	tok := Token{Type: models.TokenTypeSelect, Literal: "SELECT"}
//	if tok.IsType(models.TokenTypeSelect) {
//	    fmt.Println("This is a SELECT token")
//	}
func (t Token) IsType(expected models.TokenType) bool {
	return t.Type == expected
}

// IsAnyType checks if the token matches any of the given models.TokenType values.
// Returns true if the token's Type matches any type in the provided list.
//
// Example:
//
//	tok := Token{Type: models.TokenTypeSelect, Literal: "SELECT"}
//	dmlKeywords := []models.TokenType{
//	    models.TokenTypeSelect,
//	    models.TokenTypeInsert,
//	    models.TokenTypeUpdate,
//	    models.TokenTypeDelete,
//	}
//	if tok.IsAnyType(dmlKeywords...) {
//	    fmt.Println("This is a DML statement keyword")
//	}
func (t Token) IsAnyType(types ...models.TokenType) bool {
	for _, typ := range types {
		if t.Type == typ {
			return true
		}
	}
	return false
}
