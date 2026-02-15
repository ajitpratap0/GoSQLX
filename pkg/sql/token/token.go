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
