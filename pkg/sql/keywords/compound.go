package keywords

import "github.com/ajitpratap0/GoSQLX/pkg/models"

// IsCompoundKeyword checks if a string is a compound keyword
func (k *Keywords) IsCompoundKeyword(s string) bool {
	_, ok := k.CompoundKeywords[s]
	return ok
}

// GetCompoundKeywordType returns the token type for a compound keyword
func (k *Keywords) GetCompoundKeywordType(s string) (models.TokenType, bool) {
	t, ok := k.CompoundKeywords[s]
	return t, ok
}
