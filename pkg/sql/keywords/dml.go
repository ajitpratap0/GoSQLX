package keywords

import "github.com/ajitpratap0/GoSQLX/pkg/models"

// IsDMLKeyword checks if a given string is a DML keyword
func (k *Keywords) IsDMLKeyword(s string) bool {
	_, ok := k.DMLKeywords[s]
	return ok
}

// GetDMLKeywordType returns the token type for a DML keyword
func (k *Keywords) GetDMLKeywordType(s string) (models.TokenType, bool) {
	t, ok := k.DMLKeywords[s]
	return t, ok
}
