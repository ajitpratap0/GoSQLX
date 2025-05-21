package keywords

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// KeywordCategory represents a category of SQL keywords
type KeywordCategory map[string]models.TokenType

// Keywords holds all SQL keyword categories and configuration
type Keywords struct {
	// Keyword categories
	DMLKeywords      KeywordCategory
	CompoundKeywords KeywordCategory

	// Core keyword mapping and configuration
	keywordMap       map[string]Keyword
	reservedKeywords map[string]bool
	dialect          SQLDialect
	ignoreCase       bool
}

// NewKeywords creates a new Keywords instance
func NewKeywords() *Keywords {
	k := &Keywords{
		DMLKeywords:      make(KeywordCategory),
		CompoundKeywords: make(KeywordCategory),
		keywordMap:       make(map[string]Keyword),
		reservedKeywords: make(map[string]bool),
		ignoreCase:       true,
	}
	k.initialize()
	return k
}

// initialize sets up the initial keyword mappings
func (k *Keywords) initialize() {
	// Initialize DML keywords
	k.DMLKeywords = map[string]models.TokenType{
		"DISTINCT": models.TokenTypeKeyword,
		"ALL":      models.TokenTypeKeyword,
		"FETCH":    models.TokenTypeKeyword,
		"NEXT":     models.TokenTypeKeyword,
		"ROWS":     models.TokenTypeKeyword,
		"ONLY":     models.TokenTypeKeyword,
		"WITH":     models.TokenTypeKeyword,
		"TIES":     models.TokenTypeKeyword,
		"NULLS":    models.TokenTypeKeyword,
		"FIRST":    models.TokenTypeKeyword,
		"LAST":     models.TokenTypeKeyword,
	}

	// Initialize compound keywords
	k.CompoundKeywords = map[string]models.TokenType{
		"FULL JOIN":    models.TokenTypeKeyword,
		"CROSS JOIN":   models.TokenTypeKeyword,
		"NATURAL JOIN": models.TokenTypeKeyword,
		"GROUP BY":     models.TokenTypeKeyword,
		"ORDER BY":     models.TokenTypeKeyword,
		"LEFT JOIN":    models.TokenTypeKeyword,
	}

	// Add all keywords to the main keyword map
	for word, tokenType := range k.DMLKeywords {
		k.keywordMap[word] = Keyword{
			Word:     word,
			Type:     tokenType,
			Reserved: true,
		}
		k.reservedKeywords[word] = true
	}

	for word, tokenType := range k.CompoundKeywords {
		k.keywordMap[word] = Keyword{
			Word:     word,
			Type:     tokenType,
			Reserved: true,
		}
		k.reservedKeywords[word] = true
	}
}

// IsKeyword checks if a string is a keyword
func (k *Keywords) IsKeyword(s string) bool {
	if k.ignoreCase {
		s = strings.ToUpper(s)
	}
	_, ok := k.keywordMap[s]
	return ok
}

// GetKeywordType returns the token type for a keyword
func (k *Keywords) GetKeywordType(s string) models.TokenType {
	if k.ignoreCase {
		s = strings.ToUpper(s)
	}
	if kw, ok := k.keywordMap[s]; ok {
		return kw.Type
	}
	return models.TokenTypeWord
}

// IsReserved checks if a keyword is reserved
func (k *Keywords) IsReserved(s string) bool {
	if k.ignoreCase {
		s = strings.ToUpper(s)
	}
	return k.reservedKeywords[s]
}
