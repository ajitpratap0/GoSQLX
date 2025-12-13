package keywords

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// KeywordCategory represents a category of SQL keywords mapped to their token types.
// Each category groups related keywords together (e.g., DML keywords, compound keywords).
type KeywordCategory map[string]models.TokenType

// Keywords holds all SQL keyword categories and configuration for a specific SQL dialect.
//
// This is the main structure for keyword management, containing:
//   - Keyword categorization (DML, compound keywords)
//   - Complete keyword mapping to token types
//   - Reserved keyword tracking
//   - Dialect-specific configuration
//   - Case sensitivity settings
//
// Use New() to create a properly initialized Keywords instance:
//
//	kw := keywords.New(keywords.DialectPostgreSQL, true)
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
		"DISTINCT": models.TokenTypeDistinct,
		"ALL":      models.TokenTypeAll,
		"FETCH":    models.TokenTypeFetch,
		"NEXT":     models.TokenTypeNext,
		"ROWS":     models.TokenTypeRows,
		"ONLY":     models.TokenTypeOnly,
		"WITH":     models.TokenTypeWith,
		"TIES":     models.TokenTypeTies,
		"NULLS":    models.TokenTypeNulls,
		"FIRST":    models.TokenTypeFirst,
		"LAST":     models.TokenTypeLast,
		"PERCENT":  models.TokenTypePercent,  // SQL-99 FETCH ... PERCENT ROWS
		"ROLLUP":   models.TokenTypeRollup,   // SQL-99 grouping operation
		"CUBE":     models.TokenTypeCube,     // SQL-99 grouping operation
		"GROUPING": models.TokenTypeGrouping, // SQL-99 GROUPING SETS
		"SETS":     models.TokenTypeSets,     // SQL-99 GROUPING SETS
	}

	// Initialize compound keywords
	k.CompoundKeywords = map[string]models.TokenType{
		"FULL JOIN":     models.TokenTypeKeyword,
		"CROSS JOIN":    models.TokenTypeKeyword,
		"NATURAL JOIN":  models.TokenTypeKeyword,
		"GROUP BY":      models.TokenTypeKeyword,
		"ORDER BY":      models.TokenTypeKeyword,
		"LEFT JOIN":     models.TokenTypeKeyword,
		"GROUPING SETS": models.TokenTypeKeyword, // SQL-99 grouping operation
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

// IsKeyword checks if a string is a recognized SQL keyword.
// Returns true if the word is found in the keyword map, false otherwise.
//
// The check is case-insensitive when the Keywords instance was created
// with case-insensitive matching (default).
//
// Example:
//
//	kw := keywords.New(keywords.DialectGeneric, true)
//	kw.IsKeyword("SELECT")   // true
//	kw.IsKeyword("select")   // true (case-insensitive)
//	kw.IsKeyword("unknown")  // false
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

// IsReserved checks if a keyword is reserved and cannot be used as an identifier.
// Reserved keywords include SQL statements (SELECT, INSERT), clauses (WHERE, FROM),
// and other keywords that have special meaning in SQL syntax.
//
// Example:
//
//	kw := keywords.New(keywords.DialectGeneric, true)
//	kw.IsReserved("SELECT")      // true - reserved keyword
//	kw.IsReserved("ROW_NUMBER")  // false - window function (non-reserved)
func (k *Keywords) IsReserved(s string) bool {
	if k.ignoreCase {
		s = strings.ToUpper(s)
	}
	return k.reservedKeywords[s]
}
