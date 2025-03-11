package keywords

import (
	"strings"

	"github.com/ajitpratapsingh/GoSQLX/pkg/models"
)

// Reserved keywords that can't be used as table aliases
var RESERVED_FOR_TABLE_ALIAS = []Keyword{
	{Word: "AS", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "WITH", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "EXPLAIN", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "ANALYZE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "SELECT", Type: models.TokenTypeSelect, Reserved: true, ReservedForTableAlias: true},
	{Word: "WHERE", Type: models.TokenTypeWhere, Reserved: true, ReservedForTableAlias: true},
	{Word: "GROUP", Type: models.TokenTypeGroup, Reserved: true, ReservedForTableAlias: true},
	{Word: "SORT", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "HAVING", Type: models.TokenTypeHaving, Reserved: true, ReservedForTableAlias: true},
	{Word: "ORDER", Type: models.TokenTypeOrder, Reserved: true, ReservedForTableAlias: true},
	{Word: "PIVOT", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "UNPIVOT", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "TOP", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "LATERAL", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "VIEW", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "LIMIT", Type: models.TokenTypeLimit, Reserved: true, ReservedForTableAlias: true},
	{Word: "OFFSET", Type: models.TokenTypeOffset, Reserved: true, ReservedForTableAlias: true},
	{Word: "FETCH", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "UNION", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "EXCEPT", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "INTERSECT", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "MINUS", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "ON", Type: models.TokenTypeOn, Reserved: true, ReservedForTableAlias: true},
	{Word: "JOIN", Type: models.TokenTypeJoin, Reserved: true, ReservedForTableAlias: true},
	{Word: "INNER", Type: models.TokenTypeInner, Reserved: true, ReservedForTableAlias: true},
	{Word: "CROSS", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "FULL", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "LEFT", Type: models.TokenTypeLeft, Reserved: true, ReservedForTableAlias: true},
	{Word: "RIGHT", Type: models.TokenTypeRight, Reserved: true, ReservedForTableAlias: true},
	{Word: "NATURAL", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "USING", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "CLUSTER", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "DISTRIBUTE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "GLOBAL", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "ANTI", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "SEMI", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "RETURNING", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "ASOF", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "MATCH_CONDITION", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "OUTER", Type: models.TokenTypeOuter, Reserved: true, ReservedForTableAlias: true},
	{Word: "SET", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "QUALIFY", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "WINDOW", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "END", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "FOR", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "PARTITION", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "PREWHERE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "SETTINGS", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "FORMAT", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "START", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "CONNECT", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "AND", Type: models.TokenTypeAnd, Reserved: true, ReservedForTableAlias: true},
	{Word: "LIKE", Type: models.TokenTypeLike, Reserved: true, ReservedForTableAlias: true},
	{Word: "ASC", Type: models.TokenTypeAsc, Reserved: true, ReservedForTableAlias: true},
	{Word: "MATCH_RECOGNIZE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "SAMPLE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "TABLESAMPLE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "FROM", Type: models.TokenTypeFrom, Reserved: true, ReservedForTableAlias: true},
	{Word: "BY", Type: models.TokenTypeBy, Reserved: true, ReservedForTableAlias: true},
	{Word: "OR", Type: models.TokenTypeOr, Reserved: true, ReservedForTableAlias: true},
	{Word: "NOT", Type: models.TokenTypeNot, Reserved: true, ReservedForTableAlias: true},
	{Word: "IN", Type: models.TokenTypeIn, Reserved: true, ReservedForTableAlias: true},
	{Word: "COUNT", Type: models.TokenTypeCount, Reserved: true, ReservedForTableAlias: true},
	{Word: "SUM", Type: models.TokenTypeSum, Reserved: true, ReservedForTableAlias: true},
	{Word: "AVG", Type: models.TokenTypeAvg, Reserved: true, ReservedForTableAlias: true},
	{Word: "MIN", Type: models.TokenTypeMin, Reserved: true, ReservedForTableAlias: true},
	{Word: "MAX", Type: models.TokenTypeMax, Reserved: true, ReservedForTableAlias: true},
}

var ADDITIONAL_KEYWORDS = []Keyword{
	{Word: "BETWEEN", Type: models.TokenTypeBetween, Reserved: true, ReservedForTableAlias: false},
	{Word: "IS", Type: models.TokenTypeIs, Reserved: true, ReservedForTableAlias: false},
	{Word: "NULL", Type: models.TokenTypeNull, Reserved: true, ReservedForTableAlias: false},
	{Word: "TRUE", Type: models.TokenTypeTrue, Reserved: true, ReservedForTableAlias: false},
	{Word: "FALSE", Type: models.TokenTypeFalse, Reserved: true, ReservedForTableAlias: false},
	{Word: "ASC", Type: models.TokenTypeAsc, Reserved: true, ReservedForTableAlias: false},
	{Word: "DESC", Type: models.TokenTypeDesc, Reserved: true, ReservedForTableAlias: false},
	{Word: "CASE", Type: models.TokenTypeCase, Reserved: true, ReservedForTableAlias: false},
	{Word: "WHEN", Type: models.TokenTypeWhen, Reserved: true, ReservedForTableAlias: false},
	{Word: "THEN", Type: models.TokenTypeThen, Reserved: true, ReservedForTableAlias: false},
	{Word: "ELSE", Type: models.TokenTypeElse, Reserved: true, ReservedForTableAlias: false},
	{Word: "END", Type: models.TokenTypeEnd, Reserved: true, ReservedForTableAlias: false},
}

// addKeywordsWithCategory is a helper method to add multiple keywords
// New creates a new Keywords instance with the specified dialect and case sensitivity
func New(dialect SQLDialect, ignoreCase bool) *Keywords {
	k := &Keywords{
		reservedKeywords: make(map[string]bool),
		keywordMap:       make(map[string]Keyword),
		dialect:          dialect,
		ignoreCase:       true, // Always use case-insensitive comparison for SQL keywords
		CompoundKeywords: make(map[string]models.TokenType),
	}

	// Initialize compound keywords
	k.CompoundKeywords["GROUP BY"] = models.TokenTypeKeyword
	k.CompoundKeywords["ORDER BY"] = models.TokenTypeKeyword
	k.CompoundKeywords["LEFT JOIN"] = models.TokenTypeKeyword
	k.CompoundKeywords["FULL JOIN"] = models.TokenTypeKeyword
	k.CompoundKeywords["CROSS JOIN"] = models.TokenTypeKeyword
	k.CompoundKeywords["NATURAL JOIN"] = models.TokenTypeKeyword

	// Add standard keywords
	k.addKeywordsWithCategory(RESERVED_FOR_TABLE_ALIAS)
	k.addKeywordsWithCategory(ADDITIONAL_KEYWORDS)

	// Add dialect-specific keywords
	switch dialect {
	case DialectMySQL:
		k.addKeywordsWithCategory(MYSQL_SPECIFIC)
	case DialectPostgreSQL:
		k.addKeywordsWithCategory(POSTGRESQL_SPECIFIC)
	case DialectSQLite:
		k.addKeywordsWithCategory(SQLITE_SPECIFIC)
	}

	return k
}

func (k *Keywords) addKeywordsWithCategory(keywords []Keyword) {
	for _, kw := range keywords {
		if !k.containsKeyword(kw.Word) {
			if k.ignoreCase {
				k.keywordMap[strings.ToUpper(kw.Word)] = kw
				if kw.Reserved {
					k.reservedKeywords[strings.ToUpper(kw.Word)] = true
				}
			} else {
				k.keywordMap[kw.Word] = kw
				if kw.Reserved {
					k.reservedKeywords[kw.Word] = true
				}
			}
		}
	}
}

// containsKeyword checks if a keyword already exists in the collection
func (k *Keywords) containsKeyword(word string) bool {
	if k.ignoreCase {
		_, exists := k.keywordMap[strings.ToUpper(word)]
		return exists
	}
	_, exists := k.keywordMap[word]
	return exists
}

// GetTokenType returns the token type for a given keyword
func (k *Keywords) GetTokenType(word string) models.TokenType {
	var key string
	if k.ignoreCase {
		key = strings.ToUpper(word)
	} else {
		key = word
	}

	if kw, ok := k.keywordMap[key]; ok {
		return kw.Type
	}
	return models.TokenTypeWord
}
