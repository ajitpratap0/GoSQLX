package keywords

import (
	"github.com/ajitpratapsingh/GoSQLX/pkg/models"
)

// Basic SQL clause keywords
func (k *Keywords) getBasicKeywords() []Keyword {
	return []Keyword{
		{Word: "SELECT", Type: models.TokenTypeSelect, Reserved: true, ReservedForTableAlias: false},
		{Word: "FROM", Type: models.TokenTypeFrom, Reserved: true, ReservedForTableAlias: false},
		{Word: "WHERE", Type: models.TokenTypeWhere, Reserved: true, ReservedForTableAlias: false},
		{Word: "GROUP", Type: models.TokenTypeGroup, Reserved: true, ReservedForTableAlias: false},
		{Word: "BY", Type: models.TokenTypeBy, Reserved: true, ReservedForTableAlias: false},
		{Word: "HAVING", Type: models.TokenTypeHaving, Reserved: true, ReservedForTableAlias: false},
		{Word: "ORDER", Type: models.TokenTypeOrder, Reserved: true, ReservedForTableAlias: false},
		{Word: "LIMIT", Type: models.TokenTypeLimit, Reserved: true, ReservedForTableAlias: false},
		{Word: "OFFSET", Type: models.TokenTypeOffset, Reserved: true, ReservedForTableAlias: false},
		{Word: "AS", Type: models.TokenTypeAs, Reserved: true, ReservedForTableAlias: true},
		{Word: "WITH", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "TOP", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "DISTINCT", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "FETCH", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "ONLY", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "QUALIFY", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "UNION", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "INTERSECT", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "EXCEPT", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
	}
}
