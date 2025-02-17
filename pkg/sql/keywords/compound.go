package keywords

import (
	"strings"

	"github.com/ajitpratapsingh/GoSQLX/pkg/models"
)

func (k *Keywords) CompoundKeywords() map[string]models.TokenType {
	return map[string]models.TokenType{
		"GROUP BY":     models.TokenTypeGroupBy,
		"ORDER BY":     models.TokenTypeOrderBy,
		"LEFT JOIN":    models.TokenTypeLeftJoin,
		"RIGHT JOIN":   models.TokenTypeRightJoin,
		"INNER JOIN":   models.TokenTypeInnerJoin,
		"OUTER JOIN":   models.TokenTypeOuterJoin,
		"FULL JOIN":    models.TokenTypeFullJoin,
		"CROSS JOIN":   models.TokenTypeCrossJoin,
		"NATURAL JOIN": models.TokenTypeNaturalJoin,
	}
}

func (k *Keywords) IsCompoundKeywordStart(word string) bool {
	word = strings.ToUpper(word)
	compoundKeywords := k.CompoundKeywords()
	for key := range compoundKeywords {
		parts := strings.Split(key, " ")
		if len(parts) > 0 && parts[0] == word {
			return true
		}
	}
	return false
}
