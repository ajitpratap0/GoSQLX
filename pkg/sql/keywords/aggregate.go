package keywords

import (
	"github.com/ajitpratapsingh/GoSQLX/pkg/models"
)

// Aggregate keywords
func (k *Keywords) getAggregateKeywords() []Keyword {
	return []Keyword{
		{Word: "COUNT", Type: models.TokenTypeCount, Reserved: false, ReservedForTableAlias: false},
		{Word: "SUM", Type: models.TokenTypeSum, Reserved: false, ReservedForTableAlias: false},
		{Word: "AVG", Type: models.TokenTypeAvg, Reserved: false, ReservedForTableAlias: false},
		{Word: "MIN", Type: models.TokenTypeMin, Reserved: false, ReservedForTableAlias: false},
		{Word: "MAX", Type: models.TokenTypeMax, Reserved: false, ReservedForTableAlias: false},
		{Word: "STDDEV_POP", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
		{Word: "STDDEV_SAMP", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
		{Word: "VAR_POP", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
		{Word: "VAR_SAMP", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
		{Word: "PERCENTILE_CONT", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
		{Word: "PERCENTILE_DISC", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	}
}
