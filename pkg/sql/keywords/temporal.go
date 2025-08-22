package keywords

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Temporal keywords
func (k *Keywords) getTemporalKeywords() []Keyword {
	return []Keyword{
		{"YEAR", models.TokenTypeKeyword, true, false},
		{"MONTH", models.TokenTypeKeyword, true, false},
		{"DAY", models.TokenTypeKeyword, true, false},
		{"HOUR", models.TokenTypeKeyword, true, false},
		{"MINUTE", models.TokenTypeKeyword, true, false},
		{"SECOND", models.TokenTypeKeyword, true, false},
		{"MICROSECOND", models.TokenTypeKeyword, true, false},
		{"QUARTER", models.TokenTypeKeyword, true, false},
		{"WEEK", models.TokenTypeKeyword, true, false},
		{"DATE", models.TokenTypeKeyword, true, false},
		{"TIME", models.TokenTypeKeyword, true, false},
		{"DATETIME", models.TokenTypeKeyword, true, false},
		{"TIMESTAMP", models.TokenTypeKeyword, true, false},
		{"INTERVAL", models.TokenTypeKeyword, true, false},
		{"CURRENT_DATE", models.TokenTypeKeyword, true, false},
		{"CURRENT_TIME", models.TokenTypeKeyword, true, false},
		{"CURRENT_TIMESTAMP", models.TokenTypeKeyword, true, false},
		{"LOCALTIME", models.TokenTypeKeyword, true, false},
		{"LOCALTIMESTAMP", models.TokenTypeKeyword, true, false},
		{"NOW", models.TokenTypeKeyword, true, false},
		{"TODAY", models.TokenTypeKeyword, true, false},
		{"TOMORROW", models.TokenTypeKeyword, true, false},
		{"YESTERDAY", models.TokenTypeKeyword, true, false},
	}
}
