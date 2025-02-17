package keywords

import (
	"GoSQLX/pkg/models"
)

// Window keywords
func (k *Keywords) getWindowKeywords() []Keyword {
	return []Keyword{
		// Window Functions
		{"ROW_NUMBER", models.TokenTypeKeyword, true, false},
		{"RANK", models.TokenTypeKeyword, true, false},
		{"DENSE_RANK", models.TokenTypeKeyword, true, false},
		{"NTILE", models.TokenTypeKeyword, true, false},
		{"PERCENT_RANK", models.TokenTypeKeyword, true, false},
		{"CUME_DIST", models.TokenTypeKeyword, true, false},
		{"LAG", models.TokenTypeKeyword, true, false},
		{"LEAD", models.TokenTypeKeyword, true, false},
		{"FIRST_VALUE", models.TokenTypeKeyword, true, false},
		{"LAST_VALUE", models.TokenTypeKeyword, true, false},
		{"NTH_VALUE", models.TokenTypeKeyword, true, false},
		{"OVER", models.TokenTypeKeyword, true, false},
		{"PARTITION", models.TokenTypeKeyword, true, false},
		{"ORDER", models.TokenTypeKeyword, true, false},
		{"ROWS", models.TokenTypeKeyword, true, false},
		{"RANGE", models.TokenTypeKeyword, true, false},
		{"GROUPS", models.TokenTypeKeyword, true, false},
		{"UNBOUNDED", models.TokenTypeKeyword, true, false},
		{"PRECEDING", models.TokenTypeKeyword, true, false},
		{"FOLLOWING", models.TokenTypeKeyword, true, false},
		{"CURRENT ROW", models.TokenTypeKeyword, true, false},
	}
}
